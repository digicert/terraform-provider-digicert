package digicert

import (
	"context"
	"fmt"
	"strings"

	"github.com/digicert/digicert-terraform-provider/model"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource = &CertificateResource{}
)

type certificateResourceModel struct {
	ProfileID      types.String `tfsdk:"profile_id"`
	RequestID      types.String `tfsdk:"request_id"`
	Csr            types.String `tfsdk:"csr"`
	CommonName     types.String `tfsdk:"common_name"`
	DnsNames       types.String `tfsdk:"dns_names"`
	Tags           types.String `tfsdk:"tags"`
	SerialNumber   types.String `tfsdk:"serial_number"`
	DeliveryFormat types.String `tfsdk:"delivery_format"`
	Certificate    types.String `tfsdk:"certificate"`
}

type issuanceData struct {
	cn         string
	dnsNames   []string
	profile    *model.ProfileResponse
	tags       []string
	csr        string
	privateKey []byte
	roleName   string
}

// NewCertificateResource is a helper function to simplify the provider implementation.
func NewCertificateResource() resource.Resource {
	return &CertificateResource{}
}

// certificateResource is the resource implementation.
type CertificateResource struct {
	client Client
}

// Metadata returns the resource type name.
func (r *CertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *CertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(Client)

	if !ok {
		resp.Diagnostics.AddError(
			ClientConfigureError,
			fmt.Sprintf("Expected digicert client, got: %T", req.ProviderData),
		)

		return
	}

	r.client = client
}

// Schema defines the schema for the resource.
func (r *CertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Required: true,
			},
			"csr": schema.StringAttribute{
				Optional: true,
			},
			"common_name": schema.StringAttribute{
				Required: true,
			},
			"dns_names": schema.StringAttribute{
				Optional: true,
			},
			"tags": schema.StringAttribute{
				Optional: true,
			},
			"serial_number": schema.StringAttribute{
				Computed: true,
			},
			"request_id": schema.StringAttribute{
				Computed: true,
			},
			"delivery_format": schema.StringAttribute{
				Computed: true,
			},
			"certificate": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *CertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan certificateResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		tflog.Debug(ctx, "Error retrieving values from plan")
		return
	}

	var issuanceData issuanceData
	var err error

	// Get Common Name
	if plan.CommonName.IsNull() {
		resp.Diagnostics.AddError(MissingCommonNameError, "Common Name is required")
		return
	}
	issuanceData.cn = plan.CommonName.ValueString()
	tflog.Debug(ctx, fmt.Sprintf("Common Name: %s", issuanceData.cn))

	// Get Profile ID
	var profileID string
	if !plan.ProfileID.IsNull() {
		profileID = plan.ProfileID.ValueString()
	} else {
		resp.Diagnostics.AddError(MissingProfileIDError, "Profile ID is required")
		return
	}

	issuanceData.profile, err = r.client.GetProfile(profileID)
	if err != nil {
		resp.Diagnostics.AddError(ProfileFetchError, "Unexpected error: "+err.Error())
		return
	}

	// Get DNS Name
	if plan.DnsNames.IsNull() {
		tflog.Debug(ctx, MissingDNSName)
	} else {
		issuanceData.dnsNames = strings.Split(plan.DnsNames.ValueString(), ",")
		tflog.Debug(ctx, fmt.Sprintf("DNS Names: %+v", issuanceData.dnsNames))
	}

	// Get Tags
	if !(plan.Tags.IsNull()) {
		issuanceData.tags = strings.Split(plan.Tags.ValueString(), ",")
		tflog.Debug(ctx, fmt.Sprintf("Tags: %+v", issuanceData.tags))
	}

	// Handle CSR
	if plan.Csr.IsNull() {
		tflog.Debug(ctx, "CSR is unknown, generating CSR")

		csr, key, err := generateCSR(&issuanceData)
		if err != nil {
			resp.Diagnostics.AddError(CSRGenerationError, "Unexpected error: "+err.Error())
			return
		}
		issuanceData.csr = csr
		issuanceData.privateKey = key
		tflog.Debug(ctx, fmt.Sprintf("Generated CSR: %s", issuanceData.csr))
	} else {
		issuanceData.csr = plan.Csr.ValueString()
		tflog.Debug(ctx, fmt.Sprintf("CSR provided: %s", issuanceData.csr))
	}

	// Ensure we have CSR before proceeding
	if issuanceData.csr == "" {
		resp.Diagnostics.AddError(CSRGenerationError, "CSR is required")
		return
	}

	// Create new certificate
	tflog.Debug(ctx, "Sending certificate request")
	certificateDetails, err := r.sendCertificateRequest(&issuanceData)
	if err != nil {
		resp.Diagnostics.AddError(CreateCertificateError, "Unexpected error: "+err.Error())
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("Certificate response: %+v", certificateDetails))

	// Map response body to schema and populate Computed attribute values
	plan.SerialNumber = types.StringValue(certificateDetails.SerialNumber)
	plan.DeliveryFormat = types.StringValue(certificateDetails.DeliveryFormat)
	plan.Certificate = types.StringValue(certificateDetails.Certificate)
	plan.RequestID = types.StringValue(certificateDetails.RequestID)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		tflog.Debug(ctx, "Error setting state")
		return
	}

	if len(certificateDetails.SerialNumber) > 0 {
		tflog.Debug(ctx, "Certificate issued successfully with serial number: "+certificateDetails.SerialNumber)
	} else {
		resp.Diagnostics.AddWarning("Certificate pending with request id - "+certificateDetails.RequestID, "Run terraform apply again to fetch the approved certificate.")
		tflog.Debug(ctx, "Certificate request submitted succesfully with request-id: "+certificateDetails.RequestID)
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *CertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {

	// Get current state
	var state certificateResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		resp.Diagnostics.AddWarning("Debug", "Error fetching state")
		return
	}

	if state.ProfileID.IsNull() {
		resp.Diagnostics.AddError(
			MissingProfileIDError, "Profile id not found in state",
		)
		return
	}

	if !(state.SerialNumber.IsNull()) && len(state.SerialNumber.ValueString()) > 0 {
		tflog.Debug(ctx, "Certificate already exists in state")

		certificateStatus, err := r.client.ReadCertificate(state.SerialNumber.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				CertificateFetchError,
				"Could not read certificate with serial number "+state.SerialNumber.ValueString()+": "+err.Error(),
			)
			return
		}

		if certificateStatus == "revoked" {
			resp.Diagnostics.AddWarning(
				CertificateRevokedError,
				"Certificate with serial number "+state.SerialNumber.ValueString()+" is already revoked.",
			)
      
			tflog.Debug(ctx, "Certificate is already revoked.")
		}

		return
	}

	if !(state.RequestID.IsNull()) && len(state.RequestID.ValueString()) > 0 {

		cert, status, err := r.client.PickupCertificate(state.RequestID.ValueString(), state.ProfileID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"CertificateFetchError",
				"Could not read certificate with request ID "+state.RequestID.ValueString()+": "+err.Error(),
			)
			return
		}

		if status {
			resp.Diagnostics.AddWarning(
				"CertificatePendingError",
				"Pending with request ID - "+state.RequestID.ValueString(),
			)
			return
		}

		// Overwrite items with refreshed state
		state.Certificate = types.StringValue(cert.Certificate)
		state.SerialNumber = types.StringValue(cert.SerialNumber)
		state.DeliveryFormat = types.StringValue(cert.DeliveryFormat)

		// Set refreshed state
		diags = resp.State.Set(ctx, &state)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			resp.Diagnostics.AddWarning("Debug", "Error setting state")
			return
		}
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *CertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {

	resp.Diagnostics.AddError(
		"Update operation not supported for digicert_certificate",
		"This operation is not supported by provider.",
	)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *CertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state certificateResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Revoking certificate: %s", map[string]interface{}{"serial_number": state.SerialNumber.ValueString()})

	serialNumber := state.SerialNumber.ValueString()
	if serialNumber == "" {
		resp.Diagnostics.AddError(
			CertificateDeleteError,
			MissingSerialNumberError,
		)
		return
	}
	err := r.client.RevokeCertificate(serialNumber)
	if err != nil {
		if err.Error() != CertificateRevokedError {
			resp.Diagnostics.AddError(
				CertificateDeleteError,
				"Could not delete certificate, unexpected error: "+err.Error(),
			)
			tflog.Error(ctx, "Certificate revoke failed: %s", map[string]interface{}{"error": err.Error()})
			return
		} else {
			tflog.Info(ctx, CertificateRevokedError, map[string]interface{}{"serial_number": serialNumber})
		}

	} else {
		tflog.Info(ctx, "Certificate revoked successfully", map[string]interface{}{"serial_number": serialNumber})
	}

	// Remove resource from Terraform state
	resp.State.RemoveResource(ctx)
}

func (r *CertificateResource) sendCertificateRequest(issuanceData *issuanceData) (*model.CertificateResponse, error) {
	request := buildIssuanceRequest(issuanceData)

	// Request certificate
	response, err := r.client.IssueCertificate(request)
	if err != nil {
		return nil, fmt.Errorf("unable to enroll certificate. error=%s", err)
	}

	return response, nil
}
