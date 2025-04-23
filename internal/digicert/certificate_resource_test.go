package digicert

import (
	"context"
	"errors"
	"testing"

	clientMocks "github.com/digicert/digicert-terraform-provider/internal/digicert/client/mocks"
	"github.com/digicert/digicert-terraform-provider/model"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
)

func generateSchema() schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Required: true,
			},
			"request_id": schema.StringAttribute{
				Required: true,
			},
			"csr": schema.StringAttribute{
				Required: true,
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
			"delivery_format": schema.StringAttribute{
				Optional: true,
			},
			"certificate": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func setupMockPlanCreate() tfsdk.Plan {

	stateData := tftypes.NewValue(
		tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"profile_id":      tftypes.String,
				"request_id":      tftypes.String,
				"csr":             tftypes.String,
				"common_name":     tftypes.String,
				"dns_names":       tftypes.String,
				"tags":            tftypes.String,
				"serial_number":   tftypes.String,
				"delivery_format": tftypes.String,
				"certificate":     tftypes.String,
			},
		},
		map[string]tftypes.Value{
			"profile_id":      tftypes.NewValue(tftypes.String, "test-profile"),
			"request_id":      tftypes.NewValue(tftypes.String, nil),
			"csr":             tftypes.NewValue(tftypes.String, nil),
			"common_name":     tftypes.NewValue(tftypes.String, "test.example.com"),
			"dns_names":       tftypes.NewValue(tftypes.String, nil),
			"tags":            tftypes.NewValue(tftypes.String, nil),
			"serial_number":   tftypes.NewValue(tftypes.String, nil),
			"delivery_format": tftypes.NewValue(tftypes.String, nil),
			"certificate":     tftypes.NewValue(tftypes.String, nil),
		},
	)

	plan := tfsdk.Plan{
		Schema: generateSchema(),
		Raw:    stateData,
	}
	return plan
}

func setupMockState(serialNumber interface{}) tfsdk.State {

	resourceSchema := generateSchema()

	stateData := tftypes.NewValue(
		tftypes.Object{
			AttributeTypes: map[string]tftypes.Type{
				"profile_id":      tftypes.String,
				"request_id":      tftypes.String,
				"csr":             tftypes.String,
				"common_name":     tftypes.String,
				"dns_names":       tftypes.String,
				"tags":            tftypes.String,
				"serial_number":   tftypes.String,
				"delivery_format": tftypes.String,
				"certificate":     tftypes.String,
			},
		},
		map[string]tftypes.Value{
			"profile_id":      tftypes.NewValue(tftypes.String, "test-profile"),
			"request_id":      tftypes.NewValue(tftypes.String, "test-request-id"),
			"csr":             tftypes.NewValue(tftypes.String, "test-csr"),
			"common_name":     tftypes.NewValue(tftypes.String, "test.example.com"),
			"dns_names":       tftypes.NewValue(tftypes.String, "test.example.com"),
			"tags":            tftypes.NewValue(tftypes.String, "test-tags"),
			"serial_number":   tftypes.NewValue(tftypes.String, serialNumber),
			"delivery_format": tftypes.NewValue(tftypes.String, "PEM"),
			"certificate":     tftypes.NewValue(tftypes.String, "test-certificate"),
		},
	)

	state := tfsdk.State{
		Schema: resourceSchema,
		Raw:    stateData,
	}

	return state
}

func TestCertificateResourceDelete_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClientService := clientMocks.NewMockClient(ctrl)

	certResource := CertificateResource{
		client: mockClientService,
	}

	state := setupMockState("12345")

	ctx := context.Background()

	mockClientService.EXPECT().RevokeCertificate("12345").Return(nil)

	req := resource.DeleteRequest{
		State: state,
	}

	resp := resource.DeleteResponse{
		Diagnostics: diag.Diagnostics{},
		State:       state,
	}

	certResource.Delete(ctx, req, &resp)

	assert.False(t, resp.Diagnostics.HasError(), "Expected no error, but got one")
}

func TestCertificateResourceDelete_Failure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClientService := clientMocks.NewMockClient(ctrl)

	certResource := CertificateResource{
		client: mockClientService,
	}

	state := setupMockState("invalid")

	ctx := context.Background()

	mockClientService.EXPECT().RevokeCertificate("invalid").Return(assert.AnError)

	req := resource.DeleteRequest{
		State: state,
	}

	resp := resource.DeleteResponse{
		Diagnostics: diag.Diagnostics{},
		State:       state,
	}

	certResource.Delete(ctx, req, &resp)

	assert.True(t, resp.Diagnostics.HasError(), "Expected an error, but got none")
}

func TestCertificateResourceCreate_Success(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dummyCertificateResponse := model.CertificateResponse{
		SerialNumber:   "1234567890",
		DeliveryFormat: "PEM",
		Certificate:    "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Q3z\n-----END CERTIFICATE-----",
		Status:         "issued",
		RequestID:      "req-1234abcd",
	}

	dummyProfileResponse := model.ProfileResponse{
		Id:                         "profile-1234abcd",
		Name:                       "Test Profile",
		Status:                     "active",
		SignatureAlgorithm:         "SHA256_WITH_RSA",
		OverrideCertValidityViaApi: true,
		CertificateDeliveryFormat:  "PEM",
		AccountId:                  "account-5678efgh",
		EnrollmentMethod:           "automatic",
		PrivateKeyAttributes: &model.PrivateKeyAttributes{
			KeySize: "2048",
		},
		AllowedKeySizes: []string{"2048", "4096"},
		Template: &model.Template{
			Name: "Default Template",
		},
	}

	mockClientService := clientMocks.NewMockClient(ctrl)

	certResource := CertificateResource{
		client: mockClientService,
	}

	state := setupMockPlanCreate()

	ctx := context.Background()

	mockClientService.EXPECT().GetProfile(gomock.Any()).Return(&dummyProfileResponse, nil)
	mockClientService.EXPECT().IssueCertificate(gomock.Any()).Return(&dummyCertificateResponse, nil)

	req := resource.CreateRequest{
		Plan: state,
	}

	resp := resource.CreateResponse{
		Diagnostics: diag.Diagnostics{},
		State:       tfsdk.State(state),
	}

	certResource.Create(ctx, req, &resp)

	assert.False(t, resp.Diagnostics.HasError(), "Expected no error, but got one")
}

func TestCertificateResourceCreate_ProfileNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClientService := clientMocks.NewMockClient(ctrl)
	certResource := CertificateResource{client: mockClientService}

	state := setupMockPlanCreate()
	ctx := context.Background()

	mockClientService.EXPECT().GetProfile(gomock.Any()).Return(nil, errors.New("profile not found"))

	req := resource.CreateRequest{Plan: state}
	resp := resource.CreateResponse{Diagnostics: diag.Diagnostics{}, State: tfsdk.State(state)}

	certResource.Create(ctx, req, &resp)

	assert.True(t, resp.Diagnostics.HasError(), "Expected an error when profile is not found")
}

func TestCertificateResourceCreate_CertificateIssuanceFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dummyProfileResponse := model.ProfileResponse{
		Id:                         "profile-1234abcd",
		Name:                       "Test Profile",
		Status:                     "active",
		SignatureAlgorithm:         "SHA256_WITH_RSA",
		OverrideCertValidityViaApi: true,
		CertificateDeliveryFormat:  "PEM",
		AccountId:                  "account-5678efgh",
		EnrollmentMethod:           "automatic",
		PrivateKeyAttributes: &model.PrivateKeyAttributes{
			KeySize: "2048",
		},
		AllowedKeySizes: []string{"2048", "4096"},
		Template: &model.Template{
			Name: "Default Template",
		},
	}

	mockClientService := clientMocks.NewMockClient(ctrl)
	certResource := CertificateResource{client: mockClientService}

	state := setupMockPlanCreate()
	ctx := context.Background()

	mockClientService.EXPECT().GetProfile(gomock.Any()).Return(&dummyProfileResponse, nil)
	mockClientService.EXPECT().IssueCertificate(gomock.Any()).Return(nil, errors.New("certificate issuance failed"))

	req := resource.CreateRequest{Plan: state}
	resp := resource.CreateResponse{Diagnostics: diag.Diagnostics{}, State: tfsdk.State(state)}

	certResource.Create(ctx, req, &resp)

	assert.True(t, resp.Diagnostics.HasError(), "Expected an error when certificate issuance fails")
}

func TestCertificateResourceCreate_InvalidPlanData(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClientService := clientMocks.NewMockClient(ctrl)
	certResource := CertificateResource{client: mockClientService}

	// Simulating an invalid plan
	state := tfsdk.Plan{
		tftypes.NewValue(nil, nil),
		schema.Schema{},
	}

	ctx := context.Background()
	req := resource.CreateRequest{Plan: state}
	resp := resource.CreateResponse{Diagnostics: diag.Diagnostics{}, State: tfsdk.State(state)}

	certResource.Create(ctx, req, &resp)

	assert.True(t, resp.Diagnostics.HasError(), "Expected an error due to invalid plan data")
}

func TestCertificateResourceRead_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClientService := clientMocks.NewMockClient(ctrl)

	certResource := CertificateResource{
		client: mockClientService,
	}

	dummyCertificateResponse := model.CertificateResponse{
		SerialNumber:   "1234567890",
		DeliveryFormat: "PEM",
		Certificate:    "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Q3z\n-----END CERTIFICATE-----",
		Status:         "issued",
		RequestID:      "req-1234abcd",
	}

	state := setupMockState(nil)

	ctx := context.Background()
	mockClientService.EXPECT().PickupCertificate(gomock.Any(), gomock.Any()).Return(&dummyCertificateResponse, false, nil)

	req := resource.ReadRequest{
		State: state,
	}

	resp := resource.ReadResponse{
		Diagnostics: diag.Diagnostics{},
		State:       state,
	}

	certResource.Read(ctx, req, &resp)

	assert.False(t, resp.Diagnostics.HasError(), "Expected no error, but got one")
}
