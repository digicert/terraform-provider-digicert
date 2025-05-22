package digicert

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider = &digicertProvider{}
)

// digicertProviderModel maps provider schema data to a Go type.
type authProviderModel struct {
	Url    types.String `tfsdk:"url"`
	ApiKey types.String `tfsdk:"api_key"`
}

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &digicertProvider{}
	}
}

// digicertProvider is the provider implementation.
type digicertProvider struct {
}

// Metadata returns the provider type name.
func (p *digicertProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "digicert"
}

// Schema defines the provider-level schema for configuration data.
func (p *digicertProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Description: "The URL of the Digicert server",
				Required:    true,
			},
			"api_key": schema.StringAttribute{
				Description: "The API key for the Digicert server",
				Required:    true,
			},
		},
	}
}

func (p *digicertProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// Retrieve provider data from configuration
	var config authProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.

	var url, apiKey string
	if !config.Url.IsNull() {
		url = config.Url.ValueString()
	}
	if !config.ApiKey.IsNull() {
		apiKey = config.ApiKey.ValueString()
	}

	if len(url) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("url"),
			MissingAPIURLError,
			"URL is required for the digicert provider",
		)
	}

	if len(apiKey) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("api_key"),
			MissingAPIKeyError,
			"API key is required for the digicert provider",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := NewClient(url, apiKey)
	if err != nil {
		resp.Diagnostics.AddError(
			ClientConfigureError,
			"Digicert Client Error: "+err.Error(),
		)
		return
	}

	resp.ResourceData = client
}

// DataSources defines the data sources implemented in the provider.
func (p *digicertProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// Resources defines the resources implemented in the provider.
func (p *digicertProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertificateResource,
	}
}
