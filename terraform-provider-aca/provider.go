package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ACAProvider defines the provider implementation.
type ACAProvider struct {
	version string
}

// ACAProviderModel describes the provider data model.
type ACAProviderModel struct {
	Host    types.String `tfsdk:"host"`
	ApiKey  types.String `tfsdk:"api_key"`
	Timeout types.Int64  `tfsdk:"timeout"`
}

// ACAClient wraps the HTTP client for ACA API.
type ACAClient struct {
	Host      string
	ApiKey    string
	HTTPClient *http.Client
}

func NewProvider(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ACAProvider{
			version: version,
		}
	}
}

func (p *ACAProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "aca"
	resp.Version = p.version
}

func (p *ACAProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Interact with Autonomous Compliance Agent (ACA) API.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Description: "The ACA API host URL. e.g. https://aca.example.com",
				Required:    true,
			},
			"api_key": schema.StringAttribute{
				Description: "API key for authentication. Can be set via ACA_API_KEY env var.",
				Optional:    true,
				Sensitive:   true,
			},
			"timeout": schema.Int64Attribute{
				Description: "HTTP client timeout in seconds. Default: 30",
				Optional:    true,
			},
		},
	}
}

func (p *ACAProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config ACAProviderModel

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Host.IsUnknown() || config.Host.IsNull() || config.Host.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("host"),
			"Missing ACA API Host",
			"The provider cannot create the ACA API client as there is a missing or empty value for the host.",
		)
		return
	}

	timeout := 30
	if !config.Timeout.IsNull() && !config.Timeout.IsUnknown() {
		timeout = int(config.Timeout.ValueInt64())
	}

	client := &ACAClient{
		Host:       config.Host.ValueString(),
		ApiKey:     config.ApiKey.ValueString(),
		HTTPClient: &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}

	tflog.Info(ctx, "Configured ACA client", map[string]interface{}{
		"host": client.Host,
	})

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *ACAProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewControlResource,
		NewAuditRunResource,
	}
}

func (p *ACAProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewFindingDataSource,
		NewTemplateDataSource,
	}
}
