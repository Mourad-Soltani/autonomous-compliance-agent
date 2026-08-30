package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &TemplateDataSource{}

func NewTemplateDataSource() datasource.DataSource {
	return &TemplateDataSource{}
}

type TemplateDataSource struct {
	client *ACAClient
}

type TemplateDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Title       types.String `tfsdk:"title"`
	Category    types.String `tfsdk:"category"`
	Soc2Mapping types.String `tfsdk:"soc2_mapping"`
	Severity    types.String `tfsdk:"severity"`
	Automated   types.Bool   `tfsdk:"automated"`
	Adapter     types.String `tfsdk:"adapter"`
}

func (d *TemplateDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_template"
}

func (d *TemplateDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Fetches a policy template from ACA.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The template ID to look up. e.g. CC6.1",
				Required:            true,
			},
			"title": schema.StringAttribute{
				Computed: true,
			},
			"category": schema.StringAttribute{
				Computed: true,
			},
			"soc2_mapping": schema.StringAttribute{
				Computed: true,
			},
			"severity": schema.StringAttribute{
				Computed: true,
			},
			"automated": schema.BoolAttribute{
				Computed: true,
			},
			"adapter": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *TemplateDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*ACAClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data", "Expected *ACAClient")
		return
	}
	d.client = client
}

func (d *TemplateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state TemplateDataSourceModel
	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	httpReq, _ := http.NewRequestWithContext(ctx, "GET", d.client.Host+"/templates", nil)
	if d.client.ApiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+d.client.ApiKey)
	}

	httpResp, err := d.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to fetch templates: %s", err))
		return
	}
	defer httpResp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(httpResp.Body).Decode(&result)

	templates := result["templates"].([]interface{})
	for _, t := range templates {
		template := t.(map[string]interface{})
		if template["id"].(string) == state.ID.ValueString() {
			state.Title = types.StringValue(template["title"].(string))
			state.Category = types.StringValue(template["category"].(string))
			state.Soc2Mapping = types.StringValue(template["soc2Mapping"].(string))
			state.Severity = types.StringValue(template["severity"].(string))
			state.Automated = types.BoolValue(template["automated"].(bool))
			state.Adapter = types.StringValue(template["adapter"].(string))
			break
		}
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}
