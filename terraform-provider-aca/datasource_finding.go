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

var _ datasource.DataSource = &FindingDataSource{}

func NewFindingDataSource() datasource.DataSource {
	return &FindingDataSource{}
}

type FindingDataSource struct {
	client *ACAClient
}

type FindingDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	ControlId   types.String `tfsdk:"control_id"`
	Title       types.String `tfsdk:"title"`
	Description types.String `tfsdk:"description"`
	Severity    types.String `tfsdk:"severity"`
	Status      types.String `tfsdk:"status"`
	Resource    types.String `tfsdk:"resource"`
	Adapter     types.String `tfsdk:"adapter"`
	AuditRunId  types.String `tfsdk:"audit_run_id"`
}

func (d *FindingDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_finding"
}

func (d *FindingDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Fetches a specific compliance finding from ACA.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The finding ID to look up.",
				Required:            true,
			},
			"control_id": schema.StringAttribute{
				Computed: true,
			},
			"title": schema.StringAttribute{
				Computed: true,
			},
			"description": schema.StringAttribute{
				Computed: true,
			},
			"severity": schema.StringAttribute{
				Computed: true,
			},
			"status": schema.StringAttribute{
				Computed: true,
			},
			"resource": schema.StringAttribute{
				Computed: true,
			},
			"adapter": schema.StringAttribute{
				Computed: true,
			},
			"audit_run_id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *FindingDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *FindingDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state FindingDataSourceModel
	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	httpReq, _ := http.NewRequestWithContext(ctx, "GET", d.client.Host+"/audit/runs/"+state.ID.ValueString(), nil)
	if d.client.ApiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+d.client.ApiKey)
	}

	httpResp, err := d.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read finding: %s", err))
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		resp.Diagnostics.AddError("API Error", fmt.Sprintf("Finding not found: %d", httpResp.StatusCode))
		return
	}

	var result map[string]interface{}
	json.NewDecoder(httpResp.Body).Decode(&result)

	state.ControlId = types.StringValue(result["controlId"].(string))
	state.Title = types.StringValue(result["title"].(string))
	state.Description = types.StringValue(result["description"].(string))
	state.Severity = types.StringValue(result["severity"].(string))
	state.Status = types.StringValue(result["status"].(string))
	state.Resource = types.StringValue(result["resource"].(string))
	state.Adapter = types.StringValue(result["adapter"].(string))
	state.AuditRunId = types.StringValue(result["auditRunId"].(string))

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}
