package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &ControlResource{}
var _ resource.ResourceWithImportState = &ControlResource{}

func NewControlResource() resource.Resource {
	return &ControlResource{}
}

type ControlResource struct {
	client *ACAClient
}

type ControlResourceModel struct {
	ID                 types.String `tfsdk:"id"`
	Title              types.String `tfsdk:"title"`
	Description        types.String `tfsdk:"description"`
	Category           types.String `tfsdk:"category"`
	Soc2Mapping        types.String `tfsdk:"soc2_mapping"`
	Severity           types.String `tfsdk:"severity"`
	Adapter            types.String `tfsdk:"adapter"`
	CheckType          types.String `tfsdk:"check_type"`
	CheckConfig        types.String `tfsdk:"check_config"`
	RemediationEnabled types.Bool   `tfsdk:"remediation_enabled"`
	RemediationConfig  types.String `tfsdk:"remediation_config"`
	Automated          types.Bool   `tfsdk:"automated"`
	Active             types.Bool   `tfsdk:"active"`
	CreatedAt          types.String `tfsdk:"created_at"`
}

func (r *ControlResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_control"
}

func (r *ControlResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a custom compliance control in ACA.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier assigned by ACA.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"title": schema.StringAttribute{
				MarkdownDescription: "Human-readable title of the control.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Detailed description of what the control checks.",
				Required:            true,
			},
			"category": schema.StringAttribute{
				MarkdownDescription: "Trust Service Category: SECURITY, AVAILABILITY, CONFIDENTIALITY, PROCESSING_INTEGRITY, PRIVACY.",
				Required:            true,
			},
			"soc2_mapping": schema.StringAttribute{
				MarkdownDescription: "SOC 2 control mapping, e.g. CC6.1.",
				Required:            true,
			},
			"severity": schema.StringAttribute{
				MarkdownDescription: "Severity level: critical, high, medium, low.",
				Required:            true,
			},
			"adapter": schema.StringAttribute{
				MarkdownDescription: "Target cloud adapter: aws, azure, gcp, github, custom.",
				Required:            true,
			},
			"check_type": schema.StringAttribute{
				MarkdownDescription: "Type of check: api, cli, config, custom.",
				Required:            true,
			},
			"check_config": schema.StringAttribute{
				MarkdownDescription: "JavaScript/TypeScript implementation of the check function.",
				Required:            true,
			},
			"remediation_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether auto-remediation is enabled.",
				Optional:            true,
				Computed:            true,
			},
			"remediation_config": schema.StringAttribute{
				MarkdownDescription: "JavaScript/TypeScript implementation of the remediation function.",
				Optional:            true,
			},
			"automated": schema.BoolAttribute{
				MarkdownDescription: "Whether the control runs automatically during scans.",
				Optional:            true,
				Computed:            true,
			},
			"active": schema.BoolAttribute{
				MarkdownDescription: "Whether the control is active.",
				Computed:            true,
			},
			"created_at": schema.StringAttribute{
				MarkdownDescription: "Timestamp when the control was created.",
				Computed:            true,
			},
		},
	}
}

func (r *ControlResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*ACAClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data", "Expected *ACAClient")
		return
	}
	r.client = client
}

func (r *ControlResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ControlResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]interface{}{
		"id":                  plan.ID.ValueString(),
		"title":               plan.Title.ValueString(),
		"description":         plan.Description.ValueString(),
		"category":            plan.Category.ValueString(),
		"soc2Mapping":         plan.Soc2Mapping.ValueString(),
		"severity":            plan.Severity.ValueString(),
		"adapter":             plan.Adapter.ValueString(),
		"checkType":           plan.CheckType.ValueString(),
		"checkConfig":         plan.CheckConfig.ValueString(),
		"remediationEnabled":  plan.RemediationEnabled.ValueBool(),
		"remediationConfig":   plan.RemediationConfig.ValueString(),
		"automated":           plan.Automated.ValueBool(),
	}

	body, _ := json.Marshal(payload)
	httpReq, _ := http.NewRequestWithContext(ctx, "POST", r.client.Host+"/controls/custom", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	if r.client.ApiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.client.ApiKey)
	}

	httpResp, err := r.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create control: %s", err))
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusCreated {
		resp.Diagnostics.AddError("API Error", fmt.Sprintf("Unexpected status code: %d", httpResp.StatusCode))
		return
	}

	var result map[string]interface{}
	json.NewDecoder(httpResp.Body).Decode(&result)

	control := result["control"].(map[string]interface{})
	plan.ID = types.StringValue(control["id"].(string))
	plan.CreatedAt = types.StringValue(control["createdAt"].(string))
	plan.Active = types.BoolValue(control["active"].(bool))

	tflog.Info(ctx, "Created ACA control", map[string]interface{}{"id": plan.ID.ValueString()})

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *ControlResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ControlResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	httpReq, _ := http.NewRequestWithContext(ctx, "GET", r.client.Host+"/controls/custom/"+state.ID.ValueString(), nil)
	if r.client.ApiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.client.ApiKey)
	}

	httpResp, err := r.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read control: %s", err))
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	var control map[string]interface{}
	json.NewDecoder(httpResp.Body).Decode(&control)

	state.Title = types.StringValue(control["title"].(string))
	state.Description = types.StringValue(control["description"].(string))
	state.Active = types.BoolValue(control["active"].(bool))

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *ControlResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ControlResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]interface{}{
		"title":              plan.Title.ValueString(),
		"description":        plan.Description.ValueString(),
		"category":           plan.Category.ValueString(),
		"severity":           plan.Severity.ValueString(),
		"checkConfig":        plan.CheckConfig.ValueString(),
		"remediationEnabled": plan.RemediationEnabled.ValueBool(),
		"automated":          plan.Automated.ValueBool(),
	}

	body, _ := json.Marshal(payload)
	httpReq, _ := http.NewRequestWithContext(ctx, "PUT", r.client.Host+"/controls/custom/"+plan.ID.ValueString(), bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	if r.client.ApiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.client.ApiKey)
	}

	httpResp, err := r.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update control: %s", err))
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		resp.Diagnostics.AddError("API Error", fmt.Sprintf("Unexpected status code: %d", httpResp.StatusCode))
		return
	}

	tflog.Info(ctx, "Updated ACA control", map[string]interface{}{"id": plan.ID.ValueString()})

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *ControlResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ControlResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	httpReq, _ := http.NewRequestWithContext(ctx, "DELETE", r.client.Host+"/controls/custom/"+state.ID.ValueString(), nil)
	if r.client.ApiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.client.ApiKey)
	}

	httpResp, err := r.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete control: %s", err))
		return
	}
	defer httpResp.Body.Close()

	tflog.Info(ctx, "Deleted ACA control", map[string]interface{}{"id": state.ID.ValueString()})
}

func (r *ControlResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
