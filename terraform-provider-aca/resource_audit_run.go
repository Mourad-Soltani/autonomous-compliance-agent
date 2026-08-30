package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &AuditRunResource{}

func NewAuditRunResource() resource.Resource {
	return &AuditRunResource{}
}

type AuditRunResource struct {
	client *ACAClient
}

type AuditRunResourceModel struct {
	ID              types.String   `tfsdk:"id"`
	Name            types.String   `tfsdk:"name"`
	Adapters        types.List     `tfsdk:"adapters"`
	Controls        types.List     `tfsdk:"controls"`
	AutoRemediate   types.Bool     `tfsdk:"auto_remediate"`
	Notify          types.Bool     `tfsdk:"notify"`
	Status          types.String   `tfsdk:"status"`
	StartedAt       types.String   `tfsdk:"started_at"`
	CompletedAt     types.String   `tfsdk:"completed_at"`
	FindingsCount   types.Int64    `tfsdk:"findings_count"`
	PassedControls  types.Int64    `tfsdk:"passed_controls"`
	FailedControls  types.Int64    `tfsdk:"failed_controls"`
}

func (r *AuditRunResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_audit_run"
}

func (r *AuditRunResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Triggers a compliance audit run in ACA. This resource represents a one-time scan.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier of the audit run.",
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Human-readable name for the audit run.",
				Required:            true,
			},
			"adapters": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of adapters to scan. e.g. ["aws", "azure"].",
				Optional:            true,
			},
			"controls": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Specific controls to check. e.g. ["CC6.1", "CC6.6"].",
				Optional:            true,
			},
			"auto_remediate": schema.BoolAttribute{
				MarkdownDescription: "Automatically remediate findings.",
				Optional:            true,
				Computed:            true,
			},
			"notify": schema.BoolAttribute{
				MarkdownDescription: "Send notifications on completion.",
				Optional:            true,
				Computed:            true,
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current status of the audit run.",
			},
			"started_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "When the scan started.",
			},
			"completed_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "When the scan completed.",
			},
			"findings_count": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Total findings discovered.",
			},
			"passed_controls": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Number of controls that passed.",
			},
			"failed_controls": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Number of controls that failed.",
			},
		},
	}
}

func (r *AuditRunResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *AuditRunResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AuditRunResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var adapters []string
	if !plan.Adapters.IsNull() && !plan.Adapters.IsUnknown() {
		diags = plan.Adapters.ElementsAs(ctx, &adapters, false)
		resp.Diagnostics.Append(diags...)
	}

	var controls []string
	if !plan.Controls.IsNull() && !plan.Controls.IsUnknown() {
		diags = plan.Controls.ElementsAs(ctx, &controls, false)
		resp.Diagnostics.Append(diags...)
	}

	payload := map[string]interface{}{
		"name":           plan.Name.ValueString(),
		"adapters":       adapters,
		"controls":       controls,
		"autoRemediate":  plan.AutoRemediate.ValueBool(),
		"notify":         plan.Notify.ValueBool(),
	}

	body, _ := json.Marshal(payload)
	httpReq, _ := http.NewRequestWithContext(ctx, "POST", r.client.Host+"/audit/run", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	if r.client.ApiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.client.ApiKey)
	}

	httpResp, err := r.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to trigger audit: %s", err))
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusAccepted {
		resp.Diagnostics.AddError("API Error", fmt.Sprintf("Unexpected status code: %d", httpResp.StatusCode))
		return
	}

	var result map[string]interface{}
	json.NewDecoder(httpResp.Body).Decode(&result)

	plan.ID = types.StringValue(result["id"].(string))
	plan.Status = types.StringValue(result["status"].(string))
	plan.StartedAt = types.StringValue(result["startedAt"].(string))

	tflog.Info(ctx, "Triggered ACA audit run", map[string]interface{}{"id": plan.ID.ValueString()})

	// Poll for completion
	r.pollForCompletion(ctx, &plan)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *AuditRunResource) pollForCompletion(ctx context.Context, state *AuditRunResourceModel) {
	for i := 0; i < 60; i++ {
		time.Sleep(10 * time.Second)

		httpReq, _ := http.NewRequestWithContext(ctx, "GET", r.client.Host+"/audit/runs/"+state.ID.ValueString(), nil)
		if r.client.ApiKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+r.client.ApiKey)
		}

		httpResp, err := r.client.HTTPClient.Do(httpReq)
		if err != nil {
			continue
		}

		var result map[string]interface{}
		json.NewDecoder(httpResp.Body).Decode(&result)
		httpResp.Body.Close()

		status := result["status"].(string)
		state.Status = types.StringValue(status)

		if status == "COMPLETED" || status == "FAILED" {
			if completedAt, ok := result["completedAt"].(string); ok {
				state.CompletedAt = types.StringValue(completedAt)
			}
			if fc, ok := result["findingsCount"].(float64); ok {
				state.FindingsCount = types.Int64Value(int64(fc))
			}
			if pc, ok := result["passedControls"].(float64); ok {
				state.PassedControls = types.Int64Value(int64(pc))
			}
			if fc, ok := result["failedControls"].(float64); ok {
				state.FailedControls = types.Int64Value(int64(fc))
			}
			break
		}
	}
}

func (r *AuditRunResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AuditRunResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	httpReq, _ := http.NewRequestWithContext(ctx, "GET", r.client.Host+"/audit/runs/"+state.ID.ValueString(), nil)
	if r.client.ApiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.client.ApiKey)
	}

	httpResp, err := r.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read audit run: %s", err))
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	var result map[string]interface{}
	json.NewDecoder(httpResp.Body).Decode(&result)

	state.Status = types.StringValue(result["status"].(string))
	if completedAt, ok := result["completedAt"].(string); ok {
		state.CompletedAt = types.StringValue(completedAt)
	}
	if fc, ok := result["findingsCount"].(float64); ok {
		state.FindingsCount = types.Int64Value(int64(fc))
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *AuditRunResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Audit runs are immutable after creation
	resp.Diagnostics.AddWarning("Immutable Resource", "Audit runs cannot be updated after creation. No changes applied.")
}

func (r *AuditRunResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Audit runs are retained for compliance history
	resp.Diagnostics.AddWarning("Retention Policy", "Audit runs are retained for compliance history and cannot be deleted via Terraform.")
}
