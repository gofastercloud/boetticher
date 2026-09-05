package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// ApplyBackupJobWithRunner reconciles the namespaced platform backup job via
// the operation-scoped root SSH runner. Proxmox authorizes cluster backup
// mutation with Sys.Modify at /; keeping this path on the temporary root
// transport avoids granting that broad privilege to the durable API token.
func ApplyBackupJobWithRunner(ctx context.Context, runner CommandRunner, address, user, planNode string, plan BackupJob) (bool, error) {
	if runner == nil || address == "" || user == "" || planNode == "" {
		return false, fmt.Errorf("root backup runner and target are required")
	}
	if plan.JobName == "" || plan.StorageTarget == "" || plan.VMIDList == "" || plan.Retention == "" {
		return false, fmt.Errorf("complete platform backup plan is required")
	}
	output, err := runner.Run(ctx, address, user, "pvesh get /cluster/backup --output-format json")
	if err != nil {
		return false, fmt.Errorf("list Proxmox backup jobs: %w", err)
	}
	var jobs []struct {
		ID            string `json:"id"`
		NotesTemplate string `json:"notes-template"`
		Comment       string `json:"comment"`
	}
	if err := json.Unmarshal(output, &jobs); err != nil {
		var envelope struct {
			Data []struct {
				ID            string `json:"id"`
				NotesTemplate string `json:"notes-template"`
				Comment       string `json:"comment"`
			} `json:"data"`
		}
		if envelopeErr := json.Unmarshal(output, &envelope); envelopeErr != nil || envelope.Data == nil {
			return false, fmt.Errorf("decode Proxmox backup jobs: %w", err)
		}
		jobs = envelope.Data
	}
	args := " --storage " + shellQuote(plan.StorageTarget) + " --schedule " + shellQuote(plan.Schedule) + " --vmid " + shellQuote(plan.VMIDList) + " --prune-backups " + shellQuote(plan.Retention) + " --mode snapshot --compress zstd --enabled 1 --notes-template " + shellQuote(managedBackupMarker+" model revision "+plan.ModelRevision)
	for _, job := range jobs {
		if job.ID != plan.JobName {
			continue
		}
		if !strings.Contains(job.NotesTemplate, managedBackupMarker) && !strings.Contains(job.Comment, managedBackupMarker) {
			return false, fmt.Errorf("Proxmox backup job %q already exists but is not boetticher-owned", plan.JobName)
		}
		if _, err := runner.Run(ctx, address, user, "pvesh set /cluster/backup/"+shellQuote(plan.JobName)+args); err != nil {
			return true, fmt.Errorf("update boetticher backup job: %w", err)
		}
		return true, nil
	}
	if _, err := runner.Run(ctx, address, user, "pvesh create /cluster/backup"+args); err != nil {
		return true, fmt.Errorf("create boetticher backup job: %w", err)
	}
	return true, nil
}

type BackupJob struct {
	JobName       string
	ModelRevision string
	StorageTarget string
	Schedule      string
	VMIDList      string
	Retention     string
}

const managedBackupMarker = "Managed by boetticher;"

// ApplyBackupJob creates or updates only the namespaced boetticher platform
// job. It never deletes or edits another backup job.
func (c *Client) ApplyBackupJob(ctx context.Context, node string, plan BackupJob) error {
	_, err := c.ApplyBackupJobWithMutation(ctx, node, plan)
	return err
}

// ApplyBackupJobWithMutation is the coarse mutation-aware form used by the
// deployment report. It deliberately reports provider writes, not a detailed
// backup-job audit history.
func (c *Client) ApplyBackupJobWithMutation(ctx context.Context, node string, plan BackupJob) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("Proxmox client is required")
	}
	if node == "" || plan.JobName == "" || plan.StorageTarget == "" || plan.VMIDList == "" || plan.Retention == "" {
		return false, fmt.Errorf("complete platform backup plan is required")
	}
	var jobs []struct {
		ID            string `json:"id"`
		NotesTemplate string `json:"notes-template"`
		Comment       string `json:"comment"`
	}
	if err := c.Get(ctx, "/cluster/backup", nil, &jobs); err != nil {
		return false, fmt.Errorf("list Proxmox backup jobs: %w", err)
	}
	params := url.Values{
		"id":             {plan.JobName},
		"storage":        {plan.StorageTarget},
		"schedule":       {plan.Schedule},
		"vmid":           {plan.VMIDList},
		"prune-backups":  {plan.Retention},
		"mode":           {"snapshot"},
		"compress":       {"zstd"},
		"enabled":        {"1"},
		"notes-template": {managedBackupMarker + " model revision " + plan.ModelRevision},
	}
	for _, job := range jobs {
		if job.ID != plan.JobName {
			continue
		}
		if !strings.Contains(job.NotesTemplate, managedBackupMarker) && !strings.Contains(job.Comment, managedBackupMarker) {
			return false, fmt.Errorf("Proxmox backup job %q already exists but is not boetticher-owned", plan.JobName)
		}
		if err := c.Put(ctx, path.Join("/cluster/backup", plan.JobName), params, nil); err != nil {
			return true, fmt.Errorf("update boetticher backup job: %w", err)
		}
		return true, nil
	}
	if err := c.Post(ctx, "/cluster/backup", params, nil); err != nil {
		return true, fmt.Errorf("create boetticher backup job: %w", err)
	}
	return true, nil
}
