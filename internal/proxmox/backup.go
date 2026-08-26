package proxmox

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
)

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
	if c == nil {
		return fmt.Errorf("Proxmox client is required")
	}
	if node == "" || plan.JobName == "" || plan.StorageTarget == "" || plan.VMIDList == "" || plan.Retention == "" {
		return fmt.Errorf("complete platform backup plan is required")
	}
	var jobs []struct {
		ID            string `json:"id"`
		NotesTemplate string `json:"notes-template"`
		Comment       string `json:"comment"`
	}
	if err := c.Get(ctx, "/cluster/backup", nil, &jobs); err != nil {
		return fmt.Errorf("list Proxmox backup jobs: %w", err)
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
			return fmt.Errorf("Proxmox backup job %q already exists but is not boetticher-owned", plan.JobName)
		}
		if err := c.Put(ctx, path.Join("/cluster/backup", plan.JobName), params, nil); err != nil {
			return fmt.Errorf("update boetticher backup job: %w", err)
		}
		return nil
	}
	if err := c.Post(ctx, "/cluster/backup", params, nil); err != nil {
		return fmt.Errorf("create boetticher backup job: %w", err)
	}
	return nil
}
