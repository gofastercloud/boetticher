package proxmox

import (
	"context"
	"fmt"
	"path"
)

type StorageStatus struct {
	Storage string  `json:"storage"`
	Type    string  `json:"type"`
	Active  int     `json:"active"`
	Total   float64 `json:"total"`
	Used    float64 `json:"used"`
	Avail   float64 `json:"avail"`
}

func (c *Client) NodeStorage(ctx context.Context, node string) ([]StorageStatus, error) {
	if c == nil || node == "" {
		return nil, fmt.Errorf("Proxmox client and node are required")
	}
	var storage []StorageStatus
	if err := c.Get(ctx, path.Join("/nodes", node, "storage"), nil, &storage); err != nil {
		return nil, fmt.Errorf("list Proxmox node storage: %w", err)
	}
	return storage, nil
}
