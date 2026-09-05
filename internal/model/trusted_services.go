package model

// TrustedLabService is the existing TRUSTED inter-zone service boundary.
// Tailnet reuses this list but never inherits TRUSTED Internet egress.
type TrustedLabService struct {
	Zone     string   `json:"zone"`
	Network  string   `json:"network"`
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
}

func TrustedLabServices() []TrustedLabService {
	return []TrustedLabService{
		{"SERVERS", "10.10.20.0/24", "tcp", []string{"53", "443"}},
		{"SERVERS", "10.10.20.0/24", "udp", []string{"53", "123"}},
		{"INFRA", "10.10.10.0/24", "tcp", []string{"53", "443"}},
		{"INFRA", "10.10.10.0/24", "udp", []string{"53", "123"}},
		{"MGMT", "10.10.99.0/24", "tcp", []string{"22", "443", "8006"}},
	}
}
