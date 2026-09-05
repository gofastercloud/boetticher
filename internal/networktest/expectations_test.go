package networktest

import "testing"

func TestExpectedPlatformAccessPreservesIndependentZoneBoundary(t *testing.T) {
	for _, test := range []struct {
		name           string
		source, target string
		protocol       string
		port           int
		want           bool
	}{
		{"trusted services", "TRUSTED", "INFRA", "tcp", 443, true},
		{"trusted management", "TRUSTED", "MGMT", "tcp", 8006, true},
		{"trusted undeclared port", "TRUSTED", "INFRA", "tcp", 9443, false},
		{"servers DNS", "SERVERS", "INFRA", "udp", 123, true},
		{"servers undeclared HTTPS", "SERVERS", "INFRA", "tcp", 443, false},
		{"management services", "MGMT", "SERVERS", "tcp", 443, true},
		{"transit private", "TRANSIT", "INFRA", "tcp", 443, false},
		{"sandbox same-zone", "SANDBOX", "SANDBOX", "tcp", 443, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ExpectedPlatformAccess(test.source, test.target, test.protocol, test.port); got != test.want {
				t.Fatalf("ExpectedPlatformAccess(%q, %q, %q, %d) = %t, want %t", test.source, test.target, test.protocol, test.port, got, test.want)
			}
		})
	}
}
