package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pki"
)

// Managed endpoint certificates are public projections of the endpoint CSR
// and current controller authority. Keeping them in the runtime directory
// avoids putting private keys or secret material in the cache.
const managedCertificateCacheDirectory = "certificates"

func signOrReuseServerCertificate(authority pki.Authority, csrPEM, csrDir, cacheName, name, domain string, aliases []string) (pki.ServerCertificate, error) {
	if err := pki.ValidateClientName(cacheName); err != nil {
		return pki.ServerCertificate{}, fmt.Errorf("validate certificate cache name: %w", err)
	}
	cachePath := managedCertificateCachePath(csrDir, cacheName)
	if cached, err := pathguard.ReadFile(cachePath); err == nil {
		if certificate, validationErr := pki.ValidateServerCertificate(authority, string(cached), csrPEM, name, domain, aliases, time.Now().UTC()); validationErr == nil {
			return certificate, nil
		}
	}

	certificate, err := pki.SignServerCSR(authority, csrPEM, name, domain, aliases, time.Now().UTC())
	if err != nil {
		return pki.ServerCertificate{}, err
	}
	persistManagedCertificateCache(cachePath, certificate.ChainPEM)
	return certificate, nil
}

func signOrReuseEndpointClientCertificate(authority pki.Authority, csrPEM, csrDir, cacheName, name, domain string) (pki.ClientCertificate, error) {
	if err := pki.ValidateClientName(cacheName); err != nil {
		return pki.ClientCertificate{}, fmt.Errorf("validate certificate cache name: %w", err)
	}
	cachePath := managedCertificateCachePath(csrDir, cacheName)
	if cached, err := pathguard.ReadFile(cachePath); err == nil {
		if certificate, validationErr := pki.ValidateClientCertificate(authority, string(cached), csrPEM, name, domain, time.Now().UTC()); validationErr == nil {
			return certificate, nil
		}
	}

	certificate, err := pki.SignClientCSR(authority, csrPEM, name, domain, time.Now().UTC())
	if err != nil {
		return pki.ClientCertificate{}, err
	}
	persistManagedCertificateCache(cachePath, certificate.ChainPEM)
	return certificate, nil
}

func signOrReuseServiceClientCertificate(authority pki.Authority, csrPEM, csrDir, cacheName, identity string) (pki.ClientCertificate, error) {
	if err := pki.ValidateClientName(cacheName); err != nil {
		return pki.ClientCertificate{}, fmt.Errorf("validate certificate cache name: %w", err)
	}
	cachePath := managedCertificateCachePath(csrDir, cacheName)
	if cached, err := pathguard.ReadFile(cachePath); err == nil {
		if certificate, validationErr := pki.ValidateServiceClientCertificate(authority, string(cached), csrPEM, identity, time.Now().UTC()); validationErr == nil {
			return certificate, nil
		}
	}

	certificate, err := pki.SignServiceClientCSR(authority, csrPEM, identity, time.Now().UTC())
	if err != nil {
		return pki.ClientCertificate{}, err
	}
	persistManagedCertificateCache(cachePath, certificate.ChainPEM)
	return certificate, nil
}

func managedCertificateCachePath(csrDir, cacheName string) string {
	return filepath.Join(csrDir, managedCertificateCacheDirectory, cacheName+".chain.pem")
}

func persistManagedCertificateCache(path, chainPEM string) {
	if err := pathguard.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return
	}
	_ = writePublic(path, []byte(chainPEM))
}
