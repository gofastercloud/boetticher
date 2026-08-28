package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	loggingmodel "github.com/gofastercloud/boetticher/internal/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	policy, err := loggingmodel.LoadQueryPolicy("/etc/boetticher-log-query/policy.json")
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair("/var/lib/boetticher/identity/tls/log-query.crt", "/var/lib/boetticher/identity/tls/log-query.key")
	if err != nil {
		return err
	}
	ca, err := os.ReadFile("/etc/boetticher/pki/client-ca.crt")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("client CA is invalid")
	}
	server := &http.Server{Addr: ":19533", Handler: (loggingmodel.QueryServer{Policy: policy, Runner: loggingmodel.ExecRunner{}}).Handler(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, VerifyConnection: loggingmodel.VerifyQueryClient}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	listener, err := tls.Listen("tcp", server.Addr, server.TLSConfig)
	if err != nil {
		return err
	}
	return server.Serve(listener)
}
