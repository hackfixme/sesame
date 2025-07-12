package types

import (
	"crypto/tls"
	"crypto/x509"
)

type RemoteAuthResponse struct {
	TLSCACert     *x509.Certificate
	TLSClientCert *tls.Certificate
}
