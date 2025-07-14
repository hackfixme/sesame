package types

import (
	"crypto/tls"
	"crypto/x509"
)

// AuthResponseData is the processed data returned by a successful join request.
type AuthResponseData struct {
	TLSCACert     *x509.Certificate
	TLSClientCert *tls.Certificate
}
