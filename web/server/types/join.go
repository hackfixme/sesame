package types

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"go.hackfix.me/sesame/crypto"
)

// JoinRequest represents a request to join the Sesame service.
type JoinRequest struct {
	BaseRequest `json:"-"`
}

// JoinResponse contains the data returned for a successful join request.
type JoinResponse struct {
	BaseResponse
	TLSCACert     []byte `json:"tls_ca_cert"`
	TLSClientCert []byte `json:"tls_client_cert"`
}

// NewJoinResponse creates a new JoinResponse with the provided certificates.
func NewJoinResponse(caCert *x509.Certificate, clientCert tls.Certificate) (*JoinResponse, error) {
	clientCertPEM, err := crypto.EncodeTLSCert(clientCert)
	if err != nil {
		return nil, NewError(http.StatusInternalServerError, err.Error())
	}

	resp := &JoinResponse{
		BaseResponse:  NewBaseResponse(http.StatusOK, nil),
		TLSCACert:     caCert.Raw,
		TLSClientCert: clientCertPEM,
	}

	return resp, nil
}
