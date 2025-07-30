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

// Validate checks that the request is valid and ready for processing.
// Returns an error if validation fails.
func (r *JoinRequest) Validate() error {
	if r.User == nil {
		return NewError(http.StatusUnauthorized, "user object not found in the request context")
	}
	return nil
}

// JoinResponse is the response returned on a join request.
type JoinResponse struct {
	BaseResponse
	Data JoinResponseData `json:"data"`
}

// JoinResponseData is the data sent in the JoinResponse.
type JoinResponseData struct {
	TLSCACert     []byte `json:"tls_ca_cert,omitempty"`
	TLSClientCert []byte `json:"tls_client_cert,omitempty"`
}

// NewJoinResponse creates a new JoinResponse with the provided certificates and
// HTTP 200 status.
func NewJoinResponse(caCert *x509.Certificate, clientCert tls.Certificate) (*JoinResponse, error) {
	clientCertPEM, err := crypto.EncodeTLSCert(clientCert)
	if err != nil {
		return nil, NewError(http.StatusInternalServerError, err.Error())
	}

	resp := &JoinResponse{
		BaseResponse: NewBaseResponse(http.StatusOK, nil),
		Data: JoinResponseData{
			TLSCACert:     caCert.Raw,
			TLSClientCert: clientCertPEM,
		},
	}

	return resp, nil
}
