package types

// JoinPostResponseData contains the data returned for a successful join request.
type JoinPostResponseData struct {
	TLSCACert     []byte `json:"tls_ca_cert"`
	TLSClientCert []byte `json:"tls_client_cert"`
}
