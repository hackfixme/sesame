package types

// RemoteJoinResponseData contains the TLS information required by remote Sesame nodes.
type RemoteJoinResponseData struct {
	TLSCACert     []byte `json:"tls_ca_cert"`
	TLSClientCert []byte `json:"tls_client_cert"`
}
