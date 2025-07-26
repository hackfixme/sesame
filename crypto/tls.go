package crypto

// cryptopasta - basic cryptography examples
//
// Written in 2016 by George Tankersley <george.tankersley@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software. If not, see // <http://creativecommons.org/publicdomain/zero/1.0/>.
//
// Provides a recommended TLS configuration.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// DefaultTLSConfig returns a secure default TLS configuration.
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		// Avoids most of the memorably-named TLS attacks
		MinVersion: tls.VersionTLS13,
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have constant-time implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.CurveID(tls.Ed25519),
		},
	}
}

// NewTLSCert creates an X.509 v3 certificate for TLS operations using the
// provided subjectName, Subject Alternative Names and expiration date. If
// parent is nil, the certificate is self-signed using a new Ed25519 private
// key; otherwise the parent certificate is used to sign the new certificate
// (e.g. for client certs).
// Reference: https://eli.thegreenplace.net/2021/go-https-servers-with-tls/
func NewTLSCert(
	subjectName string, san []string, timeNow, expiration time.Time, parent *tls.Certificate,
) (tls.Certificate, error) {
	var (
		isCA     bool
		keyUsage = x509.KeyUsageDigitalSignature
	)
	if parent == nil {
		isCA = true
		keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment
	}

	template, err := createCertTemplate(subjectName, san, timeNow, expiration, isCA, keyUsage)
	if err != nil {
		return tls.Certificate{}, err
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed generating Ed25519 key pair: %w", err)
	}

	return createTLSCertFromTemplate(template, pubKey, privKey, parent)
}

// RenewTLSCert creates a renewed certificate using the existing private key
// and preserving the original certificate's properties (subject, SANs, etc.).
// The returned certificate will have a new serial number and validity period.
func RenewTLSCert(
	existingCert tls.Certificate, timeNow, expiration time.Time, parent *tls.Certificate,
) (tls.Certificate, error) {
	// Extract the existing certificate to preserve its properties
	x509Cert, err := ExtractCert(existingCert, parent == nil)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to extract existing certificate: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed generating serial number: %w", err)
	}

	// New template preserving most of the original properties
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               x509Cert.Subject,
		IsCA:                  x509Cert.IsCA,
		DNSNames:              x509Cert.DNSNames,
		IPAddresses:           x509Cert.IPAddresses,
		EmailAddresses:        x509Cert.EmailAddresses,
		URIs:                  x509Cert.URIs,
		NotBefore:             timeNow,
		NotAfter:              expiration,
		KeyUsage:              x509Cert.KeyUsage,
		ExtKeyUsage:           x509Cert.ExtKeyUsage,
		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
	}

	pubKey, err := extractPublicKey(existingCert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return createTLSCertFromTemplate(template, pubKey, existingCert.PrivateKey, parent)
}

// ShouldRenewTLSCert checks if a certificate should be renewed based on a
// threshold before expiration (e.g., renew if less than 30 days remaining).
func ShouldRenewTLSCert(cert tls.Certificate, renewThreshold time.Duration) (bool, error) {
	x509Cert, err := ExtractCert(cert, cert.Leaf != nil && cert.Leaf.IsCA)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate: %w", err)
	}

	timeUntilExpiry := time.Until(x509Cert.NotAfter)
	return timeUntilExpiry <= renewThreshold, nil
}

// SerializeTLSCert converts a tls.Certificate to a single PEM-encoded byte slice
// containing the certificate chain followed by the private key.
func SerializeTLSCert(cert tls.Certificate) ([]byte, error) {
	var buf bytes.Buffer

	// Encode each certificate in the chain as a CERTIFICATE PEM block.
	// The first certificate is the leaf, followed by any intermediates.
	for _, certDER := range cert.Certificate {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}); err != nil {
			return nil, fmt.Errorf("failed encoding certificate: %w", err)
		}
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling private key: %w", err)
	}

	if err = pem.Encode(&buf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	}); err != nil {
		return nil, fmt.Errorf("failed encoding private key: %w", err)
	}

	return buf.Bytes(), nil
}

// DeserializeTLSCert reconstructs a tls.Certificate from PEM-encoded data
// containing certificate chain and private key blocks.
// It expects one or more CERTIFICATE blocks followed by one PRIVATE KEY block.
func DeserializeTLSCert(data []byte) (tls.Certificate, error) {
	var (
		certPEMs [][]byte
		keyPEM   []byte
	)

	// Parse all PEM blocks from the input data.
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break // No more PEM blocks found
		}

		switch block.Type {
		case "CERTIFICATE":
			// Re-encode the certificate block to preserve PEM format
			certPEMs = append(certPEMs, pem.EncodeToMemory(block))
		case "PRIVATE KEY":
			keyPEM = pem.EncodeToMemory(block)
		}

		data = rest
	}

	certChainPEM := bytes.Join(certPEMs, nil)

	cert, err := tls.X509KeyPair(certChainPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed creating X509 key pair: %w", err)
	}

	return cert, nil
}

// ExtractCert finds and returns either a CA certificate or the leaf certificate
// from the certificate chain based on the ca parameter.
func ExtractCert(cert tls.Certificate, ca bool) (*x509.Certificate, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("no certificate data found")
	}

	if !ca {
		// Return leaf certificate (end-entity certificate)
		if cert.Leaf != nil {
			return cert.Leaf, nil
		}
		// First certificate in chain is typically the leaf
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed parsing first certificate in chain: %w", err)
		}
		return x509Cert, nil
	}

	// Search for CA certificate
	if cert.Leaf != nil && cert.Leaf.IsCA {
		return cert.Leaf, nil
	}

	for _, certDER := range cert.Certificate {
		x509Cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			continue
		}

		if x509Cert.IsCA {
			return x509Cert, nil
		}
	}

	return nil, errors.New("no CA certificate found in chain")
}

// generateSerialNumber creates a cryptographically secure random serial number.
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	//nolint:wrapcheck // Wrapped by the caller.
	return rand.Int(rand.Reader, serialNumberLimit)
}

// createCertTemplate creates an X.509 certificate template with the given
// parameters.
func createCertTemplate(
	subjectName string, san []string, timeNow, expiration time.Time,
	isCA bool, keyUsage x509.KeyUsage,
) (*x509.Certificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed generating serial number: %w", err)
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HACKfixme"},
			CommonName:   subjectName,
		},
		IsCA:      isCA,
		DNSNames:  san,
		NotBefore: timeNow,
		NotAfter:  expiration,
		KeyUsage:  keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}, nil
}

// createTLSCertFromTemplate creates a certificate from template and returns a
// tls.Certificate.
func createTLSCertFromTemplate(
	template *x509.Certificate, pubKey crypto.PublicKey, privKey crypto.PrivateKey,
	parent *tls.Certificate,
) (tls.Certificate, error) {
	var (
		tlsCert tls.Certificate
		certDER []byte
	)

	if parent != nil {
		// Client cert signed by the server (CA)
		parentCert, err := ExtractCert(*parent, true)
		if err != nil {
			return tlsCert, fmt.Errorf("failed to extract CA certificate from parent: %w", err)
		}

		certDER, err = x509.CreateCertificate(rand.Reader, template,
			parentCert, pubKey, parent.PrivateKey)
		if err != nil {
			return tlsCert, fmt.Errorf("failed creating X.509 certificate: %w", err)
		}
	} else {
		// Self-signed server cert
		var err error
		certDER, err = x509.CreateCertificate(rand.Reader, template,
			template, pubKey, privKey)
		if err != nil {
			return tlsCert, fmt.Errorf("failed creating X.509 certificate: %w", err)
		}
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tlsCert, fmt.Errorf("failed parsing X.509 certificate from ASN.1 DER data: %w", err)
	}

	tlsCert = tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
		Leaf:        x509Cert,
	}

	return tlsCert, nil
}

// extractPublicKey extracts the public key from a private key.
func extractPublicKey(privKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch priv := privKey.(type) {
	case ed25519.PrivateKey:
		return priv.Public(), nil
	case *ecdsa.PrivateKey:
		return &priv.PublicKey, nil
	case *rsa.PrivateKey:
		return &priv.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}
