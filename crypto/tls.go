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

// Provides a recommended TLS configuration.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		// Avoids most of the memorably-named TLS attacks
		MinVersion: tls.VersionTLS13,
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have constant-time implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveID(tls.CurveP256),
			tls.CurveID(tls.Ed25519),
		},
	}
}

// NewTLSCert creates an X.509 v3 certificate using the provided subjectName,
// Subject Alternative Names and expiration date. If parent is nil, the
// certificate is self-signed using a new Ed25519 private key; otherwise the
// parent certificate is used to sign the new certificate (e.g. for client certs).
// It returns the certificate and private key.
// Reference: https://eli.thegreenplace.net/2021/go-https-servers-with-tls/
func NewTLSCert(
	subjectName string, san []string, expiration time.Time, parent *tls.Certificate,
) (*x509.Certificate, ed25519.PrivateKey, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating serial number: %w", err)
	}

	var isCA bool
	if parent == nil {
		isCA = true
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HACKfixme"},
			CommonName:   subjectName,
		},
		IsCA:      isCA,
		DNSNames:  san,
		NotBefore: time.Now(),
		NotAfter:  expiration,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating Ed25519 key pair: %w", err)
	}

	var (
		certDER []byte
		certErr error
	)
	if parent != nil {
		if len(parent.Certificate) == 0 {
			return nil, nil, errors.New("no certificate data found in parent certificate")
		}

		x509Cert, err := x509.ParseCertificate(parent.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("failed parsing X.509 certificate from parent: %w", err)
		}

		// Client cert signed by the parent (CA) cert
		certDER, certErr = x509.CreateCertificate(rand.Reader, &template,
			x509Cert, pubKey, parent.PrivateKey)
	} else {
		// Self-signed cert used by the server (CA)
		certDER, certErr = x509.CreateCertificate(rand.Reader, &template,
			&template, pubKey, privKey)
	}
	if certErr != nil {
		return nil, nil, fmt.Errorf("failed creating X.509 certificate: %w", certErr)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing X.509 certificate from ASN.1 DER data: %w", certErr)
	}

	return cert, privKey, nil
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
			return nil, err
		}
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, err
	}

	if err := pem.Encode(&buf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	}); err != nil {
		return nil, err
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

	return tls.X509KeyPair(certChainPEM, keyPEM)
}

// ExtractCACert finds and returns the first CA certificate in the certificate
// chain that clients can use to verify server certificates, or for signing purposes.
func ExtractCACert(cert tls.Certificate) (*x509.Certificate, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("no certificate data found")
	}

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
