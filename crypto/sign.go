package crypto

// cryptopasta - basic cryptography examples
//
// Written in 2015 by George Tankersley <george.tankersley@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software. If not, see // <http://creativecommons.org/publicdomain/zero/1.0/>.
//
// Provides message authentication and asymmetric signatures.
//
// Message authentication: HMAC SHA512/256
// This is a slight twist on the highly dependable HMAC-SHA256 that gains
// performance on 64-bit systems and consistency with our hashing
// recommendation.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// NewHMACKey generates a random 256-bit secret key for HMAC use.
// Because key generation is critical, it panics if the source of randomness fails.
func NewHMACKey() *[32]byte {
	key := &[32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}

// GenerateHMAC produces a symmetric signature using a shared secret key.
func GenerateHMAC(data []byte, key *[32]byte) []byte {
	h := hmac.New(sha512.New512_256, key[:])
	h.Write(data)
	return h.Sum(nil)
}

// CheckHMAC securely checks the supplied MAC against a message using the shared secret key.
func CheckHMAC(data, suppliedMAC []byte, key *[32]byte) bool {
	expectedMAC := GenerateHMAC(data, key)
	return hmac.Equal(expectedMAC, suppliedMAC)
}

// DeriveHMACKey derives a 256-bit HMAC key from a secret using HKDF-SHA512/256.
// The secretKey should be cryptographically strong material (e.g. from ECDH).
// The info parameter provides application-specific context to ensure key separation.
// Returns an error if the key derivation process fails.
func DeriveHMACKey(secretKey []byte, info []byte) (*[32]byte, error) {
	hkdf := hkdf.New(sha512.New512_256, secretKey, nil, info)

	key := &[32]byte{}
	_, err := io.ReadFull(hkdf, key[:])
	if err != nil {
		return nil, fmt.Errorf("failed reading key: %w", err)
	}

	return key, nil
}
