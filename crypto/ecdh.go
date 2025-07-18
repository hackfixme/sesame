package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// ECDHExchange performs ECDH key exchange using the X25519 function, and
// returns the generated shared secret key, and the local public key.
// If privKeyData is nil, it generates a new private key.
func ECDHExchange(remotePubKeyData []byte, privKeyData []byte) (sharedKey []byte, pubKey []byte, err error) {
	remotePubKey, err := ecdh.X25519().NewPublicKey(remotePubKeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed instantiating X25519 public key: %w", err)
	}

	var privKey *ecdh.PrivateKey
	if privKeyData == nil {
		privKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed generating X25519 private key: %w", err)
		}
	} else {
		privKey, err = ecdh.X25519().NewPrivateKey(privKeyData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed instantiating X25519 private key: %w", err)
		}
	}

	sharedKey, err = privKey.ECDH(remotePubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed performing ECDH exchange: %w", err)
	}

	return sharedKey, privKey.PublicKey().Bytes(), nil
}
