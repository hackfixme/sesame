package common

import (
	"fmt"

	"github.com/mr-tron/base58"
)

// DecodeToken parses the given token string and returns the 32-byte nonce and
// rest of the data.
func DecodeToken(token string) ([]byte, []byte, error) {
	tokenDec, err := base58.Decode(token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding token: %w", err)
	}
	if len(tokenDec) != 64 {
		return nil, nil, ErrInvalidToken
	}

	return tokenDec[:32], tokenDec[32:], nil
}
