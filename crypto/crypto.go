package crypto

import (
	"crypto/rand"
	"fmt"
)

// RandomData returns a slice of the specified size containing random data.
func RandomData(size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("size cannot be negative")
	}

	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		return nil, fmt.Errorf("failed generating random data: %w", err)
	}

	return data, nil
}
