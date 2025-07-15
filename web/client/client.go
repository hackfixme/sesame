package client

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"

	"go.hackfix.me/sesame/crypto"
)

type Client struct {
	*http.Client
	address string
	logger  *slog.Logger
}

func New(address string, tlsConfig *tls.Config, logger *slog.Logger) *Client {
	if tlsConfig == nil {
		tlsConfig = crypto.DefaultTLSConfig()
	}

	return &Client{
		Client: &http.Client{
			Timeout: time.Minute,
			Transport: &http.Transport{
				DisableCompression: false,
				TLSClientConfig:    tlsConfig,
			},
		},
		address: address,
		logger:  logger.With("component", "web-client"),
	}
}
