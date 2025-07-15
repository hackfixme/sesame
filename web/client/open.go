package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	aerrors "go.hackfix.me/sesame/app/errors"
	stypes "go.hackfix.me/sesame/web/server/types"
)

// Open grants the specified IP addresses access to the specified service for
// the specified duration on a remote Sesame node. The client is expected to
// have previously been authenticated via an invitation token (see [Client.Auth]),
// after which it would've been provided a TLS client certificate it can use for
// these priviledged requests.
func (c *Client) Open(ctx context.Context, clients []string, serviceName string, duration time.Duration) error {
	url := &url.URL{Scheme: "https", Host: c.address, Path: "/api/v1/open"}

	reqData := stypes.OpenPostRequestData{
		Clients:     clients,
		ServiceName: serviceName,
		Duration:    duration,
	}

	errFields := []any{"url", url.String(), "method", http.MethodPost}

	reqDataJSON, err := json.Marshal(reqData)
	if err != nil {
		return aerrors.NewWithCause("failed marshaling request data", err, errFields...)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, url.String(), bytes.NewBuffer(reqDataJSON))
	if err != nil {
		return aerrors.NewWithCause("failed creating request", err, errFields...)
	}

	resp, err := c.Do(req)
	if err != nil {
		return aerrors.NewWithCause("failed sending request", err, errFields...)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return aerrors.NewWithCause("failed reading response body", err, errFields...)
	}

	var respData stypes.OpenPostResponse
	err = json.Unmarshal(respBody, &respData)
	if err != nil {
		return aerrors.NewWithCause("failed unmarshaling response body", err, errFields...)
	}

	errFields = append(errFields, "status_code", resp.StatusCode, "status", resp.Status)
	if respData.Error != "" {
		errFields = append(errFields, "cause", respData.Error)
	}
	if resp.StatusCode != http.StatusOK {
		return aerrors.NewWith("request failed", errFields...)
	}

	return nil
}
