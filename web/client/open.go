package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	aerrors "go.hackfix.me/sesame/app/errors"
	stypes "go.hackfix.me/sesame/web/server/types"
)

// Open grants access from the specified IP addresses to the specified service for
// the specified duration on a remote Sesame node. The client is expected to
// have previously been authenticated via an invitation token (see [Client.Auth]),
// after which it would've been provided a TLS client certificate it can use for
// these priviledged requests.
func (c *Client) Open(ctx context.Context, clients []string, serviceName string, duration time.Duration) (rerr error) {
	url := &url.URL{Scheme: "https", Host: c.address, Path: "/api/v1/open"}

	reqData := stypes.OpenRequest{
		Clients:     clients,
		ServiceName: serviceName,
		Duration:    duration,
	}

	errFields := []any{"url", url.String(), "method", http.MethodPost}

	reqDataJSON, err := json.Marshal(reqData)
	if err != nil {
		return aerrors.NewWithCause("failed marshalling request data", err, errFields...)
	}

	reqCtx, cancelReqCtx := context.WithCancel(ctx)
	defer cancelReqCtx()

	req, err := http.NewRequestWithContext(
		reqCtx, http.MethodPost, url.String(), bytes.NewBuffer(reqDataJSON))
	if err != nil {
		return aerrors.NewWithCause("failed creating request", err, errFields...)
	}

	resp, err := c.Do(req)
	if err != nil {
		return aerrors.NewWithCause("failed sending request", err, errFields...)
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			rerr = fmt.Errorf("failed closing response body: %w", err)
		}
	}()
	errFields = append(errFields, "status_code", resp.StatusCode, "status", resp.Status)
	if resp.StatusCode != http.StatusOK {
		return aerrors.NewWith("request failed", errFields...)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return aerrors.NewWithCause("failed reading response body", err, errFields...)
	}

	var respData stypes.OpenResponse
	err = json.Unmarshal(respBody, &respData)
	if err != nil {
		return aerrors.NewWithCause("failed unmarshalling response body", err, errFields...)
	}

	if respData.Error != nil {
		errFields = append(errFields, "cause", respData.Error)
	}
	if resp.StatusCode != http.StatusOK {
		return aerrors.NewWith("request failed", errFields...)
	}

	return nil
}
