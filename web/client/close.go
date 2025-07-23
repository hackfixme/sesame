package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	aerrors "go.hackfix.me/sesame/app/errors"
	stypes "go.hackfix.me/sesame/web/server/types"
)

// Close denies access from the specified IP addresses to the specified service
// on a remote Sesame node. The client is expected to have previously been
// authenticated via an invitation token (see [Client.Auth]), after which it
// would've been provided a TLS client certificate it can use for these
// priviledged requests.
func (c *Client) Close(ctx context.Context, clients []string, serviceName string) (rerr error) {
	url := &url.URL{Scheme: "https", Host: c.address, Path: "/api/v1/close"}

	reqData := stypes.ClosePostRequestData{
		Clients:     clients,
		ServiceName: serviceName,
	}

	errFields := []any{"url", url.String(), "method", http.MethodPost}

	reqDataJSON, err := json.Marshal(reqData)
	if err != nil {
		return aerrors.NewWithCause("failed marshalling request data", err, errFields...)
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
	defer func() {
		if err = resp.Body.Close(); err != nil {
			rerr = fmt.Errorf("failed closing response body: %w", err)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return aerrors.NewWithCause("failed reading response body", err, errFields...)
	}

	var respData stypes.ClosePostResponse
	err = json.Unmarshal(respBody, &respData)
	if err != nil {
		return aerrors.NewWithCause("failed unmarshalling response body", err, errFields...)
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
