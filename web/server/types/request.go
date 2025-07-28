package types

import (
	"net/http"

	"go.hackfix.me/sesame/db/models"
)

// Request defines the interface for HTTP request wrappers.
type Request interface {
	SetHTTPRequest(*http.Request)
	GetHTTPRequest() *http.Request
	GetUser() *models.User
	SetUser(*models.User)
}

// BaseRequest provides a base implementation for HTTP requests with user context.
type BaseRequest struct {
	*http.Request
	User *models.User `json:"-"`
}

var _ Request = (*BaseRequest)(nil)

// GetHTTPRequest returns the underlying HTTP request.
func (r *BaseRequest) GetHTTPRequest() *http.Request {
	return r.Request
}

// SetHTTPRequest sets the underlying HTTP request.
func (r *BaseRequest) SetHTTPRequest(req *http.Request) {
	r.Request = req
}

// GetUser returns the authenticated user for this request.
func (r *BaseRequest) GetUser() *models.User {
	return r.User
}

// SetUser sets the authenticated user for this request.
func (r *BaseRequest) SetUser(u *models.User) {
	r.User = u
}
