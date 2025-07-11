package errors

import (
	"errors"
	"log/slog"
	"sort"
)

// Log logs an error using the default slog logger, extracting metadata if it's
// a StructuredError.
func Log(err error) {
	var serr *StructuredError
	if !errors.As(err, &serr) {
		slog.Error(err.Error())
		return
	}

	args := make([]any, 0, len(serr.metadata)*2+2)

	cause := serr.metadata["cause"]
	if serr.cause != nil {
		cause = serr.cause
	}
	if cause != nil {
		args = append(args, "cause", cause)
	}

	keys := make([]string, 0, len(serr.metadata))
	for k := range serr.metadata {
		if k != "cause" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, k := range keys {
		args = append(args, k, serr.metadata[k])
	}

	slog.Error(serr.Error(), args...)
}
