package cli

import (
	"errors"
	"reflect"
	"time"

	"github.com/alecthomas/kong"

	"go.hackfix.me/sesame/xtime"
)

// ExpirationMapper parses the invitation expiration duration or timestamp.
type ExpirationMapper struct {
	timeNow func() time.Time
}

var _ kong.Mapper = (*ExpirationMapper)(nil)

// Decode implements the kong.Mapper interface.
func (em ExpirationMapper) Decode(kctx *kong.DecodeContext, target reflect.Value) error {
	var value string
	err := kctx.Scan.PopValueInto("expiration", &value)
	if err != nil {
		return err
	}

	timeNow := em.timeNow().UTC()

	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		dur, err := xtime.ParseDuration(value)
		if err != nil {
			return err
		}
		t = timeNow.Add(dur)
	}

	if t.Before(timeNow) {
		return errors.New("expiration time is in the past")
	}

	target.Set(reflect.ValueOf(t))

	return nil
}
