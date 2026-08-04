package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// Two AnyTLS accounts sharing a password make an inbound the core REFUSES to build,
// and a config Xray refuses to build takes every other inbound on the box down with
// it. The panel has to catch that before it persists, because AddUser's rejection is
// logged at Debug and swallowed. See firstAnytlsPasswordCollision.
func TestFirstAnytlsPasswordCollision(t *testing.T) {
	cases := []struct {
		name    string
		clients []model.Client
		want    string
	}{
		{"all distinct", []model.Client{
			{Email: "a", Password: "p1"},
			{Email: "b", Password: "p2"},
		}, ""},
		{"names the SECOND account, never the password", []model.Client{
			{Email: "a", Password: "shared"},
			{Email: "b", Password: "shared"},
		}, "b"},
		{"collision across non-adjacent accounts", []model.Client{
			{Email: "a", Password: "p1"},
			{Email: "b", Password: "p2"},
			{Email: "c", Password: "p1"},
		}, "c"},
		// An account with no password is a different error, reported elsewhere as an
		// empty client ID. Treating "" as a value would make every such pair collide.
		{"blank passwords do not collide", []model.Client{
			{Email: "a", Password: ""},
			{Email: "b", Password: ""},
		}, ""},
		{"empty list", nil, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstAnytlsPasswordCollision(c.clients); got != c.want {
				t.Errorf("firstAnytlsPasswordCollision() = %q, want %q", got, c.want)
			}
		})
	}
}

// The password itself must never reach an error message: it is a live credential and
// the caller puts this return value straight into one.
func TestAnytlsPasswordCollisionDoesNotLeakTheSecret(t *testing.T) {
	got := firstAnytlsPasswordCollision([]model.Client{
		{Email: "alice", Password: "s3cret"},
		{Email: "bob", Password: "s3cret"},
	})
	if got == "s3cret" {
		t.Fatal("returned the password itself; it is reported to the operator verbatim")
	}
	if got != "bob" {
		t.Errorf("got %q, want the colliding account's email %q", got, "bob")
	}
}
