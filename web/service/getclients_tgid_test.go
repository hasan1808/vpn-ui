package service

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// GetClients discards its json.Unmarshal error, and that discard is LOAD-BEARING.
//
// The browser's ClientBase defaults tgId to the empty STRING, while
// model.Client.TgID is an int64, so EVERY inbound the panel has ever created decodes
// with an UnmarshalTypeError on that one field. It is harmless only because Go's decoder
// skips the mistyped field and keeps going, leaving the client complete with TgID=0.
//
// Add error handling to GetClients and every inbound in the database fails at once. This
// test exists so that discovery happens here rather than on a live panel: it pins BOTH
// halves of the invariant: the error really is returned, and the data really does
// survive it.
func TestUnmarshalRecoversFromBrowserTgIdString(t *testing.T) {
	// The exact shape the browser posts, tgId included.
	const payload = `{"clients":[{"password":"pw","email":"e@x","enable":true,` +
		`"tgId":"","subId":"s","comment":"c","limitIp":2,"totalGB":0,"expiryTime":0,"reset":0}]}`

	settings := map[string][]model.Client{}
	err := json.Unmarshal([]byte(payload), &settings)

	// Half one: the error is real. If this ever stops erroring (the browser starts
	// sending a number, or Client.TgID becomes a string), the discard in GetClients is
	// no longer load-bearing and its comment should be revisited.
	if err == nil {
		t.Error("expected an UnmarshalTypeError on tgId; if the browser now sends a number, update GetClients' comment")
	}

	// Half two: and everything else survives it. This is what makes the discard safe.
	clients := settings["clients"]
	if len(clients) != 1 {
		t.Fatalf("got %d clients, want 1: the decoder no longer recovers, and GetClients silently returns nothing", len(clients))
	}
	c := clients[0]
	if c.Email != "e@x" || c.Password != "pw" || !c.Enable || c.SubID != "s" || c.Comment != "c" || c.LimitIP != 2 {
		t.Errorf("fields did not survive the mistyped tgId: %+v", c)
	}
	if c.TgID != 0 {
		t.Errorf("TgID = %d, want 0 (the mistyped field is skipped, not guessed)", c.TgID)
	}
}
