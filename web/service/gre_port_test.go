package service

import (
	"fmt"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// A GRE inbound's port is bookkeeping: GRE is IP protocol 47 and binds nothing, so the
// form has no port box and the server assigns the value (NormalizeGrePort). These tests
// pin the part that is easy to break silently, because nothing in the GRE data plane
// reads the port: it only has to be valid and unique, or the inbound tag built from it
// collides with another inbound's and the routing rules, the paired dokodemo-door inbound
// and the traffic rows all follow the wrong one.

// controllerTag mirrors how addInbound builds the tag from the settled port.
func controllerTag(inbound *model.Inbound) string {
	if inbound.Listen == "" || inbound.Listen == "0.0.0.0" || inbound.Listen == "::" || inbound.Listen == "::0" {
		return fmt.Sprintf("inbound-%v", inbound.Port)
	}
	return fmt.Sprintf("inbound-%v:%v", inbound.Listen, inbound.Port)
}

func TestNormalizeGrePortOnAdd(t *testing.T) {
	t.Run("no port at all gets a free one", func(t *testing.T) {
		s := newInboundDB(t)
		seedInbound(t, greBookkeepingPortBase, model.L2TP, "l2tp-a@example.com")

		inbound := &model.Inbound{Protocol: model.GRE, Settings: clientSettings()}
		if err := s.NormalizeGrePort(inbound, 0); err != nil {
			t.Fatalf("NormalizeGrePort: %v", err)
		}
		if inbound.Port < 1 || inbound.Port > 65535 {
			t.Fatalf("assigned port %d is not a valid port", inbound.Port)
		}
		if inbound.Port == greBookkeepingPortBase {
			t.Fatalf("assigned port %d collides with the seeded inbound", inbound.Port)
		}
		exist, err := s.checkPortExist(inbound.Listen, inbound.Port, 0)
		if err != nil {
			t.Fatalf("checkPortExist: %v", err)
		}
		if exist {
			t.Fatalf("assigned port %d would be rejected as a duplicate", inbound.Port)
		}
	})

	t.Run("a port already claimed is replaced", func(t *testing.T) {
		s := newInboundDB(t)
		taken := seedInbound(t, 4242, model.GRE, "gre-a@example.com")

		inbound := &model.Inbound{Protocol: model.GRE, Port: taken.Port, Settings: clientSettings()}
		if err := s.NormalizeGrePort(inbound, 0); err != nil {
			t.Fatalf("NormalizeGrePort: %v", err)
		}
		if inbound.Port == taken.Port {
			t.Fatalf("kept port %d, which another inbound already owns", inbound.Port)
		}
		if controllerTag(inbound) == taken.Tag {
			t.Fatalf("tag %q collides with the existing inbound", controllerTag(inbound))
		}
	})

	t.Run("a free port the caller asked for is kept", func(t *testing.T) {
		s := newInboundDB(t)
		seedInbound(t, 4242, model.GRE, "gre-a@example.com")

		inbound := &model.Inbound{Protocol: model.GRE, Port: 4243, Settings: clientSettings()}
		if err := s.NormalizeGrePort(inbound, 0); err != nil {
			t.Fatalf("NormalizeGrePort: %v", err)
		}
		if inbound.Port != 4243 {
			t.Fatalf("port %d, want the requested 4243", inbound.Port)
		}
	})

	// Only GRE hides its port box, so every other protocol must still reach the port
	// validation with whatever the caller sent, error and all.
	t.Run("other protocols are untouched", func(t *testing.T) {
		s := newInboundDB(t)

		inbound := &model.Inbound{Protocol: model.L2TP, Settings: clientSettings()}
		if err := s.NormalizeGrePort(inbound, 0); err != nil {
			t.Fatalf("NormalizeGrePort: %v", err)
		}
		if inbound.Port != 0 {
			t.Fatalf("port %d, want the l2tp inbound left at 0", inbound.Port)
		}
	})
}

// The end-to-end shape the panel and the API both take: settle the port, build the tag
// from it, save. Before the port box was hidden this could only work because a human
// typed a number.
func TestAddGreInboundWithoutAPort(t *testing.T) {
	s := newInboundDB(t)
	existing := seedInbound(t, greBookkeepingPortBase, model.GRE, "gre-a@example.com")

	inbound := &model.Inbound{UserId: 1, Protocol: model.GRE, Settings: clientSettings()}
	if err := s.NormalizeGrePort(inbound, 0); err != nil {
		t.Fatalf("NormalizeGrePort: %v", err)
	}
	inbound.Tag = controllerTag(inbound)

	added, _, err := s.AddInbound(inbound)
	if err != nil {
		t.Fatalf("AddInbound with no port: %v", err)
	}
	if added.Port == existing.Port {
		t.Fatalf("port %d collides with the existing GRE inbound", added.Port)
	}
	if added.Tag == existing.Tag {
		t.Fatalf("tag %q collides with the existing GRE inbound", added.Tag)
	}

	// A second one has to land somewhere else again, which is the case the panel's own
	// seed cannot cover on its own (a stale list, or two admins adding at once).
	second := &model.Inbound{UserId: 1, Protocol: model.GRE, Settings: clientSettings()}
	if err := s.NormalizeGrePort(second, 0); err != nil {
		t.Fatalf("NormalizeGrePort: %v", err)
	}
	second.Tag = controllerTag(second)
	if _, _, err := s.AddInbound(second); err != nil {
		t.Fatalf("AddInbound for a second portless GRE inbound: %v", err)
	}
	if second.Port == added.Port {
		t.Fatalf("both GRE inbounds landed on port %d", second.Port)
	}
}

// Editing must not renumber: UpdateInbound rebuilds the tag from the posted port, so a
// request without one would strand every routing rule keyed on the old tag.
func TestNormalizeGrePortOnUpdateKeepsStoredPort(t *testing.T) {
	s := newInboundDB(t)
	stored := seedInbound(t, 4242, model.GRE, "gre-a@example.com")

	edited := &model.Inbound{Id: stored.Id, Protocol: model.GRE, Settings: clientSettings()}
	if err := s.NormalizeGrePort(edited, stored.Id); err != nil {
		t.Fatalf("NormalizeGrePort: %v", err)
	}
	if edited.Port != stored.Port {
		t.Fatalf("port %d, want the stored %d", edited.Port, stored.Port)
	}
	if controllerTag(edited) != stored.Tag {
		t.Fatalf("tag %q, want the stored %q", controllerTag(edited), stored.Tag)
	}
}

// A port another inbound already owns is not usable on update either, and the operator
// has no box to correct it in.
func TestNormalizeGrePortOnUpdateRejectsAClaimedPort(t *testing.T) {
	s := newInboundDB(t)
	stored := seedInbound(t, 4242, model.GRE, "gre-a@example.com")
	other := seedInbound(t, 4243, model.GRE, "gre-b@example.com")

	edited := &model.Inbound{Id: stored.Id, Protocol: model.GRE, Port: other.Port, Settings: clientSettings()}
	if err := s.NormalizeGrePort(edited, stored.Id); err != nil {
		t.Fatalf("NormalizeGrePort: %v", err)
	}
	if edited.Port != stored.Port {
		t.Fatalf("port %d, want a fall back to the stored %d", edited.Port, stored.Port)
	}
}
