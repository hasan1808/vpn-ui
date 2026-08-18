package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The panel serves one of two inbound dialogs, decided by the panel-wide
// legacyInboundForm setting: the rail form in html/form/inbound.html, or the one
// it replaced in html/form/inbound_legacy.html. The rail form composes each
// protocol out of per-section templates (form/openvpn/network, /security,
// /access, /reach); the old form needs the protocol whole, so
// html/form/protocol_legacy/ keeps a copy that is still one template.
//
// Two copies of the same fields is exactly the arrangement that rots. These tests
// are the ratchet: a field added to one dialog and not the other fails here rather
// than going quietly missing from whichever dialog the operator happens to be
// using. Both are shipped, so both have to be complete.

// fieldBindingRe matches how a form control is bound to the model: v-model with
// any modifiers, and the :checked / :value pair used where a control writes
// through a handler instead (the OpenVPN cipher boxes, the transport switches).
// The captured expression names the field, which is what parity is about - markup
// around it is free to differ, and does.
var fieldBindingRe = regexp.MustCompile(`(?:v-model(?:\.[a-z]+)*|:checked|:value)="([^"]+)"`)

// splitSectionRe finds the per-section templates the rail form composes, e.g.
// {{define "form/openvpn/network"}}. The protocol name in front of the section is
// what makes a protocol "split", and therefore what makes it need a frozen copy.
var splitSectionRe = regexp.MustCompile(`\{\{define "form/([a-z0-9-]+)/(network|security|access|reach)"\}\}`)

func fieldBindings(t *testing.T, path string) map[string]bool {
	t.Helper()
	body, err := fs.ReadFile(htmlFS, path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]bool{}
	for _, m := range fieldBindingRe.FindAllStringSubmatch(string(body), -1) {
		out[strings.Join(strings.Fields(m[1]), " ")] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// missingFrom lists the bindings in `from` that `in` does not have.
func missingFrom(from, in map[string]bool) []string {
	var out []string
	for k := range from {
		if !in[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// splitProtocols is the set of protocols the rail form cut into sections, read off
// the live templates rather than listed here: a protocol split tomorrow joins this
// test on its own, instead of being forgotten until an operator reports a field
// that the old dialog never grew.
func splitProtocols(t *testing.T) []string {
	t.Helper()
	entries, err := fs.ReadDir(htmlFS, "html/form/protocol")
	if err != nil {
		t.Fatalf("read html/form/protocol: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		body, err := fs.ReadFile(htmlFS, "html/form/protocol/"+e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range splitSectionRe.FindAllStringSubmatch(string(body), -1) {
			seen[m[1]] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("no split protocol templates found - the rail form's section defines were renamed or removed, and this test can no longer tell which protocols need a frozen copy")
	}
	return sortedKeys(seen)
}

// TestLegacyInboundFormsCarryEveryField holds the two dialogs to the same field
// set, per protocol and for the shell they sit in.
//
// Compared by BINDING, not by markup: the old form is one scrolling column and the
// rail form is nine sections, so their HTML differs everywhere and always will.
// What must not differ is which fields of the model an operator can reach.
func TestLegacyInboundFormsCarryEveryField(t *testing.T) {
	for _, p := range splitProtocols(t) {
		live := fieldBindings(t, "html/form/protocol/"+p+".html")
		legacy := fieldBindings(t, "html/form/protocol_legacy/"+p+".html")

		if only := missingFrom(live, legacy); len(only) > 0 {
			t.Errorf("%s: the old inbound dialog cannot reach %d field(s) the current one can: %v\n"+
				"  add them to web/html/form/protocol_legacy/%s.html, which is the whole protocol in one template",
				p, len(only), only, p)
		}
		if only := missingFrom(legacy, live); len(only) > 0 {
			t.Errorf("%s: the current inbound dialog cannot reach %d field(s) the old one can: %v\n"+
				"  add them to the right section in web/html/form/protocol/%s.html",
				p, len(only), only, p)
		}
	}

	// The shell around the protocol form: remark, listen, ports, quota, expiry and
	// the traffic/speed limits, which both dialogs carry themselves.
	live := fieldBindings(t, "html/form/inbound.html")
	legacy := fieldBindings(t, "html/form/inbound_legacy.html")
	if only := missingFrom(live, legacy); len(only) > 0 {
		t.Errorf("the old inbound dialog cannot reach %d shell field(s) the current one can: %v\n"+
			"  add them to web/html/form/inbound_legacy.html", len(only), only)
	}
	if only := missingFrom(legacy, live); len(only) > 0 {
		t.Errorf("the current inbound dialog cannot reach %d shell field(s) the old one can: %v\n"+
			"  add them to web/html/form/inbound.html", len(only), only)
	}
}

// TestInboundModalServesTheChosenForm renders the modal both ways and checks that
// the setting actually selects a dialog.
//
// EXECUTES the template rather than parsing it: parsing proves the {{if}} is
// well-formed, not that either branch produces the right dialog, and the branch
// most operators will never see is the one that would rot unnoticed. It also
// catches the mistake this wiring invites - calling the define without passing the
// page data, which makes .legacyInboundForm unreadable and quietly serves the
// current form to a panel that asked for the old one.
func TestInboundModalServesTheChosenForm(t *testing.T) {
	tpl := parsePanelTemplates(t)

	for _, tc := range []struct {
		legacy       bool
		wantContains []string
		wantAbsent   []string
	}{
		{
			legacy: true,
			// The old dialog: no rail, antd's default footer, the Sniffing collapse
			// the old shell carried, and OpenVPN's certificates under the <a-divider>
			// caption the redesign replaced with .bo-if-sub - which is what proves the
			// frozen protocol copy was rendered and not the live one.
			wantContains: []string{`header="Sniffing"`, `cancel-text=`, `<a-divider>Certificates</a-divider>`},
			wantAbsent:   []string{`bo-cf-rail`, `bo-if-foot`, `data-sec="identity"`},
		},
		{
			legacy:       false,
			wantContains: []string{`bo-cf-rail`, `bo-if-foot`, `data-sec="identity"`},
			wantAbsent:   []string{`<a-divider>Certificates</a-divider>`, `header="Sniffing"`},
		},
	} {
		var buf bytes.Buffer
		data := map[string]any{"legacyInboundForm": tc.legacy}
		if err := tpl.ExecuteTemplate(&buf, "modals/inboundModal", data); err != nil {
			t.Fatalf("legacyInboundForm=%v: execute modals/inboundModal: %v", tc.legacy, err)
		}
		out := buf.String()
		for _, want := range tc.wantContains {
			if !strings.Contains(out, want) {
				t.Errorf("legacyInboundForm=%v: rendered dialog does not contain %q", tc.legacy, want)
			}
		}
		for _, absent := range tc.wantAbsent {
			if strings.Contains(out, absent) {
				t.Errorf("legacyInboundForm=%v: rendered dialog still contains %q, so it served the other form", tc.legacy, absent)
			}
		}
	}

	// No data at all is what {{template "modals/inboundModal"}} without a dot gives
	// the define, and it must still render - as the current form, the panel default.
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "modals/inboundModal", nil); err != nil {
		t.Fatalf("execute with nil data: %v", err)
	}
	if !strings.Contains(buf.String(), "bo-cf-rail") {
		t.Error("with no page data the modal must fall back to the current form")
	}
}

// parsePanelTemplates mirrors the production getHtmlTemplate() walk, failing on a
// parse error instead of ignoring it.
func parsePanelTemplates(t *testing.T) *template.Template {
	t.Helper()
	tpl := template.New("").Funcs(template.FuncMap{
		"i18n": func(key string, args ...string) (string, error) { return key, nil },
	})
	err := fs.WalkDir(htmlFS, "html", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		newT, perr := tpl.ParseFS(htmlFS, path+"/*.html")
		if perr != nil {
			if strings.Contains(perr.Error(), "matches no files") {
				return nil
			}
			t.Fatalf("ParseFS %s/*.html: %v", path, perr)
		}
		tpl = newT
		return nil
	})
	if err != nil {
		t.Fatalf("walk htmlFS: %v", err)
	}
	return tpl
}

// TestLegacyInboundFormRendersEverySplitProtocol checks the wiring rather than the
// contents: every protocol the rail form splits has a frozen whole copy, that copy
// declares the name the old shell asks for, and the old shell actually asks for it.
//
// Without this a newly split protocol would still parse and still render - as an
// empty stretch of dialog, because {{template "form/x"}} in the old shell would
// resolve to the rail form's header fragment and nothing else.
func TestLegacyInboundFormRendersEverySplitProtocol(t *testing.T) {
	shell, err := fs.ReadFile(htmlFS, "html/form/inbound_legacy.html")
	if err != nil {
		t.Fatalf("read html/form/inbound_legacy.html: %v", err)
	}
	for _, p := range splitProtocols(t) {
		path := "html/form/protocol_legacy/" + p + ".html"
		body, err := fs.ReadFile(htmlFS, path)
		if err != nil {
			t.Errorf("%s is split into sections for the rail form but has no whole copy at web/%s: the old dialog would render nothing for it", p, path)
			continue
		}
		if define := fmt.Sprintf(`{{define "form/legacy/%s"}}`, p); !strings.Contains(string(body), define) {
			t.Errorf("web/%s does not declare %s", path, define)
		}
		if ref := fmt.Sprintf(`{{template "form/legacy/%s"}}`, p); !strings.Contains(string(shell), ref) {
			t.Errorf("web/html/form/inbound_legacy.html never renders %s, so the old dialog shows nothing for %s", ref, p)
		}
	}
}
