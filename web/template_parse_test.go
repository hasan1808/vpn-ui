package web

import (
	"bytes"
	"html/template"
	"io/fs"
	"strings"
	"testing"
)

// TestAllTemplatesParseAndProtocolFormsDefined mirrors the production
// getHtmlTemplate() walk over the entire embedded htmlFS, but — unlike production,
// which silently ignores ParseFS errors — it FAILS on any parse error and then
// asserts every protocol form's {{define}} resolved. This catches a broken or
// mis-named per-protocol form (e.g. form/protocol/sstp.html) that would otherwise
// only surface as a runtime 500 when the inbound modal renders {{template "form/x"}}.
func TestAllTemplatesParseAndProtocolFormsDefined(t *testing.T) {
	funcMap := template.FuncMap{
		"i18n": func(key string, args ...string) (string, error) { return "", nil },
	}
	tpl := template.New("").Funcs(funcMap)
	walkErr := fs.WalkDir(htmlFS, "html", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		newT, perr := tpl.ParseFS(htmlFS, path+"/*.html")
		if perr != nil {
			// dirs with no *.html yield "pattern matches no files" — skip like production does
			if strings.Contains(perr.Error(), "matches no files") {
				return nil
			}
			t.Errorf("ParseFS %s/*.html: %v", path, perr)
			return nil
		}
		tpl = newT
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk htmlFS: %v", walkErr)
	}
	// every VPN protocol form must be defined (form/mtproto is the new one)
	for _, name := range []string{"form/ssh", "form/mtproto", "form/wgc", "form/ikev2", "form/sstp", "form/openconnect", "form/openvpn", "form/pptp", "form/l2tp", "form/anytls", "form/tuic", "form/naive"} {
		if tpl.Lookup(name) == nil {
			t.Errorf("template %q not defined — its protocol form failed to parse or is mis-named", name)
		}
	}
}

// TestEditedTemplatesParse guards the Go-template syntax of the HTML templates that
// carry the multi-select / bulk-ops / export UI. getHtmlTemplate() silently ignores
// ParseFS errors, so a broken template would only surface as a runtime 500 — this
// catches it at test time instead. Vue expressions use [[ ]] delimiters, so the only
// Go-template function the parser needs defined is i18n.
func TestEditedTemplatesParse(t *testing.T) {
	funcMap := template.FuncMap{
		"i18n": func(key string, args ...string) (string, error) { return "", nil },
	}
	files := []string{
		"html/inbounds.html",
		"html/clients.html",
		"html/component/clientActions.html", // the shared client mixin
		"html/component/clientActionIcons.html",
		"html/component/bulkOpsModal.html",
		"html/modals/client_membership_modal.html",
		"html/index.html", // dashboard incl. the unsupported-distro warning modal
		"html/admins.html",
		"html/modals/admin_modal.html",
		"html/component/aSidebar.html", // permission-gated tabs
	}
	for _, f := range files {
		b, err := htmlFS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := template.New(f).Funcs(funcMap).Parse(string(b)); err != nil {
			t.Errorf("%s failed to parse: %v", f, err)
		}
	}
}

// TestSidebarLogoSrcResolves renders the sidebar component with data and asserts the
// brand logo <img> src is prefixed with base_path. The mark lives in the nested
// "component/sidebar/content" template, which must be included WITH data ({{template
// ... .}}) — otherwise .base_path is nil and the src renders empty, so the logo 404s.
func TestSidebarLogoSrcResolves(t *testing.T) {
	funcMap := template.FuncMap{
		"i18n": func(key string, args ...string) (string, error) { return "", nil },
	}
	b, err := htmlFS.ReadFile("html/component/aSidebar.html")
	if err != nil {
		t.Fatalf("read aSidebar.html: %v", err)
	}
	tpl, err := template.New("aSidebar").Funcs(funcMap).Parse(string(b))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	data := map[string]any{"base_path": "/test/", "request_uri": "/test/panel/"}
	if err := tpl.ExecuteTemplate(&buf, "component/aSidebar", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	// The component is a Vue template string inside <script>, so html/template
	// JS-escapes the dynamic base_path (/ -> \/); the browser un-escapes it at
	// parse time. Normalise before matching.
	out := strings.ReplaceAll(buf.String(), `\/`, "/")
	if !strings.Contains(out, "/test/assets/img/logo.png") {
		t.Errorf("logo src not resolved with base_path (nil-data bug?); output:\n%s", out)
	}
	if strings.Contains(out, "<no value>") {
		t.Errorf("template produced <no value> — data not threaded into the component")
	}
}
