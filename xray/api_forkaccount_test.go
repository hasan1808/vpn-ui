package xray

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
)

// forkAccount hand-encodes protobuf because the anytls/tuic/naive account messages live
// only in the patched core (third_party/Xray-core), which the panel does not link: go.mod
// pins the published github.com/xtls/xray-core and the fork is compiled separately into
// the embedded xray binary.
//
// A bug in that encoder is invisible from the panel. A wrong field NUMBER unmarshals
// into unknownFields rather than failing, so AlterInbound accepts the request, AddUser
// returns nil, the panel reports success and leaves needRestart false, and the account,
// holding an empty credential, simply never authenticates until some unrelated edit
// forces a core restart that reloads it from the config. (A wrong type URL is the loud
// case: the core's proto registry rejects the name outright.)
//
// So it is pinned here against protobuf's own output for a message of the same shape:
// vless.Account is two proto3 strings at fields 1 and 2, exactly like
// tuic.Account{uuid=1, password=2}, and its field 1 alone stands in for the
// password-only anytls and naive accounts.
func TestForkAccountMatchesProtobufEncoding(t *testing.T) {
	cases := []struct {
		name   string
		first  string
		second string
	}{
		{"both fields", "9f1c1e2a-0000-4000-8000-abcdefabcdef", "s3cret"},
		{"second empty", "9f1c1e2a-0000-4000-8000-abcdefabcdef", ""},
		{"first empty", "", "s3cret"},
		{"both empty", "", ""},
		// Past 127 bytes the length prefix needs a second varint byte, which is the
		// one branch of appendProtoVarint a short password never reaches.
		{"long value", strings.Repeat("x", 200), strings.Repeat("y", 300)},
		{"non-ascii", "دستگاه", "رمز عبور"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := serial.ToTypedMessage(&vless.Account{Id: c.first, Flow: c.second})
			got := forkAccount("stand-in.Account",
				protoStringField{1, c.first},
				protoStringField{2, c.second},
			)

			if !bytes.Equal(got.Value, want.Value) {
				t.Errorf("encoded value = %x, protobuf produces %x", got.Value, want.Value)
			}
			if got.Type != "stand-in.Account" {
				t.Errorf("type URL = %q, want %q", got.Type, "stand-in.Account")
			}
		})
	}
}

// The naive account is the one fork account with TWO fields whose numbers the panel
// chooses by hand, and getting them backwards is the silent case described above: the
// core would read the username as the password and reject every hot-added client while
// AddUser reported success.
//
// Read out of the core's OWN generated struct tags rather than restated, because a
// restatement drifts exactly like the thing it is guarding. Skipped when the submodule
// is not checked out; the panel builds without it.
func TestNaiveAccountFieldNumbersMatchTheCore(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "third_party", "Xray-core", "proxy", "naive", "config.pb.go"))
	if err != nil {
		t.Skip("core submodule not checked out:", err)
	}

	// `protobuf:"bytes,2,opt,name=username,proto3"`
	fieldRe := regexp.MustCompile(`protobuf:"bytes,(\d+),opt,name=(\w+),proto3"`)
	core := map[string]int{}
	for _, m := range fieldRe.FindAllStringSubmatch(string(src), -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("unparseable field number %q", m[1])
		}
		core[m[2]] = n
	}
	if len(core) == 0 {
		t.Fatal("parsed no protobuf field tags out of the core's naive config.pb.go")
	}

	for name, want := range map[string]int{
		"password": naiveAccountPasswordField,
		"username": naiveAccountUsernameField,
	} {
		got, ok := core[name]
		if !ok {
			t.Errorf("the core's naive Account has no %q field; the panel encodes one at %d", name, want)
			continue
		}
		if got != want {
			t.Errorf("core has naive Account.%s at field %d, the panel encodes it at %d", name, got, want)
		}
	}
}

// The type URLs are the only link between the panel and the core's proto registry: a
// mismatch is not a compile error, it is an AlterInbound that fails at runtime. Pinned
// so a rename in the core has to be made here too.
func TestForkAccountTypeURLs(t *testing.T) {
	for got, want := range map[string]string{
		anytlsAccountType: "xray.proxy.anytls.Account",
		tuicAccountType:   "xray.proxy.tuic.Account",
		naiveAccountType:  "xray.proxy.naive.Account",
	} {
		if got != want {
			t.Errorf("account type URL = %q, want %q", got, want)
		}
	}
}
