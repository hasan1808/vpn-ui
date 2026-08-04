package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// The certificate an ocserv inbound on another vpn-ui actually handed out before the
// generator learned to set a SAN: self-issued, CA:FALSE, CN a description rather than
// an address, no subjectAltName. Kept verbatim because the golden pin below was
// verified twice against it outside this package: once with
//
//	openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
//	  openssl dgst -sha256 -binary | openssl base64
//
// and once by the real openconnect client, which accepted this pin and carried traffic
// against the gateway that presented this certificate.
const ocSelfSignedLeafPEM = `-----BEGIN CERTIFICATE-----
MIIB0jCCAVigAwIBAgIIGMdVnc3GKrgwCgYIKoZIzj0EAwMwNTEPMA0GA1UEChMG
dnBuLXVpMSIwIAYDVQQDExl2cG4tdWkgT3BlbkNvbm5lY3QgU2VydmVyMB4XDTI2
MDczMTA5MjUxM1oXDTM2MDcyODA5MjUxM1owNTEPMA0GA1UEChMGdnBuLXVpMSIw
IAYDVQQDExl2cG4tdWkgT3BlbkNvbm5lY3QgU2VydmVyMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEGJpGB4aXmKDWeFIBNZ7y4gqnLYWpfBUtrc2fLuylcwvS/k+3oL5f
67i1cYPaujloOjNUTKubudHg7K0j8PNS8nFOHmSoJA6AUE2Fe7iVE+yCa1OOGapD
wrGu0SS4QGC+ozUwMzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUH
AwEwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAwNoADBlAjEAqCRzmavOswl6DO1R
X0O6U4mkBNjd7/ljL7hly9oD6HqUEK5KDTFl1uB9yDFU5wWHAjBI58xUSHuxSXOY
iFtNdWaqoEAshIDNAPTnb82Vmj88zbDDx5HnmY3/Lf8RtSmqFU0=
-----END CERTIFICATE-----`

const ocSelfSignedLeafPin = "pin-sha256:CYZgLyqRswvjrcEay0B5opi2Y8Jw6nSvgOBUIU1IJ24="

func mkCert(t *testing.T, isCA bool, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A self-signed gateway certificate pasted into the CA box is pinned, which is the
// only thing that can authenticate it: it is not a CA, so it cannot anchor a chain.
func TestOcOutPinSelfSigned(t *testing.T) {
	if got := ocOutPinSelfSigned(ocSelfSignedLeafPEM); got != ocSelfSignedLeafPin {
		t.Fatalf("self-signed leaf: got %q, want %q", got, ocSelfSignedLeafPin)
	}
	if got := ocOutPinSelfSigned("\n\n  " + ocSelfSignedLeafPEM + "\n"); got != ocSelfSignedLeafPin {
		t.Fatalf("surrounding whitespace changed the pin: %q", got)
	}
}

// A real CA must keep being used as a CA. Pinning its key would reject the gateway,
// whose leaf this side has never seen.
func TestOcOutPinSelfSignedLeavesACAAlone(t *testing.T) {
	if got := ocOutPinSelfSigned(mkCert(t, true, "some private CA")); got != "" {
		t.Fatalf("CA certificate was pinned: %q", got)
	}
}

func TestOcOutPinSelfSignedIgnoresBundlesAndJunk(t *testing.T) {
	bundle := mkCert(t, false, "leaf") + mkCert(t, true, "issuer")
	if got := ocOutPinSelfSigned(bundle); got != "" {
		t.Fatalf("a two-certificate bundle was pinned: %q", got)
	}
	for _, junk := range []string{"", "   ", "not a pem", "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"} {
		if got := ocOutPinSelfSigned(junk); got != "" {
			t.Fatalf("junk %q produced a pin: %q", junk, got)
		}
	}
}

// The generator must name the gateway. A certificate with no subjectAltName cannot be
// verified by name by anything, which is what made a self-signed ocserv/SSTP inbound
// unreachable from any client that checks, this panel's own outbound included.
func TestSelfSignedServerCertsCarrySANs(t *testing.T) {
	for _, tc := range []struct {
		name string
		gen  func(string) (string, string, error)
	}{
		{"ocserv", (&OcservService{}).GenerateSelfSignedCert},
		{"sstp", (&SstpService{}).GenerateSelfSignedCert},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, _, err := tc.gen("203.0.113.7")
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				t.Fatal("no PEM block")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if cert.Subject.CommonName != "203.0.113.7" {
				t.Errorf("CN = %q, want the server address", cert.Subject.CommonName)
			}
			if err := cert.VerifyHostname("203.0.113.7"); err != nil {
				t.Errorf("the address it was minted for does not verify: %v", err)
			}
			var haveIP bool
			for _, ip := range cert.IPAddresses {
				if ip.Equal(net.ParseIP("203.0.113.7")) {
					haveIP = true
				}
			}
			if !haveIP {
				t.Errorf("no iPAddress SAN, got %v", cert.IPAddresses)
			}
			// Both forms: several real clients read an address out of dNSName.
			if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "203.0.113.7" {
				t.Errorf("dNSName SANs = %v, want [203.0.113.7]", cert.DNSNames)
			}
			// And it is still a leaf, so the outbound's paste-the-cert path pins it.
			if got := ocOutPinSelfSigned(certPEM); !strings.HasPrefix(got, "pin-sha256:") {
				t.Errorf("freshly generated cert is not pinnable: %q", got)
			}
		})
	}
}

// A hostname is a dNSName only; there is no address to put in an iPAddress SAN.
func TestSelfSignedServerCertAcceptsAHostname(t *testing.T) {
	certPEM, _, err := (&OcservService{}).GenerateSelfSignedCert("vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("vpn.example.com"); err != nil {
		t.Errorf("hostname does not verify: %v", err)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("a hostname produced an iPAddress SAN: %v", cert.IPAddresses)
	}
}
