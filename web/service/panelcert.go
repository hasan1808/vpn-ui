package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GeneratePanelSelfSignedCert writes a self-signed TLS certificate + key for the
// panel's own web server into dir and returns their paths. The cert carries the
// server's public IP plus 127.0.0.1 / localhost as SANs so it validates against
// the URL the operator actually uses. This backs deploy.sh's fresh-install HTTPS
// option — a browser still warns on the self-signed issuer, which is expected.
//
// ECDSA P-256, 10-year validity (matching the VPN protocols' self-signed certs).
// Cert is written 0644, key 0600. An existing pair in dir is overwritten, so
// re-running is idempotent.
func GeneratePanelSelfSignedCert(dir, ip string) (certPath, keyPath string, err error) {
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("create cert dir %s: %w", dir, err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"pro-ui"},
			CommonName:   "pro-ui panel",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	// Add the detected public IP as a SAN when it parsed to a real address (the
	// dashboard's IP probe returns "N/A" when it can't resolve one).
	if parsed := net.ParseIP(ip); parsed != nil {
		template.IPAddresses = append(template.IPAddresses, parsed)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}

	certPath = filepath.Join(dir, "panel.crt")
	keyPath = filepath.Join(dir, "panel.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err = os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write cert %s: %w", certPath, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err = os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write key %s: %w", keyPath, err)
	}

	return certPath, keyPath, nil
}
