package service

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// AcmeService manages Let's Encrypt certificate issuance via acme.sh
type AcmeService struct {
	running bool
	mu      sync.Mutex
	output  string
}

// AcmeIssueRequest contains parameters for certificate issuance
type AcmeIssueRequest struct {
	Domain  string `json:"domain"`
	Email   string `json:"email"`
	Method  string `json:"method"`  // "http" or "dns"
	CfToken string `json:"cfToken"` // Cloudflare API token (for dns method)
	CertDir string `json:"certDir"` // directory to store certs
}

// AcmeResult represents the result of an ACME operation
type AcmeResult struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Output   string `json:"output"`
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`
}

var acmeService = &AcmeService{}

// GetAcmeService returns the singleton ACME service
func GetAcmeService() *AcmeService {
	return acmeService
}

// IsRunning returns whether an ACME operation is in progress
func (s *AcmeService) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// GetOutput returns the last operation output
func (s *AcmeService) GetOutput() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.output
}

// acmePath returns the path to acme.sh, installing if necessary
func (s *AcmeService) acmePath() (string, error) {
	homeDir, _ := os.UserHomeDir()
	acmeDir := filepath.Join(homeDir, ".acme.sh")
	acmeBin := filepath.Join(acmeDir, "acme.sh")

	if _, err := os.Stat(acmeBin); err == nil {
		return acmeBin, nil
	}

	// Use the panel binary to install acme.sh
	bin, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot find panel binary: %w", err)
	}

	cmd := exec.Command(bin, "install-acme", acmeBin)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("install acme.sh: %w\n%s", err, string(output))
	}

	return acmeBin, nil
}

// IssueCert obtains a certificate using acme.sh
func (s *AcmeService) IssueCert(req AcmeIssueRequest) AcmeResult {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return AcmeResult{Success: false, Message: "Another ACME operation is in progress"}
	}
	s.running = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	var output strings.Builder

	acmeBin, err := s.acmePath()
	if err != nil {
		s.mu.Lock()
		s.output = err.Error()
		s.mu.Unlock()
		return AcmeResult{Success: false, Message: err.Error()}
	}

	acmeDir := filepath.Dir(acmeBin)

	output.WriteString("acme.sh ready\n")

	// Ensure cron daemon for auto-renewal
	output.WriteString("Checking cron daemon...\n")
	cronCheck := exec.Command("which", "crond")
	if cronCheck.Run() != nil {
		cronCheck = exec.Command("which", "cron")
		if cronCheck.Run() != nil {
			output.WriteString("Installing cron daemon...\n")
			exec.Command("sh", "-c", "apt-get install -y cron 2>/dev/null || yum install -y cronie 2>/dev/null || true").Run()
		}
	}
	exec.Command("sh", "-c", "systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null || true").Run()

	// Set CA to Let's Encrypt
	output.WriteString("Setting CA to Let's Encrypt...\n")
	args := []string{"--set-default-ca", "--server", "letsencrypt"}
	cmd := exec.Command(acmeBin, args...)
	cmd.Dir = acmeDir
	var cmdOut bytes.Buffer
	cmd.Stdout = &cmdOut
	cmd.Stderr = &cmdOut
	if err := cmd.Run(); err != nil {
		output.WriteString(fmt.Sprintf("Set CA warning: %s\n", cmdOut.String()))
	} else {
		output.WriteString(cmdOut.String())
	}

	// Build issue arguments
	issueArgs := []string{"--issue"}

	switch req.Method {
	case "dns":
		if req.CfToken == "" {
			return AcmeResult{Success: false, Message: "Cloudflare API token is required for DNS method"}
		}
		os.Setenv("CF_Token", req.CfToken)
		issueArgs = append(issueArgs, "-d", req.Domain, "--dns", "dns_cf", "--keylength", "2048")
	default:
		issueArgs = append(issueArgs, "-d", req.Domain, "--standalone", "--keylength", "2048")
	}

	output.WriteString(fmt.Sprintf("Issuing certificate for %s (method: %s)...\n", req.Domain, req.Method))

	cmd = exec.Command(acmeBin, issueArgs...)
	cmd.Dir = acmeDir
	cmdOut.Reset()
	cmd.Stdout = &cmdOut
	cmd.Stderr = &cmdOut
	err = cmd.Run()
	output.WriteString(cmdOut.String())

	if err != nil {
		s.mu.Lock()
		s.output = output.String()
		s.mu.Unlock()
		return AcmeResult{
			Success: false,
			Message: fmt.Sprintf("Certificate issuance failed: %s", err),
			Output:  output.String(),
		}
	}

	output.WriteString("Certificate issued successfully\n")

	// Install cert
	homeDir, _ := os.UserHomeDir()
	if req.CertDir == "" {
		req.CertDir = filepath.Join(homeDir, ".acme.sh", "certs", req.Domain)
	}
	os.MkdirAll(req.CertDir, 0700)

	certPath := filepath.Join(req.CertDir, "fullchain.pem")
	keyPath := filepath.Join(req.CertDir, "privkey.pem")

	output.WriteString("Installing certificate...\n")
	installArgs := []string{
		"--install-cert",
		"-d", req.Domain,
		"--key-file", keyPath,
		"--fullchain-file", certPath,
		"--reloadcmd", "true",
	}
	cmd = exec.Command(acmeBin, installArgs...)
	cmd.Dir = acmeDir
	cmdOut.Reset()
	cmd.Stdout = &cmdOut
	cmd.Stderr = &cmdOut
	err = cmd.Run()
	output.WriteString(cmdOut.String())

	if err != nil {
		s.mu.Lock()
		s.output = output.String()
		s.mu.Unlock()
		return AcmeResult{
			Success: false,
			Message: fmt.Sprintf("Certificate install failed: %s", err),
			Output:  output.String(),
		}
	}

	// Set cert paths in settings
	settingService := SettingService{}
	if err := settingService.SetCertFile(certPath); err != nil {
		output.WriteString(fmt.Sprintf("Warning: could not set cert path: %s\n", err))
	}
	if err := settingService.SetKeyFile(keyPath); err != nil {
		output.WriteString(fmt.Sprintf("Warning: could not set key path: %s\n", err))
	}

	output.WriteString(fmt.Sprintf("Certificate installed: %s\n", certPath))
	output.WriteString(fmt.Sprintf("Key installed: %s\n", keyPath))

	// Setup auto-renewal cron
	output.WriteString("Setting up auto-renewal...\n")
	cronEntry := fmt.Sprintf("0 0 1 * * %s --renew -d %s --force >/dev/null 2>&1", acmeBin, req.Domain)
	exec.Command("sh", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronEntry)).Run()

	s.mu.Lock()
	s.output = output.String()
	s.mu.Unlock()

	return AcmeResult{
		Success:  true,
		Message:  "Certificate issued and installed successfully",
		Output:   output.String(),
		CertPath: certPath,
		KeyPath:  keyPath,
	}
}

// GetCertStatus checks the status of the current certificate
func (s *AcmeService) GetCertStatus() map[string]interface{} {
	settingService := SettingService{}
	certFile, _ := settingService.GetCertFile()
	keyFile, _ := settingService.GetKeyFile()

	result := map[string]interface{}{
		"certFile": certFile,
		"keyFile":  keyFile,
		"hasCert":  certFile != "" && keyFile != "",
	}

	if certFile != "" {
		cmd := exec.Command("openssl", "x509", "-in", certFile, "-noout", "-enddate", "-subject", "-issuer")
		if output, err := cmd.CombinedOutput(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "notAfter=") {
					result["expiry"] = strings.TrimPrefix(line, "notAfter=")
				} else if strings.HasPrefix(line, "subject=") {
					result["subject"] = strings.TrimPrefix(line, "subject=")
				} else if strings.HasPrefix(line, "issuer=") {
					result["issuer"] = strings.TrimPrefix(line, "issuer=")
				}
			}
		}
	}

	homeDir, _ := os.UserHomeDir()
	acmePath := filepath.Join(homeDir, ".acme.sh", "acme.sh")
	result["acmeInstalled"] = false
	if _, err := os.Stat(acmePath); err == nil {
		result["acmeInstalled"] = true
	}

	return result
}

// RenewCert renews the certificate for the given domain
func (s *AcmeService) RenewCert(domain string) AcmeResult {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return AcmeResult{Success: false, Message: "Another ACME operation is in progress"}
	}
	s.running = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	acmeBin, err := s.acmePath()
	if err != nil {
		return AcmeResult{Success: false, Message: err.Error()}
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Renewing certificate for %s...\n", domain))

	cmd := exec.Command(acmeBin, "--renew", "-d", domain, "--force")
	cmd.Dir = filepath.Dir(acmeBin)
	var cmdOut bytes.Buffer
	cmd.Stdout = &cmdOut
	cmd.Stderr = &cmdOut
	err = cmd.Run()
	output.WriteString(cmdOut.String())

	if err != nil {
		s.mu.Lock()
		s.output = output.String()
		s.mu.Unlock()
		return AcmeResult{Success: false, Message: fmt.Sprintf("Renewal failed: %s", err), Output: output.String()}
	}

	output.WriteString("Certificate renewed successfully\n")

	s.mu.Lock()
	s.output = output.String()
	s.mu.Unlock()

	return AcmeResult{Success: true, Message: "Certificate renewed successfully", Output: output.String()}
}
