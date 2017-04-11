package machines

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

// VerifyCA makes sure there's a CA present in the specified dir
func VerifyCA(rootCADir string) error {
	caFile := filepath.Join(rootCADir, "ca.pem")
	if _, err := os.Stat(caFile); err == nil {
		// If we can stat it, assume we're good
		return nil
	}
	logrus.Debugf("Generating CA in %s", rootCADir)
	// Quiet down the cfssl logging
	log.Level = log.LevelWarning
	req := csr.CertificateRequest{
		CN:         "e2e ca",
		KeyRequest: &csr.BasicKeyRequest{"ecdsa", 256},
	}
	caCert, _, key, err := initca.New(&req)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(rootCADir, "ca.pem"), caCert, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(rootCADir, "ca-key.pem"), key, 0600); err != nil {
		return err
	}
	// Now generate a cert pair for local client use
	_, clientCert, clientKey, err := GenerateNodeCerts(rootCADir, "client", []string{"127.0.0.1"})
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(rootCADir, "cert.pem"), clientCert, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(rootCADir, "key.pem"), clientKey, 0600); err != nil {
		return err
	}

	return nil
}

// GenerateNodeCerts will create a signed cert and key for the node
// returns: ca, cert, key, error
func GenerateNodeCerts(rootCADir, cn string, hosts []string) ([]byte, []byte, []byte, error) {
	certDuration := time.Duration(10 * 365 * 24 * time.Hour)
	s, err := local.NewSignerFromFile(
		filepath.Join(rootCADir, "ca.pem"),
		filepath.Join(rootCADir, "ca-key.pem"),
		&config.Signing{
			Default: &config.SigningProfile{
				Usage: []string{
					"signing",
					"key encipherment",
					"server auth",
					"client auth",
				},
				Expiry:       certDuration,
				ExpiryString: certDuration.String(),
			},
		})

	if err != nil {
		logrus.Debug("Failed to load signer")
		return nil, nil, nil, err
	}
	req := &csr.CertificateRequest{
		CN:         cn,
		KeyRequest: &csr.BasicKeyRequest{"ecdsa", 256},
		Hosts:      hosts,
		Names:      []csr.Name{{}},
	}
	csr, key, err := csr.ParseRequest(req)
	if err != nil {
		logrus.Debug("Failed to parse csr")
		return nil, nil, nil, err
	}
	cert, err := s.Sign(signer.SignRequest{
		Request: string(csr),
		Profile: "node",
	})
	if err != nil {
		logrus.Debug("Sign failure")
		return nil, nil, nil, err
	}
	ca, err := ioutil.ReadFile(filepath.Join(rootCADir, "ca.pem"))
	if err != nil {
		logrus.Debug("ca load")
		return nil, nil, nil, err
	}
	return ca, cert, key, nil
}
