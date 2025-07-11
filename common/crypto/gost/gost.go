package gost

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
	"crypto/x509/pkix"

	"github.com/tjfoc/gmsm/sm2"
	sm2x509 "github.com/tjfoc/gmsm/x509"
)

// GOSTCurve represents GOST curve types
type GOSTCurve int

const (
	GOST2012_256 GOSTCurve = iota
	GOST2012_512
)

// String returns the string representation of the GOST curve
func (c GOSTCurve) String() string {
	switch c {
	case GOST2012_256:
		return "GOST2012_256"
	case GOST2012_512:
		return "GOST2012_512"
	default:
		return "Unknown"
	}
}

// GenerateKeyPair generates a GOST key pair
func GenerateKeyPair(curve GOSTCurve) (*sm2.PrivateKey, error) {
	// For now, we'll use SM2 as a base since GOST curves aren't directly supported
	// In a real implementation, you'd need a GOST-specific library
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate GOST %s key: %w", curve.String(), err)
	}
	return privKey, nil
}

// GenerateCertificate generates a GOST certificate
func GenerateCertificate(privKey *sm2.PrivateKey, domain string, isCA bool, expireHours int) ([]byte, []byte, error) {
	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(expireHours) * time.Hour)

	template := &sm2x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Xray GOST Certificate"},
			CommonName:   domain,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              sm2x509.KeyUsageKeyEncipherment | sm2x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []sm2x509.ExtKeyUsage{sm2x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= sm2x509.KeyUsageCertSign
	} else {
		template.DNSNames = []string{domain}
	}

	// Create certificate using SM2 (since GOST isn't directly supported)
	certDER, err := sm2x509.CreateCertificate(template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GOST certificate: %w", err)
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKey.D.Bytes(),
	})

	return certPEM, privKeyPEM, nil
}

// ParsePrivateKey parses a GOST private key from PEM format
func ParsePrivateKey(pemData []byte) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := sm2x509.ParsePKCS8UnecryptedPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GOST private key: %w", err)
	}

	return privKey, nil
}

// GetPublicKeyInfo returns public key information
func GetPublicKeyInfo(privKey *sm2.PrivateKey, curve GOSTCurve) (string, string, string) {
	pubKey := privKey.PublicKey
	return "GOST " + curve.String() + "-bit",
		fmt.Sprintf("%x", pubKey.X.Bytes()),
		fmt.Sprintf("%x", pubKey.Y.Bytes())
} 