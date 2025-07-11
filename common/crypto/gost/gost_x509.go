package gost

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	x509 "github.com/xtls/xray-core/common/crypto/x509"
	pkix "crypto/x509/pkix"
	"github.com/pedroalbanese/gogost/gost3410"
)

// GOST signature algorithm constants
const (
	GOST256 = 0x0601 // GOST R 34.10-2012 256-bit
	GOST512 = 0x0602 // GOST R 34.10-2012 512-bit
)

// GenerateGOSTSelfSignedCert создает самоподписанный X.509 сертификат GOST2012 (256 или 512)
func GenerateGOSTSelfSignedCert(curve *gost3410.Curve, sigAlg x509.SignatureAlgorithm, cn string, expireDays int) ([]byte, []byte, error) {
	fmt.Printf("DEBUG: Starting GenerateGOSTSelfSignedCert\n")
	
	prvRaw := make([]byte, curve.PointSize())
	_, err := rand.Read(prvRaw)
	if err != nil {
		return nil, nil, err
	}
	prv, err := gost3410.NewPrivateKey(curve, prvRaw)
	if err != nil {
		return nil, nil, err
	}
	pub, err := prv.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("DEBUG: Generated private key type: %T\n", prv)
	fmt.Printf("DEBUG: Generated public key type: %T\n", pub)

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(expireDays) * 24 * time.Hour)
	serial := big.NewInt(time.Now().UnixNano())
	template := x509.Certificate{
		SerialNumber:       serial,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: sigAlg,
		Subject:            pkix.Name{CommonName: cn},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA: false,
	}

	fmt.Printf("DEBUG: About to call CreateCertificate\n")
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template, &template, pub,
		&gost3410.PrivateKeyReverseDigest{Prv: prv},
	)
	if err != nil {
		fmt.Printf("DEBUG: CreateCertificate failed: %v\n", err)
		return nil, nil, err
	}

	fmt.Printf("DEBUG: CreateCertificate succeeded\n")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(prv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// GenerateGOSTCAChildCert создает сертификат, подписанный CA на GOST2012
func GenerateGOSTCAChildCert(curve *gost3410.Curve, sigAlg x509.SignatureAlgorithm, cn string, expireDays int, caCert *x509.Certificate, caKey *gost3410.PrivateKey) ([]byte, []byte, error) {
	prvRaw := make([]byte, curve.PointSize())
	_, err := rand.Read(prvRaw)
	if err != nil {
		return nil, nil, err
	}
	prv, err := gost3410.NewPrivateKey(curve, prvRaw)
	if err != nil {
		return nil, nil, err
	}
	pub, err := prv.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(expireDays) * 24 * time.Hour)
	serial := big.NewInt(time.Now().UnixNano())
	template := x509.Certificate{
		SerialNumber:       serial,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: sigAlg,
		Subject:            pkix.Name{CommonName: cn},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA: false,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template, caCert, pub,
		&gost3410.PrivateKeyReverseDigest{Prv: caKey},
	)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(prv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
} 