package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto/gost"
	sm2crypto "github.com/xtls/xray-core/common/crypto/sm2"
	"github.com/xtls/xray-core/common/errors"
	"github.com/tjfoc/gmsm/sm2"
	sm2x509 "github.com/tjfoc/gmsm/x509"
)

type Certificate struct {
	// certificate in ASN.1 DER format
	Certificate []byte
	// Private key in ASN.1 DER format
	PrivateKey []byte
}

func ParseCertificate(certPEM []byte, keyPEM []byte) (*Certificate, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("failed to decode certificate")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode key")
	}
	return &Certificate{
		Certificate: certBlock.Bytes,
		PrivateKey:  keyBlock.Bytes,
	}, nil
}

func (c *Certificate) ToPEM() ([]byte, []byte) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: c.PrivateKey})
}

type Option func(*x509.Certificate)

// SM2-specific option types
type SM2Option func(*sm2x509.Certificate)

func Authority(isCA bool) Option {
	return func(cert *x509.Certificate) {
		cert.IsCA = isCA
	}
}

func SM2Authority(isCA bool) SM2Option {
	return func(cert *sm2x509.Certificate) {
		cert.IsCA = isCA
	}
}

func NotBefore(t time.Time) Option {
	return func(c *x509.Certificate) {
		c.NotBefore = t
	}
}

func SM2NotBefore(t time.Time) SM2Option {
	return func(c *sm2x509.Certificate) {
		c.NotBefore = t
	}
}

func NotAfter(t time.Time) Option {
	return func(c *x509.Certificate) {
		c.NotAfter = t
	}
}

func SM2NotAfter(t time.Time) SM2Option {
	return func(c *sm2x509.Certificate) {
		c.NotAfter = t
	}
}

func DNSNames(names ...string) Option {
	return func(c *x509.Certificate) {
		c.DNSNames = names
	}
}

func SM2DNSNames(names ...string) SM2Option {
	return func(c *sm2x509.Certificate) {
		c.DNSNames = names
	}
}

func CommonName(name string) Option {
	return func(c *x509.Certificate) {
		c.Subject.CommonName = name
	}
}

func SM2CommonName(name string) SM2Option {
	return func(c *sm2x509.Certificate) {
		c.Subject.CommonName = name
	}
}

func KeyUsage(usage x509.KeyUsage) Option {
	return func(c *x509.Certificate) {
		c.KeyUsage = usage
	}
}

func SM2KeyUsage(usage sm2x509.KeyUsage) SM2Option {
	return func(c *sm2x509.Certificate) {
		c.KeyUsage = usage
	}
}

func Organization(org string) Option {
	return func(c *x509.Certificate) {
		c.Subject.Organization = []string{org}
	}
}

func SM2Organization(org string) SM2Option {
	return func(c *sm2x509.Certificate) {
		c.Subject.Organization = []string{org}
	}
}

func MustGenerate(parent *Certificate, opts ...Option) *Certificate {
	cert, err := Generate(parent, opts...)
	common.Must(err)
	return cert
}

// MustGenerateGOST2012_256 generates a certificate using GOST 2012-256 algorithm
func MustGenerateGOST2012_256(parent *Certificate, opts ...SM2Option) *Certificate {
	cert, err := GenerateGOST2012_256(parent, opts...)
	common.Must(err)
	return cert
}

// MustGenerateGOST2012_512 generates a certificate using GOST 2012-512 algorithm
func MustGenerateGOST2012_512(parent *Certificate, opts ...SM2Option) *Certificate {
	cert, err := GenerateGOST2012_512(parent, opts...)
	common.Must(err)
	return cert
}

// MustGenerateSM2 generates a certificate using SM2 algorithm
func MustGenerateSM2(parent *Certificate, opts ...SM2Option) *Certificate {
	cert, err := GenerateSM2(parent, opts...)
	common.Must(err)
	return cert
}

// GenerateGOST2012_256 generates a certificate using GOST 2012-256 algorithm
func GenerateGOST2012_256(parent *Certificate, opts ...SM2Option) (*Certificate, error) {
	var (
		err error
	)
	selfKey, err := gost.GenerateKeyPair(gost.GOST2012_256)
	if err != nil {
		return nil, errors.New("failed to generate GOST 2012-256 private key").Base(err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number").Base(err)
	}
	template := &sm2x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Xray GOST 2012-256 Certificate"},
			CommonName:   "",
		},
		NotBefore:             time.Now().Add(time.Hour * -1),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              sm2x509.KeyUsageKeyEncipherment | sm2x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []sm2x509.ExtKeyUsage{sm2x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	parentCert := template
	if parent != nil {
		pCert, err := sm2x509.ParseCertificate(parent.Certificate)
		if err != nil {
			return nil, errors.New("failed to parse parent certificate").Base(err)
		}
		parentCert = pCert
	}
	if parentCert.NotAfter.Before(template.NotAfter) {
		template.NotAfter = parentCert.NotAfter
	}
	if parentCert.NotBefore.After(template.NotBefore) {
		template.NotBefore = parentCert.NotBefore
	}
	for _, opt := range opts {
		opt(template)
	}
	certDER, err := sm2x509.CreateCertificate(template, parentCert, &selfKey.PublicKey, selfKey)
	if err != nil {
		return nil, errors.New("failed to create GOST 2012-256 certificate").Base(err)
	}
	privateKey, err := sm2x509.MarshalSm2UnecryptedPrivateKey(selfKey)
	if err != nil {
		return nil, errors.New("Unable to marshal GOST 2012-256 private key").Base(err)
	}
	return &Certificate{
		Certificate: certDER,
		PrivateKey:  privateKey,
	}, nil
}

// GenerateGOST2012_512 generates a certificate using GOST 2012-512 algorithm
func GenerateGOST2012_512(parent *Certificate, opts ...SM2Option) (*Certificate, error) {
	var (
		err error
	)
	selfKey, err := gost.GenerateKeyPair(gost.GOST2012_512)
	if err != nil {
		return nil, errors.New("failed to generate GOST 2012-512 private key").Base(err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number").Base(err)
	}
	template := &sm2x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Xray GOST 2012-512 Certificate"},
			CommonName:   "",
		},
		NotBefore:             time.Now().Add(time.Hour * -1),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              sm2x509.KeyUsageKeyEncipherment | sm2x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []sm2x509.ExtKeyUsage{sm2x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	parentCert := template
	if parent != nil {
		pCert, err := sm2x509.ParseCertificate(parent.Certificate)
		if err != nil {
			return nil, errors.New("failed to parse parent certificate").Base(err)
		}
		parentCert = pCert
	}
	if parentCert.NotAfter.Before(template.NotAfter) {
		template.NotAfter = parentCert.NotAfter
	}
	if parentCert.NotBefore.After(template.NotBefore) {
		template.NotBefore = parentCert.NotBefore
	}
	for _, opt := range opts {
		opt(template)
	}
	certDER, err := sm2x509.CreateCertificate(template, parentCert, &selfKey.PublicKey, selfKey)
	if err != nil {
		return nil, errors.New("failed to create GOST 2012-512 certificate").Base(err)
	}
	privateKey, err := sm2x509.MarshalSm2UnecryptedPrivateKey(selfKey)
	if err != nil {
		return nil, errors.New("Unable to marshal GOST 2012-512 private key").Base(err)
	}
	return &Certificate{
		Certificate: certDER,
		PrivateKey:  privateKey,
	}, nil
}

// GenerateSM2 generates a certificate using SM2 algorithm
func GenerateSM2(parent *Certificate, opts ...SM2Option) (*Certificate, error) {
	var (
		err error
	)
	selfKey, err := sm2crypto.GenerateKeyPair()
	if err != nil {
		return nil, errors.New("failed to generate SM2 private key").Base(err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number").Base(err)
	}
	template := &sm2x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Xray SM2 Certificate"},
			CommonName:   "",
		},
		NotBefore:             time.Now().Add(time.Hour * -1),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              sm2x509.KeyUsageKeyEncipherment | sm2x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []sm2x509.ExtKeyUsage{sm2x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	parentCert := template
	if parent != nil {
		pCert, err := sm2x509.ParseCertificate(parent.Certificate)
		if err != nil {
			return nil, errors.New("failed to parse parent certificate").Base(err)
		}
		parentCert = pCert
	}
	if parentCert.NotAfter.Before(template.NotAfter) {
		template.NotAfter = parentCert.NotAfter
	}
	if parentCert.NotBefore.After(template.NotBefore) {
		template.NotBefore = parentCert.NotBefore
	}
	for _, opt := range opts {
		opt(template)
	}
	certDER, err := sm2x509.CreateCertificate(template, parentCert, &selfKey.PublicKey, selfKey)
	if err != nil {
		return nil, errors.New("failed to create SM2 certificate").Base(err)
	}
	privateKey, err := sm2x509.MarshalSm2UnecryptedPrivateKey(selfKey)
	if err != nil {
		return nil, errors.New("Unable to marshal SM2 private key").Base(err)
	}
	return &Certificate{
		Certificate: certDER,
		PrivateKey:  privateKey,
	}, nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	case *sm2.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func Generate(parent *Certificate, opts ...Option) (*Certificate, error) {
	var (
		pKey      interface{}
		parentKey interface{}
		err       error
	)
	// higher signing performance than RSA2048
	selfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("failed to generate self private key").Base(err)
	}
	parentKey = selfKey
	if parent != nil {
		if _, e := asn1.Unmarshal(parent.PrivateKey, &ecPrivateKey{}); e == nil {
			pKey, err = x509.ParseECPrivateKey(parent.PrivateKey)
		} else if _, e := asn1.Unmarshal(parent.PrivateKey, &pkcs8{}); e == nil {
			pKey, err = x509.ParsePKCS8PrivateKey(parent.PrivateKey)
		} else if _, e := asn1.Unmarshal(parent.PrivateKey, &pkcs1PrivateKey{}); e == nil {
			pKey, err = x509.ParsePKCS1PrivateKey(parent.PrivateKey)
		}
		if err != nil {
			return nil, errors.New("failed to parse parent private key").Base(err)
		}
		parentKey = pKey
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number").Base(err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now().Add(time.Hour * -1),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	parentCert := template
	if parent != nil {
		pCert, err := x509.ParseCertificate(parent.Certificate)
		if err != nil {
			return nil, errors.New("failed to parse parent certificate").Base(err)
		}
		parentCert = pCert
	}

	if parentCert.NotAfter.Before(template.NotAfter) {
		template.NotAfter = parentCert.NotAfter
	}
	if parentCert.NotBefore.After(template.NotBefore) {
		template.NotBefore = parentCert.NotBefore
	}

	for _, opt := range opts {
		opt(template)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, publicKey(selfKey), parentKey)
	if err != nil {
		return nil, errors.New("failed to create certificate").Base(err)
	}

	privateKey, err := x509.MarshalPKCS8PrivateKey(selfKey)
	if err != nil {
		return nil, errors.New("Unable to marshal private key").Base(err)
	}

	return &Certificate{
		Certificate: derBytes,
		PrivateKey:  privateKey,
	}, nil
}
