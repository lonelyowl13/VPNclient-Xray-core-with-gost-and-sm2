package gost

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/tjfoc/gmsm/sm2"
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

// GOSTPrivateKey represents a GOST private key
type GOSTPrivateKey struct {
	PrivateKey *gost3410.PrivateKey
	Curve      GOSTCurve
}

// GOSTPublicKey represents a GOST public key
type GOSTPublicKey struct {
	PublicKey *gost3410.PublicKey
	Curve     GOSTCurve
}

// getCurve returns the appropriate GOST curve for the given curve type
func getCurve(curve GOSTCurve) *gost3410.Curve {
	switch curve {
	case GOST2012_256:
		return gost3410.CurveIdtc26gost34102012256paramSetA()
	case GOST2012_512:
		return gost3410.CurveIdtc26gost34102012512paramSetA()
	default:
		return nil
	}
}

// GenerateKeyPair generates a true GOST2012 key pair
func GenerateKeyPair(curve GOSTCurve) (*GOSTPrivateKey, error) {
	gostCurve := getCurve(curve)
	if gostCurve == nil {
		return nil, fmt.Errorf("unsupported GOST curve: %s", curve.String())
	}

	privKey, err := gost3410.GenPrivateKey(gostCurve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate GOST %s key: %w", curve.String(), err)
	}

	return &GOSTPrivateKey{
		PrivateKey: privKey,
		Curve:      curve,
	}, nil
}

// GenerateCertificate generates a GOST certificate
func GenerateCertificate(privKey *GOSTPrivateKey, domain string, isCA bool, expireHours int) ([]byte, []byte, error) {
	// Get the appropriate GOST curve
	gostCurve := getCurve(privKey.Curve)
	if gostCurve == nil {
		return nil, nil, fmt.Errorf("unsupported GOST curve: %s", privKey.Curve.String())
	}

	// Use the working manual ASN.1 GOST certificate generation function
	expireDays := expireHours / 24
	if expireDays < 1 {
		expireDays = 1
	}

	// Use domain as common name, leave other fields empty if not provided
	organization := "Xray GOST Certificate"
	organizationalUnit := ""
	locality := ""
	state := ""

	certPEM, keyPEM, err := GenerateManualASN1GOSTCertificate(gostCurve, domain, expireDays, organization, organizationalUnit, locality, state)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate GOST certificate: %w", err)
	}

	return certPEM, keyPEM, nil
}

// ParsePrivateKey parses a GOST private key from PEM format
func ParsePrivateKey(pemData []byte) (*GOSTPrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try to parse as GOST private key for different curves
	var privKey *gost3410.PrivateKey
	var curve GOSTCurve

	// Try GOST2012_256 first
	gostCurve256 := getCurve(GOST2012_256)
	if gostCurve256 != nil {
		if key, err := gost3410.NewPrivateKey(gostCurve256, block.Bytes); err == nil {
			privKey = key
			curve = GOST2012_256
		}
	}

	// If 256-bit failed, try GOST2012_512
	if privKey == nil {
		gostCurve512 := getCurve(GOST2012_512)
		if gostCurve512 != nil {
			if key, err := gost3410.NewPrivateKey(gostCurve512, block.Bytes); err == nil {
				privKey = key
				curve = GOST2012_512
			}
		}
	}

	if privKey == nil {
		return nil, fmt.Errorf("failed to parse GOST private key")
	}

	return &GOSTPrivateKey{
		PrivateKey: privKey,
		Curve:      curve,
	}, nil
}

// GetPublicKeyInfo returns public key information
func GetPublicKeyInfo(privKey *GOSTPrivateKey) (string, string, string) {
	pubKey, err := privKey.PrivateKey.PublicKey()
	if err != nil {
		return "GOST " + privKey.Curve.String() + "-bit (error getting public key)", "", ""
	}
	return "GOST " + privKey.Curve.String() + "-bit",
		fmt.Sprintf("%x", pubKey.X.Bytes()),
		fmt.Sprintf("%x", pubKey.Y.Bytes())
}

// Sign signs data using GOST2012
func (k *GOSTPrivateKey) Sign(data []byte) ([]byte, error) {
	var hash []byte

	switch k.Curve {
	case GOST2012_256:
		h := gost34112012256.New()
		h.Write(data)
		hash = h.Sum(nil)
	case GOST2012_512:
		h := gost34112012512.New()
		h.Write(data)
		hash = h.Sum(nil)
	default:
		return nil, fmt.Errorf("unsupported GOST curve for signing: %s", k.Curve.String())
	}

	signature, err := k.PrivateKey.Sign(rand.Reader, hash, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with GOST: %w", err)
	}

	return signature, nil
}

// Verify verifies a GOST signature
func (k *GOSTPublicKey) Verify(data, signature []byte) bool {
	var hash []byte

	switch k.Curve {
	case GOST2012_256:
		h := gost34112012256.New()
		h.Write(data)
		hash = h.Sum(nil)
	case GOST2012_512:
		h := gost34112012512.New()
		h.Write(data)
		hash = h.Sum(nil)
	default:
		return false
	}

	valid, err := k.PublicKey.VerifyDigest(hash, signature)
	return err == nil && valid
}

// ToSM2Key converts GOST private key to SM2 format (for compatibility)
func (k *GOSTPrivateKey) ToSM2Key() *sm2.PrivateKey {
	pubKey, err := k.PrivateKey.PublicKey()
	if err != nil {
		return nil
	}

	// Convert raw bytes to big.Int
	rawBytes := k.PrivateKey.Raw()
	d := new(big.Int).SetBytes(rawBytes)

	return &sm2.PrivateKey{
		D: d,
		PublicKey: sm2.PublicKey{
			X: pubKey.X,
			Y: pubKey.Y,
		},
	}
} 