package gost

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
)

// GenerateManualASN1GOSTCertificate generates a GOST certificate with completely manual ASN.1 encoding
func GenerateManualASN1GOSTCertificate(curve *gost3410.Curve, cn string, expireDays int, organization string, organizationalUnit string, locality string, state string) ([]byte, []byte, error) {
	// Generate GOST key pair
	prvRaw := make([]byte, curve.PointSize())
	_, err := rand.Read(prvRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	prv, err := gost3410.NewPrivateKey(curve, prvRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GOST private key: %w", err)
	}
	
	pub, err := prv.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get GOST public key: %w", err)
	}

	// Determine signature algorithm and OIDs based on curve size
	var signatureOID asn1.ObjectIdentifier
	var publicKeyOID asn1.ObjectIdentifier
	var hashOID asn1.ObjectIdentifier
	var paramSetOID asn1.ObjectIdentifier
	
	if curve.PointSize() == 32 {
		// GOST R 34.10-2012 256-bit
		signatureOID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2} // GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)
		publicKeyOID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1} // GOST R 34.10-2012 with 256 bit modulus
		hashOID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2} // GOST R 34.11-2012 with 256 bit hash
		// Use the working parameter set from the correct certificate
		paramSetOID = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0, 0} // id-GostR3410-2001-CryptoPro-A-ParamSet
	} else {
		// GOST R 34.10-2012 512-bit
		signatureOID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3} // GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)
		publicKeyOID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2} // GOST R 34.10-2012 with 512 bit modulus
		hashOID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3} // GOST R 34.11-2012 with 512 bit hash
		paramSetOID = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0, 1} // id-GostR3410-2001-CryptoPro-B-ParamSet
	}

	// Create certificate template with proper subject structure
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(expireDays) * 24 * time.Hour)
	serialNumber := big.NewInt(time.Now().UnixNano())

	// Encode public key
	pubKeyBytes := append([]byte{0x04}, pub.X.Bytes()...)
	pubKeyBytes = append(pubKeyBytes, pub.Y.Bytes()...)

	// Create TBS certificate with manual ASN.1 encoding
	tbsDER, err := createManualASN1TBSCertificate(serialNumber, signatureOID, cn, notBefore, notAfter, publicKeyOID, paramSetOID, hashOID, pubKeyBytes, organization, organizationalUnit, locality, state)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GOST TBS certificate: %w", err)
	}

	// Hash the TBS certificate with GOST hash
	hash := gost34112012256.New()
	hash.Write(tbsDER)
	hashed := hash.Sum(nil)

	// Sign the hash with GOST private key
	signer := &gost3410.PrivateKeyReverseDigest{Prv: prv}
	signature, err := signer.Sign(rand.Reader, hashed, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign GOST certificate: %w", err)
	}

	// Create the complete signed certificate
	certDER, err := createManualASN1Certificate(tbsDER, signatureOID, signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GOST certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyDER, err := asn1.Marshal(struct {
		Version    int
		Algorithm  asn1.ObjectIdentifier
		PrivateKey []byte
	}{
		Version:    0,
		Algorithm:  publicKeyOID,
		PrivateKey: prvRaw,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal GOST private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

// createManualASN1TBSCertificate creates a TBS certificate with completely manual ASN.1 encoding
func createManualASN1TBSCertificate(serialNumber *big.Int, signatureOID asn1.ObjectIdentifier, cn string, notBefore, notAfter time.Time, publicKeyOID, paramSetOID, hashOID asn1.ObjectIdentifier, pubKeyBytes []byte, organization string, organizationalUnit string, locality string, state string) ([]byte, error) {
	// Build the TBS certificate structure manually byte by byte
	var tbsBytes []byte

	// Version (optional, default 0) - [0] IMPLICIT INTEGER
	versionBytes := encodeASN1Integer(big.NewInt(0))
	tbsBytes = append(tbsBytes, encodeASN1Tagged(0, true, versionBytes)...)

	// Serial Number - INTEGER
	serialBytes := encodeASN1Integer(serialNumber)
	tbsBytes = append(tbsBytes, serialBytes...)

	// Signature Algorithm - SEQUENCE
	sigAlgParts := [][]byte{
		encodeASN1ObjectIdentifier(signatureOID),
		encodeASN1Null(),
	}
	sigAlgBytes := encodeASN1Sequence(concatBytes(sigAlgParts))
	tbsBytes = append(tbsBytes, sigAlgBytes...)

	// Issuer - SEQUENCE
	issuerBytes := createManualASN1Name(cn, organization, organizationalUnit, locality, state)
	tbsBytes = append(tbsBytes, issuerBytes...)

	// Validity - SEQUENCE
	validityParts := [][]byte{
		encodeASN1Time(notBefore),
		encodeASN1Time(notAfter),
	}
	validityBytes := encodeASN1Sequence(concatBytes(validityParts))
	tbsBytes = append(tbsBytes, validityBytes...)

	// Subject - SEQUENCE
	subjectBytes := createManualASN1Name(cn, organization, organizationalUnit, locality, state)
	tbsBytes = append(tbsBytes, subjectBytes...)

	// Subject Public Key Info - SEQUENCE
	spkiBytes := createManualASN1SubjectPublicKeyInfo(publicKeyOID, paramSetOID, hashOID, pubKeyBytes)
	tbsBytes = append(tbsBytes, spkiBytes...)

	// Create the complete TBS certificate
	return encodeASN1Sequence(tbsBytes), nil
}

// createManualASN1Name creates a name with only provided fields
func createManualASN1Name(cn string, organization string, organizationalUnit string, locality string, state string) []byte {
	var nameBytes []byte

	// Country (PRINTABLESTRING) - always include for GOST certificates
	countryBytes := encodeASN1PrintableString("RU")
	countryParts := [][]byte{
		encodeASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 6}),
		countryBytes,
	}
	countryAttr := encodeASN1Sequence(concatBytes(countryParts))
	nameBytes = append(nameBytes, encodeASN1Set(countryAttr)...)

	// Organization (UTF8STRING) - only if provided
	if organization != "" {
		orgBytes := encodeASN1UTF8String(organization)
		orgParts := [][]byte{
			encodeASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 10}),
			orgBytes,
		}
		orgAttr := encodeASN1Sequence(concatBytes(orgParts))
		nameBytes = append(nameBytes, encodeASN1Set(orgAttr)...)
	}

	// Organizational Unit (UTF8STRING) - only if provided
	if organizationalUnit != "" {
		ouBytes := encodeASN1UTF8String(organizationalUnit)
		ouParts := [][]byte{
			encodeASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 11}),
			ouBytes,
		}
		ouAttr := encodeASN1Sequence(concatBytes(ouParts))
		nameBytes = append(nameBytes, encodeASN1Set(ouAttr)...)
	}

	// Locality (UTF8STRING) - only if provided
	if locality != "" {
		localityBytes := encodeASN1UTF8String(locality)
		localityParts := [][]byte{
			encodeASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 7}),
			localityBytes,
		}
		localityAttr := encodeASN1Sequence(concatBytes(localityParts))
		nameBytes = append(nameBytes, encodeASN1Set(localityAttr)...)
	}

	// Province (UTF8STRING) - only if provided
	if state != "" {
		provinceBytes := encodeASN1UTF8String(state)
		provinceParts := [][]byte{
			encodeASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 8}),
			provinceBytes,
		}
		provinceAttr := encodeASN1Sequence(concatBytes(provinceParts))
		nameBytes = append(nameBytes, encodeASN1Set(provinceAttr)...)
	}

	// Common Name (UTF8STRING) - only if provided
	if cn != "" {
		cnBytes := encodeASN1UTF8String(cn)
		cnParts := [][]byte{
			encodeASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 3}),
			cnBytes,
		}
		cnAttr := encodeASN1Sequence(concatBytes(cnParts))
		nameBytes = append(nameBytes, encodeASN1Set(cnAttr)...)
	}

	return encodeASN1Sequence(nameBytes)
}

// createManualASN1SubjectPublicKeyInfo creates the subject public key info structure
func createManualASN1SubjectPublicKeyInfo(publicKeyOID, paramSetOID, hashOID asn1.ObjectIdentifier, pubKeyBytes []byte) []byte {
	// Algorithm
	paramsParts := [][]byte{
		encodeASN1ObjectIdentifier(paramSetOID),
		encodeASN1ObjectIdentifier(hashOID),
	}
	paramsBytes := encodeASN1Sequence(concatBytes(paramsParts))
	
	algorithmParts := [][]byte{
		encodeASN1ObjectIdentifier(publicKeyOID),
		paramsBytes,
	}
	algorithmBytes := encodeASN1Sequence(concatBytes(algorithmParts))

	// Public Key
	publicKeyBytes := encodeASN1BitString(pubKeyBytes)

	// Combine
	spkiParts := [][]byte{algorithmBytes, publicKeyBytes}
	return encodeASN1Sequence(concatBytes(spkiParts))
}

// createManualASN1Certificate creates the complete certificate
func createManualASN1Certificate(tbsDER []byte, signatureOID asn1.ObjectIdentifier, signature []byte) ([]byte, error) {
	var certBytes []byte

	// TBSCertificate - SEQUENCE
	certBytes = append(certBytes, tbsDER...)

	// Signature Algorithm - SEQUENCE
	sigAlgParts := [][]byte{
		encodeASN1ObjectIdentifier(signatureOID),
		encodeASN1Null(),
	}
	sigAlgBytes := encodeASN1Sequence(concatBytes(sigAlgParts))
	certBytes = append(certBytes, sigAlgBytes...)

	// Signature Value - BIT STRING
	signatureBytes := encodeASN1BitString(signature)
	certBytes = append(certBytes, signatureBytes...)

	return encodeASN1Sequence(certBytes), nil
}

// ASN.1 encoding helper functions
func encodeASN1Sequence(bytes []byte) []byte {
	length := encodeASN1Length(len(bytes))
	return append([]byte{0x30}, append(length, bytes...)...)
}

func encodeASN1Set(bytes []byte) []byte {
	length := encodeASN1Length(len(bytes))
	return append([]byte{0x31}, append(length, bytes...)...)
}

func encodeASN1Tagged(tag int, constructed bool, bytes []byte) []byte {
	var tagByte byte
	if constructed {
		tagByte = 0xA0 | byte(tag)
	} else {
		tagByte = byte(tag)
	}
	length := encodeASN1Length(len(bytes))
	return append([]byte{tagByte}, append(length, bytes...)...)
}

func encodeASN1ObjectIdentifier(oid asn1.ObjectIdentifier) []byte {
	// Simplified OID encoding
	oidBytes, _ := asn1.Marshal(oid)
	return oidBytes
}

func encodeASN1Integer(value *big.Int) []byte {
	// Simplified integer encoding
	intBytes, _ := asn1.Marshal(value)
	return intBytes
}

func encodeASN1PrintableString(value string) []byte {
	bytes := []byte(value)
	length := encodeASN1Length(len(bytes))
	return append([]byte{0x13}, append(length, bytes...)...)
}

func encodeASN1UTF8String(value string) []byte {
	bytes := []byte(value)
	length := encodeASN1Length(len(bytes))
	return append([]byte{0x0C}, append(length, bytes...)...)
}

func encodeASN1Time(t time.Time) []byte {
	// Simplified time encoding
	timeBytes, _ := asn1.Marshal(t)
	return timeBytes
}

func encodeASN1Null() []byte {
	return []byte{0x05, 0x00}
}

func encodeASN1BitString(bytes []byte) []byte {
	// Add unused bits count (0 for byte-aligned data)
	bitString := append([]byte{0x00}, bytes...)
	length := encodeASN1Length(len(bitString))
	return append([]byte{0x03}, append(length, bitString...)...)
}

// encodeASN1Length encodes the length field for ASN.1
func encodeASN1Length(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	
	// For lengths >= 128, we need to encode the number of bytes needed
	var lengthBytes []byte
	for length > 0 {
		lengthBytes = append([]byte{byte(length & 0xFF)}, lengthBytes...)
		length >>= 8
	}
	
	// Add the number of bytes as the first byte with the high bit set
	return append([]byte{byte(0x80 | len(lengthBytes))}, lengthBytes...)
} 

// concatBytes concatenates multiple byte slices
func concatBytes(slices [][]byte) []byte {
	var result []byte
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
} 