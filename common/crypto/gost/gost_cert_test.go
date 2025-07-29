package gost

import (
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/pedroalbanese/gogost/gost3410"
)

func TestGenerateManualASN1GOSTCertificate(t *testing.T) {
	// Test GOST 2012 256-bit certificate generation
	curve256 := gost3410.CurveIdtc26gost34102012256paramSetA()
	if curve256 == nil {
		t.Fatal("Failed to get GOST 2012 256-bit curve")
	}

	certPEM, keyPEM, err := GenerateManualASN1GOSTCertificate(curve256, "test.gost256.com", 365, "Test Organization", "", "", "")
	if err != nil {
		t.Fatalf("Failed to generate GOST 256-bit certificate: %v", err)
	}

	// Check that certificate was generated
	if len(certPEM) == 0 {
		t.Fatal("Generated certificate is empty")
	}

	// Check that private key was generated
	if len(keyPEM) == 0 {
		t.Fatal("Generated private key is empty")
	}

	// Parse certificate PEM
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("Failed to decode certificate PEM")
	}

	// Parse private key PEM
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("Failed to decode private key PEM")
	}

	fmt.Printf("✓ Generated GOST 256-bit certificate: %d bytes\n", len(certBlock.Bytes))
	fmt.Printf("✓ Generated GOST 256-bit private key: %d bytes\n", len(keyBlock.Bytes))

	// Test GOST 2012 512-bit certificate generation
	curve512 := gost3410.CurveIdtc26gost34102012512paramSetA()
	if curve512 == nil {
		t.Fatal("Failed to get GOST 2012 512-bit curve")
	}

	certPEM512, keyPEM512, err := GenerateManualASN1GOSTCertificate(curve512, "test.gost512.com", 365, "Test Organization", "", "", "")
	if err != nil {
		t.Fatalf("Failed to generate GOST 512-bit certificate: %v", err)
	}

	// Check that certificate was generated
	if len(certPEM512) == 0 {
		t.Fatal("Generated 512-bit certificate is empty")
	}

	// Check that private key was generated
	if len(keyPEM512) == 0 {
		t.Fatal("Generated 512-bit private key is empty")
	}

	// Parse certificate PEM
	certBlock512, _ := pem.Decode(certPEM512)
	if certBlock512 == nil {
		t.Fatal("Failed to decode 512-bit certificate PEM")
	}

	// Parse private key PEM
	keyBlock512, _ := pem.Decode(keyPEM512)
	if keyBlock512 == nil {
		t.Fatal("Failed to decode 512-bit private key PEM")
	}

	fmt.Printf("✓ Generated GOST 512-bit certificate: %d bytes\n", len(certBlock512.Bytes))
	fmt.Printf("✓ Generated GOST 512-bit private key: %d bytes\n", len(keyBlock512.Bytes))
}

func TestGenerateGOSTSelfSignedCert(t *testing.T) {
	// Test GOST 2012 256-bit self-signed certificate generation
	curve256 := gost3410.CurveIdtc26gost34102012256paramSetA()
	if curve256 == nil {
		t.Fatal("Failed to get GOST 2012 256-bit curve")
	}

	certPEM, keyPEM, err := GenerateGOSTSelfSignedCert(curve256, "test.selfsigned.com", 365, "Test Organization", "", "", "")
	if err != nil {
		t.Fatalf("Failed to generate GOST 256-bit self-signed certificate: %v", err)
	}

	// Check that certificate was generated
	if len(certPEM) == 0 {
		t.Fatal("Generated self-signed certificate is empty")
	}

	// Check that private key was generated
	if len(keyPEM) == 0 {
		t.Fatal("Generated self-signed private key is empty")
	}

	// Parse certificate PEM
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("Failed to decode self-signed certificate PEM")
	}

	// Parse private key PEM
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("Failed to decode self-signed private key PEM")
	}

	fmt.Printf("✓ Generated GOST 256-bit self-signed certificate: %d bytes\n", len(certBlock.Bytes))
	fmt.Printf("✓ Generated GOST 256-bit self-signed private key: %d bytes\n", len(keyBlock.Bytes))
} 