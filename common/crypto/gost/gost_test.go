package gost

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
)

func TestGenerateKeyPair(t *testing.T) {
	// Test GOST2012_256
	privKey256, err := GenerateKeyPair(GOST2012_256)
	if err != nil {
		t.Fatalf("Failed to generate GOST2012_256 key pair: %v", err)
	}
	if privKey256 == nil {
		t.Fatal("Generated private key is nil")
	}
	if privKey256.Curve != GOST2012_256 {
		t.Fatalf("Expected curve GOST2012_256, got %s", privKey256.Curve.String())
	}

	// Test GOST2012_512
	privKey512, err := GenerateKeyPair(GOST2012_512)
	if err != nil {
		t.Fatalf("Failed to generate GOST2012_512 key pair: %v", err)
	}
	if privKey512 == nil {
		t.Fatal("Generated private key is nil")
	}
	if privKey512.Curve != GOST2012_512 {
		t.Fatalf("Expected curve GOST2012_512, got %s", privKey512.Curve.String())
	}
}

func TestSignAndVerify(t *testing.T) {
	// Test GOST2012_256 signing and verification
	privKey256, err := GenerateKeyPair(GOST2012_256)
	if err != nil {
		t.Fatalf("Failed to generate GOST2012_256 key pair: %v", err)
	}

	testData := []byte("Hello, GOST2012!")
	signature, err := privKey256.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data with GOST2012_256: %v", err)
	}

	pubKey, err := privKey256.PrivateKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	gostPubKey := &GOSTPublicKey{
		PublicKey: pubKey,
		Curve:     GOST2012_256,
	}

	if !gostPubKey.Verify(testData, signature) {
		t.Fatal("GOST2012_256 signature verification failed")
	}

	// Test GOST2012_512 signing and verification
	privKey512, err := GenerateKeyPair(GOST2012_512)
	if err != nil {
		t.Fatalf("Failed to generate GOST2012_512 key pair: %v", err)
	}

	signature512, err := privKey512.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data with GOST2012_512: %v", err)
	}

	pubKey512, err := privKey512.PrivateKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	gostPubKey512 := &GOSTPublicKey{
		PublicKey: pubKey512,
		Curve:     GOST2012_512,
	}

	if !gostPubKey512.Verify(testData, signature512) {
		t.Fatal("GOST2012_512 signature verification failed")
	}
}

func TestHashFunctions(t *testing.T) {
	// Test GOST2012_256 hash function
	h256 := gost34112012256.New()
	testData := []byte("Test data for GOST2012_256")
	h256.Write(testData)
	hash256 := h256.Sum(nil)
	if len(hash256) != 32 {
		t.Fatalf("Expected GOST2012_256 hash length 32, got %d", len(hash256))
	}

	// Test GOST2012_512 hash function
	h512 := gost34112012512.New()
	testData512 := []byte("Test data for GOST2012_512")
	h512.Write(testData512)
	hash512 := h512.Sum(nil)
	if len(hash512) != 64 {
		t.Fatalf("Expected GOST2012_512 hash length 64, got %d", len(hash512))
	}
}

func TestGenerateCertificate(t *testing.T) {
	// Test GOST2012_256 certificate generation
	privKey256, err := GenerateKeyPair(GOST2012_256)
	if err != nil {
		t.Fatalf("Failed to generate GOST2012_256 key pair: %v", err)
	}

	certPEM, keyPEM, err := GenerateCertificate(privKey256, "test.local", false, 24)
	if err != nil {
		t.Fatalf("Failed to generate GOST2012_256 certificate: %v", err)
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

	fmt.Printf("✓ Generated GOST2012_256 certificate: %d bytes\n", len(certBlock.Bytes))
	fmt.Printf("✓ Generated GOST2012_256 private key: %d bytes\n", len(keyBlock.Bytes))

	// Test GOST2012_512 certificate generation
	privKey512, err := GenerateKeyPair(GOST2012_512)
	if err != nil {
		t.Fatalf("Failed to generate GOST2012_512 key pair: %v", err)
	}

	certPEM512, keyPEM512, err := GenerateCertificate(privKey512, "test.local", false, 24)
	if err != nil {
		t.Fatalf("Failed to generate GOST2012_512 certificate: %v", err)
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

	fmt.Printf("✓ Generated GOST2012_512 certificate: %d bytes\n", len(certBlock512.Bytes))
	fmt.Printf("✓ Generated GOST2012_512 private key: %d bytes\n", len(keyBlock512.Bytes))
}

func TestGetPublicKeyInfo(t *testing.T) {
	privKey, err := GenerateKeyPair(GOST2012_256)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	algo, x, y := GetPublicKeyInfo(privKey)
	if algo == "" {
		t.Fatal("Algorithm name is empty")
	}
	if x == "" {
		t.Fatal("Public key X coordinate is empty")
	}
	if y == "" {
		t.Fatal("Public key Y coordinate is empty")
	}
}

func BenchmarkGOST2012_256Sign(b *testing.B) {
	privKey, err := GenerateKeyPair(GOST2012_256)
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := make([]byte, 1024)
	rand.Read(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := privKey.Sign(testData)
		if err != nil {
			b.Fatalf("Failed to sign: %v", err)
		}
	}
}

func BenchmarkGOST2012_512Sign(b *testing.B) {
	privKey, err := GenerateKeyPair(GOST2012_512)
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := make([]byte, 1024)
	rand.Read(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := privKey.Sign(testData)
		if err != nil {
			b.Fatalf("Failed to sign: %v", err)
		}
	}
} 