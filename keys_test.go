// Tested with 1024 Keys for speed
package rsaKeyGen

import (
	"os"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	want := ""
	got := ""
	if want != got {
		t.Errorf("Error generating keys")
	}

}

func TestGeneratePrivateKey(t *testing.T) {
	_, err := generatePrivateKey(1024)
	if err != nil {
		t.Errorf("Error generating keys")
	}
}

func TestEncodePrivateKeyToPem(t *testing.T) {
	privKey, _ := generatePrivateKey(1024)
	priv := encodePrivateKeyToPem(privKey)
	if priv == nil {
		t.Errorf("Error generating Private key")
	}
}

func TestEncodePublicKeyToPem(t *testing.T) {
	privKey, _ := generatePrivateKey(1024)
	pub := encodePublicKeyToPem(privKey)
	if pub == nil {
		t.Errorf("Error Generating Public Key")
	}
}

func TestWritePemToFile(t *testing.T) {
	os.Mkdir("./tmp", 0777) //nolint
	privKey, _ := generatePrivateKey(1024)
	priv := encodePrivateKeyToPem(privKey)
	err := writePemToFile(priv, "./tmp/key")
	os.RemoveAll("./tmp/")
	if err != nil {
		t.Errorf("Error generating keys")
	}

}
