package cose

import (
	"encoding/hex"
	"testing"
)

// TestSign1 calls cose.Sign1 with a private key and payload
// and confirms the result verifies with cose.VerifySign1
func TestSign1(t *testing.T) {
	var seed [32]byte // zero seed
	var private_key, _ = GenerateKey(ML_DSA_44, seed[:])
	key, _ := DecodeKey(private_key)
	var header = Header{
		Alg: key.Alg,
		Kid: key.Kid,
	}
	var payload = []byte("It’s a dangerous business, Frodo, going out your door.")
	signature, _ := Sign1(private_key, header, payload)
	var public_key, _ = PublicKeyFromPrivateKey(private_key)
	verified, verify_error := VerifySign1(public_key, signature)
	if verify_error != nil {
		t.Fatalf("Verification failed")
	}
	if string(verified.Payload) != "It’s a dangerous business, Frodo, going out your door." {
		t.Fatalf("Invalid payload")
	}
	if verified.Header.Alg != ML_DSA_44 {
		t.Fatalf("Invalid header alg")
	}
	if hex.EncodeToString(verified.Header.Kid) != "1e1d556de7bec8153526f951c9a4534dedbe9b1ec2384f5bcaffce67a34d9071" {
		t.Fatalf("Invalid kid")
	}
}
