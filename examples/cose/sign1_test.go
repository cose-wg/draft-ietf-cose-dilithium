package cose

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type COSETestVector struct {
	Seed      string `json:"seed"`
	Key       string `json:"key"`
	KeyDiag   string `json:"key_diag"`
	Sign1     string `json:"sign1"`
	Sign1Diag string `json:"sign1_diag"`
	RawTbs    string `json:"raw_to_be_signed"`
	RawSig    string `json:"raw_signature"`
	RawPub    string `json:"raw_public_key"`
}

var seed [32]byte // zero seed
var payload = []byte("It’s a dangerous business, Frodo, going out your door.")

// TestSign1 calls cose.Sign1 with a private key and payload
// and confirms the result verifies with cose.VerifySign1
func TestSign1_0(t *testing.T) {
	var seed [32]byte // zero seed
	var private_key, _ = GenerateKey(ML_DSA_44, seed[:])
	key, _ := DecodeKey(private_key)
	var header = Header{
		Alg: key.Alg,
		Kid: key.Kid,
	}
	signature, _ := Sign1(private_key, header, payload)
	var public_key, _ = PublicKeyFromPrivateKey(private_key)
	verified, verify_error := VerifySign1(public_key, signature)
	if verify_error != nil {
		t.Fatalf("Verification failed")
	}
	if string(verified.Payload) != string(payload) {
		t.Fatalf("Invalid payload")
	}
	if verified.Header.Alg != ML_DSA_44 {
		t.Fatalf("Invalid header alg")
	}
	if hex.EncodeToString(verified.Header.Kid) != "b8969ab4b37da9f0684e42647eb8a0be8b5b661ebf5d76f0583bf5b8d3a8059a" {
		t.Fatalf("Invalid kid, want %s", hex.EncodeToString(verified.Header.Kid))
	}
	tbs, _ := ToBeSignedFromSign1(signature)
	sig, _ := SignatureFromSign1(signature)
	kd, _ := cbor.Diagnose(private_key)
	sd, _ := cbor.Diagnose(signature)
	examples, _ := json.MarshalIndent(COSETestVector{
		Seed:      hex.EncodeToString(seed[:]),
		Key:       hex.EncodeToString(private_key),
		KeyDiag:   kd,
		Sign1:     hex.EncodeToString(signature),
		Sign1Diag: sd,
		RawTbs:    hex.EncodeToString(tbs),
		RawSig:    hex.EncodeToString(sig),
		RawPub:    hex.EncodeToString(key.Pub),
	}, "", "  ")
	_ = os.WriteFile("examples/ML_DSA_44.cose.json", examples, 0644)
}

func TestSign1_1(t *testing.T) {
	var private_key, _ = GenerateKey(ML_DSA_65, seed[:])
	key, _ := DecodeKey(private_key)
	var header = Header{
		Alg: key.Alg,
		Kid: key.Kid,
	}
	signature, _ := Sign1(private_key, header, payload)
	var public_key, _ = PublicKeyFromPrivateKey(private_key)
	verified, verify_error := VerifySign1(public_key, signature)
	if verify_error != nil {
		t.Fatalf("Verification failed")
	}
	if string(verified.Payload) != string(payload) {
		t.Fatalf("Invalid payload")
	}
	if verified.Header.Alg != ML_DSA_65 {
		t.Fatalf("Invalid header alg")
	}
	if hex.EncodeToString(verified.Header.Kid) != "b788acf242f1f1d6532926d816e76e1636874267f2a48c84c4e65789ab80cc02" {
		t.Fatalf("Invalid kid, want %s", hex.EncodeToString(verified.Header.Kid))
	}
	tbs, _ := ToBeSignedFromSign1(signature)
	sig, _ := SignatureFromSign1(signature)
	kd, _ := cbor.Diagnose(private_key)
	sd, _ := cbor.Diagnose(signature)
	examples, _ := json.MarshalIndent(COSETestVector{
		Seed:      hex.EncodeToString(seed[:]),
		Key:       hex.EncodeToString(private_key),
		KeyDiag:   kd,
		Sign1:     hex.EncodeToString(signature),
		Sign1Diag: sd,
		RawTbs:    hex.EncodeToString(tbs),
		RawSig:    hex.EncodeToString(sig),
		RawPub:    hex.EncodeToString(key.Pub),
	}, "", "  ")
	_ = os.WriteFile("examples/ML_DSA_65.cose.json", examples, 0644)
}

func TestSign1_2(t *testing.T) {
	var seed [32]byte // zero seed
	var private_key, _ = GenerateKey(ML_DSA_87, seed[:])
	key, _ := DecodeKey(private_key)
	var header = Header{
		Alg: key.Alg,
		Kid: key.Kid,
	}
	signature, _ := Sign1(private_key, header, payload)
	var public_key, _ = PublicKeyFromPrivateKey(private_key)
	verified, verify_error := VerifySign1(public_key, signature)
	if verify_error != nil {
		t.Fatalf("Verification failed")
	}
	if string(verified.Payload) != string(payload) {
		t.Fatalf("Invalid payload")
	}
	if verified.Header.Alg != ML_DSA_87 {
		t.Fatalf("Invalid header alg")
	}
	if hex.EncodeToString(verified.Header.Kid) != "d9bc439f97bd6d4093e68f0f3fcf09c9a97adf888ed7308dd565247a166cb4fa" {
		t.Fatalf("Invalid kid, want %s", hex.EncodeToString(verified.Header.Kid))
	}
	tbs, _ := ToBeSignedFromSign1(signature)
	sig, _ := SignatureFromSign1(signature)
	kd, _ := cbor.Diagnose(private_key)
	sd, _ := cbor.Diagnose(signature)
	examples, _ := json.MarshalIndent(COSETestVector{
		Seed:      hex.EncodeToString(seed[:]),
		Key:       hex.EncodeToString(private_key),
		KeyDiag:   kd,
		Sign1:     hex.EncodeToString(signature),
		Sign1Diag: sd,
		RawTbs:    hex.EncodeToString(tbs),
		RawSig:    hex.EncodeToString(sig),
		RawPub:    hex.EncodeToString(key.Pub),
	}, "", "  ")
	_ = os.WriteFile("examples/ML_DSA_87.cose.json", examples, 0644)
}
