package jose

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/schemes"
)

type JOSETestVector struct {
	Priv   string `json:"priv"`
	Jwk    AKPKey `json:"jwk"`
	Jws    string `json:"jws"`
	RawTbs string `json:"raw_to_be_signed"`
	RawSig string `json:"raw_signature"`
	RawPub string `json:"raw_public_key"`
}

var seed [32]byte // zero seed
var payload = []byte("It’s a dangerous business, Frodo, going out your door.")

// TestRawSignSanity confirms sign and verify are possible with circl
func TestRawSignSanity(t *testing.T) {
	var seed [32]byte // zero seed
	suite := schemes.ByName("ML-DSA-65")
	pub, priv := suite.DeriveKey(seed[:])
	tbs := []byte("It’s a dangerous business, Frodo, going out your door.")
	var sig = suite.Sign(priv, tbs, nil)
	var ver = suite.Verify(pub, tbs, sig, nil)
	if !ver {
		t.Fatalf("Failed to verify sanity")
	}
}

// TestSign_0 calls jose.CompactSign with an private key and payload
// and confirms the resulting JWS verifies with jose.CompactVerify
func TestSign_0(t *testing.T) {
	var alg = ML_DSA_44
	var private_key, _ = GenerateKey(alg, seed[:])
	var key, _ = DecodeKey(private_key)
	var jws, sign_error = CompactSign(private_key, payload)
	if sign_error != nil {
		t.Fatalf("Signing failed")
	}
	var public_key, public_key_export_error = PublicKeyFromPrivateKey(private_key)
	if public_key_export_error != nil {
		t.Fatalf("Exporting public key failed")
	}
	var verified, verify_error = CompactVerify(public_key, jws)
	if verify_error != nil {
		t.Fatalf("Verification failed")
	}
	if string(verified.Header["alg"]) != ML_DSA_44 {
		t.Fatalf("Invalid Header Algorithm")
	}
	if string(verified.Header["kid"]) != "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o" {
		t.Fatalf("Invalid Header Key Identifier, want %s", verified.Header["kid"])
	}
	if string(verified.Payload) != string(payload) {
		t.Fatalf("Invalid Signature")
	}
	tbs := ToBeSignedFromJWS(jws)
	sig, _ := SignatureFromJWS(jws)
	pub, _ := base64.RawURLEncoding.DecodeString(key.Pub)
	examples, _ := json.MarshalIndent(JOSETestVector{
		Priv:   hex.EncodeToString(seed[:]),
		Jwk:    key,
		Jws:    jws,
		RawTbs: hex.EncodeToString(tbs),
		RawSig: hex.EncodeToString(sig),
		RawPub: hex.EncodeToString(pub),
	}, "", "  ")
	_ = os.WriteFile("examples/ML_DSA_44.jose.json", examples, 0644)
}

// TestSign_1 calls jose.CompactSign with an private key and payload
// and confirms the resulting JWS verifies with jose.CompactVerify
func TestSign_1(t *testing.T) {
	var alg = ML_DSA_65
	var private_key, _ = GenerateKey(alg, seed[:])
	var key, _ = DecodeKey(private_key)
	var jws, sign_error = CompactSign(private_key, payload)
	if sign_error != nil {
		t.Fatalf("Signing failed")
	}
	var public_key, public_key_export_error = PublicKeyFromPrivateKey(private_key)
	if public_key_export_error != nil {
		t.Fatalf("Exporting public key failed")
	}
	var verified, verify_error = CompactVerify(public_key, jws)
	if verify_error != nil {
		t.Fatalf("Verification failed")
	}
	if string(verified.Header["alg"]) != ML_DSA_65 {
		t.Fatalf("Invalid Header Algorithm")
	}
	if string(verified.Header["kid"]) != "Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM" {
		t.Fatalf("Invalid Header Key Identifier, want %s", verified.Header["kid"])
	}
	if string(verified.Payload) != string(payload) {
		t.Fatalf("Invalid Signature")
	}
	tbs := ToBeSignedFromJWS(jws)
	sig, _ := SignatureFromJWS(jws)
	pub, _ := base64.RawURLEncoding.DecodeString(key.Pub)
	examples, _ := json.MarshalIndent(JOSETestVector{
		Priv:   hex.EncodeToString(seed[:]),
		Jwk:    key,
		Jws:    jws,
		RawTbs: hex.EncodeToString(tbs),
		RawSig: hex.EncodeToString(sig),
		RawPub: hex.EncodeToString(pub),
	}, "", "  ")
	_ = os.WriteFile("examples/ML_DSA_65.jose.json", examples, 0644)
}

// TestSign_2 calls jose.CompactSign with an private key and payload
// and confirms the resulting JWS verifies with jose.CompactVerify
func TestSign_2(t *testing.T) {
	var alg = ML_DSA_87
	var private_key, _ = GenerateKey(alg, seed[:])
	var key, _ = DecodeKey(private_key)
	var jws, sign_error = CompactSign(private_key, payload)
	if sign_error != nil {
		t.Fatalf("Signing failed")
	}
	var public_key, public_key_export_error = PublicKeyFromPrivateKey(private_key)
	if public_key_export_error != nil {
		t.Fatalf("Exporting public key failed")
	}
	var verified, verify_error = CompactVerify(public_key, jws)
	if verify_error != nil {
		t.Fatalf("Verification failed")
	}
	if string(verified.Header["alg"]) != ML_DSA_87 {
		t.Fatalf("Invalid Header Algorithm")
	}
	if string(verified.Header["kid"]) != "tRn1JNIkgMsABVQBlXeDHxAIcclh-2IX0UdDEzPt5XU" {
		t.Fatalf("Invalid Header Key Identifier, want %s", verified.Header["kid"])
	}
	if string(verified.Payload) != string(payload) {
		t.Fatalf("Invalid Signature")
	}
	tbs := ToBeSignedFromJWS(jws)
	sig, _ := SignatureFromJWS(jws)
	pub, _ := base64.RawURLEncoding.DecodeString(key.Pub)
	examples, _ := json.MarshalIndent(JOSETestVector{
		Priv:   hex.EncodeToString(seed[:]),
		Jwk:    key,
		Jws:    jws,
		RawTbs: hex.EncodeToString(tbs),
		RawSig: hex.EncodeToString(sig),
		RawPub: hex.EncodeToString(pub),
	}, "", "  ")
	_ = os.WriteFile("examples/ML_DSA_87.jose.json", examples, 0644)
}
