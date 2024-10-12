package jose

import (
	"testing"

	"github.com/cloudflare/circl/sign/schemes"
)

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

// TestSign calls jose.CompactSign with an private key and payload
// and confirms the resulting JWS verifies with jose.CompactVerify
func TestSign(t *testing.T) {
	var alg = "ML-DSA-44"
	var seed [32]byte // zero seed
	var private_key, _ = GenerateKey(alg, seed[:])
	var payload = []byte("It’s a dangerous business, Frodo, going out your door.")
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
	if string(verified.header["alg"]) != "ML-DSA-44" {
		t.Fatalf("Invalid Header Algorithm")
	}
	if string(verified.header["kid"]) != "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o" {
		t.Fatalf("Invalid Header Key Identifier")
	}
	if string(verified.payload) != "It’s a dangerous business, Frodo, going out your door." {
		t.Fatalf("Invalid Signature")
	}

}
