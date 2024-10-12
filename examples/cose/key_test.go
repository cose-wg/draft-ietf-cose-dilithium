package cose

import (
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestGenerateKey calls cose.GenerateKey with an algorithm and a seed
// and confirms the resulting COSE Key is well formed
func TestGenerateKey(t *testing.T) {
	var seed [32]byte // zero seed
	var private_key, _ = GenerateKey(ML_DSA_44, seed[:])
	var cose_key AKPKey
	cbor.Unmarshal(private_key, &cose_key)
	if cose_key.Kty != AKP {
		t.Fatalf(`COSE Key did not contain expected kty (AKP)`)
	}
	if cose_key.Alg != ML_DSA_44 {
		t.Fatalf(`COSE Key did not contain expected alg (ML_DSA_44)`)
	}
	if len(cose_key.Pub) != 1312 {
		t.Fatalf(`COSE Key did not contain expected public key length (%d), want 1312`, len(cose_key.Pub))
	}
	if len(cose_key.Priv) != 32 {
		t.Fatalf(`COSE Key did not contain expected private key (seed) length (%d), want 32`, len(cose_key.Priv))
	}
}

// TestCalculateCoseKeyThumbprint calls cose.CalculateCoseKeyThumbprint with an cose key
// and confirms the resulting COSE Key thumbprint is calculated correctly
func TestCalculateCoseKeyThumbprint(t *testing.T) {
	var encoded_key = "A50102200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C0258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65"
	var cose_key, _ = hex.DecodeString(encoded_key)
	var thumbprint, _ = CalculateCoseKeyThumbprint(cose_key)
	var t1 = hex.EncodeToString(thumbprint)
	if t1 != "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec" {
		t.Fatalf(`COSE Key thumbprint calculated incorrectly (%s), want 496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec`, t1)
	}

	var seed [32]byte // zero seed
	var k2, _ = GenerateKey(ML_DSA_44, seed[:])
	var t2, _ = CalculateCoseKeyThumbprint(k2)
	var t2h = hex.EncodeToString(t2)
	if t2h != "1e1d556de7bec8153526f951c9a4534dedbe9b1ec2384f5bcaffce67a34d9071" {
		t.Fatalf(`COSE Key thumbprint calculated incorrectly (%s), want 1e1d556de7bec8153526f951c9a4534dedbe9b1ec2384f5bcaffce67a34d9071`, t2h)
	}

}
