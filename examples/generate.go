//go:generate go run generate.go
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"github.com/cose-wg/draft-ietf-cose-dilithium/example/jose"
)

type TestVector struct {
	PrivateKey jose.PrivateAlgorithmKeyPair `json:"private_key"`
	Jws        string                       `json:"jws"`
	TbsBytes   string                       `json:"to_be_signed"`
	Signature  string                       `json:"signature"`
	PublicKey  string                       `json:"public_key"`
}

type TestVectors struct {
	Seed    string     `json:"seed"`
	MLDSA44 TestVector `json:"ML-DSA-44"`
	MLDSA65 TestVector `json:"ML-DSA-65"`
	MLDSA87 TestVector `json:"ML-DSA-87"`
}

func BuildTestVector(alg string, seed []byte, payload []byte) TestVector {
	jwk, _ := jose.GenerateKey(alg, seed[:])
	_, pub, _, _ := jose.SuiteFromJWK(jwk)
	binary_pub, _ := pub.MarshalBinary()
	var private_key jose.PrivateAlgorithmKeyPair
	json.Unmarshal([]byte(jwk), &private_key)
	jws, _ := jose.CompactSign(jwk, payload)
	public_key_jwk, _ := jose.PublicKeyFromPrivateKey(jwk)
	verified, _ := jose.CompactVerify(public_key_jwk, jws)
	if verified.Header["alg"] != alg {
		panic("Failed to verify test vector signature")
	}
	tbs := jose.ToBeSignedFromJWS(jws)
	sig, _ := jose.SignatureFromJWS(jws)
	return TestVector{
		PrivateKey: private_key,
		TbsBytes:   hex.EncodeToString(tbs),
		Signature:  hex.EncodeToString(sig),
		Jws:        jws,
		PublicKey:  hex.EncodeToString(binary_pub),
	}
}

func main() {
	var seed [32]byte // zero seed
	var payload, _ = json.Marshal(jose.JWSPayload{
		Iss: "https://issuer.example",
		Sub: "https://subject.example",
		Iat: time.Now().Unix(),
	})
	examples, _ := json.MarshalIndent(TestVectors{
		Seed:    hex.EncodeToString(seed[:]),
		MLDSA44: BuildTestVector("ML-DSA-44", seed[:], payload),
		MLDSA65: BuildTestVector("ML-DSA-65", seed[:], payload),
		MLDSA87: BuildTestVector("ML-DSA-87", seed[:], payload),
	}, "", "  ")
	_ = os.WriteFile("examples.json", examples, 0644)
}
