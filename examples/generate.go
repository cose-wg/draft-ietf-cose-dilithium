//go:generate go run generate.go
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/schemes"
)

type PrivateAlgorithmKeyPair struct {
	Kty  string `json:"kty"`
	Alg  string `json:"alg"`
	Pub  string `json:"pub"`
	Priv string `json:"priv"`
}

type TestVector struct {
	PrivateKey PrivateAlgorithmKeyPair `json:"private_key"`
	Jws        string                  `json:"jws"`
	TbsBytes   string                  `json:"to_be_signed"`
	Signature  string                  `json:"signature"`
	PublicKey  string                  `json:"public_key"`
}

type TestVectors struct {
	Seed    string     `json:"seed"`
	MLDSA44 TestVector `json:"ML-DSA-44"`
	MLDSA65 TestVector `json:"ML-DSA-65"`
	MLDSA87 TestVector `json:"ML-DSA-87"`
}

type JWSHeader struct {
	Alg string `json:"alg"`
}

type JWSPayload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
}

func main() {
	var seed [32]byte // zero seed
	var p, _ = json.Marshal(JWSPayload{
		Iss: "https://issuer.example",
		Sub: "https://subject.example",
		Iat: time.Now().Unix(),
	})

	// ML-DSA-44

	ml_dsa_44 := schemes.ByName("ML-DSA-44")
	ml_dsa_44_pub, ml_dsa_44_priv := ml_dsa_44.DeriveKey(seed[:])
	ml_dsa_44_public_key, _ := ml_dsa_44_pub.MarshalBinary()

	var m1h, _ = json.Marshal(JWSHeader{
		Alg: "ML-DSA-44",
	})

	var tbs1 = base64.RawURLEncoding.EncodeToString(m1h) + "." + base64.RawURLEncoding.EncodeToString(p)
	var s1 = ml_dsa_44.Sign(ml_dsa_44_priv, []byte(tbs1), nil)
	var jws1 = tbs1 + "." + base64.RawURLEncoding.EncodeToString(s1)

	// ML-DSA-65

	ml_dsa_65 := schemes.ByName("ML-DSA-65")
	ml_dsa_65_pub, ml_dsa_65_priv := ml_dsa_65.DeriveKey(seed[:])
	ml_dsa_65_public_key, _ := ml_dsa_65_pub.MarshalBinary()

	var m2h, _ = json.Marshal(JWSHeader{
		Alg: "ML-DSA-87",
	})

	var tbs2 = base64.RawURLEncoding.EncodeToString(m2h) + "." + base64.RawURLEncoding.EncodeToString(p)
	var s2 = ml_dsa_65.Sign(ml_dsa_65_priv, []byte(tbs2), nil)
	var jws2 = tbs2 + "." + base64.RawURLEncoding.EncodeToString(s2)

	// ML-DSA-87

	ml_dsa_87 := schemes.ByName("ML-DSA-87")
	ml_dsa_87_pub, ml_dsa_87_priv := ml_dsa_87.DeriveKey(seed[:])
	ml_dsa_87_public_key, _ := ml_dsa_87_pub.MarshalBinary()

	var m3h, _ = json.Marshal(JWSHeader{
		Alg: "ML-DSA-87",
	})

	var tbs3 = base64.RawURLEncoding.EncodeToString(m3h) + "." + base64.RawURLEncoding.EncodeToString(p)
	var s3 = ml_dsa_87.Sign(ml_dsa_87_priv, []byte(tbs3), nil)
	var jws3 = tbs3 + "." + base64.RawURLEncoding.EncodeToString(s3)

	b, _ := json.MarshalIndent(TestVectors{
		Seed: hex.EncodeToString(seed[:]),
		MLDSA44: TestVector{
			PrivateKey: PrivateAlgorithmKeyPair{
				Kty:  "AKP",
				Alg:  "ML-DSA-44",
				Pub:  base64.RawURLEncoding.EncodeToString(ml_dsa_44_public_key),
				Priv: base64.RawURLEncoding.EncodeToString(seed[:]),
			},
			TbsBytes:  hex.EncodeToString([]byte(tbs1)),
			Signature: hex.EncodeToString([]byte(s1)),
			Jws:       jws1,
			PublicKey: hex.EncodeToString(ml_dsa_44_public_key),
		},
		MLDSA65: TestVector{
			PrivateKey: PrivateAlgorithmKeyPair{
				Kty:  "AKP",
				Alg:  "ML-DSA-65",
				Pub:  base64.RawURLEncoding.EncodeToString(ml_dsa_65_public_key),
				Priv: base64.RawURLEncoding.EncodeToString(seed[:]),
			},
			TbsBytes:  hex.EncodeToString([]byte(tbs2)),
			Signature: hex.EncodeToString([]byte(s2)),
			Jws:       jws2,
			PublicKey: hex.EncodeToString(ml_dsa_65_public_key),
		},
		MLDSA87: TestVector{
			PrivateKey: PrivateAlgorithmKeyPair{
				Kty:  "AKP",
				Alg:  "ML-DSA-87",
				Pub:  base64.RawURLEncoding.EncodeToString(ml_dsa_87_public_key),
				Priv: base64.RawURLEncoding.EncodeToString(seed[:]),
			},
			TbsBytes:  hex.EncodeToString([]byte(tbs3)),
			Signature: hex.EncodeToString([]byte(s3)),
			Jws:       jws3,
			PublicKey: hex.EncodeToString(ml_dsa_87_public_key),
		},
	}, "", "  ")

	_ = os.WriteFile("examples.json", b, 0644)

}
