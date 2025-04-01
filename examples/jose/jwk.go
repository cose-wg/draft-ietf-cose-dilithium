package jose

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

const (
	ML_DSA_44 = "ML-DSA-44"
	ML_DSA_65 = "ML-DSA-65"
	ML_DSA_87 = "ML-DSA-87"
)

type AKPKey struct {
	Kid  string `json:"kid"`
	Kty  string `json:"kty"`
	Alg  string `json:"alg"`
	Pub  string `json:"pub"`
	Seed string `json:"seed"`
}

func GenerateKey(alg string, seed []byte) (string, error) {
	suite := schemes.ByName(alg)
	pub, _ := suite.DeriveKey(seed[:])
	pub_bytes, _ := pub.MarshalBinary()
	jwk, err := json.Marshal(AKPKey{
		Kty:  "AKP",
		Alg:  alg,
		Pub:  base64.RawURLEncoding.EncodeToString(pub_bytes),
		Seed: base64.RawURLEncoding.EncodeToString(seed[:]),
	})
	kid, _ := CalculateJwkThumbprint(string(jwk))
	jwk_with_thumbprint, err := json.Marshal(AKPKey{
		Kid:  kid,
		Kty:  "AKP",
		Alg:  alg,
		Pub:  base64.RawURLEncoding.EncodeToString(pub_bytes),
		Seed: base64.RawURLEncoding.EncodeToString(seed[:]),
	})
	return string(jwk_with_thumbprint), err
}

func DecodeKey(jwk string) (AKPKey, error) {
	var key AKPKey
	err := json.Unmarshal([]byte(jwk), &key)
	return key, err
}

func PublicKeyFromPrivateKey(jwk string) (string, error) {
	var key map[string]string
	err := json.Unmarshal([]byte(jwk), &key)
	if err != nil {
		return "", errors.New("Failed to parse JSON")
	}
	var public_key = fmt.Sprintf(`{"kty":"%s","alg":"%s","pub":"%s"}`, key["kty"], key["alg"], key["pub"])
	return public_key, err
}

func SuiteFromJWK(jwk string) (sign.Scheme, sign.PublicKey, sign.PrivateKey, error) {
	var key map[string]string
	err := json.Unmarshal([]byte(jwk), &key)
	if err != nil {
		return nil, nil, nil, errors.New("Failed to parse JSON")
	}
	suite := schemes.ByName(key["alg"])
	if key["seed"] != "" {
		suite := schemes.ByName(key["alg"])
		seed, err := base64.RawURLEncoding.DecodeString(key["seed"])
		if err != nil {
			return nil, nil, nil, errors.New("Failed to decode jwk.seed, malformed seed")
		}
		pub, priv := suite.DeriveKey(seed[:])
		return suite, pub, priv, nil
	}
	binary_pub, err := base64.RawURLEncoding.DecodeString(key["pub"])
	pub, _ := suite.UnmarshalBinaryPublicKey(binary_pub)
	return suite, pub, nil, nil
}

// see: https://datatracker.ietf.org/doc/html/rfc7638
func CalculateJwkThumbprint(jwk string) (string, error) {
	var key map[string]string
	err := json.Unmarshal([]byte(jwk), &key)
	if err != nil {
		return "", errors.New("Failed to parse JSON")
	}
	h := sha256.New()
	switch kty := key["kty"]; kty {
	case "EC":
		h.Write([]byte(fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, key["crv"], key["kty"], key["x"], key["y"])))
	case "AKP":
		h.Write([]byte(fmt.Sprintf(`{"alg":"%s","kty":"%s","pub":"%s"}`, key["alg"], key["kty"], key["pub"])))
	default:
		return "", errors.New(`Unknown JWK key type (kty)`)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
