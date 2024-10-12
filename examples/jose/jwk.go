package jose

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/schemes"
)

type PrivateAlgorithmKeyPair struct {
	Kty  string `json:"kty"`
	Alg  string `json:"alg"`
	Pub  string `json:"pub"`
	Priv string `json:"priv"`
}

type JWSHeader struct {
	Alg string `json:"alg"`
}

type JWSPayload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
}

func generateKey(alg string, seed []byte) (string, error) {
	suite := schemes.ByName(alg)
	pub, _ := suite.DeriveKey(seed[:])
	pub_bytes, _ := pub.MarshalBinary()
	encoded, err := json.Marshal(PrivateAlgorithmKeyPair{
		Kty:  "AKP",
		Alg:  alg,
		Pub:  base64.RawURLEncoding.EncodeToString(pub_bytes),
		Priv: base64.RawURLEncoding.EncodeToString(seed[:]),
	})
	return string(encoded), err
}

// see: https://datatracker.ietf.org/doc/html/rfc7638
func calculateJwkThumbprint(jwk string) (string, error) {
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
