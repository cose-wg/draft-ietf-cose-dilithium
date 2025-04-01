package jose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/cloudflare/circl/sign/schemes"
)

type JWSHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type JWSVerification struct {
	Header  map[string]string
	Payload []byte
}

func ToBeSignedFromJWS(jws string) []byte {
	components := strings.Split(jws, ".")
	var to_be_signed_bytes = []byte(components[0] + "." + components[1])
	return to_be_signed_bytes
}

func SignatureFromJWS(jws string) ([]byte, error) {
	components := strings.Split(jws, ".")
	sig, err := base64.RawURLEncoding.DecodeString(components[2])
	if err != nil {
		return nil, errors.New("Failed to decode signature from JWS")
	}
	return sig, nil
}

func CompactSign(private_key string, payload []byte) (string, error) {
	var jwk map[string]string
	err := json.Unmarshal([]byte(private_key), &jwk)
	if err != nil {
		return "", errors.New("Failed to parse jwk private key")
	}
	// caution, this assumes circl and JOSE / COSE alg names are the name.
	suite := schemes.ByName(jwk["alg"])
	seed, err := base64.RawURLEncoding.DecodeString(jwk["seed"])
	if err != nil {
		return "", errors.New("Failed to decode jwk.priv, malformed seed")
	}
	_, priv := suite.DeriveKey(seed[:])
	var header, _ = json.Marshal(JWSHeader{
		Alg: jwk["alg"],
		Kid: jwk["kid"],
	})
	var to_be_signed_bytes = ToBeSignedFromJWS(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload))
	var signature = suite.Sign(priv, to_be_signed_bytes, nil)
	var encoded_signature = base64.RawURLEncoding.EncodeToString(signature)
	var jws = string(to_be_signed_bytes) + "." + encoded_signature
	return jws, nil
}

func CompactVerify(public_key string, jws string) (JWSVerification, error) {
	var payload []byte
	var verified = JWSVerification{}
	var jwk map[string]string
	err := json.Unmarshal([]byte(public_key), &jwk)
	if err != nil {
		return verified, errors.New("Failed to parse jwk private key")
	}
	if jwk["seed"] != "" {
		return verified, errors.New("CompactVerify cannot be called with a private key")
	}
	// caution, this assumes circl and JOSE / COSE alg names are the name.
	suite := schemes.ByName(jwk["alg"])
	pub, err := base64.RawURLEncoding.DecodeString(jwk["pub"])
	suite_public_key, malformed_public_key_error := suite.UnmarshalBinaryPublicKey(pub)
	if malformed_public_key_error != nil {
		return verified, malformed_public_key_error
	}
	components := strings.Split(jws, ".")
	var to_be_signed_bytes = ToBeSignedFromJWS(jws)
	signature, signature_encoding_error := SignatureFromJWS(jws)
	if signature_encoding_error != nil {
		return verified, signature_encoding_error
	}
	signature_match := suite.Verify(suite_public_key, to_be_signed_bytes, signature, nil)
	if !signature_match {
		return verified, errors.New("Signature not from public key")
	}
	decoded_header, decode_header_error := base64.RawURLEncoding.DecodeString(components[0])
	if decode_header_error != nil {
		return verified, errors.New("JWS Header is not encoded as base64url")
	}
	var header map[string]string
	decode_header_error = json.Unmarshal(decoded_header, &header)
	if decode_header_error != nil {
		return verified, errors.New("Failed to parse JWS header")
	}
	payload, decode_payload_error := base64.RawURLEncoding.DecodeString(components[1])
	if decode_payload_error != nil {
		return verified, errors.New("JWS Payload is not encoded as base64url")
	}
	verified.Header = header
	verified.Payload = payload
	return verified, nil
}
