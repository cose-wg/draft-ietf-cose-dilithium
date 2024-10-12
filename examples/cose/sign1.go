package cose

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type Header struct {
	Alg cose.Algorithm `cbor:"1,keyasint,omitempty"`
	Kid []byte         `cbor:"4,keyasint,omitempty"`
}

type Sign1Verification struct {
	Header  Header
	Payload []byte
}

type keySigner struct {
	alg cose.Algorithm
	key sign.PrivateKey
}

func (ks *keySigner) Algorithm() cose.Algorithm {
	return ks.alg
}

func (ks *keySigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	name, _ := AlgorithmToSuite(ks.alg)
	suite := schemes.ByName(name)
	return suite.Sign(ks.key, content, nil), nil
}

type keyVerifier struct {
	alg cose.Algorithm
	key sign.PublicKey
}

func (ks *keyVerifier) Algorithm() cose.Algorithm {
	return ks.alg
}

func (ks *keyVerifier) Verify(content []byte, signature []byte) error {
	name, _ := AlgorithmToSuite(ks.alg)
	suite := schemes.ByName(name)
	valid := suite.Verify(ks.key, content, signature, nil)
	if !valid {
		return errors.New("Signature not from public key")
	}
	return nil
}

func AlgorithmToSuite(alg cose.Algorithm) (string, error) {
	switch alg {
	case ML_DSA_44:
		return "ML-DSA-44", nil
	case ML_DSA_50:
		return "ML-DSA-50", nil
	case ML_DSA_65:
		return "ML-DSA-65", nil
	default:
		return "", errors.New(("Unknown algorithm"))
	}
}

func Sign1(private_key []byte, header Header, payload []byte) ([]byte, error) {
	var key AKPKey
	cbor.Unmarshal(private_key, &key)
	var suite sign.Scheme
	name, _ := AlgorithmToSuite(key.Alg)
	suite = schemes.ByName(name)
	_, priv := suite.DeriveKey(key.Priv)
	var signer cose.Signer = &keySigner{
		alg: key.Alg,
		key: priv,
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: header.Alg,
			cose.HeaderLabelKeyID:     header.Kid,
		},
	}
	sign1, _ := cose.Sign1(nil, signer, headers, payload, nil)
	return sign1, nil
}

func VerifySign1(public_key []byte, signature []byte) (Sign1Verification, error) {
	var key AKPKey
	var verified = Sign1Verification{}
	cbor.Unmarshal(public_key, &key)
	name, _ := AlgorithmToSuite(key.Alg)
	suite := schemes.ByName(name)
	pub, _ := suite.UnmarshalBinaryPublicKey(key.Pub)
	var sign1 cose.Sign1Message
	sign1.UnmarshalCBOR(signature)
	var verifier cose.Verifier = &keyVerifier{
		alg: key.Alg,
		key: pub,
	}
	verify_error := sign1.Verify(nil, verifier)
	if verify_error != nil {
		return verified, verify_error
	}
	var h []byte
	cbor.Unmarshal(sign1.Headers.RawProtected, &h)
	cbor.Unmarshal(h, &verified.Header)
	verified.Payload = sign1.Payload
	return verified, nil
}
