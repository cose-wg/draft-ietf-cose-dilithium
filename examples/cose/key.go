package cose

import (
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/sign/schemes"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	KTY       = 1
	EC2       = 2
	AKP       = 7
	ML_DSA_44 = 48
	ML_DSA_65 = 49
	ML_DSA_87 = 50
)

type EC2Key struct {
	Y   []byte `cbor:"-3,keyasint,omitempty"`
	X   []byte `cbor:"-2,keyasint,omitempty"`
	Crv int    `cbor:"-1,keyasint,omitempty"`
	Kty int    `cbor:"1,keyasint,omitempty"`
}

type AKPKeyThumbprint struct {
	Pub []byte `cbor:"-1,keyasint,omitempty"`
	Kty int    `cbor:"1,keyasint,omitempty"`
	Alg int    `cbor:"3,keyasint,omitempty"`
}

type AKPKey struct {
	Kid  []byte         `cbor:"2,keyasint,omitempty"`
	Kty  int            `cbor:"1,keyasint,omitempty"`
	Alg  cose.Algorithm `cbor:"3,keyasint,omitempty"`
	Pub  []byte         `cbor:"-1,keyasint,omitempty"`
	Priv []byte         `cbor:"-2,keyasint,omitempty"`
}

func GenerateKey(alg cose.Algorithm, seed []byte) ([]byte, error) {
	var pub_bytes []byte
	name, _ := AlgorithmToSuite(alg)
	suite := schemes.ByName(name)
	pub, _ := suite.DeriveKey(seed[:])
	pub_bytes, _ = pub.MarshalBinary()
	private_key, encode_private_key_error := cbor.Marshal(AKPKey{
		Kty:  AKP,
		Alg:  alg,
		Pub:  pub_bytes,
		Priv: seed,
	})
	if encode_private_key_error != nil {
		return nil, errors.New(`Failed to cbor encode cose key`)
	}
	kid, thumbprint_error := CalculateCoseKeyThumbprint(private_key)
	if thumbprint_error != nil {
		return nil, errors.New(`Failed to calculate cose key thumbprint for private key`)
	}
	private_key_with_thumbprint, encode_private_key_error := cbor.Marshal(AKPKey{
		Kid:  kid,
		Kty:  AKP,
		Alg:  alg,
		Pub:  pub_bytes,
		Priv: seed,
	})
	return private_key_with_thumbprint, nil
}

func PublicKeyFromPrivateKey(cose_key []byte) ([]byte, error) {
	var key AKPKey
	err := cbor.Unmarshal(cose_key, &key)
	if err != nil {
		return nil, errors.New("Failed to parse cbor")
	}
	key.Priv = nil
	encoded_public_key, encode_public_key_error := cbor.Marshal(key)
	if encode_public_key_error != nil {
		return nil, errors.New(`Failed to cbor encode cose key`)
	}
	return encoded_public_key, nil
}

func DecodeKey(cose_key []byte) (AKPKey, error) {
	var key AKPKey
	err := cbor.Unmarshal(cose_key, &key)
	if err != nil {
		return key, errors.New(`Failed to decode cose key`)
	}
	return key, nil
}

func CalculateCoseKeyThumbprint(cose_key []byte) ([]byte, error) {
	em, _ := cbor.CanonicalEncOptions().EncMode()
	var key map[int]int
	var thumbprint []byte
	var canonical_encoding_error error
	cbor.Unmarshal(cose_key, &key)
	var canonical_encoded_cose_key []byte
	switch key[KTY] {
	case EC2:
		var key EC2Key
		cbor.Unmarshal(cose_key, &key)
		canonical_encoded_cose_key, canonical_encoding_error = em.Marshal(key)
	case AKP:
		var key AKPKeyThumbprint
		cbor.Unmarshal(cose_key, &key)
		canonical_encoded_cose_key, canonical_encoding_error = em.Marshal(key)
	default:
		return nil, errors.New(`Unknown COSE Key Type (kty)`)
	}
	if canonical_encoding_error != nil {
		return nil, errors.New(`Failed to canonically encode cose key`)
	}
	h := sha256.New()
	h.Write(canonical_encoded_cose_key)
	thumbprint = h.Sum(nil)
	return thumbprint, nil
}
