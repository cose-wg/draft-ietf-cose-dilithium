---
title: "ML-DSA for JOSE and COSE"
abbrev: "jose-cose-dilithium"
category: std

docname: draft-ietf-cose-dilithium-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "CBOR Object Signing and Encryption"
keyword:
 - JOSE
 - COSE
 - PQC
 - DILITHIUM
 - ML-DSA
venue:
  group: "CBOR Object Signing and Encryption"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  github: "cose-wg/draft-ietf-cose-dilithium"
  latest: "https://cose-wg.github.io/draft-ietf-cose-dilithium/draft-ietf-cose-dilithium.html"

author:
 -
    fullname: "Michael Prorock"
    organization: mesur.io
    email: "mprorock@mesur.io"
 -
    fullname: "Orie Steele"
    organization: Transmute
    email: "orie@transmute.industries"
 -
    fullname: "Rafael Misoczki"
    organization: Google
    email: "rafaelmisoczki@google.com"
 -
    fullname: "Michael Osborne"
    organization: IBM
    email: "osb@zurich.ibm.com"
 -
    fullname: "Christine Cloostermans"
    organization: NXP
    email: "christine.cloostermans@nxp.com"

normative:
  IANA.jose: IANA.jose
  IANA.cose: IANA.cose
  RFC7515: JWS
  RFC7517: JWK
  RFC9053: COSE
  RFC7638: JOSE-KID
  I-D.draft-ietf-cose-key-thumbprint: COSE-KID


informative:
  I-D.draft-ietf-lamps-dilithium-certificates:  ML-DSA-CERTS

  FIPS-204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.204

  NIST-PQC-2022:
    title: "Selected Algorithms 2022"
    target: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022
---

--- abstract

This document describes JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) serializations for Module-Lattice-Based Digital Signature Standard (ML-DSA), a Post-Quantum Cryptography (PQC) digital signature scheme defined in FIPS 204.

--- middle

# Introduction

This document describes how to use ML-DSA keys and signatures as described in {{FIPS-204}} with JOSE and COSE.

# Terminology

{::boilerplate bcp14-tagged}

Some examples in this specification are truncated using "..." for readability.

# Algorithm Key Pair Type

This section describes a generic cryptographic key structure for use with algorithms not limited to those registered in this document.
The Algorithm Key Pair (AKP) Type is used to express Public and Private Keys for use with Algorithms.
When this key type is used the "alg" JSON Web Key Parameter or COSE Key Common Parameter is REQUIRED.

The concept of public and private information classes for key pairs originates from {{Section 8.1 of RFC7517}}.

The "pub" parameter contains a public key, this parameter contains public information and is REQUIRED.
Typically, a single "priv" parameter is necessary to express the private information needed to represent a private key.
When registering new algorithms, use of multiple key parameters for private information is NOT RECOMMENDED.

The key parameters for public and private information classes contain byte strings in a format specified by the "alg" value.
These classes MAY have additional structure or length checks depending on the associated "alg" parameter and its requirements.

When AKP keys are expressed in JWK, key parameters are base64url encoded.

This document requests the registration of the following key types in {{-IANA.jose}}:

| Name    | kty | Description
|---
| Algorithm Key Pair  | AKP     | JSON Web Key Type for the Algorithm Key Pair.
{: #jose-key-type align="left" title="Algorithm Key Pair Type for JOSE"}

An example truncated private key for use with ML-DSA-44 in JWK format is provided below:

~~~
{
   "kid": "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o",
   "kty": "AKP",
   "alg": "ML-DSA-44",
   "pub": "unH59k4Ru...DZgbTP07e7gEWzw4MFRrndjbDQ",
   "priv": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
~~~
{: #json-web-key-example align="left" title="The all zeros ML-DSA-44 JSON Web Key"}

This document requests the registration of the following key type in {{-IANA.cose}}:

| Name       | kty | Description
|---
| AKP  | TBD (requested assignment 7)     | COSE Key Type for the Algorithm Key Pair.
{: #cose-key-type align="left" title="Algorithm Key Pair Type for COSE"}

An example truncated private key for use with ML-DSA-44 in COSE_Key format is provided below:

~~~
{
   / kid /   2: h'b8969ab4b37da9f068...6f0583bf5b8d3a8059a',
   / kty /   1: 7, / AKP /
   / alg /   3: -48, / ML-DSA-44 /
   / pub  / -1: h'ba71f9f64e11baeb589...3830546b9dd8db0d',
   / seed / -3: h'00000000000000...0000000000000000'
}
~~~
{: #cose-key-example align="left" title="The all zeros ML-DSA-44 COSE Key"}

The AKP key type and thumbprint computation for the AKP key type is generic, and suitable for use with algorithms other than ML-DSA.

# ML-DSA Private Keys

Note that FIPS 204 defines 2 expressions for private keys: a seed (priv), and a private key that is expanded from the seed (priv_exp).

Similar to {{-ML-DSA-CERTS}} the following cases are possible:

1. Only the "seed" parameter is present.
2. Only the "priv" parameter is present.
3. Both parameters are present.

For ML-DSA keys, when "priv" is present, "seed" SHOULD be present to enable validation of the private key expansion process. 
Validation and expansion of private keys might be skipped in constrained environments.
For ML-DSA keys, when "seed" is present, it MUST have a length of 32 bytes.
When both "seed" and "priv" are present, the "seed" parameter MUST expand to the "priv" parameter.
See Security Considerations of this document for details.

Here is an elided example of the case where both "seed" and "priv" are present:

~~~
{
   "kid": "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o",
   "kty": "AKP",
   "alg": "ML-DSA-44",
   "pub": "unH59k4Ru...DZgbTP07e7gEWzw4MFRrndjbDQ",
   "seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
   "priv": "129kadu...DZgbTP07e7gEWzw4MFRr54"
}
~~~
{: #json-web-key-example-both-present align="left" title="The all zeros ML-DSA-44 JSON Web Key with both seed and priv parameters"}

# ML-DSA Algorithms

The ML-DSA Signature Scheme is parameterized to support different security levels.

In this document, the abbreviations ML-DSA-44, ML-DSA-65, and ML-DSA-87 are used to refer to ML-DSA
with the parameter choices given in Table 1 of FIPS-204.

This document requests the registration of the following algorithms in {{-IANA.jose}}:

| Name       | value | Description
|---
| ML-DSA-44  | ML-DSA-44     | JSON Web Signature Algorithm for ML-DSA-44
| ML-DSA-65  | ML-DSA-65     | JSON Web Signature Algorithm for ML-DSA-65
| ML-DSA-87  | ML-DSA-87     | JSON Web Signature Algorithm for ML-DSA-87
{: #jose-algorithms align="left" title="JOSE algorithms for ML-DSA"}

This document requests the registration of the following algorithms in {{-IANA.cose}}:

| Name       | value | Description
|---
| ML-DSA-44  | TBD (requested assignment -48)     | CBOR Object Signing Algorithm for ML-DSA-44
| ML-DSA-65  | TBD (requested assignment -49)     | CBOR Object Signing Algorithm for ML-DSA-65
| ML-DSA-87  | TBD (requested assignment -50)     | CBOR Object Signing Algorithm for ML-DSA-87
{: #cose-algorithms align="left" title="COSE algorithms for ML-DSA"}

In accordance with Algorithm Key Pair Type section of this document, ML-DSA key parameters have the following additional constraints:

The "pub" parameter is the ML-DSA public key, as described in Section 5.3 of FIPS-204.

The size of "pub", and the associated signature for each of these algorithms is defined in Table 2 of FIPS-204, and repeated here for convenience:

| Algorithm | Private Key | Public Key | Signature Size
|---
| ML-DSA-44  | 2560 | 1312 | 2420
| ML-DSA-65  | 4032 | 1952 | 3309
| ML-DSA-87  | 4896 | 2592 | 4627
{: #fips-204-table-2 align="left" title="Sizes (in bytes) of keys and signatures of ML-DSA"}

Note that "seed" size is always 32 bytes, and that KeyGen_internal is called to produce the private key sizes for "priv" in the table above.
See the ML-DSA Private Keys section of this document for more details.

These algorithms are used to produce signatures as described in Algorithm 2 of FIPS-204.
The ctx parameter MUST be the empty string for ML-DSA-44, ML-DSA-65 and ML-DSA-87.

Signatures are encoded as bytestrings using the algorithms defined in Section 7.2 of FIPS-204.

When producing JSON Web Signatures, the signature bytestrings are base64url encoded, and the encoded signature size is larger than described in the table above.

# AKP Thumbprints

When computing the COSE Key Thumbprint as described in {{-COSE-KID}}, the required parameters for algorithm key pairs are:

- "kty" (label: 1, data type: int, value: 7)
- "alg" (label: 3, data type: int, value: int)
- "pub" (label: -1, value: bstr)

The COSE Key Thumbprint is produced according to the process described in {{Section 3 of -COSE-KID}}.

When computing the JWK Thumbprint as described in {{-JOSE-KID}}, the required parameters for algorithm key pairs are:

- "kty"
- "alg"
- "pub"

Their lexicographic order, per {{Section 3.3 of -JOSE-KID}}, is:

- "alg"
- "kty"
- "pub"

The JWK Key Thumbprint is produced according to the process described in {{Section 3 of -JOSE-KID}}.

See the `kid` values in the JSON Web Key and COSE Key examples in the appendix for examples of AKP thumbprints.

# Security Considerations

The security considerations of {{-JWS}}, {{-JWK}} and {{-COSE}} applies to this specification as well.

A detailed security analysis of ML-DSA is beyond the scope of this specification, see {{FIPS-204}} for additional details.

## Size of keys and signatures

Table 2 of FIPS-204 describes the size of keys and signatures.
ML-DSA might not be the best choice for use cases that require small keys or signatures.
Use of thumbprints as described in {{RFC7638}} and {{-COSE-KID}} can reduce the need to repeat public key representations.

## Regarding HashML-DSA

This document does not specify algorithms for use with HashML-DSA as described in Section 5.4 of FIPS-204.

## Validation of keys

When an AKP algorithm requires or encourages that a key be validated before being used, all algorithm related key parameters MUST be validated.

Section 7.2 of FIPS-204 describes the encoding of ML-DSA keys and signatures.
The "pub" key parameter MUST be validated according to the pkEncode and pkDecode algorithms before being used.
For the ML-DSA algorithms registered in this document, the "priv" key parameter is a seed, and as such only a length check MUST be performed.
The length of the seed is 256 bits, which is 32 bytes.
However, if the private key ("priv_exp") is derived from the seed using KeyGen_internal is stored as part of some implementation, the skEncode and skDecode algorithms MUST be used.
FIPS-204 notes, "skDecode should only be run on inputs that come from trusted sources" and that "as the seed can be used to compute the private key, it is sensitive
data and shall be treated with the same safeguards as a private key".


## Mismatched AKP parameters

When using an AKP key with an algorithm, it is possible that the public and private information class parameters have been tampered with or mismatched.
Depending on the algorithm and implementation, the consequences of using mismatched parameters can range from operations failing to key compromise.

# IANA Considerations

## Additions to Existing Registries

### New COSE Algorithms

IANA is requested to add the following entries to the COSE Algorithms Registry.
The following completed registration templates are provided as described in RFC9053 and RFC9054.

#### ML-DSA-44

* Name: ML-DSA-44
* Value: TBD (requested assignment -48)
* Description: CBOR Object Signing Algorithm for ML-DSA-44
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes

#### ML-DSA-65

* Name: ML-DSA-65
* Value: TBD (requested assignment -49)
* Description: CBOR Object Signing Algorithm for ML-DSA-65
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes


#### ML-DSA-87

* Name: ML-DSA-87
* Value: TBD (requested assignment -50)
* Description: CBOR Object Signing Algorithm for ML-DSA-87
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes

### New COSE Key Types

IANA is requested to add the following entries to the COSE Key Types Registry.
The following completed registration templates are provided as described in RFC9053.

#### AKP

* Name: AKP
* Value: TBD (requested assignment 7)
* Description: COSE Key Type for Algorithm Key Pairs
* Capabilities: `[kty(7)]`
* Reference: RFC XXXX

### New COSE Key Type Parameters

IANA is requested to add the following entries to the COSE Key Type Parameters.
The following completed registration templates are provided as described in RFC9053.

### ML-DSA Public Key

* Key Type: TBD (requested assignment 7)
* Name: pub
* Label: -1
* CBOR Type: bstr
* Description: Public key
* Reference: RFC XXXX

### ML-DSA Private Key

* Key Type: TBD (requested assignment 7)
* Name: priv
* Label: -2
* CBOR Type: bstr
* Description: Private key
* Reference: RFC XXXX

### ML-DSA Private Key Expanded

* Key Type: TBD (requested assignment 7)
* Name: priv_exp
* Label: -3
* CBOR Type: bstr
* Description: Private key expanded form
* Reference: RFC XXXX

### New JOSE Algorithms

IANA is requested to add the following entries to the JSON Web Signature and Encryption Algorithms Registry.
The following completed registration templates are provided as described in RFC7518.

#### ML-DSA-44

* Algorithm Name: ML-DSA-44
* Algorithm Description: ML-DSA-44 as described in FIPS 204.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Value registry: {{-IANA.jose}} Algorithms
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-204}}

#### ML-DSA-65

* Algorithm Name: ML-DSA-65
* Algorithm Description: ML-DSA-65 as described in FIPS 204.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Value registry: {{-IANA.jose}} Algorithms
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-204}}

#### ML-DSA-87

* Algorithm Name: ML-DSA-87
* Algorithm Description: ML-DSA-87 as described in FIPS 204.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Value registry: {{-IANA.jose}} Algorithms
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-204}}

### New JOSE Key Types

IANA is requested to add the following entries to the JSON Web Key Types Registry.
The following completed registration templates are provided as described in RFC7518 RFC7638.

#### AKP

* "kty" Parameter Value: AKP
* Key Type Description: Algorithm Key Pair
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX

### New JSON Web Key Parameters

IANA is requested to add the following entries to the JSON Web Key Parameters Registry.
The following completed registration templates are provided as described in RFC7517, and RFC7638.

#### AKP Public Key

* Parameter Name: pub
* Parameter Description: Public key
* Used with "kty" Value(s): AKP
* Parameter Information Class: Public
* Change Controller: IETF
* Specification Document(s): RFC XXXX

#### AKP Private Key

* Parameter Name: priv
* Parameter Description: Private key
* Used with "kty" Value(s): AKP
* Parameter Information Class: Private
* Change Controller: IETF
* Specification Document(s): RFC XXXX

#### AKP Private Key Expanded

* Parameter Name: priv_exp
* Parameter Description: Private key expanded form
* Used with "kty" Value(s): AKP
* Parameter Information Class: Private
* Change Controller: IETF
* Specification Document(s): RFC XXXX

--- back

# Examples

## JOSE

~~~~~~~~~~
{::include ./examples/jose/examples/ML_DSA_44.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_44 title="ML_DSA_44"}

~~~~~~~~~~
{::include ./examples/jose/examples/ML_DSA_65.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_65 title="ML_DSA_65"}

~~~~~~~~~~
{::include ./examples/jose/examples/ML_DSA_87.jose.json}
~~~~~~~~~~
{: #jose_example_ML_DSA_87 title="ML_DSA_87"}

## COSE

~~~~~~~~~~
{::include ./examples/cose/examples/ML_DSA_44.cose.json}
~~~~~~~~~~
{: #cose_example_ML_DSA_44 title="ML_DSA_44"}

~~~~~~~~~~
{::include ./examples/cose/examples/ML_DSA_65.cose.json}
~~~~~~~~~~
{: #cose_example_ML_DSA_65 title="ML_DSA_65"}

~~~~~~~~~~
{::include ./examples/cose/examples/ML_DSA_87.cose.json}
~~~~~~~~~~
{: #cose_example_ML_DSA_87 title="ML_DSA_87"}

# Acknowledgments
{:numbered="false"}

We would like to thank Simo Sorce, Ilari Liusvaara, Neil Madden, Anders Rundgren, David Waite, Russ Housley, Filip Skokan, and Lucas Prabel for their comments and reviews of this document.
