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
  I-D.draft-ietf-cose-sphincs-plus: SLH-DSA
  I-D.draft-ietf-cose-key-thumbprint: COSE-KID

informative:

  FIPS-204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.204

  NIST-PQC-2022:
    title: "Selected Algorithms 2022"
    target: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022
---

--- abstract

This document describes JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) serializations for Module-Lattice-Based Digital Signature Standard (ML-DSA), which was derived from Dilithium, a Post-Quantum Cryptography (PQC) based digital signature scheme.

This document does not define any new cryptography, only seralizations of existing cryptographic systems described in {{FIPS-204}}.

Note to RFC Editor: This document should not proceed to AUTH48 until NIST completes paramater tuning and selection as a part of the [PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) standardization process.

--- middle

# Introduction

This document describes how to use ML-DSA keys and signatures as described in {{FIPS-204}} with JOSE and COSE.
To reduce implementation burden, the key type and thumbprint computations for ML-DSA are generic, and suitable for use with other algorithms such as SLH-DSA as described in {{-SLH-DSA}}.

# Terminology

{::boilerplate bcp14-tagged}

# ML-DSA Algorithms

The ML-DSA Signature Scheme is paramaterized to support different security levels.

This document requests the registration of the following algorithms in {{-IANA.jose}}:

| Name       | alg | Description
|---
| ML-DSA-44  | ML-DSA-44     | JSON Web Signature Algorithm for ML-DSA-44
| ML-DSA-65  | ML-DSA-65     | JSON Web Signature Algorithm for ML-DSA-65
| ML-DSA-87  | ML-DSA-87     | JSON Web Signature Algorithm for ML-DSA-87
{: #jose-algorithms align="left" title="JOSE algorithms for ML-DSA"}

This document requests the registration of the following algorithms in {{-IANA.cose}}:

| Name       | alg | Description
|---
| ML-DSA-44  | TBD (requested assignment -48)     | CBOR Object Signing Algorithm for ML-DSA-44
| ML-DSA-65  | TBD (requested assignment -49)     | CBOR Object Signing Algorithm for ML-DSA-65
| ML-DSA-87  | TBD (requested assignment -50)     | CBOR Object Signing Algorithm for ML-DSA-87
{: #cose-algorithms align="left" title="COSE algorithms for ML-DSA"}

# Algorithm Key Pair Type

The Algorithm Key Pair (AKP) Type is used to express Public and Private Keys for use with Algorithms.
When this key type is used the "alg" JSON Web Key Parameter or COSE Key Common Parameter is REQUIRED.

This document requests the registration of the following key types in {{-IANA.jose}}:

| Name    | kty | Description
|---
| Algorithm Key Pair  | AKP     | JSON Web Key Type for the Algorithm Key Pair.
{: #jose-key-type align="left" title="Algorithm Key Pair Type for JOSE"}

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


This document requests the registration of the following algorithms in {{-IANA.cose}}:

| Name       | kty | Description
|---
| AKP  | TBD (requested assignment 7)     | COSE Key Type for the Algorithm Key Pair.
{: #cose-key-type align="left" title="Algorithm Key Pair Type for COSE"}

~~~
{
   / kid /   2: h'b8969ab4b37da9f068...6f0583bf5b8d3a8059a',
   / kty /   1: 7, / AKP /
   / alg /   3: -48, / ML-DSA-44 /
   / pub  / -1: h'ba71f9f64e11baeb58...c3830546b9dd8db0d',
   / priv / -2: h'00000000000000...0000000000000000'
}
~~~
{: #cose-key-example align="left" title="The all zeros ML-DSA-44 COSE Key"}

# ML-DSA Private Keys

Note that FIPS 204 defines 2 expressions for private keys, a seed, and a private key that is expanded from the seed.
For the algorithms defined in this document, the private key is always the seed, and never the expanded expression.
The AKP Key Type MAY be used with algorithms not defined in this specification, and those algorithms MAY encode their private keys differently.

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
* Name: public_key
* Label: -1
* CBOR Type: bstr
* Description: Public key
* Reference: RFC XXXX

### ML-DSA Private Key

* Key Type: TBD (requested assignment 7)
* Name: private_key
* Label: -2
* CBOR Type: bstr
* Description: Private key or seed used to derive a private key.
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
* Parameter Description: Private key or seed used to derive a private key.
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

We would like to thank Simo Sorce, Ilari Liusvaara, Neil Madden, Anders Rundgren, David Waite, and Russ Housley for their review feedback.
