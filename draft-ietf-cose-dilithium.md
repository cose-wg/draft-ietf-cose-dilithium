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

informative:

  FIPS-204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://csrc.nist.gov/pubs/fips/204/ipd

  NIST-PQC-2022:
    title: "Selected Algorithms 2022"
    target: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022


--- abstract

This document describes JOSE and COSE serializations for ML-DSA, which was derived from Dilithium, a Post-Quantum Cryptography (PQC) based digital signature scheme.

This document does not define any new cryptography, only seralizations of existing cryptographic systems described in {{FIPS-204}}.

Note to RFC Editor: This document should not proceed to AUTH48 until NIST completes paramater tuning and selection as a part of the [PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) standardization process.

--- middle

# Introduction

ML-DSA is derived from Version 3.1 of CRYSTALS-DILITHIUM, as noted in {{FIPS-204}}.

CRYSTALS-DILITHIUM is one of the post quantum cryptography algorithms selected in {{NIST-PQC-2022}}.

TODO: Add complete examples for `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`.

# Terminology

{::boilerplate bcp14-tagged}

# The ML-DSA Algorithm Family

The ML-DSA Signature Scheme is paramaterized to support different security level.

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

# The ML-DSA Key Type

Private and Public Keys are produced to enable the sign and verify opertaions for each of the ML-DSA Algorithms.

This document requests the registration of the following key types in {{-IANA.jose}}:

| Name    | kty | Description
|---
| ML-DSA  | ML-DSA     | JSON Web Key Type for the ML-DSA Algorithm Family.
{: #jose-key-type align="left" title="JSON Web Key Type for ML-DSA"}

This document requests the registration of the following algorithms in {{-IANA.cose}}:

| Name       | kty | Description
|---
| ML-DSA  | TBD (requested assignment 7)     | COSE Key Type for the ML-DSA Algorithm Family.
{: #cose-key-type align="left" title="COSE Key Type for ML-DSA"}

# Security Considerations

TODO Security


# IANA Considerations

## Additions to Existing Registries

### New COSE Algorithms

* Name: ML-DSA-44
* Label: TBD (requested assignment -48)
* Value type: int
* Value registry: {{-IANA.cose}}
* Description: CBOR Object Signing Algorithm for ML-DSA-44


* Name: ML-DSA-65
* Label: TBD (requested assignment -49)
* Value type: int
* Value registry: {{-IANA.cose}}
* Description: CBOR Object Signing Algorithm for ML-DSA-65


* Name: ML-DSA-87
* Label: TBD (requested assignment -50)
* Value type: int
* Value registry: {{-IANA.cose}}
* Description: CBOR Object Signing Algorithm for ML-DSA-87

### New COSE Key Types

* Name: ML-DSA
* Label: TBD (requested assignment 7)
* Value type: int
* Value registry: {{-IANA.cose}}
* Description: COSE Key Type for the ML-DSA Algorithm Family


### New JOSE Algorithms

* Name: ML-DSA-44
* Value registry: {{-IANA.jose}} Algorithms
* Description: JSON Web Signature Algorithm for ML-DSA-44


* Name: ML-DSA-65
* Value registry: {{-IANA.jose}} Algorithms
* Description: JSON Web Signature Algorithm for ML-DSA-65


* Name: ML-DSA-87
* Value registry: {{-IANA.jose}} Algorithms
* Description: JSON Web Signature Algorithm for ML-DSA-87

### New JOSE Key Types

* Name: ML-DSA
* Value registry: {{-IANA.jose}} Algorithms
* Description: JSON Web Key Type for the ML-DSA Algorithm Family.


--- back

# Examples

## JOSE

### Key Pair

~~~json
{
  "kty": "ML-DSA",
  "alg": "ML-DSA-44",
  "pub": "V53SIdVF...uvw2nuCQ",
  "priv": "V53SIdVF...cDKLbsBY"
}
~~~
{: #ML-DSA-44-private-jwk title="Example ML-DSA-44 Private JSON Web Key"}

~~~json
{
  "kty": "ML-DSA",
  "alg": "ML-DSA-44",
  "pub": "V53SIdVF...uvw2nuCQ"
}
~~~
{: #ML-DSA-44-public-jwk title="Example ML-DSA-44 Public JSON Web Key"}

### Thumbprint URI

TODO

### JSON Web Signature


~~~json
{
  "alg": "ML-DSA-44"
}
~~~
{: #ML-DSA-44-jose-protected-header title="Example ML-DSA-44 Decoded Protected Header"}

~~~
eyJhbGciOiJ...LCJraWQiOiI0MiJ9\
.\
eyJpc3MiOiJ1cm46d...XVpZDo0NTYifQ\
.\
5MSEgQ0dZB4SeLC...AAAAAABIhMUE
~~~
{: #ML-DSA-44-jose-jws title="Example ML-DSA-44 Compact JSON Web Signature"}

## COSE

### Key Pair

~~~~ cbor-diag
{                                   / COSE Key                /
  1: 7,                             / ML-DSA Key Type         /
  3: -48,                           / ML-DSA-44 Algorithm     /
  -13: h'7803c0f9...3f6e2c70',      / ML-DSA Private Key      /
  -14: h'7803c0f9...3bba7abd',      / ML-DSA Public Key       /
}
~~~~
{: #ML-DSA-44-private-cose-key title="Example ML-DSA-44 Private COSE Key"}

~~~~ cbor-diag
{                                   / COSE Key                /
  1: 7,                             / ML-DSA Key Type         /
  3: -48,                           / ML-DSA-44 Algorithm     /
  -13: h'7803c0f9...3f6e2c70'       / ML-DSA Private Key      /
}
~~~~
{: #ML-DSA-44-public-cose-key title="Example ML-DSA-44 Public COSE Key"}

### Thumbprint URI

TODO

### COSE Sign 1


~~~~ cbor-diag
{                               / Protected                 /
  1: -48                        / Algorithm                 /
}
~~~~
{: #ML-DSA-44-cose-protected-header-diagnostic title="Example ML-DSA-44 COSE Protected Header"}


~~~~ cbor-diag
18(                                 / COSE Sign 1            /
    [
      h'a10139d902',                / Protected              /
      {},                           / Unprotected            /
      h'66616b65',                  / Payload                /
      h'53e855e8...0f263549'        / Signature              /
    ]
)
~~~~
{: #ML-DSA-44-cose-sign-1-diagnostic title="Example ML-DSA-44 COSE Sign 1"}


# Acknowledgments
{:numbered="false"}

TODO acknowledge.
