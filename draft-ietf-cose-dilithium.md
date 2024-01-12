---
title: "JOSE and COSE Encoding for Dilithium"
abbrev: "jose-cose-dilithium"
category: info

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
  github: "OR13/draft-ietf-cose-dilithium"
  latest: "https://OR13.github.io/draft-ietf-cose-dilithium/draft-ietf-cose-dilithium.html"

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
  IANA.jose#web-signature-encryption-algorithms: IANA.jose.algorithms
  IANA.jose#web-key-types: IANA.jose.key-types
  IANA.cose#algorithms: IANA.cose.algorithms
  IANA.cose#key-type: IANA.cose.key-types


informative:

  FIPS-204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://csrc.nist.gov/pubs/fips/204/ipd

  NIST-PQC-2022:
    title: "Selected Algorithms 2022"
    target: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022


--- abstract

This document describes JOSE and COSE serializations for ML-DSA,
which was derived from Dilithium, a Post-Quantum Cryptography (PQC) based suite.

This document does not define any new cryptography, only seralizations
of existing cryptographic systems described in {{FIPS-204}}.

Note to RFC Editor: This document should not proceed to AUTH48 until NIST
completes paramater tuning and selection as a part of the
[PQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
standardization process.

--- middle

# Introduction

ML-DSA is derived from Version 3.1 of CRYSTALS-DILITHIUM, as noted in {{FIPS-204}}.

CRYSTALS-DILITHIUM is one of the post quantum cryptography algorithms selected in {{NIST-PQC-2022}}.

# Terminology

{::boilerplate bcp14-tagged}

# The ML-DSA Algorithm Family

The ML-DSA Signature Scheme is paramaterized to support different security level.

This document requests the registration of the following algorithms in {{-IANA.jose.algorithms}}:

| Name       | alg | Description
|---
| ML-DSA-44  | ML-DSA-44     | JSON Web Signature Algorithm for ML-DSA-44
{: #jose-algorithms align="left" title="JOSE algorithms for ML-DSA"}

This document requests the registration of the following algorithms in {{-IANA.cose.algorithms}}:

| Name       | alg | Description
|---
| ML-DSA-44  | TBD (requested assignment -48)     | CBOR Object Signing Algorithm for ML-DSA-44
{: #cose-algorithms align="left" title="COSE algorithms for ML-DSA"}

# The ML-DSA Key Type

Private and Public Keys are produced to enable the sign and verify opertaions for each of the ML-DSA Algorithms.

This document requests the registration of the following key types in {{-IANA.jose.key-types}}:

| Name    | kty | Description
|---
| ML-DSA  | ML-DSA     | JSON Web Key Type for the ML-DSA Algorithm Family.
{: #jose-key-type align="left" title="JSON Web Key Type for ML-DSA"}

This document requests the registration of the following algorithms in {{-IANA.cose.key-types}}:

| Name       | kty | Description
|---
| ML-DSA  | TBD (requested assignment 7)     | COSE Key Type for the ML-DSA Algorithm Family.
{: #cose-key-type align="left" title="COSE Key Type for ML-DSA"}

# Security Considerations

TODO Security


# IANA Considerations

## Additions to Existing Registries

#### New COSE Algorithms

* Name: ML-DSA-44
* Label: TBD (requested assignment -48)
* Value type: int
* Value registry: {{-IANA.cose.algorithms}}
* Description: CBOR Object Signing Algorithm for ML-DSA-44

#### New COSE Key Types

* Name: ML-DSA
* Label: TBD (requested assignment 7)
* Value type: int
* Value registry: {{-IANA.cose.key-types}}
* Description: COSE Key Type for the ML-DSA Algorithm Family


#### New JOSE Algorithms

* Name: ML-DSA-44
* Value registry: {{-IANA.jose.algorithms}}
* Description: JSON Web Signature Algorithm for ML-DSA-44

#### New JOSE Key Types

* Name: ML-DSA
* Value registry: {{-IANA.jose.key-types}}
* Description: JSON Web Key Type for the ML-DSA Algorithm Family.


--- back

# Examples

## JOSE

### Key Pair

### Thumbprint URI

### JSON Web Signature

## COSE

### Key Pair

### Thumbprint URI

### COSE Sign 1

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
