%%%

    title = "Use of Static-Static ECDH in JSON Object Signing and Encryption (JOSE)"
    abbr = "JoseECDHSS"
    category = "info"
    docname = "draft-amringer-jose-ecdh-ss-00"
    workgroup = "(No Working Group)"
    keyword = ["encryption", "AEAD", "cryptography", "security", "authenticated encryption", "jose"]

    date = 2019-07-23T23:51:00Z

    [[author]]
    initials="G."
    surname="Amringer"
    fullname="Guillaume Amringer"
      [author.address]
      email = "g.amringer@gmail.com"
      [author.address.postal]
      country = "Canada"

%%%

.# Abstract

This document defines how to use the Static-Static mode of ECDH in JSON Object
Signing and Encryption (JOSE).

{mainmatter}

# Introduction

The Internet Research Task Force (IRTF) JOSE Working Group defined the ECDH-ES
as a key agreement mechanism in the JOSE context. This document defines how to
use the ECDH key agreement mechanism in Static-Static mode in JOSE in an
interoperable manner.

This document defines the conventions to use in the context of [@!RFC7516]

## Notation and Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**MAY**",
and "**OPTIONAL**" in this document are to be interpreted as described in
[@!RFC2119].

The JOSE key format ("JSON Web Key (JWK)") is defined by [@!RFC7517] and
thumbprints for it ("JSON Web Key (JWK) Thumbprint") in [@!RFC7638].

# Key Agreement with Elliptic Curve Diffie-Hellman Static-Static

This section defines the specifics of key agreement with Elliptic Curve
Diffie-Hellman Static-Static [@!RFC6090], in combination with the Concat KDF,
as defined in
[Section 5.8.2.1 of NIST.800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
for use as a symmetric key to wrap the CEK with the "C20PKW", "XC20PKW",
"A128KW", "A192KW", "A256KW" algorithms, in the Key Agreement with Key Wrapping
mode.

This mode is used as defined as the atlernate way for ECDH-ES in
[Section 4.6.2 of RFC7518](https://tools.ietf.org/html/rfc7518#section-4.6.2).

The following "alg" (algorithm) Header Parameter values are used to indicate
that the JWE Encrypted Key is the result of encrypting the CEK using the
corresponding algorithm:

| "alg" value | Key Management Algorithm |
| ----------- | ------------------------ |
| ECDH-SS | ECDH-SS using Concat KDF for use directly as a symmetric key |
| ECDH-SS+C20PKW | ECDH-SS using Concat KDF and CEK wrapped with C20PKW |
| ECDH-SS+XC20PKW | ECDH-SS using Concat KDF and CEK wrapped with XC20PKW |
| ECDH-SS+A128KW | ECDH-SS using Concat KDF and CEK wrapped with A128KW |
| ECDH-SS+A192KW | ECDH-SS using Concat KDF and CEK wrapped with A192KW |
| ECDH-SS+A256KW | ECDH-SS using Concat KDF and CEK wrapped with A256KW |

# IANA Considerations

The following is added to the "JSON Web Signature and Encryption Algorithms"
registry:

o Algorithm Name: "ECDH-SS"
o Algorithm Description:  ECDH-SS using Concat KDF
o Algorithm Usage Location(s): "alg"
o JOSE Implementation Requirements: Optional
o Change Controller: IESG
o Specification Document(s): Section 2 of [RFC-THIS]
o Algorithm Analysis Documents(s): [@!RFC8439]

o Algorithm Name: "ECDH-SS+C20PKW"
o Algorithm Description:  ECDH-SS using Concat KDF and "C20PKW"
o Algorithm Usage Location(s): "alg"
o JOSE Implementation Requirements: Optional
o Change Controller: IESG
o Specification Document(s): Section 2 of [RFC-THIS]
o Algorithm Analysis Documents(s): [@?I-D.irtf-cfrg-xchacha]

o Algorithm Name: "ECDH-SS+XC20PKW"
o Algorithm Description:  ECDH-SS using Concat KDF and "XC20PKW"
o Algorithm Usage Location(s): "alg"
o JOSE Implementation Requirements: Optional
o Change Controller: IESG
o Specification Document(s): Section 2 of [RFC-THIS]
o Algorithm Analysis Documents(s): [@?I-D.irtf-cfrg-xchacha]

o Algorithm Name: "ECDH-SS+A128KW"
o Algorithm Description:  ECDH-SS using Concat KDF and "A128KW"
o Algorithm Usage Location(s): "alg"
o JOSE Implementation Requirements: Optional
o Change Controller: IESG
o Specification Document(s): Section 2 of [RFC-THIS]
o Algorithm Analysis Documents(s): [@?I-D.irtf-cfrg-xchacha]

o Algorithm Name: "ECDH-SS+A192KW"
o Algorithm Description:  ECDH-SS using Concat KDF and "A192KW"
o Algorithm Usage Location(s): "alg"
o JOSE Implementation Requirements: Optional
o Change Controller: IESG
o Specification Document(s): Section 2 of [RFC-THIS]
o Algorithm Analysis Documents(s): [@?I-D.irtf-cfrg-xchacha]

o Algorithm Name: "ECDH-SS+A256KW"
o Algorithm Description:  ECDH-SS using Concat KDF and "A256KW"
o Algorithm Usage Location(s): "alg"
o JOSE Implementation Requirements: Optional
o Change Controller: IESG
o Specification Document(s): Section 2 of [RFC-THIS]
o Algorithm Analysis Documents(s): [@?I-D.irtf-cfrg-xchacha]

{backmatter}
