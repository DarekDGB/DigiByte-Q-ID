# Third-Party Notices

This project, **DigiByte Q-ID**, is licensed under the MIT License.

It may optionally interface with or depend on third-party open-source
cryptographic libraries for post-quantum cryptography (PQC) and hybrid
signature support. No third-party source code is directly vendored into
this repository.

---

## Open Quantum Safe (liboqs)

- Project: https://openquantumsafe.org  
- Repository: https://github.com/open-quantum-safe/liboqs  
- License: MIT License  

**Purpose:**  
Post-quantum cryptographic algorithms, including:
- ML-DSA (NIST FIPS 204, formerly Dilithium)
- Falcon (post-quantum signature scheme)

liboqs may internally reference or link to additional algorithm
implementations that carry their own permissive licenses (e.g. BSD,
Apache 2.0). Users and integrators are responsible for reviewing the
licenses of any compiled or linked cryptographic backends used in their
environment.

---

## Usage Clarification

- This repository defines **protocols, interfaces, and verification rules**.
- Cryptographic backends are **pluggable and optional**.
- No post-quantum cryptographic implementation is embedded directly
  in this codebase.
- Selection and deployment of real PQC backends is the responsibility
  of the integrator.

---

## Protocol Lineage (Non-Code)

DigiByte Q-ID is a **clean-room protocol design**.

It is conceptually inspired by earlier authentication protocols such as:
- Digi-ID
- BitID

No source code, libraries, or implementations from those projects are
included, vendored, or derived in this repository.

Mention of these protocols is **historical and conceptual only** and does
not imply shared code, licensing, dependency, or endorsement.

---

## No Endorsement

Reference to third-party projects does not imply endorsement.
All trademarks and project names remain the property of their respective
owners.

---

Copyright (c) 2025  
Author: DarekDGB  
License: MIT
