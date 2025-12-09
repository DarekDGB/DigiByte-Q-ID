# Contributing to DigiByte Q-ID

DigiByte Q-ID is a **post-quantum identity system** designed to provide:
- secure user identity,
- PQC signatures and verification,
- encrypted profile storage,
- recovery mechanisms,
- and clean integration paths for wallets, DigiAssets, or shield components.

This repository defines **identity logic only**.  
It does *not* implement wallet features, shield behaviour, or consensus rules.  
Contributions must preserve this separation.

---

## ✅ What Contributions Are Welcome

### ✔ PQC Improvements
- enhancements to Falcon/Dilithium signer or verifier backends  
- better key derivation logic  
- safer recovery workflows  

### ✔ Identity System Extensions
- enriched `identity_state` handling  
- improved encrypted storage patterns  
- UX-safe backup / restore logic  

### ✔ Protocol Enhancements
- improved handshake logic  
- better authentication flow  
- channel upgrades  
- clearer error handling  

### ✔ Integrations
Extensions to:
- `wallet_adapter.py`  
- `shield_adapter.py`  
- `assets_adapter.py`  

are welcome **as long as Q-ID stays identity-focused**.

### ✔ Documentation
Improvements to the docs under `docs/`:
- Identity Model  
- PQC backend  
- Recovery  
- Architecture  

---

## ❌ What Will NOT Be Accepted

### 🚫 1. Mixing Identity Logic With Wallet Logic  
Q-ID must stay independent.  
No:
- transaction code  
- wallet UI  
- shield decisions  
- asset logic  
- network code  

### 🚫 2. Moving Encryption or Key Logic Outside the Identity Layer  
All cryptography must remain inside:
- `core/`   
- `storage/`  

### 🚫 3. Introducing Black-Box ML or Non-Deterministic Behaviour  
Q-ID must remain:
- explainable  
- auditable  
- deterministic  

### 🚫 4. Modifying DigiByte Consensus  
Q-ID is strictly an **identity layer**, not a blockchain protocol.

---

## 🧱 Design Principles

1. **Identity First** — Q-ID is not a wallet, asset system, or shield engine.  
2. **Modularity** — components must remain isolated and replaceable.  
3. **PQC-Ready** — cryptography must support post-quantum security.  
4. **Explainability** — no hidden logic.  
5. **Determinism** — given the same inputs, identity operations must yield the same outputs.  
6. **Security by Default** — encrypted storage and recovery must be safe and predictable.  

---

## 🔄 Pull Request Requirements

Every PR must include:

- a clear explanation of the change  
- tests for new logic (`tests/`)  
- updated docs if needed  
- confirmation that architecture boundaries remain intact  

Architectural direction is guided by **@DarekDGB**.  
Developers review implementation quality and CI health.

---

## 🧪 Testing

The test suite validates:

- PQC sign & verify  
- identity state transitions  
- encrypted storage  
- recovery flows  
- protocol handshakes  
- integration behaviour  

New features **must** include new tests.

---

## 📝 License

By contributing, you agree that your work is licensed under the MIT License.  
© 2025 **DarekDGB**
