# CONTRIBUTING

## DigiByte Q-ID — v1.0.1

---

## 🧭 Contribution Philosophy

This is a **security-critical repository**.

Contributions are welcome, but must follow strict rules:

- Deterministic behavior only
- Fail-closed logic
- No silent fallback
- No hidden side effects
- Tests define truth

If unsure → do not assume → ask.

---

## 🔒 Core Rules (Non-Negotiable)

### 1. Fail-Closed Only
- Any invalid state MUST return failure
- Never auto-correct or recover silently

### 2. Deterministic Canonicalization
- Always use:

    qid.canonical.canonical_json_bytes

- Never introduce custom JSON serialization

### 3. No Silent Fallback
- If backend / dependency missing → FAIL
- Never fallback automatically

### 4. Hybrid = AND
- ML-DSA AND Falcon must both verify
- No OR logic allowed

---

## 🧪 Testing Requirements

Every change MUST:

- Maintain **100% coverage**
- Include regression tests
- Include negative (failure) tests
- Pass CI with zero warnings

If coverage drops → PR rejected

---

## 🧱 Code Standards

- No global state
- Explicit inputs only
- Explicit outputs only
- No hidden mutation
- Type-safe functions

---

## 📦 Allowed Changes

- Bug fixes (with regression test)
- Documentation improvements
- Test improvements
- Hardening (non-breaking)

---

## 🚫 Forbidden Changes

- Silent behavior changes
- Partial validation
- Optional failure paths
- Changing canonicalization rules
- Reducing test coverage

---

## 🔄 Pull Request Process

1. Fork repo
2. Create branch
3. Implement change
4. Add tests
5. Run CI locally (if possible)
6. Submit PR

PR must include:

- clear description
- reasoning
- test proof

---

## 🛡️ Review Standard

All PRs are reviewed with:

- security-first mindset
- fail-closed enforcement
- determinism verification
- test coverage validation

---

## 📢 Questions / Contact

For questions or coordination:

📧 adamantinewalletos@gmail.com

---

## 🧠 Final Principle

Do not guess.  
Do not assume.  
Do not weaken invariants.

Only build what can be verified.

---

© DarekDGB
