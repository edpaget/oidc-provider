# Roadmap 01: Security Hardening (Remaining)

Phases 1-4 completed. Two phases remain.

## Phase 5: Remove unused dependencies

`buddy/buddy-sign`, `buddy/buddy-core`, and `ring/ring-core` are declared in `deps.edn` but never imported. Remove them to reduce the dependency surface.

## Phase 6: Client secret hashing guidance

Add a `hash-client-secret` utility function using `buddy-hashers` or `MessageDigest` for production use, and update `authenticate-client` to support hashed secrets via a `:client-secret-hash` field as an alternative to plaintext `:client-secret`. Document that the in-memory store with plaintext secrets is for development only.
