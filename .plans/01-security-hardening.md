# Roadmap 01: Security Hardening (Remaining)

Phases 1-5 completed. One phase remains.

## Phase 6: Client secret hashing guidance

Add a `hash-client-secret` utility function using `buddy-hashers` or `MessageDigest` for production use, and update `authenticate-client` to support hashed secrets via a `:client-secret-hash` field as an alternative to plaintext `:client-secret`. Document that the in-memory store with plaintext secrets is for development only.
