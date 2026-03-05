# Roadmap 02: Decouple authn Dependency

The oidc-provider library currently depends on `local/authn` and re-exports five symbols from `authn.protocol`: the `CredentialValidator` and `ClaimsProvider` protocols, `get-claims`, and two Malli schemas (`CredentialHash`, `Claims`). This coupling prevents independent publishing and forces consumers to pull in the entire `authn` library (which includes session management, Ring middleware, etc.) when they only need the provider.

The dependency surface is small — oidc-provider uses none of authn's session, middleware, or handler code. The fix is to define equivalent protocols directly in `oidc-provider.protocol` and remove the `authn` dependency entirely.

## Phase 1: Define native protocols in oidc-provider.protocol

Replace the re-exported vars with protocol definitions owned by oidc-provider:

- Define `ClaimsProvider` protocol with `get-claims [this user-id scope]` — returns a claims map for the given user and requested scopes. This is the only protocol actively called by the library (in `token_endpoint.clj`).
- Define the `Claims` Malli schema (currently `[:map-of :keyword :any]`) directly.
- Remove `CredentialValidator`, `CredentialHash`, and `validate-credentials` — these are stored in the `Provider` record but never actually called by any oidc-provider code path. The provider delegates authentication to the application layer before `authorize` is called, so there is no reason to require a credential validator.
- Remove the `(:require [authn.protocol :as authn])` import.

## Phase 2: Update core.clj Provider record and setup

- Remove `:credential-validator` from the `Provider` defrecord and `ProviderSetup` schema
- Keep `:claims-provider` and update its schema check to use the new `oidc-provider.protocol/ClaimsProvider`
- Update `create-provider` to no longer accept or wire a credential validator

## Phase 3: Update deps.edn

- Remove `local/authn {:local/root "../authn"}` from `oidc-provider/deps.edn`
- Verify the project compiles and all tests pass with no authn on the classpath

## Phase 4: Update tests

- Update `TestClaimsProvider` in `core_test.clj` to satisfy the new `oidc-provider.protocol/ClaimsProvider` protocol instead of `authn.protocol/ClaimsProvider`
- Remove any test references to `CredentialValidator` or `TestValidator`
- Verify all existing tests still pass
