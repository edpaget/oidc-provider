# Roadmap 06: Clojars Publishing

Sets up build tooling and CI for publishing oidc-provider (and potentially other libraries) to Clojars. No project in this monorepo currently publishes to Clojars.

Prerequisite: Roadmap 02 (Decouple authn) must be completed first so the library has no `local/root` dependencies.

## Phase 1: build.clj for oidc-provider

Create `oidc-provider/build.clj` using `tools.build`:

- Define `lib` as a group/artifact (e.g., `io.github.edwardpaget/oidc-provider` or a chosen group)
- `jar` task: `write-pom`, `copy-dir`, `jar` — produces a library JAR
- `install` task: installs to local Maven repo for testing
- All dependencies should be Maven coordinates (no `local/root` deps remain after Roadmap 02)

## Phase 2: POM metadata

Configure `pom.xml` generation with:
- SCM URL pointing to the monorepo
- License (choose one — EPL-2.0 is conventional for Clojure libs)
- Description
- Developer info

## Phase 3: Version management

Decide on versioning strategy:
- Use a `version` file or hardcode in `build.clj`
- Consider `0.1.0` as initial release
- Tag-based versioning for CI (e.g., `oidc-provider-v0.1.0`)

## Phase 4: Deploy task

Add a `deploy` task to `build.clj` using `slipset/deps-deploy` or `com.github.clojure/tools.build`'s deploy support:

```clojure
;; deps.edn alias
:deploy {:extra-deps {slipset/deps-deploy {:mvn/version "0.2.2"}}
         :exec-fn deps-deploy.deps-deploy/deploy
         :exec-args {:installer :remote :artifact "target/oidc-provider-0.1.0.jar"}}
```

Requires `CLOJARS_USERNAME` and `CLOJARS_PASSWORD` (deploy token) environment variables.

## Phase 5: CI integration

Add a GitHub Actions workflow (or equivalent) for:
- Running tests on PR
- Publishing to Clojars on tagged releases matching `oidc-provider-v*`
- Ensure the workflow handles the monorepo structure (only publish when oidc-provider changes)
