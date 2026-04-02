(ns oidc-provider.error
  "Error type hierarchy for classifying OAuth2/OIDC errors.

  Defines a keyword hierarchy using `derive` so that Ring handlers can dispatch
  on `(:type (ex-data e))` via `isa?` rather than matching on exception message
  strings. All domain-layer `ex-info` throws should include a `:type` key drawn
  from this hierarchy."
  (:refer-clojure :exclude [type]))

(def hierarchy
  "Keyword hierarchy for OAuth2/OIDC error types.

  `::request-error` covers client-side request problems (400-level).
  `::auth-error` covers authentication/authorization failures (401-level)."
  (-> (make-hierarchy)
      (derive ::invalid-request ::request-error)
      (derive ::invalid-grant ::request-error)
      (derive ::invalid-client-metadata ::request-error)
      (derive ::unsupported-grant-type ::request-error)
      (derive ::unsupported-response-type ::request-error)
      (derive ::invalid-scope ::request-error)
      (derive ::invalid-target ::request-error)
      (derive ::invalid-client ::auth-error)
      (derive ::invalid-token ::auth-error)))

(defn request-error?
  "Returns true when `type` is a request error (400-level) in the hierarchy."
  [type]
  (isa? hierarchy type ::request-error))

(defn auth-error?
  "Returns true when `type` is an authentication error (401-level) in the hierarchy."
  [type]
  (isa? hierarchy type ::auth-error))
