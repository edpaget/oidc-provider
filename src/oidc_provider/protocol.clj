(ns oidc-provider.protocol
  "Core protocols and schemas for OIDC provider extensibility.

  Defines the [[ClaimsProvider]] protocol for supplying user claims to ID tokens,
  along with storage protocols ([[ClientStore]], [[AuthorizationCodeStore]],
  [[TokenStore]]) for pluggable persistence."
  (:require
   [malli.util :as mu]))

(set! *warn-on-reflection* true)

(defprotocol ClaimsProvider
  "Provides user claims for ID token generation.

  Implementations supply the claims map included in ID tokens based on the
  authenticated user and the requested scopes."
  (get-claims [this user-id scope]
    "Returns a claims map for the given `user-id` and `scope` vector.

    The returned map must include at minimum `:sub`. Additional claims such as
    `:name`, `:email`, etc. should be included based on the requested scopes."))

(def Claims
  "Malli schema for a claims map."
  [:map-of :keyword :any])

(def ClientConfig
  "Malli schema for OAuth2/OIDC client configuration.

  The optional `:default-resource` field provides audience binding for access tokens
  when the request omits a `resource` parameter (RFC 8707). When set, tokens issued
  for this client will be scoped to the given resource URIs by default. An explicit
  `resource` parameter in the request overrides this default."
  [:map
   [:client-id :string]
   [:client-type [:enum "confidential" "public"]]
   [:client-secret-hash {:optional true} :string]
   [:redirect-uris [:vector :string]]
   [:grant-types [:vector [:enum "authorization_code" "refresh_token" "client_credentials"]]]
   [:response-types [:vector [:enum "code" "token" "id_token"]]]
   [:scopes [:vector :string]]
   [:token-endpoint-auth-method {:optional true}
    [:enum "client_secret_basic" "client_secret_post" "none"]]
   [:default-resource {:optional true} [:vector {:min 1} :string]]
   [:client-name {:optional true} :string]
   [:client-uri {:optional true} :string]
   [:logo-uri {:optional true} :string]
   [:contacts {:optional true} [:vector :string]]
   [:registration-access-token {:optional true} :string]])

(def ClientRegistration
  "Malli schema for client registration input.

  Derived from [[ClientConfig]] with `:client-id` made optional, since the store
  may auto-generate one during registration."
  (mu/optional-keys ClientConfig [:client-id]))

(defprotocol ClientStore
  "Protocol for managing OAuth2/OIDC client registrations."
  (get-client [this client-id]
    "Retrieves client configuration by client-id.

    Takes an OAuth2 client identifier and looks up the client configuration. Returns
    the client configuration map matching the ClientConfig schema if found, or nil if
    the client doesn't exist.")

  (register-client [this client-config]
    "Registers a new client.

    Takes a client configuration map matching the ClientConfig schema. Stores the client
    and generates a client-id if one isn't provided. Returns the registered client
    configuration including the client-id.")

  (update-client [this client-id updated-config]
    "Updates an existing client's configuration.

    Merges `updated-config` into the existing client config for `client-id`, preserving
    fields not present in `updated-config`. Returns the updated client config, or nil
    if the client does not exist.")

  (delete-client [this client-id]
    "Removes a client registration by `client-id`.

    Returns true if the client existed and was removed, false if the client was
    not found."))

(defprotocol AuthorizationCodeStore
  "Protocol for storing and retrieving authorization codes.

  Wrap the backing store with [[oidc-provider.store/HashingAuthorizationCodeStore]]
  to transparently SHA-256 hash codes before delegation, ensuring every
  implementation stores hashed keys rather than plaintext codes."
  (save-authorization-code [this code user-id client-id redirect-uri scope nonce expiry code-challenge code-challenge-method resource]
    "Saves an authorization code with associated metadata.

    Takes an authorization code string, user identifier, OAuth2 client identifier,
    the redirect URI from the authorization request, a vector of scope strings, an
    optional nonce for replay protection, an expiration timestamp (milliseconds
    since epoch), optional PKCE `code-challenge` and `code-challenge-method`
    strings, and an optional `resource` vector of target resource indicator URIs
    (per RFC 8707). Stores the code and metadata. Returns true if saved successfully.")

  (get-authorization-code [this code]
    "Retrieves authorization code metadata.

    Takes an authorization code string and looks up its associated metadata. Returns
    a map with keys `[:user-id :client-id :redirect-uri :scope :nonce :expiry]`
    and optionally `:code-challenge`, `:code-challenge-method`, and `:resource`
    if found, or nil if the code doesn't exist or has been deleted.")

  (delete-authorization-code [this code]
    "Deletes an authorization code.

    Takes an authorization code string and removes it from storage. Authorization codes
    are single-use, so they should be deleted after being exchanged for tokens. Returns
    true if deleted successfully.")

  (consume-authorization-code [this code]
    "Atomically retrieves and deletes an authorization code.

    Takes an authorization code string, removes it from storage, and returns its
    metadata map. If the code does not exist (or has already been consumed), returns
    `nil`. This prevents replay attacks where concurrent requests could both read the
    same code before either deletes it.")

  (mark-code-exchanged [this code access-token refresh-token]
    "Records that an authorization code was exchanged for tokens.

    Takes the authorization code, the issued access token string, and an optional
    refresh token string (may be `nil`). Stores a record associating the code with
    its issued tokens so that replay detection can revoke them per RFC 6749 §10.5.
    Returns true if recorded successfully.")

  (get-code-tokens [this code]
    "Retrieves the tokens issued for a previously consumed authorization code.

    Takes an authorization code string and returns a map with `:access-token` and
    optionally `:refresh-token` if the code was previously exchanged, or `nil` if
    no record exists."))

(defprotocol TokenStore
  "Protocol for managing access and refresh tokens.

  Wrap the backing store with [[oidc-provider.store/HashingTokenStore]]
  to transparently SHA-256 hash tokens before delegation, ensuring every
  implementation stores hashed keys rather than plaintext secrets."
  (save-access-token [this token user-id client-id scope expiry resource]
    "Saves an access token.

    Takes an access token string, user identifier, OAuth2 client identifier, a vector
    of scope strings, an expiration timestamp (milliseconds since epoch), and an optional
    `resource` vector of target resource indicator URIs (per RFC 8707). Stores the token
    and its metadata. Returns true if saved successfully.")

  (get-access-token [this token]
    "Retrieves access token metadata.

    Takes an access token string and looks up its associated metadata. Returns a map
    with keys `[:user-id :client-id :scope :expiry]` if found, or nil if the token
    doesn't exist or has been revoked.")

  (save-refresh-token [this token user-id client-id scope expiry resource]
    "Saves a refresh token.

    Takes a refresh token string, user identifier, OAuth2 client identifier, a vector
    of scope strings, an optional expiration timestamp (milliseconds since epoch, or
    `nil` for no expiry), and an optional `resource` vector of target resource indicator
    URIs (per RFC 8707). Stores the token and its metadata. Returns true if saved
    successfully.")

  (get-refresh-token [this token]
    "Retrieves refresh token metadata.

    Takes a refresh token string and looks up its associated metadata. Returns a map
    with keys `[:user-id :client-id :scope]` if found, or nil if the token doesn't
    exist or has been revoked.")

  (revoke-token [this token]
    "Revokes a token.

    Takes a token string (either access or refresh token) and revokes it, preventing
    it from being used in future requests. Returns true if revoked successfully."))

(defn validate-resource-indicators
  "Validates that each resource indicator is an absolute URI without a fragment component per RFC 8707.

  Takes a vector of resource URI strings. Throws `ex-info` with `{:error \"invalid_target\"}`
  if any URI is not absolute or contains a fragment."
  [resources]
  (doseq [r resources]
    (let [uri (java.net.URI. r)]
      (when (or (not (.isAbsolute uri))
                (.getFragment uri))
        (throw (ex-info "Invalid resource indicator"
                        {:error "invalid_target" :resource r}))))))
