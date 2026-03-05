(ns oidc-provider.protocol
  "Core protocols for OIDC provider extensibility.

  For authentication protocols ([[authn.protocol/CredentialValidator]] and
  [[authn.protocol/ClaimsProvider]]), see the authn package."
  (:require
   [authn.protocol :as authn]))

(set! *warn-on-reflection* true)

(def CredentialValidator
  "Re-exported from [[authn.protocol/CredentialValidator]]."
  authn/CredentialValidator)

(def ClaimsProvider
  "Re-exported from [[authn.protocol/ClaimsProvider]]."
  authn/ClaimsProvider)

(def get-claims
  "Re-exported from [[authn.protocol/get-claims]]."
  authn/get-claims)

(def CredentialHash
  "Re-exported from [[authn.protocol/CredentialHash]]."
  authn/CredentialHash)

(def Claims
  "Re-exported from [[authn.protocol/Claims]]."
  authn/Claims)

(def ClientConfig
  "Malli schema for OAuth2/OIDC client configuration."
  [:map
   [:client-id :string]
   [:client-secret {:optional true} :string]
   [:redirect-uris [:vector :string]]
   [:grant-types [:vector [:enum "authorization_code" "refresh_token" "client_credentials"]]]
   [:response-types [:vector [:enum "code" "token" "id_token"]]]
   [:scopes [:vector :string]]
   [:token-endpoint-auth-method {:optional true}
    [:enum "client_secret_basic" "client_secret_post" "none"]]])

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
    configuration including the client-id."))

(defprotocol AuthorizationCodeStore
  "Protocol for storing and retrieving authorization codes."
  (save-authorization-code [this code user-id client-id redirect-uri scope nonce expiry]
    "Saves an authorization code with associated metadata.

    Takes an authorization code string, user identifier, OAuth2 client identifier,
    the redirect URI from the authorization request, a vector of scope strings, an
    optional nonce for replay protection, and an expiration timestamp (milliseconds
    since epoch). Stores the code and metadata. Returns true if saved successfully.")

  (get-authorization-code [this code]
    "Retrieves authorization code metadata.

    Takes an authorization code string and looks up its associated metadata. Returns
    a map with keys `[:user-id :client-id :redirect-uri :scope :nonce :expiry]` if
    found, or nil if the code doesn't exist or has been deleted.")

  (delete-authorization-code [this code]
    "Deletes an authorization code.

    Takes an authorization code string and removes it from storage. Authorization codes
    are single-use, so they should be deleted after being exchanged for tokens. Returns
    true if deleted successfully."))

(defprotocol TokenStore
  "Protocol for managing access and refresh tokens."
  (save-access-token [this token user-id client-id scope expiry]
    "Saves an access token.

    Takes an access token string, user identifier, OAuth2 client identifier, a vector
    of scope strings, and an expiration timestamp (milliseconds since epoch). Stores
    the token and its metadata. Returns true if saved successfully.")

  (get-access-token [this token]
    "Retrieves access token metadata.

    Takes an access token string and looks up its associated metadata. Returns a map
    with keys `[:user-id :client-id :scope :expiry]` if found, or nil if the token
    doesn't exist or has been revoked.")

  (save-refresh-token [this token user-id client-id scope]
    "Saves a refresh token.

    Takes a refresh token string, user identifier, OAuth2 client identifier, and a
    vector of scope strings. Stores the token and its metadata. Refresh tokens don't
    expire automatically. Returns true if saved successfully.")

  (get-refresh-token [this token]
    "Retrieves refresh token metadata.

    Takes a refresh token string and looks up its associated metadata. Returns a map
    with keys `[:user-id :client-id :scope]` if found, or nil if the token doesn't
    exist or has been revoked.")

  (revoke-token [this token]
    "Revokes a token.

    Takes a token string (either access or refresh token) and revokes it, preventing
    it from being used in future requests. Returns true if revoked successfully."))
