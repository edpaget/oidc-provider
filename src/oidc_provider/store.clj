(ns oidc-provider.store
  "In-memory implementations of storage protocols for development and testing.

  Clients should use `:client-secret-hash` (via [[oidc-provider.util/hash-client-secret]])
  for credential storage."
  (:require
   [oidc-provider.protocol :as proto]
   [oidc-provider.util :as util]))

(set! *warn-on-reflection* true)

(defrecord InMemoryClientStore [clients]
  proto/ClientStore
  (get-client [_ client-id]
    (get @clients client-id))

  (register-client [_ client-config]
    (let [client-id (or (:client-id client-config)
                        (str (java.util.UUID/randomUUID)))
          client    (assoc client-config :client-id client-id)]
      (swap! clients assoc client-id client)
      client))

  (update-client [_ client-id updated-config]
    (let [existing (get @clients client-id)]
      (when existing
        (let [merged (-> (merge existing updated-config)
                         (assoc :client-id client-id))]
          (swap! clients assoc client-id merged)
          merged)))))

(defn create-client-store
  "Creates an in-memory client store.

  Args:
    initial-clients: Optional vector of client configurations to pre-populate

  Returns:
    InMemoryClientStore instance"
  ([]
   (create-client-store []))
  ([initial-clients]
   (let [clients-map (into {} (map (fn [c] [(:client-id c) c])) initial-clients)]
     (->InMemoryClientStore (atom clients-map)))))

(defrecord InMemoryAuthorizationCodeStore [codes]
  proto/AuthorizationCodeStore
  (save-authorization-code [_ code user-id client-id redirect-uri scope nonce expiry code-challenge code-challenge-method resource]
    (swap! codes assoc code (cond-> {:user-id      user-id
                                     :client-id    client-id
                                     :redirect-uri redirect-uri
                                     :scope        scope
                                     :nonce        nonce
                                     :expiry       expiry}
                              code-challenge        (assoc :code-challenge code-challenge)
                              code-challenge-method (assoc :code-challenge-method code-challenge-method)
                              resource              (assoc :resource resource)))
    true)

  (get-authorization-code [_ code]
    (get @codes code))

  (delete-authorization-code [_ code]
    (swap! codes dissoc code)
    true)

  (consume-authorization-code [_ code]
    (let [result (atom nil)]
      (swap! codes (fn [m]
                     (reset! result (get m code))
                     (dissoc m code)))
      @result)))

(defn create-authorization-code-store
  "Creates an in-memory authorization code store.

  Returns:
    InMemoryAuthorizationCodeStore instance"
  []
  (->InMemoryAuthorizationCodeStore (atom {})))

(defrecord InMemoryTokenStore [access-tokens refresh-tokens]
  proto/TokenStore
  (save-access-token [_ token user-id client-id scope expiry resource]
    (swap! access-tokens assoc token (cond-> {:user-id   user-id
                                              :client-id client-id
                                              :scope     scope
                                              :expiry    expiry}
                                       resource (assoc :resource resource)))
    true)

  (get-access-token [_ token]
    (get @access-tokens token))

  (save-refresh-token [_ token user-id client-id scope expiry resource]
    (swap! refresh-tokens assoc token (cond-> {:user-id   user-id
                                               :client-id client-id
                                               :scope     scope}
                                        expiry   (assoc :expiry expiry)
                                        resource (assoc :resource resource)))
    true)

  (get-refresh-token [_ token]
    (get @refresh-tokens token))

  (revoke-token [_ token]
    (swap! access-tokens dissoc token)
    (swap! refresh-tokens dissoc token)
    true))

(defn create-token-store
  "Creates an in-memory token store.

  Returns:
    InMemoryTokenStore instance"
  []
  (->InMemoryTokenStore (atom {}) (atom {})))

;; ---------------------------------------------------------------------------
;; Hashing wrapper functions
;;
;; These hash the token/code with SHA-256 before delegating to the protocol,
;; ensuring every store implementation receives hashed keys rather than
;; plaintext secrets.
;; ---------------------------------------------------------------------------

(defn save-access-token
  "Hashes `token` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/save-access-token]]."
  [store token user-id client-id scope expiry resource]
  (proto/save-access-token store (util/hash-token token) user-id client-id scope expiry resource))

(defn get-access-token
  "Hashes `token` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/get-access-token]]."
  [store token]
  (proto/get-access-token store (util/hash-token token)))

(defn save-refresh-token
  "Hashes `token` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/save-refresh-token]]."
  [store token user-id client-id scope expiry resource]
  (proto/save-refresh-token store (util/hash-token token) user-id client-id scope expiry resource))

(defn get-refresh-token
  "Hashes `token` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/get-refresh-token]]."
  [store token]
  (proto/get-refresh-token store (util/hash-token token)))

(defn revoke-token
  "Hashes `token` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/revoke-token]]."
  [store token]
  (proto/revoke-token store (util/hash-token token)))

(defn save-authorization-code
  "Hashes `code` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/save-authorization-code]]."
  [store code user-id client-id redirect-uri scope nonce expiry code-challenge code-challenge-method resource]
  (proto/save-authorization-code store (util/hash-token code) user-id client-id redirect-uri scope nonce expiry code-challenge code-challenge-method resource))

(defn get-authorization-code
  "Hashes `code` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/get-authorization-code]]."
  [store code]
  (proto/get-authorization-code store (util/hash-token code)))

(defn delete-authorization-code
  "Hashes `code` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/delete-authorization-code]]."
  [store code]
  (proto/delete-authorization-code store (util/hash-token code)))

(defn consume-authorization-code
  "Hashes `code` with SHA-256 via [[util/hash-token]] then delegates to
  [[proto/consume-authorization-code]]."
  [store code]
  (proto/consume-authorization-code store (util/hash-token code)))
