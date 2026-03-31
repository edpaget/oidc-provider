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
          merged))))

  (delete-client [_ client-id]
    (let [existed? (atom false)]
      (swap! clients (fn [m]
                       (reset! existed? (contains? m client-id))
                       (dissoc m client-id)))
      @existed?)))

(defn create-client-store
  "Creates an in-memory [[InMemoryClientStore]]. When called with an
  `initial-clients` vector, pre-populates the store with those client
  configurations keyed by `:client-id`."
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
  "Creates an in-memory [[InMemoryAuthorizationCodeStore]] backed by an atom."
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
  "Creates an in-memory [[InMemoryTokenStore]] with separate atoms for access
  tokens and refresh tokens."
  []
  (->InMemoryTokenStore (atom {}) (atom {})))

(defrecord ^{:doc "A [[proto/TokenStore]] decorator that SHA-256 hashes every token
  via [[oidc-provider.util/hash-token]] before delegating to `inner`, ensuring the
  backing store never holds plaintext token values."}
 HashingTokenStore [inner]
  proto/TokenStore
  (save-access-token [_ token user-id client-id scope expiry resource]
    (proto/save-access-token inner (util/hash-token token) user-id client-id scope expiry resource))
  (get-access-token [_ token]
    (proto/get-access-token inner (util/hash-token token)))
  (save-refresh-token [_ token user-id client-id scope expiry resource]
    (proto/save-refresh-token inner (util/hash-token token) user-id client-id scope expiry resource))
  (get-refresh-token [_ token]
    (proto/get-refresh-token inner (util/hash-token token)))
  (revoke-token [_ token]
    (proto/revoke-token inner (util/hash-token token))))

(defrecord ^{:doc "A [[proto/AuthorizationCodeStore]] decorator that SHA-256 hashes every
  authorization code via [[oidc-provider.util/hash-token]] before delegating to `inner`,
  ensuring the backing store never holds plaintext code values."}
 HashingAuthorizationCodeStore [inner]
  proto/AuthorizationCodeStore
  (save-authorization-code [_ code user-id client-id redirect-uri scope nonce expiry code-challenge code-challenge-method resource]
    (proto/save-authorization-code inner (util/hash-token code) user-id client-id redirect-uri scope nonce expiry code-challenge code-challenge-method resource))
  (get-authorization-code [_ code]
    (proto/get-authorization-code inner (util/hash-token code)))
  (delete-authorization-code [_ code]
    (proto/delete-authorization-code inner (util/hash-token code)))
  (consume-authorization-code [_ code]
    (proto/consume-authorization-code inner (util/hash-token code))))
