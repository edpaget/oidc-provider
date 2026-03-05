(ns oidc-provider.store
  "In-memory implementations of storage protocols for development and testing."
  (:require
   [oidc-provider.protocol :as proto]))

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
      client)))

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
  (save-authorization-code [_ code user-id client-id redirect-uri scope nonce expiry]
    (swap! codes assoc code {:user-id user-id
                             :client-id client-id
                             :redirect-uri redirect-uri
                             :scope scope
                             :nonce nonce
                             :expiry expiry})
    true)

  (get-authorization-code [_ code]
    (get @codes code))

  (delete-authorization-code [_ code]
    (swap! codes dissoc code)
    true))

(defn create-authorization-code-store
  "Creates an in-memory authorization code store.

  Returns:
    InMemoryAuthorizationCodeStore instance"
  []
  (->InMemoryAuthorizationCodeStore (atom {})))

(defrecord InMemoryTokenStore [access-tokens refresh-tokens]
  proto/TokenStore
  (save-access-token [_ token user-id client-id scope expiry]
    (swap! access-tokens assoc token {:user-id user-id
                                      :client-id client-id
                                      :scope scope
                                      :expiry expiry})
    true)

  (get-access-token [_ token]
    (get @access-tokens token))

  (save-refresh-token [_ token user-id client-id scope]
    (swap! refresh-tokens assoc token {:user-id user-id
                                       :client-id client-id
                                       :scope scope})
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
