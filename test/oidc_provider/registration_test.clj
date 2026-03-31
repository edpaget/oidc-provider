(ns oidc-provider.registration-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.protocol :as proto]
   [oidc-provider.registration :as reg]
   [oidc-provider.store :as store]
   [oidc-provider.util :as util])
  (:import
   (java.time Clock Instant ZoneOffset)))

(deftest register-minimal-client-test
  (testing "applies RFC 7591 defaults for a minimal registration request"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)]
      (is (= ["authorization_code"] (:grant_types response)))
      (is (= ["code"] (:response_types response)))
      (is (= "client_secret_basic" (:token_endpoint_auth_method response)))
      (is (string? (:client_secret response))))))

(deftest registered-client-retrievable-test
  (testing "registered client is retrievable from the store"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id response)
          stored       (proto/get-client client-store client-id)]
      (is (= client-id (:client-id stored))))))

(deftest register-confidential-client-test
  (testing "client_secret_basic auth method generates a secret and stores its hash"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris              ["https://app.example.com/callback"]
                         :token_endpoint_auth_method "client_secret_basic"}
                        client-store)
          client-id    (:client_id response)
          stored       (proto/get-client client-store client-id)]
      (is (nil? (:client-secret stored)))
      (is (util/verify-client-secret (:client_secret response) (:client-secret-hash stored))))))

(deftest registration-access-token-test
  (testing "response token is plaintext, stored value is a PBKDF2 hash that verifies"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id response)
          stored       (proto/get-client client-store client-id)
          plaintext    (:registration_access_token response)]
      (is (str/starts-with? (:registration-access-token stored) "PBKDF2"))
      (is (util/verify-client-secret plaintext (:registration-access-token stored))))))

(deftest register-with-custom-metadata-test
  (testing "client_name and scope are preserved in response"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]
                         :client_name   "My App"
                         :scope         "openid profile"}
                        client-store)]
      (is (= "My App" (:client_name response)))
      (is (= "openid profile" (:scope response))))))

(deftest register-missing-redirect-uris-test
  (testing "throws invalid_client_metadata when redirect_uris is missing"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {}
                           (store/create-client-store))))))

(deftest register-empty-redirect-uris-test
  (testing "throws invalid_client_metadata when redirect_uris is empty"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris []}
                           (store/create-client-store))))))

(deftest register-invalid-grant-type-test
  (testing "throws invalid_client_metadata for unsupported grant type"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris ["https://app.example.com/callback"]
                            :grant_types   ["implicit"]}
                           (store/create-client-store))))))

(deftest register-http-localhost-redirect-test
  (testing "http://localhost redirect URI is accepted for native clients"
    (let [response (reg/handle-registration-request
                    {:redirect_uris    ["http://localhost:3000/callback"]
                     :application_type "native"}
                    (store/create-client-store))]
      (is (= ["http://localhost:3000/callback"] (:redirect_uris response))))))

(deftest register-http-127-redirect-test
  (testing "http://127.0.0.1 redirect URI is accepted for native clients"
    (let [response (reg/handle-registration-request
                    {:redirect_uris    ["http://127.0.0.1:8080/callback"]
                     :application_type "native"}
                    (store/create-client-store))]
      (is (= ["http://127.0.0.1:8080/callback"] (:redirect_uris response))))))

(deftest register-https-redirect-test
  (testing "https redirect URI is accepted"
    (let [response (reg/handle-registration-request
                    {:redirect_uris ["https://app.example.com/callback"]}
                    (store/create-client-store))]
      (is (= ["https://app.example.com/callback"] (:redirect_uris response))))))

(deftest register-http-non-localhost-test
  (testing "throws invalid_client_metadata for http URI on non-localhost host"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris ["http://evil.example.com/callback"]}
                           (store/create-client-store))))))

(deftest register-invalid-uri-test
  (testing "throws invalid_client_metadata for malformed URI"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris ["not a uri"]}
                           (store/create-client-store))))))

(deftest register-relative-uri-test
  (testing "throws invalid_client_metadata for relative URI"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris ["/callback"]}
                           (store/create-client-store))))))

(deftest register-inconsistent-grant-response-test
  (testing "throws invalid_client_metadata when grant_types and response_types are inconsistent"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris  ["https://app.example.com/callback"]
                            :grant_types    ["authorization_code"]
                            :response_types ["token"]}
                           (store/create-client-store))))))

(deftest register-with-extended-metadata-test
  (testing "client_uri, logo_uri, and contacts are preserved in response"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]
                         :client_uri    "https://example.com"
                         :logo_uri      "https://example.com/logo.png"
                         :contacts      ["admin@example.com"]}
                        client-store)]
      (is (= "https://example.com" (:client_uri response)))
      (is (= "https://example.com/logo.png" (:logo_uri response)))
      (is (= ["admin@example.com"] (:contacts response))))))

(deftest register-validates-client-uri-test
  (testing "throws invalid_client_metadata for non-HTTPS client_uri"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris ["https://app.example.com/callback"]
                            :client_uri    "http://example.com"}
                           (store/create-client-store))))))

(deftest register-validates-logo-uri-test
  (testing "throws invalid_client_metadata for non-HTTPS logo_uri"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris ["https://app.example.com/callback"]
                            :logo_uri      "not-a-uri"}
                           (store/create-client-store))))))

(deftest register-public-client-type-test
  (testing "auth method none sets client-type to public in store"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris              ["https://app.example.com/callback"]
                         :token_endpoint_auth_method "none"}
                        client-store)
          client-id    (:client_id response)
          stored       (proto/get-client client-store client-id)]
      (is (= "public" (:client-type stored))))))

(deftest register-confidential-client-type-test
  (testing "auth method client_secret_basic sets client-type to confidential in store"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris              ["https://app.example.com/callback"]
                         :token_endpoint_auth_method "client_secret_basic"}
                        client-store)
          client-id    (:client_id response)
          stored       (proto/get-client client-store client-id)]
      (is (= "confidential" (:client-type stored))))))

(deftest register-confidential-client-type-post-test
  (testing "auth method client_secret_post sets client-type to confidential in store"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {:redirect_uris              ["https://app.example.com/callback"]
                         :token_endpoint_auth_method "client_secret_post"}
                        client-store)
          client-id    (:client_id response)
          stored       (proto/get-client client-store client-id)]
      (is (= "confidential" (:client-type stored))))))

(deftest client-read-does-not-expose-registration-token-test
  (testing "handle-client-read response does not contain registration_access_token"
    (let [client-store (store/create-client-store)
          reg-response (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id reg-response)
          token        (:registration_access_token reg-response)
          read-result  (reg/handle-client-read client-store client-id token)]
      (is (not (contains? read-result :registration_access_token))))))

(deftest client-read-success-test
  (testing "reads back client configuration with valid token"
    (let [client-store (store/create-client-store)
          reg-response (reg/handle-registration-request
                        {:redirect_uris              ["https://app.example.com/callback"]
                         :client_name                "My App"
                         :scope                      "openid profile"
                         :token_endpoint_auth_method "none"}
                        client-store)
          client-id    (:client_id reg-response)
          token        (:registration_access_token reg-response)
          read-result  (reg/handle-client-read client-store client-id token)]
      (is (= (dissoc reg-response :registration_access_token :client_id_issued_at)
             read-result)))))

(deftest client-read-invalid-token-test
  (testing "throws invalid_token when token does not match"
    (let [client-store (store/create-client-store)
          reg-response (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id reg-response)]
      (is (thrown-with-msg? Exception #"invalid_token"
                            (reg/handle-client-read client-store client-id "wrong-token"))))))

(deftest client-read-unknown-client-test
  (testing "throws invalid_token for nonexistent client_id"
    (is (thrown-with-msg? Exception #"invalid_token"
                          (reg/handle-client-read (store/create-client-store)
                                                  "nonexistent-id" "any-token")))))

(deftest register-native-client-custom-scheme-test
  (testing "native client with custom URI scheme succeeds"
    (let [response (reg/handle-registration-request
                    {:redirect_uris    ["cursor://callback"]
                     :application_type "native"}
                    (store/create-client-store))]
      (is (= ["cursor://callback"] (:redirect_uris response)))
      (is (= "native" (:application_type response))))))

(deftest register-native-client-loopback-test
  (testing "native client with HTTP loopback URI succeeds"
    (let [response (reg/handle-registration-request
                    {:redirect_uris    ["http://localhost:9090/callback"]
                     :application_type "native"}
                    (store/create-client-store))]
      (is (= ["http://localhost:9090/callback"] (:redirect_uris response))))))

(deftest register-web-client-rejects-loopback-test
  (testing "web client (default) rejects HTTP loopback URI"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris ["http://localhost:3000/callback"]}
                           (store/create-client-store))))))

(deftest register-web-client-rejects-custom-scheme-test
  (testing "web client rejects custom URI scheme"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris    ["cursor://callback"]
                            :application_type "web"}
                           (store/create-client-store))))))

(deftest register-native-client-rejects-fragment-test
  (testing "native client rejects custom scheme URI with fragment"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {:redirect_uris    ["cursor://callback#frag"]
                            :application_type "native"}
                           (store/create-client-store))))))

(deftest register-defaults-application-type-to-web-test
  (testing "omitting application_type defaults to web in response"
    (let [response (reg/handle-registration-request
                    {:redirect_uris ["https://app.example.com/callback"]}
                    (store/create-client-store))]
      (is (= "web" (:application_type response))))))

(deftest response-includes-client-secret-expires-at-test
  (testing "client_secret_expires_at is 0 when client_secret is issued"
    (let [response (reg/handle-registration-request
                    {:redirect_uris              ["https://app.example.com/callback"]
                     :token_endpoint_auth_method "client_secret_basic"}
                    (store/create-client-store))]
      (is (= 0 (:client_secret_expires_at response))))))

(deftest response-omits-client-secret-expires-at-for-public-test
  (testing "client_secret_expires_at is absent for public clients"
    (let [response (reg/handle-registration-request
                    {:redirect_uris              ["https://app.example.com/callback"]
                     :token_endpoint_auth_method "none"}
                    (store/create-client-store))]
      (is (nil? (:client_secret_expires_at response))))))

(deftest response-includes-client-id-issued-at-test
  (testing "client_id_issued_at is epoch seconds from provided clock"
    (let [fixed-instant (Instant/parse "2026-01-15T12:00:00Z")
          clock         (Clock/fixed fixed-instant ZoneOffset/UTC)
          response      (reg/handle-registration-request
                         {:redirect_uris ["https://app.example.com/callback"]}
                         (store/create-client-store)
                         {:clock clock})]
      (is (= (.getEpochSecond fixed-instant) (:client_id_issued_at response))))))

(deftest registration-client-uri-included-test
  (testing "registration_client_uri is included when registration-endpoint is configured"
    (let [response (reg/handle-registration-request
                    {:redirect_uris ["https://app.example.com/callback"]}
                    (store/create-client-store)
                    {:registration-endpoint "https://op.example.com/register"})]
      (is (= (str "https://op.example.com/register/" (:client_id response))
             (:registration_client_uri response))))))

(deftest registration-client-uri-omitted-test
  (testing "registration_client_uri is absent when registration-endpoint is not configured"
    (let [response (reg/handle-registration-request
                    {:redirect_uris ["https://app.example.com/callback"]}
                    (store/create-client-store))]
      (is (nil? (:registration_client_uri response))))))

(deftest explicit-none-produces-public-client-test
  (testing "explicitly requesting none produces a public client with no secret"
    (let [response (reg/handle-registration-request
                    {:redirect_uris              ["https://app.example.com/callback"]
                     :token_endpoint_auth_method "none"}
                    (store/create-client-store))]
      (is (= "none" (:token_endpoint_auth_method response)))
      (is (nil? (:client_secret response))))))

;; ---------------------------------------------------------------------------
;; Client update tests (RFC 7592 §2.2)
;; ---------------------------------------------------------------------------

(defn- register-test-client
  "Registers a client and returns [client-store reg-response]."
  ([]
   (register-test-client {}))
  ([extra-request]
   (let [client-store (store/create-client-store)
         response     (reg/handle-registration-request
                       (merge {:redirect_uris ["https://app.example.com/callback"]}
                              extra-request)
                       client-store)]
     [client-store response])))

(deftest handle-client-update-success-test
  (testing "updates client metadata and returns updated config"
    (let [[store reg] (register-test-client)
          client-id   (:client_id reg)
          token       (:registration_access_token reg)
          result      (reg/handle-client-update
                       store client-id token
                       {:redirect_uris ["https://new.example.com/callback"]})]
      (is (= ["https://new.example.com/callback"] (:redirect_uris result)))
      (is (= client-id (:client_id result))))))

(deftest handle-client-update-invalid-token-test
  (testing "throws invalid_token when token does not match"
    (let [[store reg] (register-test-client)
          client-id   (:client_id reg)]
      (is (thrown-with-msg? Exception #"invalid_token"
                            (reg/handle-client-update
                             store client-id "wrong-token"
                             {:redirect_uris ["https://new.example.com/callback"]}))))))

(deftest handle-client-update-invalid-metadata-test
  (testing "throws invalid_client_metadata for invalid redirect URI"
    (let [[store reg] (register-test-client)
          client-id   (:client_id reg)
          token       (:registration_access_token reg)]
      (is (thrown-with-msg? Exception #"invalid_client_metadata"
                            (reg/handle-client-update
                             store client-id token
                             {:redirect_uris ["not-a-url"]}))))))

(deftest handle-client-update-preserves-credentials-test
  (testing "update preserves client_id, client_secret, and registration_access_token"
    (let [[store reg] (register-test-client)
          client-id   (:client_id reg)
          token       (:registration_access_token reg)
          _           (reg/handle-client-update
                       store client-id token
                       {:redirect_uris ["https://new.example.com/callback"]})
          stored      (proto/get-client store client-id)]
      (is (= client-id (:client-id stored)))
      (is (util/verify-client-secret token (:registration-access-token stored)))
      (is (some? (:client-secret-hash stored))))))

(deftest handle-client-update-replaces-metadata-test
  (testing "update replaces all mutable metadata fields"
    (let [[store reg] (register-test-client {:client_name "Original"
                                             :scope       "openid"})
          client-id   (:client_id reg)
          token       (:registration_access_token reg)
          result      (reg/handle-client-update
                       store client-id token
                       {:redirect_uris ["https://new.example.com/callback"]
                        :client_name   "Updated"
                        :scope         "openid profile"})]
      (is (= "Updated" (:client_name result)))
      (is (= "openid profile" (:scope result))))))

;; ---------------------------------------------------------------------------
;; Client delete tests (RFC 7592 §2.3)
;; ---------------------------------------------------------------------------

(deftest handle-client-delete-success-test
  (testing "deletes client and subsequent read throws invalid_token"
    (let [[store reg] (register-test-client)
          client-id   (:client_id reg)
          token       (:registration_access_token reg)]
      (is (nil? (reg/handle-client-delete store client-id token)))
      (is (thrown-with-msg? Exception #"invalid_token"
                            (reg/handle-client-read store client-id token))))))

(deftest handle-client-delete-invalid-token-test
  (testing "throws invalid_token when token does not match"
    (let [[store reg] (register-test-client)
          client-id   (:client_id reg)]
      (is (thrown-with-msg? Exception #"invalid_token"
                            (reg/handle-client-delete store client-id "wrong-token"))))))

(deftest handle-client-delete-already-deleted-test
  (testing "throws invalid_token when client was already deleted"
    (let [[store reg] (register-test-client)
          client-id   (:client_id reg)
          token       (:registration_access_token reg)]
      (reg/handle-client-delete store client-id token)
      (is (thrown-with-msg? Exception #"invalid_token"
                            (reg/handle-client-delete store client-id token))))))

(deftest handle-client-update-changes-auth-method-test
  (testing "updating to auth method none clears client-secret-hash"
    (let [[store reg] (register-test-client {:token_endpoint_auth_method "client_secret_basic"})
          client-id   (:client_id reg)
          token       (:registration_access_token reg)
          result      (reg/handle-client-update
                       store client-id token
                       {:redirect_uris              ["https://app.example.com/callback"]
                        :token_endpoint_auth_method "none"})]
      (is (= "none" (:token_endpoint_auth_method result)))
      (is (nil? (:client-secret-hash (proto/get-client store client-id)))))))

(deftest handle-client-update-ignores-client-id-in-body-test
  (testing "client_id in update body is silently ignored"
    (let [[store reg] (register-test-client)
          client-id   (:client_id reg)
          token       (:registration_access_token reg)
          result      (reg/handle-client-update
                       store client-id token
                       {:redirect_uris ["https://app.example.com/callback"]
                        :client_id     "attacker-id"})]
      (is (= client-id (:client_id result))))))
