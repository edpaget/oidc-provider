(ns oidc-provider.token-endpoint-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store]
   [oidc-provider.token :as token]
   [oidc-provider.token-endpoint :as token-ep]
   [oidc-provider.util :as util])
  (:import
   [com.nimbusds.jose.jwk RSAKey]
   [com.nimbusds.oauth2.sdk.pkce CodeChallenge CodeChallengeMethod CodeVerifier]
   [java.time Clock Instant ZoneOffset]
   [java.util Base64]))

(defn- make-provider-config [overrides]
  (let [key (token/generate-rsa-key)]
    (merge {:issuer                   "https://test.example.com"
            :key-set                  (token/normalize-to-jwk-set key)
            :active-signing-key-id    (.getKeyID ^RSAKey key)
            :access-token-ttl-seconds 3600
            :clock                    (Clock/systemUTC)}
           overrides)))

(def ^:private secret123-hash (util/hash-client-secret "secret123"))

(defrecord TestClaimsProvider []
  proto/ClaimsProvider
  (get-claims [_ user-id _scope]
    {:sub   user-id
     :email "test@example.com"
     :name  "Test User"}))

(defn- test-client-store [overrides]
  (store/create-client-store
   [(merge {:client-id          "test-client"
            :client-type        "confidential"
            :client-secret-hash secret123-hash
            :redirect-uris      ["https://app.example.com/callback"]
            :grant-types        ["authorization_code"]
            :response-types     ["code"]
            :scopes             ["openid"]}
           overrides)]))

(defn- encode-basic-auth [client-id secret]
  (str "Basic " (.encodeToString (Base64/getEncoder)
                                 (.getBytes (str client-id ":" secret) "UTF-8"))))

(deftest authenticate-client-wrong-secret-test
  (testing "rejects wrong client secret"
    (is (thrown-with-msg?
         Exception #"Invalid client credentials"
         (token-ep/handle-token-request
          {:grant_type "authorization_code" :code "some-code"}
          (encode-basic-auth "test-client" "wrong-secret")
          (make-provider-config {})
          (test-client-store {})
          (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          (store/->HashingTokenStore (store/create-token-store))
          (->TestClaimsProvider))))))

(deftest authenticate-client-missing-secret-test
  (testing "rejects missing client secret when required"
    (is (thrown-with-msg?
         Exception #"Client requires Basic authentication"
         (token-ep/handle-token-request
          {:grant_type "authorization_code" :client_id "test-client" :code "some-code"}
          nil
          (make-provider-config {})
          (test-client-store {})
          (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          (store/->HashingTokenStore (store/create-token-store))
          (->TestClaimsProvider))))))

(deftest handle-authorization-code-grant-test
  (testing "exchanges authorization code for tokens stored with correct metadata"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid" "profile" "email"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {:id-token-ttl-seconds 3600})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry nil nil nil)
      (let [response   (token-ep/handle-authorization-code-grant
                        {:code         code
                         :redirect_uri "https://app.example.com/callback"}
                        (proto/get-client client-store "test-client")
                        provider-config
                        code-store
                        token-store
                        claims-provider)
            token-data (proto/get-access-token token-store (:access_token response))
            id-claims  (token/validate-id-token provider-config (:id_token response) "test-client")]
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "openid profile"}
               (select-keys response [:token_type :expires_in :scope])))
        (is (= "user-123" (:user-id token-data)))
        (is (= "test-client" (:client-id token-data)))
        (is (= "user-123" (:sub id-claims)))
        (is (= "nonce123" (:nonce id-claims)))))))

(deftest authorization-code-grant-no-openid-scope-test
  (testing "omits id_token when openid is not in scope"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["profile" "email"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["profile"] nil expiry nil nil nil)
      (let [response   (token-ep/handle-authorization-code-grant
                        {:code         code
                         :redirect_uri "https://app.example.com/callback"}
                        (proto/get-client client-store "test-client")
                        provider-config
                        code-store
                        token-store
                        claims-provider)
            token-data (proto/get-access-token token-store (:access_token response))]
        (is (= nil (:id_token response)))
        (is (= "user-123" (:user-id token-data)))
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "profile"}
               (select-keys response [:token_type :expires_in :scope])))))))

(deftest handle-authorization-code-grant-expired-test
  (testing "throws on expired authorization code"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (- (System/currentTimeMillis) 1000)]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (is (thrown-with-msg? Exception #"expired"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://app.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest redirect-uri-missing-enforcement-test
  (testing "throws when redirect_uri is missing but was in authorization request"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (is (thrown-with-msg? Exception #"Missing redirect_uri"
                            (token-ep/handle-authorization-code-grant
                             {:code code}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest redirect-uri-mismatch-enforcement-test
  (testing "throws when redirect_uri does not match"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (is (thrown-with-msg? Exception #"Redirect URI mismatch"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://evil.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest handle-refresh-token-grant-test
  (testing "refreshes access token with correct stored metadata and rotates refresh token"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid" "profile"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client" ["openid" "profile"] nil nil)
      (let [response   (token-ep/handle-refresh-token-grant
                        {:refresh_token refresh-token}
                        (proto/get-client client-store "test-client")
                        provider-config
                        token-store)
            token-data (proto/get-access-token token-store (:access_token response))]
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "openid profile"}
               (select-keys response [:token_type :expires_in :scope])))
        (is (some? (proto/get-refresh-token token-store (:refresh_token response))))
        (is (= "user-123" (:user-id token-data)))
        (is (= "test-client" (:client-id token-data)))))))

(deftest grant-type-authorization-code-rejected-test
  (testing "authorization_code rejected for client without grant type"
    (let [client-store    (store/create-client-store
                           [{:client-id          "cc-only-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      []
                             :grant-types        ["client_credentials"]
                             :response-types     []
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "cc-only-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (is (thrown-with-msg? Exception #"Client not authorized for authorization_code"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://app.example.com/callback"}
                             (proto/get-client client-store "cc-only-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest grant-type-refresh-token-rejected-test
  (testing "refresh_token rejected for client without grant type"
    (let [client-store    (store/create-client-store
                           [{:client-id          "authcode-only-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "authcode-only-client" ["openid"] nil nil)
      (is (thrown-with-msg? Exception #"Client not authorized for refresh_token"
                            (token-ep/handle-refresh-token-grant
                             {:refresh_token refresh-token}
                             (proto/get-client client-store "authcode-only-client")
                             provider-config
                             token-store))))))

(deftest handle-client-credentials-grant-test
  (testing "issues token with correct stored metadata"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      []
                             :grant-types        ["client_credentials"]
                             :response-types     []
                             :scopes             ["api:read" "api:write"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {})
          response        (token-ep/handle-client-credentials-grant
                           {:scope "api:read"}
                           (proto/get-client client-store "test-client")
                           provider-config
                           token-store)
          token-data      (proto/get-access-token token-store (:access_token response))]
      (is (= {:token_type "Bearer" :expires_in 3600 :scope "api:read"}
             (select-keys response [:token_type :expires_in :scope])))
      (is (= "test-client" (:client-id token-data)))
      (is (= ["api:read"] (:scope token-data))))))

(deftest authorization-code-grant-pkce-success-test
  (testing "exchanges code with valid PKCE verifier"
    (let [verifier        (CodeVerifier.)
          challenge       (.getValue (CodeChallenge/compute CodeChallengeMethod/S256 verifier))
          verifier-str    (.getValue verifier)
          client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid" "profile"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {:id-token-ttl-seconds 3600})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry challenge "S256" nil)
      (let [response   (token-ep/handle-authorization-code-grant
                        {:code          code
                         :redirect_uri  "https://app.example.com/callback"
                         :code_verifier verifier-str}
                        (proto/get-client client-store "test-client")
                        provider-config
                        code-store
                        token-store
                        claims-provider)
            token-data (proto/get-access-token token-store (:access_token response))]
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "openid profile"}
               (select-keys response [:token_type :expires_in :scope])))
        (is (= "user-123" (:user-id token-data)))))))

(deftest authorization-code-grant-pkce-wrong-verifier-test
  (testing "rejects wrong PKCE verifier"
    (let [verifier        (CodeVerifier.)
          challenge       (.getValue (CodeChallenge/compute CodeChallengeMethod/S256 verifier))
          wrong-verifier  (.getValue (CodeVerifier.))
          client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry challenge "S256" nil)
      (is (thrown-with-msg? Exception #"PKCE verification failed"
                            (token-ep/handle-authorization-code-grant
                             {:code          code
                              :redirect_uri  "https://app.example.com/callback"
                              :code_verifier wrong-verifier}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest authorization-code-grant-pkce-missing-verifier-test
  (testing "rejects missing verifier when challenge was stored"
    (let [verifier        (CodeVerifier.)
          challenge       (.getValue (CodeChallenge/compute CodeChallengeMethod/S256 verifier))
          client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry challenge "S256" nil)
      (is (thrown-with-msg? Exception #"Missing code_verifier"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://app.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest authorization-code-grant-pkce-unexpected-verifier-test
  (testing "rejects verifier when no challenge was stored"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (is (thrown-with-msg? Exception #"Unexpected code_verifier"
                            (token-ep/handle-authorization-code-grant
                             {:code          code
                              :redirect_uri  "https://app.example.com/callback"
                              :code_verifier "some-verifier"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest authorization-code-grant-passes-resource-to-tokens-test
  (testing "resource from auth code round-trips to tokens and response"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid" "profile"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {:id-token-ttl-seconds 3600})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))
          resources       ["https://api.example.com" "https://data.example.com"]]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry nil nil resources)
      (let [response    (token-ep/handle-authorization-code-grant
                         {:code         code
                          :redirect_uri "https://app.example.com/callback"}
                         (proto/get-client client-store "test-client")
                         provider-config
                         code-store
                         token-store
                         claims-provider)
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (= resources (:resource response)))
        (is (= resources (:resource access-data)))
        (is (nil? (:refresh_token response)))))))

(deftest authorization-code-grant-no-resource-test
  (testing "no resource in auth code means no resource in tokens or response"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["profile"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["profile"] nil expiry nil nil nil)
      (let [response    (token-ep/handle-authorization-code-grant
                         {:code         code
                          :redirect_uri "https://app.example.com/callback"}
                         (proto/get-client client-store "test-client")
                         provider-config
                         code-store
                         token-store
                         claims-provider)
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (nil? (:resource response)))
        (is (nil? (:resource access-data)))))))

(deftest refresh-token-grant-narrows-resource-test
  (testing "requesting a subset of original resources succeeds"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid" "profile"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid" "profile"] nil
                                ["https://api.example.com" "https://data.example.com"])
      (let [response    (token-ep/handle-refresh-token-grant
                         {:refresh_token refresh-token
                          :resource      ["https://api.example.com"]}
                         (proto/get-client client-store "test-client")
                         provider-config
                         token-store)
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (= ["https://api.example.com"] (:resource response)))
        (is (= ["https://api.example.com"] (:resource access-data)))
        (is (some? (proto/get-refresh-token token-store (:refresh_token response))))))))

(deftest refresh-token-grant-rejects-expanded-resource-test
  (testing "requesting a resource not in original set throws invalid_target"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid"] nil
                                ["https://api.example.com"])
      (is (thrown-with-msg? Exception #"Requested resource exceeds original grant"
                            (token-ep/handle-refresh-token-grant
                             {:refresh_token refresh-token
                              :resource      ["https://evil.example.com"]}
                             (proto/get-client client-store "test-client")
                             provider-config
                             token-store))))))

(deftest refresh-token-grant-preserves-resource-test
  (testing "no resource param on refresh preserves original resources"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid"] nil
                                ["https://api.example.com"])
      (let [response    (token-ep/handle-refresh-token-grant
                         {:refresh_token refresh-token}
                         (proto/get-client client-store "test-client")
                         provider-config
                         token-store)
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (= ["https://api.example.com"] (:resource response)))
        (is (= ["https://api.example.com"] (:resource access-data)))
        (is (some? (proto/get-refresh-token token-store (:refresh_token response))))))))

(deftest client-credentials-grant-with-resource-test
  (testing "resource is stored and returned in response"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      []
                             :grant-types        ["client_credentials"]
                             :response-types     []
                             :scopes             ["api:read"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {})
          response        (token-ep/handle-client-credentials-grant
                           {:scope    "api:read"
                            :resource ["https://api.example.com"]}
                           (proto/get-client client-store "test-client")
                           provider-config
                           token-store)
          access-data     (proto/get-access-token token-store (:access_token response))]
      (is (= ["https://api.example.com"] (:resource response)))
      (is (= ["https://api.example.com"] (:resource access-data))))))

(deftest handle-token-request-multi-value-resource-test
  (testing "vector resource param produces a vector in the response"
    (let [client-store (test-client-store {:grant-types    ["client_credentials"]
                                           :redirect-uris  []
                                           :response-types []
                                           :scopes         ["api:read"]})
          token-store  (store/->HashingTokenStore (store/create-token-store))
          response     (token-ep/handle-token-request
                        {:grant_type "client_credentials"
                         :scope      "api:read"
                         :resource   ["https://api.example.com" "https://data.example.com"]}
                        (encode-basic-auth "test-client" "secret123")
                        (make-provider-config {}) client-store
                        (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store)) token-store
                        (->TestClaimsProvider))
          access-data  (proto/get-access-token token-store (:access_token response))]
      (is (= ["https://api.example.com" "https://data.example.com"] (:resource response)))
      (is (= ["https://api.example.com" "https://data.example.com"] (:resource access-data))))))

(deftest authenticate-client-hashed-secret-test
  (testing "authenticates with correct secret against hashed store"
    (let [secret   "my-secret"
          response (token-ep/handle-token-request
                    {:grant_type "client_credentials" :scope "api:read"}
                    (encode-basic-auth "hashed-client" secret)
                    (make-provider-config {})
                    (test-client-store {:client-id          "hashed-client"
                                        :client-secret-hash (util/hash-client-secret secret)
                                        :grant-types        ["client_credentials"]
                                        :redirect-uris      []
                                        :response-types     []
                                        :scopes             ["api:read"]})
                    (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
                    (store/->HashingTokenStore (store/create-token-store))
                    (->TestClaimsProvider))]
      (is (= "Bearer" (:token_type response)))
      (is (= "api:read" (:scope response))))))

(deftest authenticate-client-hashed-secret-wrong-test
  (testing "rejects wrong secret against hashed store"
    (is (thrown-with-msg?
         Exception #"Invalid client credentials"
         (token-ep/handle-token-request
          {:grant_type "client_credentials" :scope "api:read"}
          (encode-basic-auth "hashed-client" "wrong-secret")
          (make-provider-config {})
          (test-client-store {:client-id          "hashed-client"
                              :client-secret-hash (util/hash-client-secret "correct-secret")
                              :grant-types        ["client_credentials"]
                              :redirect-uris      []
                              :response-types     []
                              :scopes             ["api:read"]})
          (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          (store/->HashingTokenStore (store/create-token-store))
          (->TestClaimsProvider))))))

(deftest confidential-client-no-credentials-test
  (testing "rejects confidential client with no stored secret or hash"
    (is (thrown-with-msg?
         Exception #"Client configured for secret-based auth has no stored credentials"
         (token-ep/handle-token-request
          {:grant_type "client_credentials" :scope "api:read"}
          (encode-basic-auth "misconfigured" "any-secret")
          (make-provider-config {})
          (test-client-store {:client-id          "misconfigured"
                              :client-secret-hash nil
                              :grant-types        ["client_credentials"]
                              :redirect-uris      []
                              :response-types     []})
          (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          (store/->HashingTokenStore (store/create-token-store))
          (->TestClaimsProvider))))))

(deftest explicit-auth-method-no-credentials-test
  (testing "rejects client with explicit auth method but no stored secret"
    (is (thrown-with-msg?
         Exception #"Client configured for secret-based auth has no stored credentials"
         (token-ep/handle-token-request
          {:grant_type "client_credentials" :scope "api:read"}
          (encode-basic-auth "basic-no-secret" "any-secret")
          (make-provider-config {})
          (test-client-store {:client-id                  "basic-no-secret"
                              :client-type                nil
                              :client-secret-hash         nil
                              :token-endpoint-auth-method "client_secret_basic"
                              :grant-types                ["client_credentials"]
                              :redirect-uris              []
                              :response-types             []
                              :scopes                     ["api:read"]})
          (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          (store/->HashingTokenStore (store/create-token-store))
          (->TestClaimsProvider))))
    (is (thrown-with-msg?
         Exception #"Client configured for secret-based auth has no stored credentials"
         (token-ep/handle-token-request
          {:grant_type "client_credentials" :scope         "api:read"
           :client_id  "post-no-secret"     :client_secret "any-secret"}
          nil
          (make-provider-config {})
          (test-client-store {:client-id                  "post-no-secret"
                              :client-type                nil
                              :client-secret-hash         nil
                              :token-endpoint-auth-method "client_secret_post"
                              :grant-types                ["client_credentials"]
                              :redirect-uris              []
                              :response-types             []
                              :scopes                     ["api:read"]})
          (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          (store/->HashingTokenStore (store/create-token-store))
          (->TestClaimsProvider))))))

(deftest refresh-token-expired-rejection-test
  (testing "rejects an expired refresh token"
    (let [past-instant    (-> (Instant/now) (.minusSeconds 3600))
          fixed-clock     (Clock/fixed past-instant ZoneOffset/UTC)
          client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {})
          refresh-token   (token/generate-refresh-token)
          past-expiry     (.millis fixed-clock)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid"] past-expiry nil)
      (is (thrown-with-msg? Exception #"Refresh token expired"
                            (token-ep/handle-refresh-token-grant
                             {:refresh_token refresh-token}
                             (proto/get-client client-store "test-client")
                             provider-config
                             token-store))))))

(deftest refresh-token-valid-before-expiry-test
  (testing "accepts a refresh token that has not yet expired"
    (let [future-instant  (-> (Instant/now) (.plusSeconds 3600))
          future-clock    (Clock/fixed future-instant ZoneOffset/UTC)
          client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid" "profile"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          refresh-token   (token/generate-refresh-token)
          future-expiry   (.millis future-clock)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid" "profile"] future-expiry nil)
      (let [response (token-ep/handle-refresh-token-grant
                      {:refresh_token refresh-token}
                      (proto/get-client client-store "test-client")
                      provider-config
                      token-store)]
        (is (= "Bearer" (:token_type response)))
        (is (= "openid profile" (:scope response)))
        (is (some? (proto/get-refresh-token token-store (:refresh_token response))))))))

(deftest refresh-token-rotation-revokes-old-token-test
  (testing "old refresh token is revoked and new one has correct metadata"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid" "profile"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          old-refresh     (token/generate-refresh-token)]
      (proto/save-refresh-token token-store old-refresh "user-123" "test-client"
                                ["openid" "profile"] nil nil)
      (let [response    (token-ep/handle-refresh-token-grant
                         {:refresh_token old-refresh}
                         (proto/get-client client-store "test-client")
                         provider-config
                         token-store)
            new-refresh (:refresh_token response)
            old-data    (proto/get-refresh-token token-store old-refresh)
            new-data    (proto/get-refresh-token token-store new-refresh)]
        (is (nil? old-data))
        (is (= "user-123" (:user-id new-data)))
        (is (= "test-client" (:client-id new-data)))
        (is (= ["openid" "profile"] (:scope new-data)))))))

(deftest refresh-token-rotation-disabled-test
  (testing "with rotation disabled, no new refresh token is issued and old remains valid"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {:rotate-refresh-tokens false})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid"] nil nil)
      (let [response (token-ep/handle-refresh-token-grant
                      {:refresh_token refresh-token}
                      (proto/get-client client-store "test-client")
                      provider-config
                      token-store)
            old-data (proto/get-refresh-token token-store refresh-token)]
        (is (nil? (:refresh_token response)))
        (is (= "user-123" (:user-id old-data)))))))

(deftest refresh-token-rotation-preserves-expiry-test
  (testing "rotated token gets a fresh expiry based on TTL, not the old expiry"
    (let [now-instant     (Instant/parse "2026-01-01T00:00:00Z")
          fixed-clock     (Clock/fixed now-instant ZoneOffset/UTC)
          client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {:refresh-token-ttl-seconds 86400
                                                 :rotate-refresh-tokens     true
                                                 :clock                     fixed-clock})
          old-refresh     (token/generate-refresh-token)
          old-expiry      (+ (.millis fixed-clock) (* 1000 1800))]
      (proto/save-refresh-token token-store old-refresh "user-123" "test-client"
                                ["openid"] old-expiry nil)
      (let [response (token-ep/handle-refresh-token-grant
                      {:refresh_token old-refresh}
                      (proto/get-client client-store "test-client")
                      provider-config
                      token-store)
            new-data (proto/get-refresh-token token-store (:refresh_token response))
            expected (+ (.millis fixed-clock) (* 1000 86400))]
        (is (= expected (:expiry new-data)))))))

(deftest code-consumed-on-validation-failure-test
  (testing "authorization code is consumed even when exchange fails"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (is (thrown-with-msg? Exception #"Redirect URI mismatch"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://evil.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider)))
      (is (nil? (proto/get-authorization-code code-store code))))))

(deftest code-consumed-on-successful-exchange-test
  (testing "authorization code is deleted from store after successful exchange"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code"]
                             :response-types     ["code"]
                             :scopes             ["openid"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (token-ep/handle-authorization-code-grant
       {:code         code
        :redirect_uri "https://app.example.com/callback"}
       (proto/get-client client-store "test-client")
       provider-config
       code-store
       token-store
       claims-provider)
      (is (nil? (proto/get-authorization-code code-store code))))))

(deftest authorization-code-grant-with-refresh-token-grant-type-test
  (testing "client with refresh_token grant type receives a refresh token"
    (let [client-store    (store/create-client-store
                           [{:client-id          "test-client"
                             :client-type        "confidential"
                             :client-secret-hash secret123-hash
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["authorization_code" "refresh_token"]
                             :response-types     ["code"]
                             :scopes             ["openid" "profile"]}])
          code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {:id-token-ttl-seconds 3600})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry nil nil nil)
      (let [response     (token-ep/handle-authorization-code-grant
                          {:code         code
                           :redirect_uri "https://app.example.com/callback"}
                          (proto/get-client client-store "test-client")
                          provider-config
                          code-store
                          token-store
                          claims-provider)
            refresh-data (proto/get-refresh-token token-store (:refresh_token response))]
        (is (= "user-123" (:user-id refresh-data)))
        (is (= "test-client" (:client-id refresh-data)))))))

(deftest parse-basic-auth-url-decoded-test
  (testing "URL-decodes client_id and client_secret per RFC 6749 §2.3.1"
    (let [encoded (.encodeToString (Base64/getEncoder)
                                   (.getBytes "my%20client:secret%3Avalue" "UTF-8"))
          header  (str "Basic " encoded)
          result  (token-ep/parse-basic-auth header)]
      (is (= "my client" (:client-id result)))
      (is (= "secret:value" (:client-secret result))))))

(deftest parse-basic-auth-no-colon-test
  (testing "returns nil when decoded value has no colon separator"
    (let [encoded (.encodeToString (Base64/getEncoder)
                                   (.getBytes "nocredentials" "UTF-8"))
          header  (str "Basic " encoded)]
      (is (nil? (token-ep/parse-basic-auth header))))))

(deftest parse-basic-auth-malformed-base64-test
  (testing "returns nil for malformed Base64 input"
    (is (nil? (token-ep/parse-basic-auth "Basic !!!")))))

(deftest parse-basic-auth-case-insensitive-scheme-test
  (testing "accepts Basic auth scheme regardless of case"
    (let [encoded (.encodeToString (Base64/getEncoder)
                                   (.getBytes "my-client:secret123" "UTF-8"))]
      (is (= {:client-id "my-client" :client-secret "secret123"}
             (token-ep/parse-basic-auth (str "basic " encoded))))
      (is (= {:client-id "my-client" :client-secret "secret123"}
             (token-ep/parse-basic-auth (str "BASIC " encoded)))))))

(deftest client-credentials-rejects-public-client-test
  (testing "client_credentials grant throws for public clients"
    (let [token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {})]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"client_credentials grant requires a confidential client"
           (token-ep/handle-client-credentials-grant
            {:scope "read"}
            (proto/get-client (test-client-store {:client-id          "public-cc"
                                                  :client-type        "public"
                                                  :client-secret-hash nil
                                                  :grant-types        ["client_credentials"]
                                                  :scopes             ["read"]})
                              "public-cc")
            provider-config token-store))))))

(deftest server-rejects-unconfigured-grant-type-test
  (testing "rejects grant type not in server grant-types-supported"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"Unsupported grant type"
         (token-ep/handle-token-request
          {:grant_type "client_credentials" :client_id "test-client"}
          (encode-basic-auth "test-client" "secret123")
          (make-provider-config {:grant-types-supported ["authorization_code"]})
          (test-client-store {:grant-types ["authorization_code" "client_credentials"]})
          (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          (store/->HashingTokenStore (store/create-token-store))
          (->TestClaimsProvider))))
    (is (= "unsupported_grant_type"
           (try (token-ep/handle-token-request
                 {:grant_type "client_credentials" :client_id "test-client"}
                 (encode-basic-auth "test-client" "secret123")
                 (make-provider-config {:grant-types-supported ["authorization_code"]})
                 (test-client-store {:grant-types ["authorization_code" "client_credentials"]})
                 (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
                 (store/->HashingTokenStore (store/create-token-store))
                 (->TestClaimsProvider))
                (catch clojure.lang.ExceptionInfo e
                  (:error (ex-data e))))))))

(deftest server-allows-configured-grant-type-test
  (testing "allows grant type that is in server grant-types-supported"
    (let [code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {:grant-types-supported ["authorization_code"]})
          client-store    (test-client-store {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-1" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (let [response    (token-ep/handle-token-request
                         {:grant_type   "authorization_code"
                          :code         code
                          :redirect_uri "https://app.example.com/callback"}
                         (encode-basic-auth "test-client" "secret123")
                         provider-config client-store code-store token-store
                         (->TestClaimsProvider))
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (= "user-1" (:user-id access-data)))))))

(deftest server-default-allows-authorization-code-test
  (testing "default config allows authorization_code"
    (let [code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {})
          client-store    (test-client-store {:grant-types ["authorization_code" "refresh_token"]})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-1" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (let [response    (token-ep/handle-token-request
                         {:grant_type   "authorization_code"
                          :code         code
                          :redirect_uri "https://app.example.com/callback"}
                         (encode-basic-auth "test-client" "secret123")
                         provider-config client-store code-store token-store
                         (->TestClaimsProvider))
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (= "user-1" (:user-id access-data)))))))

(deftest server-default-allows-refresh-token-test
  (testing "default config allows refresh_token"
    (let [code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          token-store     (store/->HashingTokenStore (store/create-token-store))
          provider-config (make-provider-config {})
          client-store    (test-client-store {:grant-types ["authorization_code" "refresh_token"]})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-1" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (let [auth-response    (token-ep/handle-token-request
                              {:grant_type   "authorization_code"
                               :code         code
                               :redirect_uri "https://app.example.com/callback"}
                              (encode-basic-auth "test-client" "secret123")
                              provider-config client-store code-store token-store
                              (->TestClaimsProvider))
            refresh-response (token-ep/handle-token-request
                              {:grant_type    "refresh_token"
                               :refresh_token (:refresh_token auth-response)}
                              (encode-basic-auth "test-client" "secret123")
                              provider-config client-store code-store token-store
                              (->TestClaimsProvider))
            access-data      (proto/get-access-token token-store (:access_token refresh-response))]
        (is (= "user-1" (:user-id access-data)))))))

(deftest server-empty-grant-types-rejects-all-test
  (testing "empty grant-types-supported rejects all grant types"
    (is (= "unsupported_grant_type"
           (try (token-ep/handle-token-request
                 {:grant_type "authorization_code" :code "any"}
                 (encode-basic-auth "test-client" "secret123")
                 (make-provider-config {:grant-types-supported []})
                 (test-client-store {})
                 (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
                 (store/->HashingTokenStore (store/create-token-store))
                 (->TestClaimsProvider))
                (catch clojure.lang.ExceptionInfo e
                  (:error (ex-data e))))))))

(deftest server-default-allows-client-credentials-test
  (testing "default config allows client_credentials"
    (let [token-store (store/->HashingTokenStore (store/create-token-store))
          response    (token-ep/handle-token-request
                       {:grant_type "client_credentials" :scope "read"}
                       (encode-basic-auth "test-client" "secret123")
                       (make-provider-config {})
                       (test-client-store {:grant-types ["client_credentials"]
                                           :scopes      ["read"]})
                       (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
                       token-store
                       (->TestClaimsProvider))
          access-data (proto/get-access-token token-store (:access_token response))]
      (is (= "test-client" (:client-id access-data))))))

(deftest unknown-grant-type-returns-error-code-test
  (testing "completely unknown grant type returns unsupported_grant_type error"
    (is (= "unsupported_grant_type"
           (try (token-ep/handle-token-request
                 {:grant_type "urn:custom:grant" :client_id "test-client"}
                 (encode-basic-auth "test-client" "secret123")
                 (make-provider-config {})
                 (test-client-store {})
                 (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
                 (store/->HashingTokenStore (store/create-token-store))
                 (->TestClaimsProvider))
                (catch clojure.lang.ExceptionInfo e
                  (:error (ex-data e))))))))

(deftest authenticate-client-rejects-basic-for-post-client-test
  (testing "client_secret_post client is rejected when authenticating via any Basic header"
    (let [cs (test-client-store {:client-id                  "post-client"
                                 :token-endpoint-auth-method "client_secret_post"})]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"Client requires POST body authentication"
           (token-ep/authenticate-client {:client_id "post-client"}
                                         (encode-basic-auth "post-client" "secret123") cs)))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"Client requires POST body authentication"
           (token-ep/authenticate-client {:client_id "post-client"} "Basic !!!" cs))))))

(deftest authenticate-client-rejects-missing-secret-for-post-client-test
  (testing "client_secret_post client is rejected when no client_secret in params"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"Client requires POST body authentication with client_secret"
         (token-ep/authenticate-client
          {:client_id "post-client"} nil
          (test-client-store {:client-id                  "post-client"
                              :token-endpoint-auth-method "client_secret_post"}))))))

(deftest authenticate-client-succeeds-for-post-client-test
  (testing "client_secret_post client authenticates successfully via POST body"
    (let [result (token-ep/authenticate-client
                  {:client_id "post-client" :client_secret "secret123"} nil
                  (test-client-store {:client-id                  "post-client"
                                      :token-endpoint-auth-method "client_secret_post"}))]
      (is (= "post-client" (:client-id result))))))

(deftest authenticate-client-ignores-redundant-post-params-for-basic-client-test
  (testing "client_secret_basic client succeeds via Basic auth even with redundant POST body credentials"
    (let [result (token-ep/authenticate-client
                  {:client_id "basic-client" :client_secret "secret123"}
                  (encode-basic-auth "basic-client" "secret123")
                  (test-client-store {:client-id                  "basic-client"
                                      :token-endpoint-auth-method "client_secret_basic"}))]
      (is (= "basic-client" (:client-id result))))))

(deftest authenticate-client-defaults-confidential-to-basic-test
  (testing "confidential client without auth method defaults to client_secret_basic"
    (let [result (token-ep/authenticate-client
                  {} (encode-basic-auth "legacy-client" "secret123")
                  (test-client-store {:client-id "legacy-client"}))]
      (is (= "legacy-client" (:client-id result))))))

(deftest authenticate-client-defaults-confidential-rejects-post-test
  (testing "confidential client without auth method rejects POST-only authentication"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"Client requires Basic authentication"
         (token-ep/authenticate-client
          {:client_id "legacy-client" :client_secret "secret123"} nil
          (test-client-store {:client-id "legacy-client"}))))))

(deftest authenticate-client-defaults-public-to-none-test
  (testing "public client without auth method defaults to none and rejects client_secret"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"Public client must not provide a client_secret"
         (token-ep/authenticate-client
          {:client_id "legacy-public" :client_secret "some-secret"} nil
          (test-client-store {:client-id          "legacy-public"
                              :client-type        "public"
                              :client-secret-hash nil}))))))

(deftest authenticate-client-public-rejects-basic-header-test
  (testing "public client rejects request with any Basic auth header"
    (let [cs (test-client-store {:client-id          "public-basic"
                                 :client-type        "public"
                                 :client-secret-hash nil})]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"Public client must not provide a client_secret"
           (token-ep/authenticate-client {:client_id "public-basic"}
                                         (encode-basic-auth "public-basic" "") cs)))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"Public client must not provide a client_secret"
           (token-ep/authenticate-client {:client_id "public-basic"}
                                         "Basic not-valid-base64!" cs))))))

(deftest authenticate-client-legacy-no-client-type-with-secret-test
  (testing "client without :client-type but with secret hash defaults to client_secret_basic"
    (let [result (token-ep/authenticate-client
                  {} (encode-basic-auth "pre-type-client" "secret123")
                  (test-client-store {:client-id   "pre-type-client"
                                      :client-type nil}))]
      (is (= "pre-type-client" (:client-id result))))))

(deftest authenticate-client-legacy-no-client-type-without-secret-test
  (testing "client without :client-type and without secret hash defaults to none"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"Public client must not provide a client_secret"
         (token-ep/authenticate-client
          {:client_id "pre-type-public" :client_secret "some-secret"} nil
          (test-client-store {:client-id          "pre-type-public"
                              :client-type        nil
                              :client-secret-hash nil}))))))

(deftest client-credentials-rejects-untyped-client-without-secret-test
  (testing "client_credentials grant rejects client with nil :client-type and no secret"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"client_credentials grant requires a confidential client"
         (token-ep/handle-client-credentials-grant
          {:scope "read"}
          (proto/get-client (test-client-store {:client-id          "untyped-no-secret"
                                                :client-type        nil
                                                :client-secret-hash nil
                                                :grant-types        ["client_credentials"]
                                                :scopes             ["read"]})
                            "untyped-no-secret")
          (make-provider-config {}) (store/->HashingTokenStore (store/create-token-store)))))))

(deftest client-credentials-succeeds-for-untyped-client-with-secret-test
  (testing "client_credentials grant succeeds for client with nil :client-type but valid secret hash"
    (let [token-store (store/->HashingTokenStore (store/create-token-store))
          response    (token-ep/handle-client-credentials-grant
                       {:scope "read"}
                       (proto/get-client (test-client-store {:client-id   "untyped-with-secret"
                                                             :client-type nil
                                                             :grant-types ["client_credentials"]
                                                             :scopes      ["read"]})
                                         "untyped-with-secret")
                       (make-provider-config {}) token-store)]
      (is (= "Bearer" (:token_type response)))
      (is (some? (proto/get-access-token token-store (:access_token response)))))))

(deftest auth-method-none-rejected-for-confidential-test
  (testing "rejects confidential clients with token-endpoint-auth-method set to none"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"Confidential client must not use auth method 'none'"
         (token-ep/authenticate-client
          {:client_id "confused-client"} nil
          (test-client-store {:client-id                  "confused-client"
                              :token-endpoint-auth-method "none"
                              :grant-types                ["client_credentials"]
                              :redirect-uris              []
                              :response-types             []}))))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"Confidential client must not use auth method 'none'"
         (token-ep/authenticate-client
          {:client_id "migrated-client"} nil
          (test-client-store {:client-id                  "migrated-client"
                              :client-type                nil
                              :token-endpoint-auth-method "none"
                              :grant-types                ["client_credentials"]
                              :redirect-uris              []
                              :response-types             []}))))))

(deftest authenticate-client-bearer-header-not-treated-as-basic-test
  (testing "non-Basic Authorization header is not treated as Basic auth"
    (let [result (token-ep/authenticate-client
                  {:client_id "public-client"}
                  "Bearer some-access-token"
                  (test-client-store {:client-id          "public-client"
                                      :client-type        "public"
                                      :client-secret-hash nil}))]
      (is (= "public-client" (:client-id result))))))

(deftest authenticate-client-rejects-unsupported-auth-method-test
  (testing "rejects client with unsupported token-endpoint-auth-method"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"Unsupported token_endpoint_auth_method"
         (token-ep/authenticate-client
          {:client_id "custom-auth-client"} nil
          (test-client-store {:client-id                  "custom-auth-client"
                              :token-endpoint-auth-method "private_key_jwt"
                              :grant-types                ["client_credentials"]
                              :redirect-uris              []
                              :response-types             []}))))))
