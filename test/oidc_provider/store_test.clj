(ns oidc-provider.store-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store]))

(deftest update-client-success-test
  (testing "updates an existing client with new metadata"
    (let [client-store (store/create-client-store)
          registered   (proto/register-client client-store
                                              {:client-type                "public"
                                               :redirect-uris              ["https://app.example.com/cb"]
                                               :grant-types                ["authorization_code"]
                                               :response-types             ["code"]
                                               :scopes                     ["openid"]
                                               :token-endpoint-auth-method "none"})
          client-id    (:client-id registered)
          updated      (proto/update-client client-store client-id
                                            {:client-name "Updated App"
                                             :client-uri  "https://example.com"})]
      (is (= "Updated App" (:client-name updated)))
      (is (= "https://example.com" (:client-uri updated)))
      (is (= "Updated App" (:client-name (proto/get-client client-store client-id)))))))

(deftest update-client-unknown-test
  (testing "returns nil for a nonexistent client"
    (let [client-store (store/create-client-store)]
      (is (nil? (proto/update-client client-store "nonexistent" {:client-name "X"}))))))

(deftest update-client-preserves-unmodified-test
  (testing "preserves fields not included in the update"
    (let [client-store (store/create-client-store)
          registered   (proto/register-client client-store
                                              {:client-type                "public"
                                               :redirect-uris              ["https://app.example.com/cb"]
                                               :grant-types                ["authorization_code"]
                                               :response-types             ["code"]
                                               :scopes                     ["openid"]
                                               :token-endpoint-auth-method "none"
                                               :client-name                "Original"})
          client-id    (:client-id registered)
          updated      (proto/update-client client-store client-id
                                            {:client-uri "https://example.com"})]
      (is (= "Original" (:client-name updated)))
      (is (= ["https://app.example.com/cb"] (:redirect-uris updated)))
      (is (= "https://example.com" (:client-uri updated))))))

(deftest consume-authorization-code-test
  (testing "returns code data and removes code from store"
    (let [code-store (store/create-authorization-code-store)
          expiry     (+ (System/currentTimeMillis) 60000)]
      (store/save-authorization-code code-store "code-1" "user-1" "client-1"
                                     "https://app.example.com/cb" ["openid"] nil expiry nil nil nil)
      (let [data (store/consume-authorization-code code-store "code-1")]
        (is (= "user-1" (:user-id data)))
        (is (= "client-1" (:client-id data)))
        (is (nil? (store/get-authorization-code code-store "code-1")))))))

(deftest consume-authorization-code-missing-test
  (testing "returns nil for nonexistent code"
    (let [code-store (store/create-authorization-code-store)]
      (is (nil? (store/consume-authorization-code code-store "nonexistent"))))))

(deftest consume-authorization-code-idempotent-test
  (testing "second consume returns nil"
    (let [code-store (store/create-authorization-code-store)
          expiry     (+ (System/currentTimeMillis) 60000)]
      (store/save-authorization-code code-store "code-1" "user-1" "client-1"
                                     "https://app.example.com/cb" ["openid"] nil expiry nil nil nil)
      (is (some? (store/consume-authorization-code code-store "code-1")))
      (is (nil? (store/consume-authorization-code code-store "code-1"))))))

(deftest save-refresh-token-with-expiry-test
  (testing "stores and retrieves expiry on a refresh token"
    (let [token-store (store/create-token-store)
          expiry      (+ (System/currentTimeMillis) 60000)]
      (store/save-refresh-token token-store "rt-1" "user-1" "client-1" ["openid"] expiry nil)
      (let [data (store/get-refresh-token token-store "rt-1")]
        (is (= expiry (:expiry data)))
        (is (= "user-1" (:user-id data)))
        (is (= ["openid"] (:scope data)))))))

(deftest save-refresh-token-without-expiry-test
  (testing "nil expiry means no :expiry key in stored data"
    (let [token-store (store/create-token-store)]
      (store/save-refresh-token token-store "rt-2" "user-1" "client-1" ["openid"] nil nil)
      (let [data (store/get-refresh-token token-store "rt-2")]
        (is (not (contains? data :expiry)))
        (is (= "user-1" (:user-id data)))))))

(deftest access-token-stored-as-hash-test
  (testing "plaintext token is not a key in the internal atom"
    (let [token-store (store/create-token-store)]
      (store/save-access-token token-store "at-plaintext" "user-1" "client-1" ["openid"] 999999999999 nil)
      (is (some? (store/get-access-token token-store "at-plaintext")))
      (is (not (contains? @(.access-tokens token-store) "at-plaintext"))))))

(deftest refresh-token-stored-as-hash-test
  (testing "plaintext refresh token is not a key in the internal atom"
    (let [token-store (store/create-token-store)]
      (store/save-refresh-token token-store "rt-plaintext" "user-1" "client-1" ["openid"] nil nil)
      (is (some? (store/get-refresh-token token-store "rt-plaintext")))
      (is (not (contains? @(.refresh-tokens token-store) "rt-plaintext"))))))

(deftest authorization-code-stored-as-hash-test
  (testing "plaintext code is not a key in the internal atom"
    (let [code-store (store/create-authorization-code-store)
          expiry     (+ (System/currentTimeMillis) 60000)]
      (store/save-authorization-code code-store "code-plain" "user-1" "client-1"
                                     "https://app.example.com/cb" ["openid"] nil expiry nil nil nil)
      (is (some? (store/get-authorization-code code-store "code-plain")))
      (is (not (contains? @(.codes code-store) "code-plain"))))))

(deftest hashing-token-store-access-token-test
  (testing "HashingTokenStore hashes access tokens before storing in inner store"
    (let [inner     (store/create-token-store)
          decorator (store/->HashingTokenStore inner)]
      (proto/save-access-token decorator "at-plain" "user-1" "client-1" ["openid"] 999999999999 nil)
      (is (= "user-1" (:user-id (proto/get-access-token decorator "at-plain"))))
      (is (not (contains? @(.access-tokens inner) "at-plain"))))))

(deftest hashing-token-store-refresh-token-test
  (testing "HashingTokenStore hashes refresh tokens before storing in inner store"
    (let [inner     (store/create-token-store)
          decorator (store/->HashingTokenStore inner)]
      (proto/save-refresh-token decorator "rt-plain" "user-1" "client-1" ["openid"] nil nil)
      (is (= "user-1" (:user-id (proto/get-refresh-token decorator "rt-plain"))))
      (is (not (contains? @(.refresh-tokens inner) "rt-plain"))))))

(deftest hashing-token-store-revoke-access-token-test
  (testing "HashingTokenStore revokes access token by hashed key"
    (let [inner     (store/create-token-store)
          decorator (store/->HashingTokenStore inner)]
      (proto/save-access-token decorator "at-revoke" "user-1" "client-1" ["openid"] 999999999999 nil)
      (proto/revoke-token decorator "at-revoke")
      (is (nil? (proto/get-access-token decorator "at-revoke"))))))

(deftest hashing-token-store-revoke-refresh-token-test
  (testing "HashingTokenStore revokes refresh token by hashed key"
    (let [inner     (store/create-token-store)
          decorator (store/->HashingTokenStore inner)]
      (proto/save-refresh-token decorator "rt-revoke" "user-1" "client-1" ["openid"] nil nil)
      (proto/revoke-token decorator "rt-revoke")
      (is (nil? (proto/get-refresh-token decorator "rt-revoke"))))))

(deftest hashing-authorization-code-store-test
  (testing "HashingAuthorizationCodeStore hashes codes before storing in inner store"
    (let [inner     (store/create-authorization-code-store)
          decorator (store/->HashingAuthorizationCodeStore inner)
          expiry    (+ (System/currentTimeMillis) 60000)]
      (proto/save-authorization-code decorator "code-plain" "user-1" "client-1"
                                     "https://app.example.com/cb" ["openid"] nil expiry nil nil nil)
      (is (= "user-1" (:user-id (proto/get-authorization-code decorator "code-plain"))))
      (is (not (contains? @(.codes inner) "code-plain"))))))

(deftest hashing-authorization-code-store-consume-test
  (testing "HashingAuthorizationCodeStore consume hashes and atomically removes"
    (let [inner     (store/create-authorization-code-store)
          decorator (store/->HashingAuthorizationCodeStore inner)
          expiry    (+ (System/currentTimeMillis) 60000)]
      (proto/save-authorization-code decorator "code-consume" "user-1" "client-1"
                                     "https://app.example.com/cb" ["openid"] nil expiry nil nil nil)
      (is (= "user-1" (:user-id (proto/consume-authorization-code decorator "code-consume"))))
      (is (nil? (proto/get-authorization-code decorator "code-consume"))))))
