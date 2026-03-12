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

(deftest save-refresh-token-with-expiry-test
  (testing "stores and retrieves expiry on a refresh token"
    (let [token-store (store/create-token-store)
          expiry      (+ (System/currentTimeMillis) 60000)]
      (proto/save-refresh-token token-store "rt-1" "user-1" "client-1" ["openid"] expiry nil)
      (let [data (proto/get-refresh-token token-store "rt-1")]
        (is (= expiry (:expiry data)))
        (is (= "user-1" (:user-id data)))
        (is (= ["openid"] (:scope data)))))))

(deftest save-refresh-token-without-expiry-test
  (testing "nil expiry means no :expiry key in stored data"
    (let [token-store (store/create-token-store)]
      (proto/save-refresh-token token-store "rt-2" "user-1" "client-1" ["openid"] nil nil)
      (let [data (proto/get-refresh-token token-store "rt-2")]
        (is (not (contains? data :expiry)))
        (is (= "user-1" (:user-id data)))))))
