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
