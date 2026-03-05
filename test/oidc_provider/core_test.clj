(ns oidc-provider.core-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.core :as core]
   [oidc-provider.protocol :as proto]))

(defrecord TestValidator []
  proto/CredentialValidator
  (validate-credentials [_ credentials _client-id]
    (when (and (= (:username credentials) "test-user")
               (= (:password credentials) "test-pass"))
      "user-123")))

(defrecord TestClaimsProvider []
  proto/ClaimsProvider
  (get-claims [_ user-id scope]
    (cond-> {:sub user-id}
      (some #{"profile"} scope)
      (assoc :name "Test User"
             :given_name "Test"
             :family_name "User")

      (some #{"email"} scope)
      (assoc :email "test@example.com"
             :email_verified true))))

(deftest create-provider-test
  (testing "creates provider with minimal config"
    (let [provider (core/create-provider
                    {:issuer "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint "https://test.example.com/token"
                     :jwks-uri "https://test.example.com/jwks"})]
      (is (some? provider))
      (is (= "https://test.example.com" (get-in provider [:config :issuer])))
      (is (some? (:signing-key (:provider-config provider)))))))

(deftest register-client-test
  (testing "registers client successfully"
    (let [provider (core/create-provider
                    {:issuer "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint "https://test.example.com/token"
                     :jwks-uri "https://test.example.com/jwks"})
          client   (core/register-client
                    provider
                    {:client-id "test-client"
                     :client-secret "secret123"
                     :redirect-uris ["https://app.example.com/callback"]
                     :grant-types ["authorization_code" "refresh_token"]
                     :response-types ["code"]
                     :scopes ["openid" "profile" "email"]})]
      (is (= "test-client" (:client-id client)))
      (is (= "secret123" (:client-secret client)))
      (is (= ["https://app.example.com/callback"] (:redirect-uris client)))))

  (testing "retrieves registered client"
    (let [provider (core/create-provider
                    {:issuer "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint "https://test.example.com/token"
                     :jwks-uri "https://test.example.com/jwks"})
          _        (core/register-client
                    provider
                    {:client-id "test-client"
                     :client-secret "secret123"
                     :redirect-uris ["https://app.example.com/callback"]
                     :grant-types ["authorization_code"]
                     :response-types ["code"]
                     :scopes ["openid"]})
          client   (core/get-client provider "test-client")]
      (is (some? client))
      (is (= "test-client" (:client-id client))))))

(deftest discovery-metadata-test
  (testing "returns valid discovery metadata"
    (let [provider (core/create-provider
                    {:issuer "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint "https://test.example.com/token"
                     :jwks-uri "https://test.example.com/jwks"})
          metadata (core/discovery-metadata provider)]
      (is (= "https://test.example.com" (:issuer metadata)))
      (is (= "https://test.example.com/authorize" (:authorization_endpoint metadata)))
      (is (= "https://test.example.com/token" (:token_endpoint metadata)))
      (is (= "https://test.example.com/jwks" (:jwks_uri metadata)))
      (is (some? (:response_types_supported metadata)))
      (is (some? (:grant_types_supported metadata))))))

(deftest jwks-test
  (testing "returns valid JWKS"
    (let [provider (core/create-provider
                    {:issuer "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint "https://test.example.com/token"
                     :jwks-uri "https://test.example.com/jwks"})
          jwks     (core/jwks provider)]
      (is (vector? (:keys jwks)))
      (is (pos? (count (:keys jwks))))
      (is (some? (:kid (first (:keys jwks)))))
      (is (= "RSA" (:kty (first (:keys jwks))))))))
