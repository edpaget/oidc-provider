(ns oidc-provider.core-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.core :as core]
   [oidc-provider.protocol :as proto]))

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
  (testing "creates provider with correct config and generated signing key"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})]
      (is (= "https://test.example.com" (get-in provider [:config :issuer])))
      (is (= 3600 (:access-token-ttl-seconds (:provider-config provider)))))))

(deftest register-client-test
  (testing "registers client successfully"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})
          client   (core/register-client
                    provider
                    {:client-id      "test-client"
                     :client-secret  "secret123"
                     :redirect-uris  ["https://app.example.com/callback"]
                     :grant-types    ["authorization_code" "refresh_token"]
                     :response-types ["code"]
                     :scopes         ["openid" "profile" "email"]})]
      (is (= "test-client" (:client-id client)))
      (is (= "secret123" (:client-secret client)))
      (is (= ["https://app.example.com/callback"] (:redirect-uris client))))))

(deftest retrieve-registered-client-test
  (testing "retrieves registered client by id"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})
          _        (core/register-client
                    provider
                    {:client-id      "test-client"
                     :client-secret  "secret123"
                     :redirect-uris  ["https://app.example.com/callback"]
                     :grant-types    ["authorization_code"]
                     :response-types ["code"]
                     :scopes         ["openid"]})
          client   (core/get-client provider "test-client")]
      (is (= "test-client" (:client-id client))))))

(deftest discovery-metadata-test
  (testing "returns valid discovery metadata"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})
          metadata (core/discovery-metadata provider)]
      (is (= "https://test.example.com" (:issuer metadata)))
      (is (= "https://test.example.com/authorize" (:authorization_endpoint metadata)))
      (is (= "https://test.example.com/token" (:token_endpoint metadata)))
      (is (= "https://test.example.com/jwks" (:jwks_uri metadata)))
      (is (= ["code"] (:response_types_supported metadata))))))

(deftest discovery-includes-registration-endpoint-test
  (testing "includes registration_endpoint when configured"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"
                     :registration-endpoint  "https://test.example.com/register"})
          metadata (core/discovery-metadata provider)]
      (is (= "https://test.example.com/register" (:registration_endpoint metadata))))))

(deftest discovery-omits-registration-endpoint-test
  (testing "omits registration_endpoint when not configured"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})
          metadata (core/discovery-metadata provider)]
      (is (nil? (:registration_endpoint metadata))))))

(deftest jwks-test
  (testing "returns JWKS with single RSA key"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})
          jwks     (core/jwks provider)
          key      (first (:keys jwks))]
      (is (= 1 (count (:keys jwks))))
      (is (= "RSA" (:kty key)))
      (is (= "AQAB" (:e key))))))
