(ns oidc-provider.core-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.core :as core]
   [oidc-provider.protocol :as proto]
   [oidc-provider.token :as token]
   [oidc-provider.util :as util])
  (:import
   [com.nimbusds.jose.jwk JWKSet RSAKey]))

(def ^:private secret123-hash (util/hash-client-secret "secret123"))

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
                    {:client-id          "test-client"
                     :client-type        "confidential"
                     :client-secret-hash secret123-hash
                     :redirect-uris      ["https://app.example.com/callback"]
                     :grant-types        ["authorization_code" "refresh_token"]
                     :response-types     ["code"]
                     :scopes             ["openid" "profile" "email"]})]
      (is (= "test-client" (:client-id client)))
      (is (= secret123-hash (:client-secret-hash client)))
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
                    {:client-id          "test-client"
                     :client-type        "confidential"
                     :client-secret-hash secret123-hash
                     :redirect-uris      ["https://app.example.com/callback"]
                     :grant-types        ["authorization_code"]
                     :response-types     ["code"]
                     :scopes             ["openid"]})
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
      (is (= "AQAB" (:e key)))
      (is (= "sig" (:use key))))))

(deftest create-provider-with-multiple-keys-test
  (testing ":signing-keys + :active-signing-key-id produces correct JWKSet"
    (let [k1       (token/generate-rsa-key)
          k2       (token/generate-rsa-key)
          provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"
                     :signing-keys           [k1 k2]
                     :active-signing-key-id  (.getKeyID ^RSAKey k2)})
          pc       (:provider-config provider)
          key-set  (:key-set pc)]
      (is (= 2 (count (.getKeys ^JWKSet key-set))))
      (is (= (.getKeyID ^RSAKey k2) (:active-signing-key-id pc))))))

(deftest create-provider-default-refresh-token-ttl-test
  (testing "refresh-token-ttl-seconds defaults to 30 days"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})]
      (is (= 2592000 (:refresh-token-ttl-seconds (:provider-config provider)))))))

(deftest create-provider-refresh-token-ttl-none-test
  (testing "refresh-token-ttl-seconds :none produces nil (unlimited)"
    (let [provider (core/create-provider
                    {:issuer                    "https://test.example.com"
                     :authorization-endpoint    "https://test.example.com/authorize"
                     :token-endpoint            "https://test.example.com/token"
                     :jwks-uri                  "https://test.example.com/jwks"
                     :refresh-token-ttl-seconds :none})]
      (is (nil? (:refresh-token-ttl-seconds (:provider-config provider)))))))

(deftest create-provider-active-key-defaults-to-first-test
  (testing "omitted :active-signing-key-id defaults to first key"
    (let [k1       (token/generate-rsa-key)
          k2       (token/generate-rsa-key)
          provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"
                     :signing-keys           [k1 k2]})
          pc       (:provider-config provider)]
      (is (= (.getKeyID ^RSAKey k1) (:active-signing-key-id pc))))))
