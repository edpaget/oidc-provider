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

(deftest register-client-missing-client-type-test
  (testing "rejects config missing required :client-type"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})]
      (is (thrown? AssertionError
                   (core/register-client
                    provider
                    {:client-id      "bad-client"
                     :redirect-uris  ["https://app.example.com/callback"]
                     :grant-types    ["authorization_code"]
                     :response-types ["code"]
                     :scopes         ["openid"]}))))))

(deftest register-client-invalid-grant-type-test
  (testing "rejects config with invalid grant type"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})]
      (is (thrown? AssertionError
                   (core/register-client
                    provider
                    {:client-id      "bad-client"
                     :client-type    "confidential"
                     :redirect-uris  ["https://app.example.com/callback"]
                     :grant-types    ["invalid_grant"]
                     :response-types ["code"]
                     :scopes         ["openid"]}))))))

(deftest register-client-without-client-id-test
  (testing "accepts config without client-id (store generates one)"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})
          client   (core/register-client
                    provider
                    {:client-type    "public"
                     :redirect-uris  ["https://app.example.com/callback"]
                     :grant-types    ["authorization_code"]
                     :response-types ["code"]
                     :scopes         ["openid"]})]
      (is (= "public" (:client-type client)))
      (is (= client (core/get-client provider (:client-id client)))))))

(deftest register-client-empty-map-test
  (testing "rejects empty config map"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"
                     :jwks-uri               "https://test.example.com/jwks"})]
      (is (thrown? AssertionError
                   (core/register-client provider {}))))))

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

(deftest create-provider-without-oidc-test
  (testing "creates provider without jwks-uri or signing keys"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"})
          pc       (:provider-config provider)]
      (is (nil? (:key-set pc)))
      (is (nil? (:active-signing-key-id pc)))
      (is (= 3600 (:access-token-ttl-seconds pc))))))

(deftest jwks-empty-without-signing-keys-test
  (testing "jwks returns empty keys when no signing key configured"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"})
          jwks     (core/jwks provider)]
      (is (= {:keys []} jwks)))))

(deftest discovery-omits-jwks-uri-without-oidc-test
  (testing "discovery metadata omits jwks_uri when not configured"
    (let [provider (core/create-provider
                    {:issuer                 "https://test.example.com"
                     :authorization-endpoint "https://test.example.com/authorize"
                     :token-endpoint         "https://test.example.com/token"})
          metadata (core/discovery-metadata provider)]
      (is (nil? (:jwks_uri metadata)))
      (is (= "https://test.example.com" (:issuer metadata))))))

(deftest create-provider-validates-https-issuer-test
  (testing "HTTPS issuer passes validation"
    (let [provider (core/create-provider
                    {:issuer                 "https://example.com"
                     :authorization-endpoint "https://example.com/authorize"
                     :token-endpoint         "https://example.com/token"})]
      (is (= "https://example.com" (get-in provider [:config :issuer]))))))

(deftest create-provider-rejects-http-issuer-test
  (testing "HTTP issuer is rejected by default"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"https scheme"
         (core/create-provider
          {:issuer                 "http://example.com"
           :authorization-endpoint "http://example.com/authorize"
           :token-endpoint         "http://example.com/token"})))))

(deftest create-provider-rejects-query-in-issuer-test
  (testing "issuer with query component is rejected"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"query component"
         (core/create-provider
          {:issuer                 "https://example.com?q=1"
           :authorization-endpoint "https://example.com/authorize"
           :token-endpoint         "https://example.com/token"})))))

(deftest create-provider-rejects-fragment-in-issuer-test
  (testing "issuer with fragment component is rejected"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"fragment component"
         (core/create-provider
          {:issuer                 "https://example.com#frag"
           :authorization-endpoint "https://example.com/authorize"
           :token-endpoint         "https://example.com/token"})))))

(deftest create-provider-allows-http-with-option-test
  (testing "HTTP issuer passes with :allow-http-issuer true"
    (let [provider (core/create-provider
                    {:issuer                 "http://localhost"
                     :authorization-endpoint "http://localhost/authorize"
                     :token-endpoint         "http://localhost/token"
                     :allow-http-issuer      true})]
      (is (= "http://localhost" (get-in provider [:config :issuer]))))))
