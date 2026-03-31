(ns oidc-provider.token-test
  "Tests for multi-key signing, validation, rotation, and JWKS output."
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.token :as token])
  (:import
   [com.nimbusds.jose.jwk JWKSet RSAKey]
   [java.time Clock Instant ZoneOffset]))

(deftest normalize-single-key-to-jwk-set-test
  (testing "single RSAKey wraps into a one-key JWKSet with kid preserved"
    (let [k      (token/generate-rsa-key)
          result (token/normalize-to-jwk-set k)]
      (is (instance? JWKSet result))
      (is (= 1 (count (.getKeys ^JWKSet result))))
      (is (= (.getKeyID ^RSAKey k)
             (.getKeyID ^RSAKey (first (.getKeys ^JWKSet result))))))))

(deftest normalize-jwk-set-passthrough-test
  (testing "existing JWKSet passes through unchanged"
    (let [k       (token/generate-rsa-key)
          jwk-set (JWKSet. ^com.nimbusds.jose.jwk.JWK k)
          result  (token/normalize-to-jwk-set jwk-set)]
      (is (identical? jwk-set result)))))

(defn- make-config
  [key-set active-kid]
  {:issuer                   "https://test.example.com"
   :key-set                  key-set
   :active-signing-key-id    active-kid
   :access-token-ttl-seconds 3600
   :clock                    (Clock/systemUTC)})

(deftest sign-with-active-key-test
  (testing "token kid header matches the active key's kid"
    (let [k1      (token/generate-rsa-key)
          k2      (token/generate-rsa-key)
          key-set (JWKSet. ^java.util.List (java.util.ArrayList. [k1 k2]))
          config  (make-config key-set (.getKeyID ^RSAKey k2))
          jwt-str (token/generate-id-token config "user-1" "client-1" {} {})
          parsed  (com.nimbusds.jwt.SignedJWT/parse jwt-str)]
      (is (= (.getKeyID ^RSAKey k2)
             (.getKeyID (.getHeader parsed)))))))

(deftest validate-with-correct-key-from-set-test
  (testing "validation auto-selects correct key by kid"
    (let [k1      (token/generate-rsa-key)
          k2      (token/generate-rsa-key)
          key-set (JWKSet. ^java.util.List (java.util.ArrayList. [k1 k2]))
          config  (make-config key-set (.getKeyID ^RSAKey k2))
          jwt-str (token/generate-id-token config "user-1" "client-1" {} {})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (= "user-1" (:sub claims))))))

(deftest validate-after-key-rotation-test
  (testing "token signed by old key validates when old key still in set"
    (let [old-key  (token/generate-rsa-key)
          new-key  (token/generate-rsa-key)
          old-set  (JWKSet. ^com.nimbusds.jose.jwk.JWK old-key)
          old-cfg  (make-config old-set (.getKeyID ^RSAKey old-key))
          jwt-str  (token/generate-id-token old-cfg "user-1" "client-1" {} {})
          both-set (JWKSet. ^java.util.List (java.util.ArrayList. [new-key old-key]))
          new-cfg  (make-config both-set (.getKeyID ^RSAKey new-key))
          claims   (token/validate-id-token new-cfg jwt-str "client-1")]
      (is (= "user-1" (:sub claims))))))

(deftest validate-fails-when-key-removed-test
  (testing "validation fails when signing key is no longer in set"
    (let [k1      (token/generate-rsa-key)
          k2      (token/generate-rsa-key)
          k1-set  (JWKSet. ^com.nimbusds.jose.jwk.JWK k1)
          cfg1    (make-config k1-set (.getKeyID ^RSAKey k1))
          jwt-str (token/generate-id-token cfg1 "user-1" "client-1" {} {})
          k2-set  (JWKSet. ^com.nimbusds.jose.jwk.JWK k2)
          cfg2    (make-config k2-set (.getKeyID ^RSAKey k2))]
      (is (thrown-with-msg? Exception #"Invalid token signature"
                            (token/validate-id-token cfg2 jwt-str "client-1"))))))

(deftest jwks-returns-all-public-keys-test
  (testing "JWKS output has correct count and no private material"
    (let [k1      (token/generate-rsa-key)
          k2      (token/generate-rsa-key)
          key-set (JWKSet. ^java.util.List (java.util.ArrayList. [k1 k2]))
          config  (make-config key-set (.getKeyID ^RSAKey k1))
          result  (token/jwks config)
          keys    (:keys result)]
      (is (= 2 (count keys)))
      (is (every? #(= "RSA" (:kty %)) keys))
      (is (every? #(nil? (:d %)) keys))
      (is (every? #(= "sig" (:use %)) keys)))))

(deftest validate-id-token-uses-injected-clock-test
  (testing "validation uses injected clock, not system clock"
    (let [k            (token/generate-rsa-key)
          key-set      (JWKSet. ^com.nimbusds.jose.jwk.JWK k)
          config       (make-config key-set (.getKeyID ^RSAKey k))
          jwt-str      (token/generate-id-token config "user-1" "client-1" {} {})
          future-clock (Clock/fixed (.plusSeconds (Instant/now) (* 365 24 3600))
                                    ZoneOffset/UTC)
          future-cfg   (assoc config :clock future-clock)]
      (is (thrown-with-msg? Exception #"Token expired"
                            (token/validate-id-token future-cfg jwt-str "client-1"))))))

(defn- single-key-config []
  (let [k       (token/generate-rsa-key)
        key-set (JWKSet. ^com.nimbusds.jose.jwk.JWK k)]
    (make-config key-set (.getKeyID ^RSAKey k))))

(deftest claims-provider-cannot-overwrite-sub-test
  (testing "ClaimsProvider returning :sub does not overwrite the ID token subject"
    (let [config  (single-key-config)
          jwt-str (token/generate-id-token config "user-1" "client-1" {:sub "evil"} {})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (= "user-1" (:sub claims))))))

(deftest claims-provider-cannot-overwrite-iss-test
  (testing "ClaimsProvider returning :iss does not change the issuer"
    (let [config  (single-key-config)
          jwt-str (token/generate-id-token config "user-1" "client-1" {:iss "https://evil.com"} {})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (= "https://test.example.com" (:iss claims))))))

(deftest claims-provider-cannot-overwrite-aud-test
  (testing "ClaimsProvider returning :aud does not change the audience"
    (let [config  (single-key-config)
          jwt-str (token/generate-id-token config "user-1" "client-1" {:aud "evil-client"} {})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (= ["client-1"] (:aud claims))))))

(deftest claims-provider-cannot-overwrite-nonce-test
  (testing "ClaimsProvider returning :nonce does not overwrite the real nonce"
    (let [config  (single-key-config)
          jwt-str (token/generate-id-token config "user-1" "client-1"
                                           {:nonce "evil-nonce"} {:nonce "real-nonce"})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (= "real-nonce" (:nonce claims))))))

(deftest custom-claims-passthrough-test
  (testing "custom claims from ClaimsProvider are included in the ID token"
    (let [config  (single-key-config)
          jwt-str (token/generate-id-token config "user-1" "client-1"
                                           {:email "a@b.com" :role "admin"} {})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (= "a@b.com" (:email claims)))
      (is (= "admin" (:role claims))))))

(deftest id-token-contains-azp-claim-test
  (testing "azp claim is set to client-id when :azp opt is true"
    (let [config  (single-key-config)
          jwt-str (token/generate-id-token config "user-1" "client-1" {} {:azp true})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (= "client-1" (:azp claims))))))

(deftest id-token-omits-azp-when-not-requested-test
  (testing "azp claim is absent when :azp opt is not provided"
    (let [config  (single-key-config)
          jwt-str (token/generate-id-token config "user-1" "client-1" {} {})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (nil? (:azp claims))))))

(deftest claims-provider-cannot-overwrite-azp-test
  (testing "ClaimsProvider returning :azp does not overwrite the authorized party"
    (let [config  (single-key-config)
          jwt-str (token/generate-id-token config "user-1" "client-1" {:azp "evil-client"} {:azp true})
          claims  (token/validate-id-token config jwt-str "client-1")]
      (is (= "client-1" (:azp claims))))))
