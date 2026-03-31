(ns oidc-provider.token
  "Token generation and validation using Nimbus OAuth SDK."
  (:require
   [cheshire.core :as json]
   [malli.core :as m])
  (:import
   [com.nimbusds.jose JWSAlgorithm JWSHeader$Builder]
   [com.nimbusds.jose.crypto RSASSASigner]
   [com.nimbusds.jose.jwk JWKSet KeyUse RSAKey RSAKey$Builder]
   [com.nimbusds.jose.jwk.source ImmutableJWKSet]
   [com.nimbusds.jose.proc BadJOSEException JWSVerificationKeySelector]
   [com.nimbusds.jwt JWTClaimsSet JWTClaimsSet$Builder SignedJWT]
   [com.nimbusds.jwt.proc DefaultJWTProcessor]
   [com.nimbusds.oauth2.sdk AuthorizationCode]
   [com.nimbusds.oauth2.sdk.token BearerAccessToken RefreshToken]
   [com.nimbusds.openid.connect.sdk.claims AccessTokenHash]
   [java.security KeyPairGenerator SecureRandom]
   [java.time Clock Instant]
   [java.util Date UUID]))

(set! *warn-on-reflection* true)

(def ProviderConfig
  "Malli schema for OIDC provider configuration."
  [:map
   [:issuer :string]
   [:key-set {:optional true} [:fn (fn [ks] (instance? JWKSet ks))]]
   [:active-signing-key-id {:optional true} :string]
   [:access-token-ttl-seconds {:optional true} pos-int?]
   [:id-token-ttl-seconds {:optional true} pos-int?]
   [:authorization-code-ttl-seconds {:optional true} pos-int?]
   [:refresh-token-ttl-seconds {:optional true} pos-int?]
   [:rotate-refresh-tokens {:optional true} :boolean]
   [:clock [:fn (fn [c] (instance? Clock c))]]])

(defn generate-rsa-key
  "Generates an RSA key pair for signing tokens. The `key-size` parameter
  specifies the key size in bits and defaults to 2048 when called with no
  arguments. Returns an `RSAKey` instance configured for signature use."
  ([]
   (generate-rsa-key 2048))
  ([key-size]
   (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "RSA")]
     (.initialize generator ^int key-size (SecureRandom.))
     (let [key-pair                                       (.generateKeyPair generator)
           ^java.security.interfaces.RSAPublicKey pub-key (.getPublic key-pair)
           ^RSAKey$Builder builder                        (RSAKey$Builder. pub-key)]
       (doto builder
         (.privateKey (.getPrivate key-pair))
         (.keyID (str (UUID/randomUUID)))
         (.keyUse KeyUse/SIGNATURE))
       (.build builder)))))

(defn normalize-to-jwk-set
  "Normalizes a key input to a `JWKSet`. If the input is already a `JWKSet`, it
  passes through unchanged. If it is a single `RSAKey`, it wraps it in a
  one-element `JWKSet`."
  [key-or-set]
  (if (instance? JWKSet key-or-set)
    key-or-set
    (JWKSet. ^com.nimbusds.jose.jwk.JWK key-or-set)))

(defn- active-signing-key
  [^JWKSet key-set ^String kid]
  (let [^RSAKey k (.getKeyByKeyId key-set kid)]
    (when-not k
      (throw (ex-info "Active signing key not found in key set" {:kid kid})))
    k))

(defn- add-seconds
  [^Clock clock seconds]
  (Date/from (.plusSeconds (Instant/now clock) seconds)))

(def ^:private protected-claims
  "Claim names managed by the provider that must not be overwritten by ClaimsProvider."
  #{"iss" "sub" "aud" "exp" "iat" "nonce" "auth_time" "azp" "at_hash"})

(defn generate-id-token
  "Generates a signed OIDC ID token as a JWT string. Takes a `provider-config`
  map (matching the `ProviderConfig` schema), a `user-id` (set as the `sub`
  claim), a `client-id` (set as the `aud` claim), a `claims` map of additional
  claims to include, and an `opts` map supporting `:nonce` for replay protection,
  `:auth-time` for the authentication timestamp, `:azp` to include the authorized
  party claim per OIDC Core §2, and `:access-token` to compute the `at_hash` claim
  per OIDC Core §3.1.3.6."
  [{:keys [issuer key-set active-signing-key-id id-token-ttl-seconds clock] :as config}
   user-id client-id claims
   {:keys [nonce auth-time azp access-token]}]
  {:pre [(m/validate ProviderConfig config)]}
  (when-not key-set
    (throw (ex-info "Signing key required for ID token generation; configure :signing-key or :signing-keys" {})))
  (let [ttl                           (or id-token-ttl-seconds 3600)
        ^JWTClaimsSet$Builder builder (JWTClaimsSet$Builder.)]
    (doto builder
      (.issuer issuer)
      (.subject user-id)
      (.audience (java.util.Arrays/asList (into-array String [client-id])))
      (.expirationTime ^Date (add-seconds clock ttl))
      (.issueTime ^Date (Date/from (Instant/now clock))))
    (when azp
      (.claim builder "azp" client-id))
    (when access-token
      (.claim builder "at_hash"
              (.getValue (AccessTokenHash/compute (BearerAccessToken. ^String access-token) JWSAlgorithm/RS256))))
    (when nonce
      (.claim builder "nonce" nonce))
    (when auth-time
      (.claim builder "auth_time" (long auth-time)))
    (doseq [[k v] (remove (fn [[k _]] (protected-claims (name k))) claims)]
      (.claim builder (name k) v))
    (let [claims-set            (.build builder)
          ^RSAKey signing-key   (active-signing-key key-set active-signing-key-id)
          header                (-> (JWSHeader$Builder. JWSAlgorithm/RS256)
                                    (.keyID (.getKeyID signing-key))
                                    (.build))
          ^SignedJWT signed-jwt (SignedJWT. header claims-set)
          signer                (RSASSASigner. signing-key)]
      (.sign signed-jwt signer)
      (.serialize signed-jwt))))

(defn generate-access-token
  "Generates a bearer access token and returns its string value."
  []
  (.getValue (BearerAccessToken.)))

(defn generate-refresh-token
  "Generates a cryptographically random refresh token using the Nimbus SDK
  `RefreshToken` class, which produces a 256-bit `SecureRandom` base64url value."
  []
  (.getValue (RefreshToken.)))

(defn generate-authorization-code
  "Generates a cryptographically random authorization code using the Nimbus SDK
  `AuthorizationCode` class, which produces a 256-bit `SecureRandom` base64url value."
  []
  (.getValue (AuthorizationCode.)))

(defn validate-id-token
  "Validates an ID token's signature and claims against the given
  `provider-config`. Verifies that the `token` string was signed with a key from
  the provider's key set, that the issuer matches, that `expected-client-id`
  appears in the audience, and that the token has not expired. Returns the
  validated claims as a keyword map, or throws `ex-info` on failure."
  [{:keys [issuer key-set clock] :as config} token expected-client-id]
  {:pre [(m/validate ProviderConfig config)]}
  (when-not key-set
    (throw (ex-info "Signing key required for ID token validation; configure :signing-key or :signing-keys" {})))
  (let [^DefaultJWTProcessor processor (DefaultJWTProcessor.)
        key-selector                   (JWSVerificationKeySelector.
                                        JWSAlgorithm/RS256
                                        (ImmutableJWKSet. ^JWKSet key-set))]
    (.setJWSKeySelector processor key-selector)
    (let [^JWTClaimsSet claims (try
                                 (.process processor ^String token nil)
                                 (catch BadJOSEException e
                                   (throw (ex-info "Invalid token signature"
                                                   {:token token} e))))
          issuer-val           (.getIssuer claims)
          audience             (.getAudience claims)
          ^Date expiry         (.getExpirationTime claims)
          now                  (Date/from (.instant ^Clock clock))]
      (when-not (= issuer-val issuer)
        (throw (ex-info "Issuer mismatch"
                        {:expected issuer
                         :actual   issuer-val})))
      (when-not (some #{expected-client-id} audience)
        (throw (ex-info "Audience mismatch"
                        {:expected expected-client-id
                         :actual   audience})))
      (when (.before expiry now)
        (throw (ex-info "Token expired"
                        {:expiry expiry
                         :now    now})))
      (into {} (map (fn [[k v]] [(keyword k) v]))
            (.getClaims claims)))))

(defn jwks
  "Returns the JWKS (JSON Web Key Set) for the given `provider-config` as a map
  with a `:keys` vector containing the public keys in JWK format, suitable for
  exposing at the `jwks_uri` discovery endpoint."
  [{:keys [key-set] :as config}]
  {:pre [(m/validate ProviderConfig config)]}
  (if key-set
    {:keys (->> (.getKeys ^JWKSet key-set)
                (mapv (fn [k] (json/parse-string
                               (.toJSONString (.toPublicJWK ^RSAKey k))
                               true))))}
    {:keys []}))
