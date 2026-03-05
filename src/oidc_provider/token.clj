(ns oidc-provider.token
  "Token generation and validation using Nimbus OAuth SDK."
  (:require
   [cheshire.core :as json]
   [malli.core :as m])
  (:import
   [com.nimbusds.jose JWSAlgorithm JWSHeader$Builder]
   [com.nimbusds.jose.crypto RSASSASigner RSASSAVerifier]
   [com.nimbusds.jose.jwk RSAKey RSAKey$Builder]
   [com.nimbusds.jwt JWTClaimsSet JWTClaimsSet$Builder SignedJWT]
   [com.nimbusds.oauth2.sdk.token BearerAccessToken]
   [java.security KeyPairGenerator SecureRandom]
   [java.time Instant]
   [java.util Date UUID]))

(set! *warn-on-reflection* true)

(def ProviderConfig
  "Malli schema for OIDC provider configuration."
  [:map
   [:issuer :string]
   [:signing-key [:fn (fn [k] (instance? RSAKey k))]]
   [:access-token-ttl-seconds {:optional true} pos-int?]
   [:id-token-ttl-seconds {:optional true} pos-int?]
   [:authorization-code-ttl-seconds {:optional true} pos-int?]])

(defn generate-rsa-key
  "Generates an RSA key pair for signing tokens.

  Args:
    key-size: Key size in bits (default 2048)

  Returns:
    RSAKey instance"
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
         (.keyID (str (UUID/randomUUID))))
       (.build builder)))))

(defn- add-seconds
  [seconds]
  (Date/from (.plusSeconds (Instant/now) seconds)))

(defn generate-id-token
  "Generates a signed OIDC ID token.

  Args:
    provider-config: Provider configuration map matching ProviderConfig schema
    user-id: User identifier (becomes 'sub' claim)
    client-id: OAuth2 client identifier (becomes 'aud' claim)
    claims: Additional claims map to include in the token
    opts: Optional parameters
      - :nonce - Nonce value for replay protection
      - :auth-time - Authentication timestamp

  Returns:
    Signed JWT string"
  [{:keys [issuer signing-key id-token-ttl-seconds] :as config}
   user-id client-id claims
   {:keys [nonce auth-time]}]
  {:pre [(m/validate ProviderConfig config)]}
  (let [ttl                           (or id-token-ttl-seconds 3600)
        ^JWTClaimsSet$Builder builder (JWTClaimsSet$Builder.)]
    (doto builder
      (.issuer issuer)
      (.subject user-id)
      (.audience (java.util.Arrays/asList (into-array String [client-id])))
      (.expirationTime ^Date (add-seconds ttl))
      (.issueTime ^Date (Date/from (Instant/now))))
    (when nonce
      (.claim builder "nonce" nonce))
    (when auth-time
      (.claim builder "auth_time" (long auth-time)))
    (doseq [[k v] claims]
      (.claim builder (name k) v))
    (let [claims-set            (.build builder)
          ^RSAKey signing-key'  signing-key
          header                (-> (JWSHeader$Builder. JWSAlgorithm/RS256)
                                    (.keyID (.getKeyID signing-key'))
                                    (.build))
          ^SignedJWT signed-jwt (SignedJWT. header claims-set)
          signer                (RSASSASigner. signing-key')]
      (.sign signed-jwt signer)
      (.serialize signed-jwt))))

(defn generate-access-token
  "Generates a bearer access token.

  Returns:
    String token value"
  []
  (.getValue (BearerAccessToken.)))

(defn generate-refresh-token
  "Generates a refresh token.

  Returns:
    String token value"
  []
  (str (UUID/randomUUID)))

(defn generate-authorization-code
  "Generates an authorization code.

  Returns:
    String code value"
  []
  (str (UUID/randomUUID)))

(defn validate-id-token
  "Validates an ID token signature and claims.

  Args:
    provider-config: Provider configuration map
    token: ID token string
    expected-client-id: Expected audience (client-id)

  Returns:
    Validated claims map

  Throws:
    ex-info on validation failure"
  [{:keys [issuer signing-key] :as config} token expected-client-id]
  {:pre [(m/validate ProviderConfig config)]}
  (let [^SignedJWT signed-jwt (SignedJWT/parse ^String token)
        ^RSAKey signing-key'  signing-key
        verifier              (RSASSAVerifier. (.toPublicJWK signing-key'))]
    (when-not (.verify signed-jwt verifier)
      (throw (ex-info "Invalid token signature" {:token token})))
    (let [^JWTClaimsSet claims (.getJWTClaimsSet signed-jwt)
          issuer-val           (.getIssuer claims)
          audience             (.getAudience claims)
          ^Date expiry         (.getExpirationTime claims)
          now                  (Date.)]
      (when-not (= issuer-val issuer)
        (throw (ex-info "Issuer mismatch"
                        {:expected issuer
                         :actual issuer-val})))
      (when-not (some #{expected-client-id} audience)
        (throw (ex-info "Audience mismatch"
                        {:expected expected-client-id
                         :actual audience})))
      (when (.before expiry now)
        (throw (ex-info "Token expired"
                        {:expiry expiry
                         :now now})))
      (into {} (map (fn [[k v]] [(keyword k) v]))
            (.getClaims claims)))))

(defn jwks
  "Returns JWKS (JSON Web Key Set) for token validation.

  Args:
    provider-config: Provider configuration map

  Returns:
    Map with :keys vector containing public key in JWK format"
  [{:keys [signing-key] :as config}]
  {:pre [(m/validate ProviderConfig config)]}
  (let [^RSAKey signing-key' signing-key]
    {:keys [(json/parse-string
             (.toJSONString (.toPublicJWK signing-key'))
             true)]}))
