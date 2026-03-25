(ns oidc-provider.util
  "Shared utility functions for the OIDC provider.

  Includes [[constant-time-eq?]] for timing-safe string comparison,
  [[hash-client-secret]] / [[verify-client-secret]] for PBKDF2-based
  client secret hashing, and [[valid-web-redirect-uri?]] /
  [[valid-native-redirect-uri?]] for redirect URI validation split by
  `application_type` per OpenID Connect Dynamic Client Registration 1.0."
  (:require
   [clojure.string :as str]
   [malli.core :as m])
  (:import
   (com.nimbusds.oauth2.sdk.auth Secret)
   (java.net URI URISyntaxException)
   (java.security MessageDigest SecureRandom)
   (java.util Base64 UUID)
   (javax.crypto SecretKeyFactory)
   (javax.crypto.spec PBEKeySpec)))

(set! *warn-on-reflection* true)

(defn constant-time-eq?
  "Compares two strings in constant time using `MessageDigest/isEqual`
  to prevent timing side-channel attacks."
  [^String a ^String b]
  (MessageDigest/isEqual (.getBytes a "UTF-8") (.getBytes b "UTF-8")))

(m/=> generate-client-secret [:=> [:cat] :string])

(defn generate-client-secret
  "Generates a cryptographically random client secret suitable for OAuth2 confidential clients.

  Delegates to the Nimbus SDK `Secret` class, which produces a 256-bit `SecureRandom`
  base64url-encoded value. Integrators building admin APIs can use this to create client
  secrets that are consistent with those issued by
  [[oidc-provider.registration/handle-registration-request]]."
  []
  (.getValue (Secret.)))

(m/=> generate-client-id [:=> [:cat] :string])

(defn generate-client-id
  "Generates a unique client identifier as a random UUID string."
  []
  (str (UUID/randomUUID)))

(def ^:private pbkdf2-algorithm "PBKDF2WithHmacSHA256")
(def ^:private pbkdf2-iterations 310000)
(def ^:private salt-bytes 20)
(def ^:private key-length-bits 256)

(def ^:private ^java.util.Base64$Encoder b64-encoder (Base64/getEncoder))
(def ^:private ^java.util.Base64$Decoder b64-decoder (Base64/getDecoder))

(m/=> hash-client-secret [:=> [:cat :string] :string])

(defn hash-client-secret
  "Hashes a client secret using PBKDF2WithHmacSHA256 with a random 160-bit salt
  and 310,000 iterations per OWASP recommendations.

  Returns an encoded string in the format `algorithm:iterations:salt:hash` where
  binary values are base64-encoded. Use [[verify-client-secret]] to check a
  plaintext secret against the returned hash."
  [^String secret]
  (let [salt (byte-array salt-bytes)
        _    (.nextBytes (SecureRandom.) salt)
        spec (PBEKeySpec. (.toCharArray secret) salt pbkdf2-iterations key-length-bits)
        hash (.getEncoded (.generateSecret (SecretKeyFactory/getInstance pbkdf2-algorithm) spec))]
    (str pbkdf2-algorithm
         ":" pbkdf2-iterations
         ":" (.encodeToString b64-encoder salt)
         ":" (.encodeToString b64-encoder hash))))

(m/=> verify-client-secret [:=> [:cat :string :string] :boolean])

(defn verify-client-secret
  "Verifies a plaintext `secret` against a `hashed` string produced by
  [[hash-client-secret]].

  Parses the encoded `algorithm:iterations:salt:hash` format, re-derives the key
  with the same parameters, and compares in constant time. Returns `true` if the
  secret matches, `false` otherwise. Returns `false` on malformed hash input."
  [^String secret ^String hashed]
  (try
    (let [[algorithm iterations-str salt-b64 hash-b64] (.split hashed ":" 4)
          salt                                         (.decode b64-decoder ^String salt-b64)
          expected                                     (.decode b64-decoder ^String hash-b64)
          iterations                                   (Integer/parseInt iterations-str)
          spec                                         (PBEKeySpec. (.toCharArray secret) salt iterations key-length-bits)
          actual                                       (.getEncoded (.generateSecret (SecretKeyFactory/getInstance algorithm) spec))]
      (MessageDigest/isEqual expected actual))
    (catch Exception _ false)))

(defn- loopback-host?
  "Returns true when `host` is a loopback address: localhost, 127.0.0.1, or [::1]."
  [^String host]
  (or (= host "localhost")
      (= host "127.0.0.1")
      (contains? #{"[::1]" "::1"} host)))

(defn- custom-scheme-uri?
  "Returns true when `uri` uses a non-HTTP/HTTPS scheme, is absolute, and has no fragment."
  [^URI uri ^String scheme]
  (and (not (contains? #{"http" "https"} scheme))
       (.isAbsolute uri)
       (nil? (.getFragment uri))))

(m/=> valid-web-redirect-uri? [:=> [:cat :string] :boolean])

(defn valid-web-redirect-uri?
  "Returns true when `uri-str` is an absolute HTTPS URI with a host.
  For `application_type` `\"web\"` clients per OpenID Connect Dynamic Client Registration."
  [uri-str]
  (try
    (let [uri    (URI. ^String uri-str)
          scheme (some-> (.getScheme uri) str/lower-case)]
      (and (.isAbsolute uri)
           (some? (.getHost uri))
           (= scheme "https")))
    (catch URISyntaxException _ false)))

(m/=> valid-native-redirect-uri? [:=> [:cat :string] :boolean])

(defn valid-native-redirect-uri?
  "Returns true when `uri-str` is a valid redirect URI for `application_type` `\"native\"` clients.
  Accepts HTTPS, HTTP on loopback (localhost/127.0.0.1/[::1]), or custom URI schemes
  (e.g., `cursor://callback`) per RFC 8252 Section 7.1. Rejects URIs with fragments per
  RFC 6749 Section 3.1.2."
  [uri-str]
  (try
    (let [uri    (URI. ^String uri-str)
          scheme (some-> (.getScheme uri) str/lower-case)
          host   (some-> (.getHost uri) str/lower-case)]
      (or (and (= scheme "https")
               (.isAbsolute uri)
               (some? host))
          (and (= scheme "http")
               (loopback-host? host)
               (.isAbsolute uri))
          (custom-scheme-uri? uri scheme)))
    (catch URISyntaxException _ false)))

(m/=> valid-redirect-uri-https-only? [:=> [:cat :string] :boolean])

(defn valid-redirect-uri-https-only?
  "Returns true when `uri-str` is an absolute URI with HTTPS scheme only.
  Unlike [[valid-native-redirect-uri?]], this rejects HTTP even on loopback addresses.
  Intended for metadata-document clients where HTTPS is strictly required."
  [uri-str]
  (try
    (let [uri    (URI. ^String uri-str)
          scheme (some-> (.getScheme uri) str/lower-case)]
      (and (.isAbsolute uri)
           (some? (.getHost uri))
           (= scheme "https")))
    (catch URISyntaxException _ false)))

(m/=> validate-issuer [:=> [:cat :string :boolean] :nil])

(defn validate-issuer
  "Validates that `issuer-str` is a well-formed issuer identifier per RFC 8414 §2.
  The issuer must be an absolute HTTPS URL with a host and no query or fragment
  component. When `allow-http?` is true, HTTP scheme is also accepted (useful for
  local development). Throws `ex-info` with an `:invalid-issuer` error on failure."
  [issuer-str allow-http?]
  (try
    (let [uri    (URI. ^String issuer-str)
          scheme (some-> (.getScheme uri) str/lower-case)]
      (when-not (.isAbsolute uri)
        (throw (ex-info "Issuer must be an absolute URI" {:issuer issuer-str :error :invalid-issuer})))
      (when-not (some? (.getHost uri))
        (throw (ex-info "Issuer must have a host" {:issuer issuer-str :error :invalid-issuer})))
      (when (some? (.getQuery uri))
        (throw (ex-info "Issuer must not contain a query component" {:issuer issuer-str :error :invalid-issuer})))
      (when (some? (.getFragment uri))
        (throw (ex-info "Issuer must not contain a fragment component" {:issuer issuer-str :error :invalid-issuer})))
      (when-not (if allow-http?
                  (contains? #{"http" "https"} scheme)
                  (= scheme "https"))
        (throw (ex-info "Issuer must use the https scheme" {:issuer issuer-str :error :invalid-issuer}))))
    (catch URISyntaxException _
      (throw (ex-info "Issuer is not a valid URI" {:issuer issuer-str :error :invalid-issuer})))))

(m/=> hash-token [:=> [:cat :string] :string])

(defn hash-token
  "Computes a SHA-256 digest of `token` and returns it as a base64url string
  without padding.

  Intended for hashing high-entropy opaque tokens (access tokens, refresh
  tokens, authorization codes) before storage. Unlike [[hash-client-secret]],
  no salt or key-stretching is needed because the input is already 256-bit
  random."
  [^String token]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder))
                   (.digest (MessageDigest/getInstance "SHA-256")
                            (.getBytes token "UTF-8"))))

(m/=> truncate [:=> [:cat [:maybe :string] :int] :string])

(defn truncate
  "Returns `s` truncated to at most `max-len` characters, appending `\"...\"`
  when truncation occurs."
  [s max-len]
  (if (nil? s)
    ""
    (cond
      (<= max-len 0)         ""
      (<= (count s) max-len) s
      (< max-len 3)          (subs "..." 0 max-len)
      :else                  (str (subs s 0 (- max-len 3)) "..."))))
