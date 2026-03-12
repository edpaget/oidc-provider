(ns oidc-provider.util
  "Shared utility functions for the OIDC provider.

  Includes [[constant-time-eq?]] for timing-safe string comparison,
  and [[hash-client-secret]] / [[verify-client-secret]] for PBKDF2-based
  client secret hashing suitable for production deployments."
  (:require
   [malli.core :as m])
  (:import
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

  Uses `java.security.SecureRandom` to produce a 32-byte (256-bit) base64url-encoded
  string. Integrators building admin APIs can use this to create client secrets that
  are consistent with those issued by [[oidc-provider.registration/handle-registration-request]]."
  []
  (let [bytes (byte-array 32)
        _     (.nextBytes (SecureRandom.) bytes)]
    (.encodeToString (Base64/getUrlEncoder) bytes)))

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
  secret matches, `false` otherwise."
  [^String secret ^String hashed]
  (let [[algorithm iterations-str salt-b64 hash-b64] (.split hashed ":" 4)
        salt                                         (.decode b64-decoder ^String salt-b64)
        expected                                     (.decode b64-decoder ^String hash-b64)
        iterations                                   (Integer/parseInt iterations-str)
        spec                                         (PBEKeySpec. (.toCharArray secret) salt iterations key-length-bits)
        actual                                       (.getEncoded (.generateSecret (SecretKeyFactory/getInstance algorithm) spec))]
    (MessageDigest/isEqual expected actual)))
