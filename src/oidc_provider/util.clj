(ns oidc-provider.util
  "Shared utility functions for the OIDC provider."
  (:import
   (java.security MessageDigest)))

(set! *warn-on-reflection* true)

(defn constant-time-eq?
  "Compares two strings in constant time using `MessageDigest/isEqual`
  to prevent timing side-channel attacks."
  [^String a ^String b]
  (MessageDigest/isEqual (.getBytes a "UTF-8") (.getBytes b "UTF-8")))
