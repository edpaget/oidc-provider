(ns oidc-provider.util-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.util :as util]))

(deftest hash-client-secret-produces-verifiable-hash-test
  (testing "a hashed secret round-trips through verify"
    (let [secret "my-client-secret"
          hashed (util/hash-client-secret secret)]
      (is (true? (util/verify-client-secret secret hashed))))))

(deftest verify-client-secret-rejects-wrong-secret-test
  (testing "verify returns false for the wrong plaintext"
    (let [hashed (util/hash-client-secret "correct-secret")]
      (is (false? (util/verify-client-secret "wrong-secret" hashed))))))

(deftest verify-client-secret-malformed-hash-test
  (testing "returns false for a malformed hash string"
    (is (false? (util/verify-client-secret "anything" "garbage")))))

(deftest hash-client-secret-unique-salts-test
  (testing "hashing the same secret twice produces different encoded strings"
    (let [secret "same-secret"
          hash-a (util/hash-client-secret secret)
          hash-b (util/hash-client-secret secret)]
      (is (not= hash-a hash-b))
      (is (true? (util/verify-client-secret secret hash-a)))
      (is (true? (util/verify-client-secret secret hash-b))))))

(deftest valid-web-redirect-uri-test
  (testing "accepts HTTPS URIs, rejects HTTP loopback, HTTP non-localhost, and custom schemes"
    (is (true? (util/valid-web-redirect-uri? "https://example.com/callback")))
    (is (false? (util/valid-web-redirect-uri? "http://localhost/callback")))
    (is (false? (util/valid-web-redirect-uri? "http://example.com/callback")))
    (is (false? (util/valid-web-redirect-uri? "cursor://callback")))
    (is (false? (util/valid-web-redirect-uri? "/callback")))))

(deftest valid-web-redirect-uri-rejects-fragment-test
  (testing "rejects HTTPS URIs with fragment components per RFC 6749 §3.1.2"
    (is (false? (util/valid-web-redirect-uri? "https://example.com/cb#frag")))))

(deftest valid-native-redirect-uri-accepts-custom-scheme-test
  (testing "accepts custom URI schemes for native clients"
    (is (true? (util/valid-native-redirect-uri? "cursor://callback")))
    (is (true? (util/valid-native-redirect-uri? "com.example.app://callback/path")))
    (is (true? (util/valid-native-redirect-uri? "vscode://vscode.github-authentication/did-authenticate")))))

(deftest valid-native-redirect-uri-accepts-loopback-test
  (testing "accepts HTTP on localhost, 127.0.0.1, and [::1]"
    (is (true? (util/valid-native-redirect-uri? "http://localhost/callback")))
    (is (true? (util/valid-native-redirect-uri? "http://127.0.0.1/callback")))
    (is (true? (util/valid-native-redirect-uri? "http://[::1]/callback")))
    (is (true? (util/valid-native-redirect-uri? "http://[::1]:8080/callback")))))

(deftest valid-native-redirect-uri-rejects-fragment-test
  (testing "rejects URIs with fragments for all URI types per RFC 6749 §3.1.2"
    (is (false? (util/valid-native-redirect-uri? "cursor://callback#fragment")))
    (is (false? (util/valid-native-redirect-uri? "https://example.com/cb#frag")))
    (is (false? (util/valid-native-redirect-uri? "http://localhost/cb#frag")))))

(deftest valid-native-redirect-uri-rejects-http-non-loopback-test
  (testing "rejects HTTP on non-loopback hosts"
    (is (false? (util/valid-native-redirect-uri? "http://evil.com/callback")))))

(deftest valid-redirect-uri-https-only-accepts-https-test
  (testing "accepts HTTPS URIs"
    (is (true? (util/valid-redirect-uri-https-only? "https://example.com/callback")))))

(deftest valid-redirect-uri-https-only-rejects-http-loopback-test
  (testing "rejects HTTP even on loopback addresses"
    (is (false? (util/valid-redirect-uri-https-only? "http://localhost/callback")))
    (is (false? (util/valid-redirect-uri-https-only? "http://127.0.0.1/callback")))
    (is (false? (util/valid-redirect-uri-https-only? "http://[::1]/callback")))))

(deftest valid-redirect-uri-https-only-rejects-fragment-test
  (testing "rejects HTTPS URIs with fragment components per RFC 6749 §3.1.2"
    (is (false? (util/valid-redirect-uri-https-only? "https://example.com/cb#frag")))))

(deftest valid-redirect-uri-https-only-rejects-relative-test
  (testing "rejects relative URIs and malformed strings"
    (is (false? (util/valid-redirect-uri-https-only? "/callback")))
    (is (false? (util/valid-redirect-uri-https-only? "not a uri!!")))))

(deftest hash-token-deterministic-test
  (testing "same input always produces the same hash"
    (let [token "abc123"
          hash1 (util/hash-token token)
          hash2 (util/hash-token token)]
      (is (= hash1 hash2)))))

(deftest hash-token-different-inputs-test
  (testing "different inputs produce different hashes"
    (is (not= (util/hash-token "token-a") (util/hash-token "token-b")))))

(deftest hash-token-base64url-format-test
  (testing "output is base64url without padding"
    (let [h (util/hash-token "some-random-token")]
      (is (not (re-find #"[+/=]" h)))
      (is (re-matches #"[A-Za-z0-9_-]+" h)))))

(deftest truncate-test
  (testing "truncates strings to max-len"
    (is (= "hi" (util/truncate "hi" 10)))
    (is (= "hello" (util/truncate "hello" 5)))
    (is (= "hello w..." (util/truncate "hello world" 10)))
    (is (= "..." (util/truncate "hello" 3)))
    (is (= ".." (util/truncate "hello" 2)))
    (is (= "" (util/truncate "hello" 0)))
    (is (= "" (util/truncate nil 10)))))

(deftest validate-issuer-accepts-https-test
  (testing "valid HTTPS issuer passes"
    (is (nil? (util/validate-issuer "https://example.com" false)))))

(deftest validate-issuer-accepts-https-with-path-test
  (testing "HTTPS issuer with path passes"
    (is (nil? (util/validate-issuer "https://example.com/tenant/123" false)))))

(deftest validate-issuer-rejects-http-test
  (testing "HTTP issuer is rejected by default"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"https scheme"
         (util/validate-issuer "http://example.com" false)))))

(deftest validate-issuer-rejects-query-test
  (testing "issuer with query component is rejected"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"query component"
         (util/validate-issuer "https://example.com?q=1" false)))))

(deftest validate-issuer-rejects-fragment-test
  (testing "issuer with fragment component is rejected"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"fragment component"
         (util/validate-issuer "https://example.com#frag" false)))))

(deftest validate-issuer-rejects-malformed-uri-test
  (testing "malformed URI is rejected"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"not a valid URI"
         (util/validate-issuer ":/not valid" false)))))

(deftest validate-issuer-rejects-relative-uri-test
  (testing "relative URI is rejected"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"absolute URI"
         (util/validate-issuer "example.com" false)))))

(deftest validate-issuer-rejects-ftp-scheme-test
  (testing "non-http/https scheme is rejected"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"https scheme"
         (util/validate-issuer "ftp://example.com" false)))))

(deftest validate-issuer-allows-http-when-opted-in-test
  (testing "HTTP issuer passes with allow-http? true"
    (is (nil? (util/validate-issuer "http://localhost" true)))))

(deftest validate-issuer-rejects-ftp-even-with-allow-http-test
  (testing "non-http/https scheme is rejected even with allow-http?"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"https scheme"
         (util/validate-issuer "ftp://example.com" true)))))
