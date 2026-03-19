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

(deftest valid-redirect-uri-test
  (testing "accepts HTTPS URIs"
    (is (true? (util/valid-redirect-uri? "https://example.com/callback"))))
  (testing "accepts HTTP on localhost, 127.0.0.1, and IPv6 loopback"
    (is (true? (util/valid-redirect-uri? "http://localhost/callback")))
    (is (true? (util/valid-redirect-uri? "http://127.0.0.1/callback")))
    (is (true? (util/valid-redirect-uri? "http://[::1]/callback"))))
  (testing "accepts bare ::1 host form returned by some JDK URI#getHost implementations"
    (is (true? (util/valid-redirect-uri? "http://[::1]:8080/callback"))))
  (testing "rejects HTTP on non-localhost hosts"
    (is (false? (util/valid-redirect-uri? "http://example.com/callback"))))
  (testing "rejects relative URIs and malformed strings"
    (is (false? (util/valid-redirect-uri? "/callback")))
    (is (false? (util/valid-redirect-uri? "not a uri!!")))))

(deftest valid-redirect-uri-https-only-test
  (testing "accepts HTTPS URIs"
    (is (true? (util/valid-redirect-uri-https-only? "https://example.com/callback"))))
  (testing "rejects HTTP even on loopback addresses"
    (is (false? (util/valid-redirect-uri-https-only? "http://localhost/callback")))
    (is (false? (util/valid-redirect-uri-https-only? "http://127.0.0.1/callback")))
    (is (false? (util/valid-redirect-uri-https-only? "http://[::1]/callback"))))
  (testing "rejects relative URIs and malformed strings"
    (is (false? (util/valid-redirect-uri-https-only? "/callback")))
    (is (false? (util/valid-redirect-uri-https-only? "not a uri!!")))))

(deftest truncate-test
  (testing "truncates strings to max-len"
    (is (= "hi" (util/truncate "hi" 10)))
    (is (= "hello" (util/truncate "hello" 5)))
    (is (= "hello w..." (util/truncate "hello world" 10)))
    (is (= "..." (util/truncate "hello" 3)))
    (is (= ".." (util/truncate "hello" 2)))
    (is (= "" (util/truncate "hello" 0)))
    (is (= "" (util/truncate nil 10)))))
