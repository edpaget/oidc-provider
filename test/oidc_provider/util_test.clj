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

(deftest hash-client-secret-unique-salts-test
  (testing "hashing the same secret twice produces different encoded strings"
    (let [secret "same-secret"
          hash-a (util/hash-client-secret secret)
          hash-b (util/hash-client-secret secret)]
      (is (not= hash-a hash-b))
      (is (true? (util/verify-client-secret secret hash-a)))
      (is (true? (util/verify-client-secret secret hash-b))))))
