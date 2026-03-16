(ns oidc-provider.revocation-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.protocol :as proto]
   [oidc-provider.revocation :as revocation]
   [oidc-provider.store :as store]
   [oidc-provider.util :as util]))

(defn- make-fixtures []
  (let [client-store (store/create-client-store
                      [{:client-id          "test-client"
                        :client-type        "confidential"
                        :client-secret-hash (util/hash-client-secret "secret123")
                        :redirect-uris      ["https://app.example.com/callback"]
                        :grant-types        ["authorization_code" "refresh_token"]
                        :response-types     ["code"]
                        :scopes             ["openid"]}])
        token-store  (store/create-token-store)
        auth-header  (str "Basic " (.encodeToString
                                    (java.util.Base64/getEncoder)
                                    (.getBytes "test-client:secret123" "UTF-8")))]
    {:client-store client-store
     :token-store  token-store
     :auth-header  auth-header}))

(deftest revoke-access-token-test
  (testing "revokes an access token and returns 200"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)]
      (proto/save-access-token token-store "at-123" "user-1" "test-client" ["openid"] 999999999999 nil)
      (let [result (revocation/handle-revocation-request
                    {:token "at-123" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (nil? (proto/get-access-token token-store "at-123")))))))

(deftest revoke-refresh-token-test
  (testing "revokes a refresh token and returns 200"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)]
      (proto/save-refresh-token token-store "rt-123" "user-1" "test-client" ["openid"] nil nil)
      (let [result (revocation/handle-revocation-request
                    {:token "rt-123" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (nil? (proto/get-refresh-token token-store "rt-123")))))))

(deftest revoke-unknown-token-test
  (testing "returns 200 for unknown token per RFC 7009"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)
          result                                         (revocation/handle-revocation-request
                                                          {:token "nonexistent" :client_id "test-client"}
                                                          auth-header client-store token-store)]
      (is (= 200 (:status result))))))

(deftest revoke-missing-token-param-test
  (testing "returns 400 when token parameter is missing"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)
          result                                         (revocation/handle-revocation-request
                                                          {:client_id "test-client"}
                                                          auth-header client-store token-store)]
      (is (= 400 (:status result))))))

(deftest revoke-unauthenticated-test
  (testing "returns 401 when client authentication fails"
    (let [{:keys [client-store token-store]} (make-fixtures)
          bad-auth                           (str "Basic " (.encodeToString
                                                            (java.util.Base64/getEncoder)
                                                            (.getBytes "test-client:wrong" "UTF-8")))
          result                             (revocation/handle-revocation-request
                                              {:token "at-123" :client_id "test-client"}
                                              bad-auth client-store token-store)]
      (is (= 401 (:status result))))))
