(ns oidc-provider.revocation-test
  (:require
   [clojure.test :refer [deftest is testing]]
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
      (store/save-access-token token-store "at-123" "user-1" "test-client" ["openid"] 999999999999 nil)
      (let [result (revocation/handle-revocation-request
                    {:token "at-123" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (nil? (store/get-access-token token-store "at-123")))))))

(deftest revoke-refresh-token-test
  (testing "revokes a refresh token and returns 200"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)]
      (store/save-refresh-token token-store "rt-123" "user-1" "test-client" ["openid"] nil nil)
      (let [result (revocation/handle-revocation-request
                    {:token "rt-123" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (nil? (store/get-refresh-token token-store "rt-123")))))))

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

(deftest revoke-other-clients-access-token-test
  (testing "cannot revoke another client's access token"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)]
      (store/save-access-token token-store "at-other" "user-1" "other-client" ["openid"] 999999999999 nil)
      (let [result (revocation/handle-revocation-request
                    {:token "at-other" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (some? (store/get-access-token token-store "at-other")))))))

(deftest revoke-other-clients-refresh-token-test
  (testing "cannot revoke another client's refresh token"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)]
      (store/save-refresh-token token-store "rt-other" "user-1" "other-client" ["openid"] nil nil)
      (let [result (revocation/handle-revocation-request
                    {:token "rt-other" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (some? (store/get-refresh-token token-store "rt-other")))))))

(deftest revoke-missing-token-error-body-test
  (testing "400 response includes error body and cache-control headers"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)
          result                                         (revocation/handle-revocation-request
                                                          {:client_id "test-client"}
                                                          auth-header client-store token-store)]
      (is (= 400 (:status result)))
      (is (= {:error "invalid_request" :error_description "Missing token parameter"} (:body result)))
      (is (= "no-store" (get-in result [:headers "Cache-Control"]))))))

(deftest revoke-unauthenticated-error-body-test
  (testing "401 response includes error body and cache-control headers"
    (let [{:keys [client-store token-store]} (make-fixtures)
          bad-auth                           (str "Basic " (.encodeToString
                                                            (java.util.Base64/getEncoder)
                                                            (.getBytes "test-client:wrong" "UTF-8")))
          result                             (revocation/handle-revocation-request
                                              {:token "at-123" :client_id "test-client"}
                                              bad-auth client-store token-store)]
      (is (= 401 (:status result)))
      (is (= {:error "invalid_client"} (:body result)))
      (is (= "no-store" (get-in result [:headers "Cache-Control"]))))))

(deftest revoke-with-access-token-hint-test
  (testing "hint access_token revokes access token successfully"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)]
      (store/save-access-token token-store "at-hint" "user-1" "test-client" ["openid"] 999999999999 nil)
      (let [result (revocation/handle-revocation-request
                    {:token "at-hint" :token_type_hint "access_token" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (nil? (store/get-access-token token-store "at-hint")))))))

(deftest revoke-with-refresh-token-hint-test
  (testing "hint refresh_token revokes refresh token successfully"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)]
      (store/save-refresh-token token-store "rt-hint" "user-1" "test-client" ["openid"] nil nil)
      (let [result (revocation/handle-revocation-request
                    {:token "rt-hint" :token_type_hint "refresh_token" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (nil? (store/get-refresh-token token-store "rt-hint")))))))

(deftest revoke-with-wrong-hint-test
  (testing "wrong hint still revokes via fallback lookup"
    (let [{:keys [client-store token-store auth-header]} (make-fixtures)]
      (store/save-refresh-token token-store "rt-wrong" "user-1" "test-client" ["openid"] nil nil)
      (let [result (revocation/handle-revocation-request
                    {:token "rt-wrong" :token_type_hint "access_token" :client_id "test-client"}
                    auth-header client-store token-store)]
        (is (= 200 (:status result)))
        (is (nil? (store/get-refresh-token token-store "rt-wrong")))))))

(deftest revoke-malformed-basic-auth-test
  (testing "returns 401 for malformed Basic auth instead of 500"
    (let [{:keys [client-store token-store]} (make-fixtures)
          result                             (revocation/handle-revocation-request
                                              {:token "at-123" :client_id "test-client"}
                                              "Basic !!!" client-store token-store)]
      (is (= 401 (:status result))))))

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
