(ns oidc-provider.registration-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.protocol :as proto]
   [oidc-provider.registration :as reg]
   [oidc-provider.store :as store]))

(deftest register-minimal-client-test
  (testing "applies RFC 7591 defaults for a minimal registration request"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)]
      (is (= ["authorization_code"] (get response "grant_types")))
      (is (= ["code"] (get response "response_types")))
      (is (= "none" (get response "token_endpoint_auth_method")))
      (is (nil? (get response "client_secret"))))))

(deftest registered-client-retrievable-test
  (testing "registered client is retrievable from the store"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get response "client_id")
          stored       (proto/get-client client-store client-id)]
      (is (= client-id (:client-id stored))))))

(deftest register-confidential-client-test
  (testing "client_secret_basic auth method generates a secret"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris"              ["https://app.example.com/callback"]
                         "token_endpoint_auth_method" "client_secret_basic"}
                        client-store)
          client-id    (get response "client_id")
          stored       (proto/get-client client-store client-id)]
      (is (= (get response "client_secret") (:client-secret stored))))))

(deftest registration-access-token-test
  (testing "response includes registration_access_token matching stored value"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get response "client_id")
          stored       (proto/get-client client-store client-id)]
      (is (= (get response "registration_access_token")
             (:registration-access-token stored))))))

(deftest register-with-custom-metadata-test
  (testing "client_name and scope are preserved in response"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]
                         "client_name"   "My App"
                         "scope"         "openid profile"}
                        client-store)]
      (is (= "My App" (get response "client_name")))
      (is (= "openid profile" (get response "scope"))))))

(deftest register-missing-redirect-uris-test
  (testing "throws invalid_client_metadata when redirect_uris is missing"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {}
                           (store/create-client-store))))))

(deftest register-empty-redirect-uris-test
  (testing "throws invalid_client_metadata when redirect_uris is empty"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {"redirect_uris" []}
                           (store/create-client-store))))))

(deftest register-invalid-grant-type-test
  (testing "throws invalid_client_metadata for unsupported grant type"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {"redirect_uris" ["https://app.example.com/callback"]
                            "grant_types"   ["implicit"]}
                           (store/create-client-store))))))
