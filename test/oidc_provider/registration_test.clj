(ns oidc-provider.registration-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.protocol :as proto]
   [oidc-provider.registration :as reg]
   [oidc-provider.store :as store]
   [oidc-provider.util :as util]))

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
  (testing "client_secret_basic auth method generates a secret and stores its hash"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris"              ["https://app.example.com/callback"]
                         "token_endpoint_auth_method" "client_secret_basic"}
                        client-store)
          client-id    (get response "client_id")
          stored       (proto/get-client client-store client-id)]
      (is (string? (get response "client_secret")))
      (is (nil? (:client-secret stored)))
      (is (util/verify-client-secret (get response "client_secret") (:client-secret-hash stored))))))

(deftest registration-access-token-test
  (testing "response token is plaintext, stored value is a PBKDF2 hash that verifies"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get response "client_id")
          stored       (proto/get-client client-store client-id)
          plaintext    (get response "registration_access_token")]
      (is (string? plaintext))
      (is (str/starts-with? (:registration-access-token stored) "PBKDF2"))
      (is (util/verify-client-secret plaintext (:registration-access-token stored))))))

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

(deftest register-http-localhost-redirect-test
  (testing "http://localhost redirect URI is accepted"
    (let [response (reg/handle-registration-request
                    {"redirect_uris" ["http://localhost:3000/callback"]}
                    (store/create-client-store))]
      (is (= ["http://localhost:3000/callback"] (get response "redirect_uris"))))))

(deftest register-http-127-redirect-test
  (testing "http://127.0.0.1 redirect URI is accepted"
    (let [response (reg/handle-registration-request
                    {"redirect_uris" ["http://127.0.0.1:8080/callback"]}
                    (store/create-client-store))]
      (is (= ["http://127.0.0.1:8080/callback"] (get response "redirect_uris"))))))

(deftest register-https-redirect-test
  (testing "https redirect URI is accepted"
    (let [response (reg/handle-registration-request
                    {"redirect_uris" ["https://app.example.com/callback"]}
                    (store/create-client-store))]
      (is (= ["https://app.example.com/callback"] (get response "redirect_uris"))))))

(deftest register-http-non-localhost-test
  (testing "throws invalid_client_metadata for http URI on non-localhost host"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {"redirect_uris" ["http://evil.example.com/callback"]}
                           (store/create-client-store))))))

(deftest register-invalid-uri-test
  (testing "throws invalid_client_metadata for malformed URI"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {"redirect_uris" ["not a uri"]}
                           (store/create-client-store))))))

(deftest register-relative-uri-test
  (testing "throws invalid_client_metadata for relative URI"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {"redirect_uris" ["/callback"]}
                           (store/create-client-store))))))

(deftest register-inconsistent-grant-response-test
  (testing "throws invalid_client_metadata when grant_types and response_types are inconsistent"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {"redirect_uris"  ["https://app.example.com/callback"]
                            "grant_types"    ["authorization_code"]
                            "response_types" ["token"]}
                           (store/create-client-store))))))

(deftest register-with-extended-metadata-test
  (testing "client_uri, logo_uri, and contacts are preserved in response"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]
                         "client_uri"    "https://example.com"
                         "logo_uri"      "https://example.com/logo.png"
                         "contacts"      ["admin@example.com"]}
                        client-store)]
      (is (= "https://example.com" (get response "client_uri")))
      (is (= "https://example.com/logo.png" (get response "logo_uri")))
      (is (= ["admin@example.com"] (get response "contacts"))))))

(deftest register-validates-client-uri-test
  (testing "throws invalid_client_metadata for non-HTTPS client_uri"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {"redirect_uris" ["https://app.example.com/callback"]
                            "client_uri"    "http://example.com"}
                           (store/create-client-store))))))

(deftest register-validates-logo-uri-test
  (testing "throws invalid_client_metadata for non-HTTPS logo_uri"
    (is (thrown-with-msg? Exception #"invalid_client_metadata"
                          (reg/handle-registration-request
                           {"redirect_uris" ["https://app.example.com/callback"]
                            "logo_uri"      "not-a-uri"}
                           (store/create-client-store))))))

(deftest register-public-client-type-test
  (testing "auth method none sets client-type to public in store"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get response "client_id")
          stored       (proto/get-client client-store client-id)]
      (is (= "public" (:client-type stored))))))

(deftest register-confidential-client-type-test
  (testing "auth method client_secret_basic sets client-type to confidential in store"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris"              ["https://app.example.com/callback"]
                         "token_endpoint_auth_method" "client_secret_basic"}
                        client-store)
          client-id    (get response "client_id")
          stored       (proto/get-client client-store client-id)]
      (is (= "confidential" (:client-type stored))))))

(deftest register-confidential-client-type-post-test
  (testing "auth method client_secret_post sets client-type to confidential in store"
    (let [client-store (store/create-client-store)
          response     (reg/handle-registration-request
                        {"redirect_uris"              ["https://app.example.com/callback"]
                         "token_endpoint_auth_method" "client_secret_post"}
                        client-store)
          client-id    (get response "client_id")
          stored       (proto/get-client client-store client-id)]
      (is (= "confidential" (:client-type stored))))))

(deftest client-read-does-not-expose-registration-token-test
  (testing "handle-client-read response does not contain registration_access_token"
    (let [client-store (store/create-client-store)
          reg-response (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get reg-response "client_id")
          token        (get reg-response "registration_access_token")
          read-result  (reg/handle-client-read client-store client-id token)]
      (is (= 200 (:status read-result)))
      (is (not (contains? (:body read-result) "registration_access_token"))))))

(deftest client-read-success-test
  (testing "reads back client configuration with valid token"
    (let [client-store (store/create-client-store)
          reg-response (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]
                         "client_name"   "My App"
                         "scope"         "openid profile"}
                        client-store)
          client-id    (get reg-response "client_id")
          token        (get reg-response "registration_access_token")
          read-result  (reg/handle-client-read client-store client-id token)]
      (is (= 200 (:status read-result)))
      (is (= (dissoc reg-response "client_secret" "registration_access_token")
             (:body read-result))))))

(deftest client-read-invalid-token-test
  (testing "returns 401 when token does not match"
    (let [client-store (store/create-client-store)
          reg-response (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get reg-response "client_id")
          read-result  (reg/handle-client-read client-store client-id "wrong-token")]
      (is (= 401 (:status read-result)))
      (is (= {"error" "invalid_token"} (:body read-result))))))

(deftest client-read-unknown-client-test
  (testing "returns 401 for nonexistent client_id"
    (let [client-store (store/create-client-store)
          read-result  (reg/handle-client-read client-store "nonexistent-id" "any-token")]
      (is (= 401 (:status read-result)))
      (is (= {"error" "invalid_token"} (:body read-result))))))
