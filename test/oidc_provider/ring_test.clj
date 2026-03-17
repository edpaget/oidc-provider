(ns oidc-provider.ring-test
  (:require
   [cheshire.core :as json]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.registration :as reg]
   [oidc-provider.ring :as ring]
   [oidc-provider.store :as store]
   [oidc-provider.util :as util])
  (:import
   (java.io ByteArrayInputStream)))

(defn- json-body [m]
  (ByteArrayInputStream. (.getBytes (json/generate-string m) "UTF-8")))

(defn- valid-request-body []
  (json-body {"redirect_uris" ["https://app.example.com/callback"]}))

(deftest post-registration-success-test
  (testing "valid POST returns 201 with JSON body containing client_id"
    (let [handler  (ring/registration-handler (store/create-client-store))
          response (handler {:request-method :post
                             :body           (valid-request-body)})]
      (is (= 201 (:status response)))
      (is (= "application/json" (get-in response [:headers "Content-Type"])))
      (let [body (json/parse-string (:body response))]
        (is (string? (get body "client_id")))))))

(deftest post-registration-invalid-metadata-test
  (testing "POST with empty object returns 400 with invalid_client_metadata"
    (let [handler  (ring/registration-handler (store/create-client-store))
          response (handler {:request-method :post
                             :body           (json-body {})})]
      (is (= 400 (:status response)))
      (is (= "invalid_client_metadata"
             (get (json/parse-string (:body response)) "error"))))))

(deftest post-registration-malformed-json-test
  (testing "POST with non-JSON body returns 400"
    (let [handler  (ring/registration-handler (store/create-client-store))
          response (handler {:request-method :post
                             :body           (ByteArrayInputStream. (.getBytes "not json" "UTF-8"))})]
      (is (= 400 (:status response))))))

(deftest post-registration-empty-body-test
  (testing "POST with nil body returns 400"
    (let [handler  (ring/registration-handler (store/create-client-store))
          response (handler {:request-method :post
                             :body           nil})]
      (is (= 400 (:status response))))))

(deftest get-client-read-success-test
  (testing "GET with valid Bearer token returns 200 with client data"
    (let [client-store (store/create-client-store)
          handler      (ring/registration-handler client-store)
          reg-response (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get reg-response "client_id")
          token        (get reg-response "registration_access_token")
          response     (handler {:request-method :get
                                 :uri            (str "/register/" client-id)
                                 :headers        {"authorization" (str "Bearer " token)}})]
      (is (= 200 (:status response)))
      (is (= (dissoc reg-response "registration_access_token")
             (json/parse-string (:body response)))))))

(deftest get-client-read-invalid-token-test
  (testing "GET with wrong Bearer token returns 401"
    (let [client-store (store/create-client-store)
          handler      (ring/registration-handler client-store)
          reg-response (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get reg-response "client_id")
          response     (handler {:request-method :get
                                 :uri            (str "/register/" client-id)
                                 :headers        {"authorization" "Bearer wrong-token"}})]
      (is (= 401 (:status response))))))

(deftest get-client-read-missing-auth-test
  (testing "GET without Authorization header returns 401"
    (let [client-store (store/create-client-store)
          handler      (ring/registration-handler client-store)
          reg-response (reg/handle-registration-request
                        {"redirect_uris" ["https://app.example.com/callback"]}
                        client-store)
          client-id    (get reg-response "client_id")
          response     (handler {:request-method :get
                                 :uri            (str "/register/" client-id)
                                 :headers        {}})]
      (is (= 401 (:status response))))))

(deftest method-not-allowed-test
  (testing "DELETE returns 405 with Allow header"
    (let [handler  (ring/registration-handler (store/create-client-store))
          response (handler {:request-method :delete
                             :uri            "/register/some-id"})]
      (is (= 405 (:status response)))
      (is (= "GET, POST" (get-in response [:headers "Allow"]))))))

(deftest registration-malli-error-description-test
  (testing "Malli validation failure uses generic error_description"
    (let [handler  (ring/registration-handler (store/create-client-store))
          response (handler {:request-method :post
                             :body           (json-body {})})
          body     (json/parse-string (:body response))]
      (is (= 400 (:status response)))
      (is (= "invalid_client_metadata" (get body "error_description"))))))

(deftest registration-semantic-error-description-test
  (testing "semantic validation error surfaces specific error_description"
    (let [handler  (ring/registration-handler (store/create-client-store))
          response (handler {:request-method :post
                             :body           (json-body {"redirect_uris" ["not-a-url"]})})
          body     (json/parse-string (:body response))]
      (is (= 400 (:status response)))
      (is (= "Invalid redirect URI: not-a-url" (get body "error_description"))))))

(deftest error-response-does-not-leak-ex-data-test
  (testing "exception with sensitive ex-data only exposes error and error_description"
    (let [handler  (ring/registration-handler (store/create-client-store))
          response (handler {:request-method :post
                             :body           (json-body {"redirect_uris" ["not-a-url"]})})
          body     (json/parse-string (:body response))]
      (is (= 400 (:status response)))
      (is (= #{"error" "error_description"} (set (keys body)))))))

(defn- revocation-fixtures []
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
    {:handler     (ring/revocation-handler client-store token-store)
     :auth-header auth-header}))

(deftest revocation-wrong-content-type-test
  (testing "POST with application/json returns 415"
    (let [{:keys [handler auth-header]} (revocation-fixtures)
          response                      (handler {:request-method :post
                                                  :headers        {"content-type"  "application/json"
                                                                   "authorization" auth-header}
                                                  :params         {:token "at-123"}})]
      (is (= 415 (:status response)))
      (is (= "application/x-www-form-urlencoded" (get-in response [:headers "Accept"]))))))

(deftest revocation-missing-content-type-test
  (testing "POST with no content-type returns 415"
    (let [{:keys [handler auth-header]} (revocation-fixtures)
          response                      (handler {:request-method :post
                                                  :headers        {"authorization" auth-header}
                                                  :params         {:token "at-123"}})]
      (is (= 415 (:status response))))))

(deftest revocation-valid-content-type-test
  (testing "POST with application/x-www-form-urlencoded proceeds normally"
    (let [{:keys [handler auth-header]} (revocation-fixtures)
          response                      (handler {:request-method :post
                                                  :headers        {"content-type"  "application/x-www-form-urlencoded; charset=UTF-8"
                                                                   "authorization" auth-header}
                                                  :params         {:token "nonexistent" :client_id "test-client"}})]
      (is (= 200 (:status response))))))
