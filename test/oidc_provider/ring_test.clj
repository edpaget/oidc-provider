(ns oidc-provider.ring-test
  (:require
   [cheshire.core :as json]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.registration :as reg]
   [oidc-provider.ring :as ring]
   [oidc-provider.store :as store])
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

(deftest gated-registration-success-test
  (testing "POST with correct initial access token succeeds"
    (let [handler  (ring/registration-handler (store/create-client-store)
                                              :initial-access-token "secret-token")
          response (handler {:request-method :post
                             :headers        {"authorization" "Bearer secret-token"}
                             :body           (valid-request-body)})]
      (is (= 201 (:status response))))))

(deftest gated-registration-missing-token-test
  (testing "POST without token when gated returns 401"
    (let [handler  (ring/registration-handler (store/create-client-store)
                                              :initial-access-token "secret-token")
          response (handler {:request-method :post
                             :headers        {}
                             :body           (valid-request-body)})]
      (is (= 401 (:status response))))))

(deftest gated-registration-wrong-token-test
  (testing "POST with wrong token when gated returns 401"
    (let [handler  (ring/registration-handler (store/create-client-store)
                                              :initial-access-token "secret-token")
          response (handler {:request-method :post
                             :headers        {"authorization" "Bearer wrong-token"}
                             :body           (valid-request-body)})]
      (is (= 401 (:status response))))))
