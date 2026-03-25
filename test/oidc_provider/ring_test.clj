(ns oidc-provider.ring-test
  (:require
   [cheshire.core :as json]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.core :as core]
   [oidc-provider.protocol :as proto]
   [oidc-provider.registration :as reg]
   [oidc-provider.ring :as ring]
   [oidc-provider.store :as store]
   [oidc-provider.util :as util])
  (:import
   (java.io ByteArrayInputStream)
   (java.time Clock Instant ZoneOffset)))

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
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id reg-response)
          token        (:registration_access_token reg-response)
          response     (handler {:request-method :get
                                 :uri            (str "/register/" client-id)
                                 :headers        {"authorization" (str "Bearer " token)}})]
      (is (= 200 (:status response)))
      (is (= (dissoc reg-response :registration_access_token)
             (json/parse-string (:body response) true))))))

(deftest get-client-read-invalid-token-test
  (testing "GET with wrong Bearer token returns 401"
    (let [client-store (store/create-client-store)
          handler      (ring/registration-handler client-store)
          reg-response (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id reg-response)
          response     (handler {:request-method :get
                                 :uri            (str "/register/" client-id)
                                 :headers        {"authorization" "Bearer wrong-token"}})]
      (is (= 401 (:status response))))))

(deftest get-client-read-missing-auth-test
  (testing "GET without Authorization header returns 401"
    (let [client-store (store/create-client-store)
          handler      (ring/registration-handler client-store)
          reg-response (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id reg-response)
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

(defn- token-fixtures []
  (let [provider    (core/create-provider
                     {:issuer                 "https://test.example.com"
                      :authorization-endpoint "https://test.example.com/authorize"
                      :token-endpoint         "https://test.example.com/token"
                      :client-store           (store/create-client-store
                                               [{:client-id          "cc-client"
                                                 :client-type        "confidential"
                                                 :client-secret-hash (util/hash-client-secret "secret123")
                                                 :redirect-uris      []
                                                 :grant-types        ["client_credentials"]
                                                 :response-types     []
                                                 :scopes             ["api:read"]}])})
        auth-header (str "Basic " (.encodeToString
                                   (java.util.Base64/getEncoder)
                                   (.getBytes "cc-client:secret123" "UTF-8")))]
    {:handler     (ring/token-handler provider)
     :auth-header auth-header}))

(deftest token-handler-success-cache-headers-test
  (testing "success response includes Cache-Control and Pragma headers"
    (let [{:keys [handler auth-header]} (token-fixtures)
          response                      (handler {:request-method :post
                                                  :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                                   "authorization" auth-header}
                                                  :params         {:grant_type "client_credentials"
                                                                   :scope      "api:read"}})]
      (is (= 200 (:status response)))
      (is (= "no-store" (get-in response [:headers "Cache-Control"])))
      (is (= "no-cache" (get-in response [:headers "Pragma"]))))))

(deftest token-handler-error-cache-headers-test
  (testing "error response includes Cache-Control and Pragma headers"
    (let [{:keys [handler]} (token-fixtures)
          response          (handler {:request-method :post
                                      :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                       "authorization" "Basic bad"}
                                      :params         {:grant_type "client_credentials"}})]
      (is (= 400 (:status response)))
      (is (= "no-store" (get-in response [:headers "Cache-Control"])))
      (is (= "no-cache" (get-in response [:headers "Pragma"]))))))

(deftest token-handler-method-not-allowed-test
  (testing "GET returns 405 with Allow header"
    (let [{:keys [handler]} (token-fixtures)
          response          (handler {:request-method :get})]
      (is (= 405 (:status response)))
      (is (= "POST" (get-in response [:headers "Allow"]))))))

(deftest token-handler-wrong-content-type-test
  (testing "POST with application/json returns 415"
    (let [{:keys [handler auth-header]} (token-fixtures)
          response                      (handler {:request-method :post
                                                  :headers        {"content-type"  "application/json"
                                                                   "authorization" auth-header}
                                                  :params         {:grant_type "client_credentials"}})]
      (is (= 415 (:status response))))))

(deftest token-handler-missing-content-type-test
  (testing "POST with no content-type returns 415"
    (let [{:keys [handler auth-header]} (token-fixtures)
          response                      (handler {:request-method :post
                                                  :headers        {"authorization" auth-header}
                                                  :params         {:grant_type "client_credentials"}})]
      (is (= 415 (:status response))))))

(deftest token-handler-unsupported-grant-type-test
  (testing "POST with unsupported grant_type returns 400 with error"
    (let [{:keys [handler auth-header]} (token-fixtures)
          response                      (handler {:request-method :post
                                                  :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                                   "authorization" auth-header}
                                                  :params         {:grant_type "urn:unsupported"}})
          body                          (json/parse-string (:body response) true)]
      (is (= 400 (:status response)))
      (is (string? (:error body))))))

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

(deftest revocation-auth-failure-response-format-test
  (testing "401 returns JSON error body with WWW-Authenticate header"
    (let [{:keys [handler]} (revocation-fixtures)
          bad-auth          (str "Basic " (.encodeToString
                                           (java.util.Base64/getEncoder)
                                           (.getBytes "test-client:wrong" "UTF-8")))
          response          (handler {:request-method :post
                                      :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                       "authorization" bad-auth}
                                      :params         {:token "at-123" :client_id "test-client"}})
          body              (json/parse-string (:body response) true)]
      (is (= 401 (:status response)))
      (is (= {:error "invalid_client"} body))
      (is (= "application/json" (get-in response [:headers "Content-Type"])))
      (is (= "Bearer" (get-in response [:headers "WWW-Authenticate"]))))))

(deftest revocation-missing-token-response-format-test
  (testing "400 returns JSON error body with Content-Type header"
    (let [{:keys [handler auth-header]} (revocation-fixtures)
          response                      (handler {:request-method :post
                                                  :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                                   "authorization" auth-header}
                                                  :params         {:client_id "test-client"}})
          body                          (json/parse-string (:body response) true)]
      (is (= 400 (:status response)))
      (is (= "invalid_request" (:error body)))
      (is (= "application/json" (get-in response [:headers "Content-Type"]))))))

;; ---------------------------------------------------------------------------
;; UserInfo handler tests
;; ---------------------------------------------------------------------------

(defrecord TestClaimsProvider []
  proto/ClaimsProvider
  (get-claims [_ user-id scope]
    (cond-> {:sub user-id}
      (some #{"profile"} scope)
      (assoc :name "Test User")
      (some #{"email"} scope)
      (assoc :email "test@example.com"))))

(defn- userinfo-fixtures
  ([] (userinfo-fixtures (Clock/systemUTC)))
  ([clock]
   (let [token-store   (store/create-token-store)
         claims        (->TestClaimsProvider)
         access-token  "valid-access-token"
         future-expiry (+ (.millis ^Clock (Clock/systemUTC)) 3600000)]
     (store/save-access-token token-store access-token "test-user" "client-1"
                              ["openid" "profile" "email"] future-expiry nil)
     {:handler      (ring/userinfo-handler token-store claims clock)
      :access-token access-token})))

(deftest userinfo-valid-token-returns-claims-test
  (testing "GET with valid Bearer token returns JSON claims"
    (let [{:keys [handler access-token]} (userinfo-fixtures)
          response                       (handler {:request-method :get
                                                   :headers        {"authorization" (str "Bearer " access-token)}})]
      (is (= 200 (:status response)))
      (is (= "application/json" (get-in response [:headers "Content-Type"])))
      (is (= {:sub "test-user" :name "Test User" :email "test@example.com"}
             (json/parse-string (:body response) true))))))

(deftest userinfo-scope-filtering-test
  (testing "claims are filtered by the access token's scope"
    (let [token-store  (store/create-token-store)
          claims       (->TestClaimsProvider)
          access-token "openid-only-token"
          expiry       (+ (.millis ^Clock (Clock/systemUTC)) 3600000)
          _            (store/save-access-token token-store access-token "test-user" "client-1"
                                                ["openid"] expiry nil)
          handler      (ring/userinfo-handler token-store claims (Clock/systemUTC))
          response     (handler {:request-method :get
                                 :headers        {"authorization" (str "Bearer " access-token)}})]
      (is (= 200 (:status response)))
      (is (= {:sub "test-user"}
             (json/parse-string (:body response) true))))))

(deftest userinfo-missing-token-returns-401-test
  (testing "GET without Authorization header returns 401 with WWW-Authenticate"
    (let [{:keys [handler]} (userinfo-fixtures)
          response          (handler {:request-method :get
                                      :headers        {}})]
      (is (= 401 (:status response)))
      (is (= "Bearer" (get-in response [:headers "WWW-Authenticate"])))
      (is (= "" (:body response))))))

(deftest userinfo-unknown-token-returns-401-test
  (testing "GET with unknown Bearer token returns 401"
    (let [{:keys [handler]} (userinfo-fixtures)
          response          (handler {:request-method :get
                                      :headers        {"authorization" "Bearer unknown-token"}})]
      (is (= 401 (:status response))))))

(deftest userinfo-expired-token-returns-401-test
  (testing "GET with expired Bearer token returns 401"
    (let [past-clock   (Clock/fixed (Instant/parse "2020-01-01T00:00:00Z") ZoneOffset/UTC)
          now-clock    (Clock/systemUTC)
          token-store  (store/create-token-store)
          claims       (->TestClaimsProvider)
          access-token "expired-token"
          past-expiry  (.millis ^Clock past-clock)
          _            (store/save-access-token token-store access-token "test-user" "client-1"
                                                ["openid"] past-expiry nil)
          handler      (ring/userinfo-handler token-store claims now-clock)
          response     (handler {:request-method :get
                                 :headers        {"authorization" (str "Bearer " access-token)}})]
      (is (= 401 (:status response))))))

(deftest userinfo-method-not-allowed-test
  (testing "DELETE returns 405 with Allow header"
    (let [{:keys [handler]} (userinfo-fixtures)
          response          (handler {:request-method :delete})]
      (is (= 405 (:status response)))
      (is (= "GET, POST" (get-in response [:headers "Allow"]))))))

(deftest userinfo-post-valid-token-test
  (testing "POST with valid Bearer token also returns claims"
    (let [{:keys [handler access-token]} (userinfo-fixtures)
          response                       (handler {:request-method :post
                                                   :headers        {"authorization" (str "Bearer " access-token)}})]
      (is (= 200 (:status response)))
      (is (= "test-user" (:sub (json/parse-string (:body response) true)))))))
