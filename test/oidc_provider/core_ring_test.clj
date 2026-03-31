(ns oidc-provider.core-ring-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.core :as core]
   [oidc-provider.protocol :as proto]
   [oidc-provider.registration :as reg]
   [oidc-provider.store :as store]
   [oidc-provider.util :as util])
  (:import
   (java.time Clock Instant ZoneOffset)))

(defn- make-provider []
  (core/create-provider
   {:issuer                 "https://test.example.com"
    :authorization-endpoint "https://test.example.com/authorize"
    :token-endpoint         "https://test.example.com/token"}))

;; ---------------------------------------------------------------------------
;; Registration response tests
;; ---------------------------------------------------------------------------

(deftest post-registration-success-test
  (testing "valid POST returns 201 with client data"
    (let [provider (make-provider)
          response (core/registration-response
                    provider
                    {:request-method :post
                     :body           {:redirect_uris ["https://app.example.com/callback"]}})]
      (is (= 201 (:status response)))
      (is (some? (core/get-client provider (:client_id (:body response))))))))

(deftest post-registration-invalid-metadata-test
  (testing "POST with empty object returns 400 with invalid_client_metadata"
    (let [response (core/registration-response
                    (make-provider)
                    {:request-method :post
                     :body           {}})]
      (is (= 400 (:status response)))
      (is (= :invalid_client_metadata (:error (:body response)))))))

(deftest post-registration-non-map-body-test
  (testing "POST with non-map body returns 400"
    (let [response (core/registration-response
                    (make-provider)
                    {:request-method :post
                     :body           "not a map"})]
      (is (= 400 (:status response))))))

(deftest post-registration-nil-body-test
  (testing "POST with nil body returns 400"
    (let [response (core/registration-response
                    (make-provider)
                    {:request-method :post
                     :body           nil})]
      (is (= 400 (:status response))))))

(deftest get-client-read-success-test
  (testing "GET with valid Bearer token returns 200 with client data"
    (let [provider     (make-provider)
          client-store (:client-store provider)
          reg-response (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id reg-response)
          token        (:registration_access_token reg-response)
          response     (core/registration-response
                        provider
                        {:request-method :get
                         :uri            (str "/register/" client-id)
                         :headers        {"authorization" (str "Bearer " token)}})]
      (is (= 200 (:status response)))
      (is (= (dissoc reg-response :registration_access_token :client_secret
                     :client_id_issued_at :client_secret_expires_at)
             (:body response))))))

(deftest get-client-read-invalid-token-test
  (testing "GET with wrong Bearer token returns 401"
    (let [provider     (make-provider)
          client-store (:client-store provider)
          reg-response (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id reg-response)
          response     (core/registration-response
                        provider
                        {:request-method :get
                         :uri            (str "/register/" client-id)
                         :headers        {"authorization" "Bearer wrong-token"}})]
      (is (= 401 (:status response))))))

(deftest get-client-read-missing-auth-test
  (testing "GET without Authorization header returns 401"
    (let [provider     (make-provider)
          client-store (:client-store provider)
          reg-response (reg/handle-registration-request
                        {:redirect_uris ["https://app.example.com/callback"]}
                        client-store)
          client-id    (:client_id reg-response)
          response     (core/registration-response
                        provider
                        {:request-method :get
                         :uri            (str "/register/" client-id)
                         :headers        {}})]
      (is (= 401 (:status response))))))

(deftest registration-method-not-allowed-test
  (testing "DELETE returns 405 with Allow header"
    (let [response (core/registration-response
                    (make-provider)
                    {:request-method :delete
                     :uri            "/register/some-id"})]
      (is (= 405 (:status response)))
      (is (= "GET, POST" (get-in response [:headers "Allow"]))))))

(deftest registration-malli-error-description-test
  (testing "Malli validation failure uses generic error_description"
    (let [response (core/registration-response
                    (make-provider)
                    {:request-method :post
                     :body           {}})]
      (is (= 400 (:status response)))
      (is (= "invalid_client_metadata" (:error_description (:body response)))))))

(deftest registration-semantic-error-description-test
  (testing "semantic validation error surfaces specific error_description"
    (let [response (core/registration-response
                    (make-provider)
                    {:request-method :post
                     :body           {:redirect_uris ["not-a-url"]}})]
      (is (= 400 (:status response)))
      (is (= "Invalid redirect URI: not-a-url" (:error_description (:body response)))))))

(deftest error-response-does-not-leak-ex-data-test
  (testing "error body only exposes error and error_description"
    (let [response (core/registration-response
                    (make-provider)
                    {:request-method :post
                     :body           {:redirect_uris ["not-a-url"]}})]
      (is (= 400 (:status response)))
      (is (= #{:error :error_description} (set (keys (:body response))))))))

;; ---------------------------------------------------------------------------
;; Token response tests
;; ---------------------------------------------------------------------------

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
    {:provider    provider
     :auth-header auth-header}))

(deftest token-response-success-cache-headers-test
  (testing "success response includes Cache-Control and Pragma headers"
    (let [{:keys [provider auth-header]} (token-fixtures)
          response                       (core/token-response
                                          provider
                                          {:request-method :post
                                           :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                            "authorization" auth-header}
                                           :params         {:grant_type "client_credentials"
                                                            :scope      "api:read"}})]
      (is (= 200 (:status response)))
      (is (= "no-store" (get-in response [:headers "Cache-Control"])))
      (is (= "no-cache" (get-in response [:headers "Pragma"]))))))

(deftest token-response-error-cache-headers-test
  (testing "error response includes Cache-Control and Pragma headers"
    (let [{:keys [provider]} (token-fixtures)
          response           (core/token-response
                              provider
                              {:request-method :post
                               :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                "authorization" "Basic bad"}
                               :params         {:grant_type "client_credentials"}})]
      (is (= 400 (:status response)))
      (is (= "no-store" (get-in response [:headers "Cache-Control"])))
      (is (= "no-cache" (get-in response [:headers "Pragma"]))))))

(deftest token-response-method-not-allowed-test
  (testing "GET returns 405 with Allow header"
    (let [{:keys [provider]} (token-fixtures)
          response           (core/token-response provider {:request-method :get})]
      (is (= 405 (:status response)))
      (is (= "POST" (get-in response [:headers "Allow"]))))))

(deftest token-response-wrong-content-type-test
  (testing "POST with application/json returns 415"
    (let [{:keys [provider auth-header]} (token-fixtures)
          response                       (core/token-response
                                          provider
                                          {:request-method :post
                                           :headers        {"content-type"  "application/json"
                                                            "authorization" auth-header}
                                           :params         {:grant_type "client_credentials"}})]
      (is (= 415 (:status response))))))

(deftest token-response-missing-content-type-test
  (testing "POST with no content-type returns 415"
    (let [{:keys [provider auth-header]} (token-fixtures)
          response                       (core/token-response
                                          provider
                                          {:request-method :post
                                           :headers        {"authorization" auth-header}
                                           :params         {:grant_type "client_credentials"}})]
      (is (= 415 (:status response))))))

(deftest token-response-unsupported-grant-type-test
  (testing "POST with unsupported grant_type returns 400 with error"
    (let [{:keys [provider auth-header]} (token-fixtures)
          response                       (core/token-response
                                          provider
                                          {:request-method :post
                                           :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                            "authorization" auth-header}
                                           :params         {:grant_type "urn:unsupported"}})]
      (is (= 400 (:status response)))
      (is (= "unsupported_grant_type" (:error (:body response)))))))

;; ---------------------------------------------------------------------------
;; Revocation response tests
;; ---------------------------------------------------------------------------

(defn- revocation-fixtures []
  (let [provider    (core/create-provider
                     {:issuer                 "https://test.example.com"
                      :authorization-endpoint "https://test.example.com/authorize"
                      :token-endpoint         "https://test.example.com/token"
                      :client-store           (store/create-client-store
                                               [{:client-id          "test-client"
                                                 :client-type        "confidential"
                                                 :client-secret-hash (util/hash-client-secret "secret123")
                                                 :redirect-uris      ["https://app.example.com/callback"]
                                                 :grant-types        ["authorization_code" "refresh_token"]
                                                 :response-types     ["code"]
                                                 :scopes             ["openid"]}])})
        auth-header (str "Basic " (.encodeToString
                                   (java.util.Base64/getEncoder)
                                   (.getBytes "test-client:secret123" "UTF-8")))]
    {:provider    provider
     :auth-header auth-header}))

(deftest revocation-wrong-content-type-test
  (testing "POST with application/json returns 415"
    (let [{:keys [provider auth-header]} (revocation-fixtures)
          response                       (core/revocation-response
                                          provider
                                          {:request-method :post
                                           :headers        {"content-type"  "application/json"
                                                            "authorization" auth-header}
                                           :params         {:token "at-123"}})]
      (is (= 415 (:status response)))
      (is (= "application/x-www-form-urlencoded" (get-in response [:headers "Accept"]))))))

(deftest revocation-missing-content-type-test
  (testing "POST with no content-type returns 415"
    (let [{:keys [provider auth-header]} (revocation-fixtures)
          response                       (core/revocation-response
                                          provider
                                          {:request-method :post
                                           :headers        {"authorization" auth-header}
                                           :params         {:token "at-123"}})]
      (is (= 415 (:status response))))))

(deftest revocation-valid-content-type-test
  (testing "POST with application/x-www-form-urlencoded proceeds normally"
    (let [{:keys [provider auth-header]} (revocation-fixtures)
          response                       (core/revocation-response
                                          provider
                                          {:request-method :post
                                           :headers        {"content-type"  "application/x-www-form-urlencoded; charset=UTF-8"
                                                            "authorization" auth-header}
                                           :params         {:token "nonexistent" :client_id "test-client"}})]
      (is (= 200 (:status response))))))

(deftest revocation-auth-failure-response-format-test
  (testing "401 returns error body with WWW-Authenticate header"
    (let [{:keys [provider]} (revocation-fixtures)
          bad-auth           (str "Basic " (.encodeToString
                                            (java.util.Base64/getEncoder)
                                            (.getBytes "test-client:wrong" "UTF-8")))
          response           (core/revocation-response
                              provider
                              {:request-method :post
                               :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                "authorization" bad-auth}
                               :params         {:token "at-123" :client_id "test-client"}})]
      (is (= 401 (:status response)))
      (is (= {:error :invalid_client} (:body response)))
      (is (= "Bearer" (get-in response [:headers "WWW-Authenticate"]))))))

(deftest revocation-missing-token-response-format-test
  (testing "400 returns error body with error details"
    (let [{:keys [provider auth-header]} (revocation-fixtures)
          response                       (core/revocation-response
                                          provider
                                          {:request-method :post
                                           :headers        {"content-type"  "application/x-www-form-urlencoded"
                                                            "authorization" auth-header}
                                           :params         {:client_id "test-client"}})]
      (is (= 400 (:status response)))
      (is (= :invalid_request (:error (:body response)))))))

;; ---------------------------------------------------------------------------
;; UserInfo response tests
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
   (let [claims       (->TestClaimsProvider)
         access-token "valid-access-token"
         provider     (core/create-provider
                       {:issuer                 "https://test.example.com"
                        :authorization-endpoint "https://test.example.com/authorize"
                        :token-endpoint         "https://test.example.com/token"
                        :claims-provider        claims
                        :clock                  clock})
         expiry       (+ (.millis ^Clock (Clock/systemUTC)) 3600000)]
     (proto/save-access-token (:token-store provider) access-token "test-user" "client-1"
                              ["openid" "profile" "email"] expiry nil)
     {:provider     provider
      :access-token access-token})))

(deftest userinfo-valid-token-returns-claims-test
  (testing "GET with valid Bearer token returns claims"
    (let [{:keys [provider access-token]} (userinfo-fixtures)
          response                        (core/userinfo-response
                                           provider
                                           {:request-method :get
                                            :headers        {"authorization" (str "Bearer " access-token)}})]
      (is (= 200 (:status response)))
      (is (= {:sub "test-user" :name "Test User" :email "test@example.com"}
             (:body response))))))

(deftest userinfo-scope-filtering-test
  (testing "claims are filtered by the access token's scope"
    (let [claims       (->TestClaimsProvider)
          access-token "openid-only-token"
          provider     (core/create-provider
                        {:issuer                 "https://test.example.com"
                         :authorization-endpoint "https://test.example.com/authorize"
                         :token-endpoint         "https://test.example.com/token"
                         :claims-provider        claims})
          expiry       (+ (.millis ^Clock (Clock/systemUTC)) 3600000)
          _            (proto/save-access-token (:token-store provider) access-token "test-user" "client-1"
                                                ["openid"] expiry nil)
          response     (core/userinfo-response
                        provider
                        {:request-method :get
                         :headers        {"authorization" (str "Bearer " access-token)}})]
      (is (= 200 (:status response)))
      (is (= {:sub "test-user"} (:body response))))))

(deftest userinfo-missing-token-returns-401-test
  (testing "GET without Authorization header returns 401 with WWW-Authenticate"
    (let [{:keys [provider]} (userinfo-fixtures)
          response           (core/userinfo-response
                              provider
                              {:request-method :get
                               :headers        {}})]
      (is (= 401 (:status response)))
      (is (= "Bearer" (get-in response [:headers "WWW-Authenticate"]))))))

(deftest userinfo-unknown-token-returns-401-test
  (testing "GET with unknown Bearer token returns 401"
    (let [{:keys [provider]} (userinfo-fixtures)
          response           (core/userinfo-response
                              provider
                              {:request-method :get
                               :headers        {"authorization" "Bearer unknown-token"}})]
      (is (= 401 (:status response))))))

(deftest userinfo-expired-token-returns-401-test
  (testing "GET with expired Bearer token returns 401"
    (let [past-clock   (Clock/fixed (Instant/parse "2020-01-01T00:00:00Z") ZoneOffset/UTC)
          now-clock    (Clock/systemUTC)
          claims       (->TestClaimsProvider)
          access-token "expired-token"
          provider     (core/create-provider
                        {:issuer                 "https://test.example.com"
                         :authorization-endpoint "https://test.example.com/authorize"
                         :token-endpoint         "https://test.example.com/token"
                         :claims-provider        claims
                         :clock                  now-clock})
          past-expiry  (.millis ^Clock past-clock)
          _            (proto/save-access-token (:token-store provider) access-token "test-user" "client-1"
                                                ["openid"] past-expiry nil)
          response     (core/userinfo-response
                        provider
                        {:request-method :get
                         :headers        {"authorization" (str "Bearer " access-token)}})]
      (is (= 401 (:status response))))))

(deftest userinfo-method-not-allowed-test
  (testing "DELETE returns 405 with Allow header"
    (let [{:keys [provider]} (userinfo-fixtures)
          response           (core/userinfo-response
                              provider
                              {:request-method :delete})]
      (is (= 405 (:status response)))
      (is (= "GET, POST" (get-in response [:headers "Allow"]))))))

(deftest userinfo-post-valid-token-test
  (testing "POST with valid Bearer token also returns claims"
    (let [{:keys [provider access-token]} (userinfo-fixtures)
          response                        (core/userinfo-response
                                           provider
                                           {:request-method :post
                                            :headers        {"authorization" (str "Bearer " access-token)}})]
      (is (= 200 (:status response)))
      (is (= "test-user" (:sub (:body response)))))))
