(ns oidc-provider.authorization-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.authorization :as authz]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store]))

(deftest parse-valid-authorization-request-test
  (testing "parses valid authorization request"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :client-secret  "secret"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid" "profile" "email"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid+profile&state=xyz&nonce=abc"
          request      (authz/parse-authorization-request query-string client-store)]
      (is (= "code" (:response_type request)))
      (is (= "test-client" (:client_id request)))
      (is (= "https://app.example.com/callback" (:redirect_uri request)))
      (is (= "openid profile" (:scope request)))
      (is (= "xyz" (:state request))))))

(deftest parse-authorization-request-invalid-redirect-uri-test
  (testing "throws on invalid redirect_uri"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :client-secret  "secret"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://evil.com/callback"]
      (is (thrown-with-msg? Exception #"Invalid redirect_uri"
                            (authz/parse-authorization-request query-string client-store))))))

(deftest parse-authorization-request-unknown-client-test
  (testing "throws on unknown client"
    (let [client-store (store/create-client-store [])
          query-string "response_type=code&client_id=unknown&redirect_uri=https://app.example.com/callback"]
      (is (thrown-with-msg? Exception #"Unknown client"
                            (authz/parse-authorization-request query-string client-store))))))

(deftest handle-authorization-approval-test
  (testing "generates authorization code stored with correct metadata"
    (let [code-store      (store/create-authorization-code-store)
          provider-config {:issuer                         "https://test.example.com"
                           :authorization-code-ttl-seconds 600}
          request         {:response_type "code"
                           :client_id     "test-client"
                           :redirect_uri  "https://app.example.com/callback"
                           :scope         "openid profile"
                           :state         "xyz"
                           :nonce         "abc"}
          response        (authz/handle-authorization-approval
                           request
                           "user-123"
                           provider-config
                           code-store)
          code            (get-in response [:params :code])
          code-data       (proto/get-authorization-code code-store code)]
      (is (= "https://app.example.com/callback" (:redirect-uri response)))
      (is (= "xyz" (get-in response [:params :state])))
      (is (= "user-123" (:user-id code-data)))
      (is (= "test-client" (:client-id code-data)))
      (is (= ["openid" "profile"] (:scope code-data))))))

(deftest handle-authorization-denial-test
  (testing "generates error response"
    (let [request  {:redirect_uri "https://app.example.com/callback"
                    :state        "xyz"}
          response (authz/handle-authorization-denial
                    request
                    "access_denied"
                    "User denied access")]
      (is (= "https://app.example.com/callback" (:redirect-uri response)))
      (is (= "access_denied" (get-in response [:params :error])))
      (is (= "User denied access" (get-in response [:params :error_description])))
      (is (= "xyz" (get-in response [:params :state]))))))

(deftest build-redirect-url-test
  (testing "builds redirect URL with query params"
    (let [response {:redirect-uri "https://app.example.com/callback"
                    :params       {:code "abc123" :state "xyz"}}
          url      (authz/build-redirect-url response)]
      (is (str/starts-with? url "https://app.example.com/callback?"))
      (is (str/includes? url "code=abc123"))
      (is (str/includes? url "state=xyz")))))

(deftest build-redirect-url-existing-params-test
  (testing "appends to existing query params"
    (let [response {:redirect-uri "https://app.example.com/callback?existing=param"
                    :params       {:code "abc123"}}
          url      (authz/build-redirect-url response)]
      (is (str/includes? url "existing=param"))
      (is (str/includes? url "&code=abc123")))))

(deftest parse-authorization-request-with-pkce-test
  (testing "valid request with code_challenge and code_challenge_method=S256"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
          request      (authz/parse-authorization-request query-string client-store)]
      (is (= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" (:code_challenge request)))
      (is (= "S256" (:code_challenge_method request))))))

(deftest parse-authorization-request-pkce-defaults-method-test
  (testing "code_challenge without code_challenge_method defaults to S256"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
          request      (authz/parse-authorization-request query-string client-store)]
      (is (= "S256" (:code_challenge_method request))))))

(deftest parse-authorization-request-rejects-plain-method-test
  (testing "code_challenge_method=plain is rejected"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid&code_challenge=abc&code_challenge_method=plain"]
      (is (thrown-with-msg? Exception #"Invalid authorization request"
                            (authz/parse-authorization-request query-string client-store))))))

(deftest handle-authorization-approval-stores-pkce-test
  (testing "stores code-challenge and code-challenge-method with authorization code"
    (let [code-store      (store/create-authorization-code-store)
          provider-config {:issuer                         "https://test.example.com"
                           :authorization-code-ttl-seconds 600}
          request         {:response_type         "code"
                           :client_id             "test-client"
                           :redirect_uri          "https://app.example.com/callback"
                           :scope                 "openid"
                           :code_challenge        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                           :code_challenge_method "S256"}
          response        (authz/handle-authorization-approval
                           request "user-123" provider-config code-store)
          code            (get-in response [:params :code])
          code-data       (proto/get-authorization-code code-store code)]
      (is (= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" (:code-challenge code-data)))
      (is (= "S256" (:code-challenge-method code-data))))))

(deftest public-client-requires-pkce-test
  (testing "public client without code_challenge is rejected"
    (let [client-store (store/create-client-store
                        [{:client-id      "public-client"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=public-client&redirect_uri=https://app.example.com/callback&scope=openid"]
      (is (thrown-with-msg? Exception #"Public clients must use PKCE"
                            (authz/parse-authorization-request query-string client-store))))))

(deftest public-client-with-pkce-succeeds-test
  (testing "public client with code_challenge succeeds"
    (let [client-store (store/create-client-store
                        [{:client-id      "public-client"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=public-client&redirect_uri=https://app.example.com/callback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
          request      (authz/parse-authorization-request query-string client-store)]
      (is (= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" (:code_challenge request)))
      (is (= "S256" (:code_challenge_method request))))))

(deftest confidential-client-without-pkce-succeeds-test
  (testing "confidential client without code_challenge succeeds"
    (let [client-store (store/create-client-store
                        [{:client-id      "conf-client"
                          :client-secret  "secret123"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=conf-client&redirect_uri=https://app.example.com/callback&scope=openid"
          request      (authz/parse-authorization-request query-string client-store)]
      (is (= "conf-client" (:client_id request))))))

(deftest parse-authorization-request-with-resource-test
  (testing "single resource param is parsed as vector"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :client-secret  "secret"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid&resource=https%3A%2F%2Fapi.example.com"
          request      (authz/parse-authorization-request query-string client-store)]
      (is (= ["https://api.example.com"] (:resource request))))))

(deftest parse-authorization-request-with-multiple-resources-test
  (testing "multiple resource params are all collected"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :client-secret  "secret"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid&resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Fother.example.com"
          request      (authz/parse-authorization-request query-string client-store)]
      (is (= ["https://api.example.com" "https://other.example.com"] (:resource request))))))

(deftest parse-authorization-request-rejects-relative-resource-test
  (testing "relative URI resource is rejected with invalid_target"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :client-secret  "secret"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid&resource=%2Frelative%2Fpath"]
      (is (thrown-with-msg? Exception #"Invalid resource indicator"
                            (authz/parse-authorization-request query-string client-store))))))

(deftest parse-authorization-request-rejects-fragment-resource-test
  (testing "URI with fragment resource is rejected with invalid_target"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :client-secret  "secret"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid&resource=https%3A%2F%2Fapi.example.com%23frag"]
      (is (thrown-with-msg? Exception #"Invalid resource indicator"
                            (authz/parse-authorization-request query-string client-store))))))

(deftest handle-authorization-approval-stores-resource-test
  (testing "resource indicators round-trip through code store"
    (let [code-store      (store/create-authorization-code-store)
          provider-config {:issuer                         "https://test.example.com"
                           :authorization-code-ttl-seconds 600}
          request         {:response_type "code"
                           :client_id     "test-client"
                           :redirect_uri  "https://app.example.com/callback"
                           :scope         "openid"
                           :resource      ["https://api.example.com" "https://other.example.com"]}
          response        (authz/handle-authorization-approval
                           request "user-123" provider-config code-store)
          code            (get-in response [:params :code])
          code-data       (proto/get-authorization-code code-store code)]
      (is (= ["https://api.example.com" "https://other.example.com"] (:resource code-data))))))
