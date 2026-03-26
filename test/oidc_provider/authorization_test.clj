(ns oidc-provider.authorization-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.authorization :as authz]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store]
   [oidc-provider.util :as util])
  (:import
   [java.time Clock]))

(def ^:private secret-hash (util/hash-client-secret "secret"))
(def ^:private secret123-hash (util/hash-client-secret "secret123"))

(deftest parse-valid-authorization-request-test
  (testing "parses valid authorization request"
    (let [client-store (store/create-client-store
                        [{:client-id          "test-client"
                          :client-type        "confidential"
                          :client-secret-hash secret-hash
                          :redirect-uris      ["https://app.example.com/callback"]
                          :response-types     ["code"]
                          :scopes             ["openid" "profile" "email"]}])
          params       {:response_type "code"
                        :client_id     "test-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "openid profile"
                        :state         "xyz"
                        :nonce         "abc"}
          request      (authz/parse-authorization-request params client-store)]
      (is (= "code" (:response_type request)))
      (is (= "test-client" (:client_id request)))
      (is (= "https://app.example.com/callback" (:redirect_uri request)))
      (is (= "openid profile" (:scope request)))
      (is (= "xyz" (:state request))))))

(deftest parse-authorization-request-invalid-redirect-uri-test
  (testing "throws on invalid redirect_uri"
    (let [client-store (store/create-client-store
                        [{:client-id          "test-client"
                          :client-type        "confidential"
                          :client-secret-hash secret-hash
                          :redirect-uris      ["https://app.example.com/callback"]
                          :response-types     ["code"]
                          :scopes             ["openid"]}])
          params       {:response_type "code"
                        :client_id     "test-client"
                        :redirect_uri  "https://evil.com/callback"}]
      (is (thrown-with-msg? Exception #"Invalid redirect_uri"
                            (authz/parse-authorization-request params client-store))))))

(deftest parse-authorization-request-unknown-client-test
  (testing "throws on unknown client"
    (let [client-store (store/create-client-store [])
          params       {:response_type "code"
                        :client_id     "unknown"
                        :redirect_uri  "https://app.example.com/callback"}]
      (is (thrown-with-msg? Exception #"Unknown client"
                            (authz/parse-authorization-request params client-store))))))

(defn- make-client-store
  "Creates a client store with a single test client."
  [& {:keys [response-types scopes]
      :or   {response-types ["code"] scopes ["openid" "profile"]}}]
  (store/create-client-store
   [{:client-id          "test-client"
     :client-type        "confidential"
     :client-secret-hash secret-hash
     :redirect-uris      ["https://app.example.com/callback"]
     :response-types     response-types
     :scopes             scopes}]))

(deftest redirectable-error-includes-state-test
  (testing "unsupported response_type includes state and redirect_uri in ex-data"
    (let [client-store (make-client-store :response-types ["code"])
          params       {:response_type "token"
                        :client_id     "test-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :state         "abc123"}]
      (try
        (authz/parse-authorization-request params client-store)
        (is false "expected exception")
        (catch clojure.lang.ExceptionInfo e
          (is (= "abc123" (:state (ex-data e))))
          (is (= "https://app.example.com/callback" (:redirect_uri (ex-data e))))
          (is (= ["code"] (:supported (ex-data e)))))))))

(deftest redirectable-scope-error-includes-state-test
  (testing "invalid scope includes state and redirect_uri in ex-data"
    (let [client-store (make-client-store :scopes ["openid"])
          params       {:response_type "code"
                        :client_id     "test-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "admin"
                        :state         "def456"}]
      (try
        (authz/parse-authorization-request params client-store)
        (is false "expected exception")
        (catch clojure.lang.ExceptionInfo e
          (is (= "def456" (:state (ex-data e))))
          (is (= "https://app.example.com/callback" (:redirect_uri (ex-data e))))
          (is (= ["openid"] (:allowed (ex-data e)))))))))

(deftest redirectable-pkce-error-includes-state-test
  (testing "public client without PKCE includes state and redirect_uri in ex-data"
    (let [client-store (store/create-client-store
                        [{:client-id      "pub-client"
                          :client-type    "public"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          params       {:response_type "code"
                        :client_id     "pub-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :state         "pkce-state"}]
      (try
        (authz/parse-authorization-request params client-store)
        (is false "expected exception")
        (catch clojure.lang.ExceptionInfo e
          (is (= "pkce-state" (:state (ex-data e))))
          (is (= "https://app.example.com/callback" (:redirect_uri (ex-data e))))
          (is (= "invalid_request" (:error (ex-data e)))))))))

(deftest redirectable-error-without-state-test
  (testing "redirectable error omits state when client did not send one"
    (let [client-store (make-client-store :response-types ["code"])
          params       {:response_type "token"
                        :client_id     "test-client"
                        :redirect_uri  "https://app.example.com/callback"}]
      (try
        (authz/parse-authorization-request params client-store)
        (is false "expected exception")
        (catch clojure.lang.ExceptionInfo e
          (is (nil? (:state (ex-data e))))
          (is (= "https://app.example.com/callback" (:redirect_uri (ex-data e)))))))))

(deftest non-redirectable-error-excludes-state-test
  (testing "unknown client error does not include state"
    (let [client-store (store/create-client-store [])
          params       {:response_type "code"
                        :client_id     "unknown"
                        :redirect_uri  "https://app.example.com/callback"
                        :state         "xyz"}]
      (try
        (authz/parse-authorization-request params client-store)
        (is false "expected exception")
        (catch clojure.lang.ExceptionInfo e
          (is (nil? (:state (ex-data e))))
          (is (nil? (:redirect_uri (ex-data e)))))))))

(deftest invalid-redirect-uri-excludes-state-test
  (testing "invalid redirect_uri error does not include state"
    (let [client-store (make-client-store)
          params       {:response_type "code"
                        :client_id     "test-client"
                        :redirect_uri  "https://evil.com/callback"
                        :state         "xyz"}]
      (try
        (authz/parse-authorization-request params client-store)
        (is false "expected exception")
        (catch clojure.lang.ExceptionInfo e
          (is (nil? (:state (ex-data e)))))))))

(deftest handle-authorization-approval-test
  (testing "generates authorization code stored with correct metadata"
    (let [code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          provider-config {:issuer                         "https://test.example.com"
                           :authorization-code-ttl-seconds 600
                           :clock                          (Clock/systemUTC)}
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
      (is (= "https://test.example.com" (get-in response [:params :iss])))
      (is (= "user-123" (:user-id code-data)))
      (is (= "test-client" (:client-id code-data)))
      (is (= ["openid" "profile"] (:scope code-data))))))

(deftest handle-authorization-denial-test
  (testing "generates error response with iss parameter"
    (let [request         {:redirect_uri "https://app.example.com/callback"
                           :state        "xyz"}
          provider-config {:issuer "https://test.example.com"
                           :clock  (Clock/systemUTC)}
          response        (authz/handle-authorization-denial
                           request
                           "access_denied"
                           "User denied access"
                           provider-config)]
      (is (= "https://app.example.com/callback" (:redirect-uri response)))
      (is (= "access_denied" (get-in response [:params :error])))
      (is (= "User denied access" (get-in response [:params :error_description])))
      (is (= "xyz" (get-in response [:params :state])))
      (is (= "https://test.example.com" (get-in response [:params :iss]))))))

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
                          :client-type    "public"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          params       {:response_type         "code"
                        :client_id             "test-client"
                        :redirect_uri          "https://app.example.com/callback"
                        :scope                 "openid"
                        :code_challenge        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                        :code_challenge_method "S256"}
          request      (authz/parse-authorization-request params client-store)]
      (is (= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" (:code_challenge request)))
      (is (= "S256" (:code_challenge_method request))))))

(deftest parse-authorization-request-pkce-defaults-method-test
  (testing "code_challenge without code_challenge_method defaults to S256"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :client-type    "public"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          params       {:response_type  "code"
                        :client_id      "test-client"
                        :redirect_uri   "https://app.example.com/callback"
                        :scope          "openid"
                        :code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}
          request      (authz/parse-authorization-request params client-store)]
      (is (= "S256" (:code_challenge_method request))))))

(deftest parse-authorization-request-rejects-plain-method-test
  (testing "code_challenge_method=plain is rejected"
    (let [client-store (store/create-client-store
                        [{:client-id      "test-client"
                          :client-type    "public"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          params       {:response_type         "code"
                        :client_id             "test-client"
                        :redirect_uri          "https://app.example.com/callback"
                        :scope                 "openid"
                        :code_challenge        "abc"
                        :code_challenge_method "plain"}]
      (is (thrown-with-msg? Exception #"Invalid authorization request"
                            (authz/parse-authorization-request params client-store))))))

(deftest handle-authorization-approval-stores-pkce-test
  (testing "stores code-challenge and code-challenge-method with authorization code"
    (let [code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          provider-config {:issuer                         "https://test.example.com"
                           :authorization-code-ttl-seconds 600
                           :clock                          (Clock/systemUTC)}
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
                          :client-type    "public"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          params       {:response_type "code"
                        :client_id     "public-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "openid"}]
      (is (thrown-with-msg? Exception #"Public clients must use PKCE"
                            (authz/parse-authorization-request params client-store))))))

(deftest public-client-with-pkce-succeeds-test
  (testing "public client with code_challenge succeeds"
    (let [client-store (store/create-client-store
                        [{:client-id      "public-client"
                          :client-type    "public"
                          :redirect-uris  ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes         ["openid"]}])
          params       {:response_type         "code"
                        :client_id             "public-client"
                        :redirect_uri          "https://app.example.com/callback"
                        :scope                 "openid"
                        :code_challenge        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                        :code_challenge_method "S256"}
          request      (authz/parse-authorization-request params client-store)]
      (is (= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" (:code_challenge request)))
      (is (= "S256" (:code_challenge_method request))))))

(deftest confidential-client-without-pkce-succeeds-test
  (testing "confidential client without code_challenge succeeds"
    (let [client-store (store/create-client-store
                        [{:client-id          "conf-client"
                          :client-type        "confidential"
                          :client-secret-hash secret123-hash
                          :redirect-uris      ["https://app.example.com/callback"]
                          :response-types     ["code"]
                          :scopes             ["openid"]}])
          params       {:response_type "code"
                        :client_id     "conf-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "openid"}
          request      (authz/parse-authorization-request params client-store)]
      (is (= "conf-client" (:client_id request))))))

(deftest confidential-client-hashed-secret-no-pkce-test
  (testing "confidential client with hashed secret (no plaintext) does not require PKCE"
    (let [client-store (store/create-client-store
                        [{:client-id          "hashed-conf"
                          :client-type        "confidential"
                          :client-secret-hash "pbkdf2:sha256:some-hash"
                          :redirect-uris      ["https://app.example.com/callback"]
                          :response-types     ["code"]
                          :scopes             ["openid"]}])
          params       {:response_type "code"
                        :client_id     "hashed-conf"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "openid"}
          request      (authz/parse-authorization-request params client-store)]
      (is (= "hashed-conf" (:client_id request))))))

(deftest parse-authorization-request-with-resource-test
  (testing "single resource param is parsed as vector"
    (let [client-store (store/create-client-store
                        [{:client-id          "test-client"
                          :client-type        "confidential"
                          :client-secret-hash secret-hash
                          :redirect-uris      ["https://app.example.com/callback"]
                          :response-types     ["code"]
                          :scopes             ["openid"]}])
          params       {:response_type "code"
                        :client_id     "test-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "openid"
                        :resource      "https://api.example.com"}
          request      (authz/parse-authorization-request params client-store)]
      (is (= ["https://api.example.com"] (:resource request))))))

(deftest parse-authorization-request-with-multiple-resources-test
  (testing "multiple resource params are all collected"
    (let [client-store (store/create-client-store
                        [{:client-id          "test-client"
                          :client-type        "confidential"
                          :client-secret-hash secret-hash
                          :redirect-uris      ["https://app.example.com/callback"]
                          :response-types     ["code"]
                          :scopes             ["openid"]}])
          params       {:response_type "code"
                        :client_id     "test-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "openid"
                        :resource      ["https://api.example.com" "https://other.example.com"]}
          request      (authz/parse-authorization-request params client-store)]
      (is (= ["https://api.example.com" "https://other.example.com"] (:resource request))))))

(deftest parse-authorization-request-rejects-relative-resource-test
  (testing "relative URI resource is rejected with invalid_target"
    (let [client-store (store/create-client-store
                        [{:client-id          "test-client"
                          :client-type        "confidential"
                          :client-secret-hash secret-hash
                          :redirect-uris      ["https://app.example.com/callback"]
                          :response-types     ["code"]
                          :scopes             ["openid"]}])
          params       {:response_type "code"
                        :client_id     "test-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "openid"
                        :resource      "/relative/path"}]
      (is (thrown-with-msg? Exception #"Invalid resource indicator"
                            (authz/parse-authorization-request params client-store))))))

(deftest parse-authorization-request-rejects-fragment-resource-test
  (testing "URI with fragment resource is rejected with invalid_target"
    (let [client-store (store/create-client-store
                        [{:client-id          "test-client"
                          :client-type        "confidential"
                          :client-secret-hash secret-hash
                          :redirect-uris      ["https://app.example.com/callback"]
                          :response-types     ["code"]
                          :scopes             ["openid"]}])
          params       {:response_type "code"
                        :client_id     "test-client"
                        :redirect_uri  "https://app.example.com/callback"
                        :scope         "openid"
                        :resource      "https://api.example.com#frag"}]
      (is (thrown-with-msg? Exception #"Invalid resource indicator"
                            (authz/parse-authorization-request params client-store))))))

(deftest authorization-approval-nil-issuer-test
  (testing "omits :iss from response when provider-config has no :issuer"
    (let [code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          provider-config {:authorization-code-ttl-seconds 600
                           :clock                          (Clock/systemUTC)}
          request         {:response_type "code"
                           :client_id     "test-client"
                           :redirect_uri  "https://app.example.com/callback"
                           :scope         "openid"}
          response        (authz/handle-authorization-approval
                           request "user-123" provider-config code-store)]
      (is (contains? (:params response) :code))
      (is (not (contains? (:params response) :iss))))))

(deftest authorization-denial-nil-issuer-test
  (testing "omits :iss from response when provider-config has no :issuer"
    (let [request         {:redirect_uri "https://app.example.com/callback"
                           :state        "xyz"}
          provider-config {:clock (Clock/systemUTC)}
          response        (authz/handle-authorization-denial
                           request "access_denied" "User denied" provider-config)]
      (is (= "access_denied" (get-in response [:params :error])))
      (is (not (contains? (:params response) :iss))))))

(deftest build-redirect-url-custom-scheme-test
  (testing "builds redirect URL with query params for custom URI scheme"
    (let [response {:redirect-uri "cursor://callback"
                    :params       {:code "abc123" :state "xyz"}}
          url      (authz/build-redirect-url response)]
      (is (str/starts-with? url "cursor://callback?"))
      (is (str/includes? url "code=abc123"))
      (is (str/includes? url "state=xyz")))))

(deftest handle-authorization-approval-stores-resource-test
  (testing "resource indicators round-trip through code store"
    (let [code-store      (store/->HashingAuthorizationCodeStore (store/create-authorization-code-store))
          provider-config {:issuer                         "https://test.example.com"
                           :authorization-code-ttl-seconds 600
                           :clock                          (Clock/systemUTC)}
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
