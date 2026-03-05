(ns oidc-provider.authorization-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.authorization :as authz]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store]))

(deftest parse-authorization-request-test
  (testing "parses valid authorization request"
    (let [client-store (store/create-client-store
                        [{:client-id "test-client"
                          :redirect-uris ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes ["openid" "profile" "email"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://app.example.com/callback&scope=openid+profile&state=xyz&nonce=abc"
          request      (authz/parse-authorization-request query-string client-store)]
      (is (= "code" (:response_type request)))
      (is (= "test-client" (:client_id request)))
      (is (= "https://app.example.com/callback" (:redirect_uri request)))
      (is (= "openid profile" (:scope request)))
      (is (= "xyz" (:state request)))
      (is (= "abc" (:nonce request)))))

  (testing "throws on invalid redirect_uri"
    (let [client-store (store/create-client-store
                        [{:client-id "test-client"
                          :redirect-uris ["https://app.example.com/callback"]
                          :response-types ["code"]
                          :scopes ["openid"]}])
          query-string "response_type=code&client_id=test-client&redirect_uri=https://evil.com/callback"]
      (is (thrown-with-msg? Exception #"Invalid redirect_uri"
                            (authz/parse-authorization-request query-string client-store)))))

  (testing "throws on unknown client"
    (let [client-store (store/create-client-store [])
          query-string "response_type=code&client_id=unknown&redirect_uri=https://app.example.com/callback"]
      (is (thrown-with-msg? Exception #"Unknown client"
                            (authz/parse-authorization-request query-string client-store))))))

(deftest handle-authorization-approval-test
  (testing "generates authorization code response"
    (let [code-store      (store/create-authorization-code-store)
          provider-config {:issuer "https://test.example.com"
                           :authorization-code-ttl-seconds 600}
          request         {:response_type "code"
                           :client_id "test-client"
                           :redirect_uri "https://app.example.com/callback"
                           :scope "openid profile"
                           :state "xyz"
                           :nonce "abc"}
          response        (authz/handle-authorization-approval
                           request
                           "user-123"
                           provider-config
                           code-store)]
      (is (= "https://app.example.com/callback" (:redirect-uri response)))
      (is (some? (get-in response [:params :code])))
      (is (= "xyz" (get-in response [:params :state])))
      (let [code      (get-in response [:params :code])
            code-data (proto/get-authorization-code code-store code)]
        (is (= "user-123" (:user-id code-data)))
        (is (= "test-client" (:client-id code-data)))
        (is (= ["openid" "profile"] (:scope code-data)))
        (is (= "abc" (:nonce code-data)))))))

(deftest handle-authorization-denial-test
  (testing "generates error response"
    (let [request  {:redirect_uri "https://app.example.com/callback"
                    :state "xyz"}
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
                    :params {:code "abc123" :state "xyz"}}
          url      (authz/build-redirect-url response)]
      (is (str/starts-with? url "https://app.example.com/callback?"))
      (is (str/includes? url "code=abc123"))
      (is (str/includes? url "state=xyz"))))

  (testing "appends to existing query params"
    (let [response {:redirect-uri "https://app.example.com/callback?existing=param"
                    :params {:code "abc123"}}
          url      (authz/build-redirect-url response)]
      (is (str/includes? url "existing=param"))
      (is (str/includes? url "&code=abc123")))))
