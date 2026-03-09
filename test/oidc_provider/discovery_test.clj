(ns oidc-provider.discovery-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.discovery :as discovery]))

(deftest discovery-includes-code-challenge-methods-test
  (testing "default config includes code_challenge_methods_supported with S256"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= ["S256"] (:code_challenge_methods_supported result))))))

(deftest discovery-custom-code-challenge-methods-test
  (testing "custom code_challenge_methods_supported value is respected"
    (let [config {:issuer                           "https://test.example.com"
                  :authorization-endpoint           "https://test.example.com/authorize"
                  :token-endpoint                   "https://test.example.com/token"
                  :jwks-uri                         "https://test.example.com/jwks"
                  :code-challenge-methods-supported ["S256" "plain"]}
          result (discovery/openid-configuration config)]
      (is (= ["S256" "plain"] (:code_challenge_methods_supported result))))))

(deftest discovery-includes-resource-indicators-supported-test
  (testing "default config includes resource_indicators_supported as true"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= true (:resource_indicators_supported result))))))

(deftest discovery-custom-resource-indicators-supported-test
  (testing "explicit false value is respected"
    (let [config {:issuer                        "https://test.example.com"
                  :authorization-endpoint        "https://test.example.com/authorize"
                  :token-endpoint                "https://test.example.com/token"
                  :jwks-uri                      "https://test.example.com/jwks"
                  :resource-indicators-supported false}
          result (discovery/openid-configuration config)]
      (is (= false (:resource_indicators_supported result))))))
