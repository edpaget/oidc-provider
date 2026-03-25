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

(deftest discovery-default-client-id-metadata-document-supported-test
  (testing "default config does not include client_id_metadata_document_supported"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (not (contains? result :client_id_metadata_document_supported))))))

(deftest discovery-explicit-client-id-metadata-document-supported-test
  (testing "explicit true value is respected"
    (let [config {:issuer                                "https://test.example.com"
                  :authorization-endpoint                "https://test.example.com/authorize"
                  :token-endpoint                        "https://test.example.com/token"
                  :jwks-uri                              "https://test.example.com/jwks"
                  :client-id-metadata-document-supported true}
          result (discovery/openid-configuration config)]
      (is (= true (:client_id_metadata_document_supported result))))))

(deftest discovery-includes-subject-types-supported-test
  (testing "default config includes subject_types_supported with public"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= ["public"] (:subject_types_supported result))))))

(deftest discovery-includes-id-token-signing-alg-values-supported-test
  (testing "default config includes id_token_signing_alg_values_supported with RS256"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= ["RS256"] (:id_token_signing_alg_values_supported result))))))

(deftest discovery-includes-token-endpoint-auth-methods-supported-test
  (testing "default config includes token_endpoint_auth_methods_supported"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= ["client_secret_basic" "client_secret_post" "none"]
             (:token_endpoint_auth_methods_supported result))))))

(deftest discovery-required-fields-present-test
  (testing "all OIDC Discovery section 3 REQUIRED fields are present"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= "https://test.example.com" (:issuer result)))
      (is (= "https://test.example.com/authorize" (:authorization_endpoint result)))
      (is (= "https://test.example.com/token" (:token_endpoint result)))
      (is (= ["code"] (:response_types_supported result)))
      (is (= ["public"] (:subject_types_supported result))))))

(deftest discovery-required-fields-id-token-signing-alg-test
  (testing "id_token_signing_alg_values_supported is REQUIRED per OIDC Discovery section 3"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= ["RS256"] (:id_token_signing_alg_values_supported result))))))

(deftest discovery-jwks-uri-present-when-configured-test
  (testing "jwks_uri is included when provided in config"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= "https://test.example.com/jwks" (:jwks_uri result))))))

(deftest discovery-default-grant-types-include-client-credentials-test
  (testing "default grant_types_supported includes client_credentials"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= ["authorization_code" "refresh_token" "client_credentials"]
             (:grant_types_supported result))))))

(deftest discovery-request-uri-parameter-supported-test
  (testing "request_uri_parameter_supported defaults to false"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= false (:request_uri_parameter_supported result))))))

(deftest discovery-custom-request-uri-parameter-supported-test
  (testing "explicit true value is respected"
    (let [config {:issuer                          "https://test.example.com"
                  :authorization-endpoint          "https://test.example.com/authorize"
                  :token-endpoint                  "https://test.example.com/token"
                  :jwks-uri                        "https://test.example.com/jwks"
                  :request-uri-parameter-supported true}
          result (discovery/openid-configuration config)]
      (is (= true (:request_uri_parameter_supported result))))))

(deftest discovery-request-parameter-supported-test
  (testing "request_parameter_supported defaults to false"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= false (:request_parameter_supported result))))))

(deftest discovery-custom-request-parameter-supported-test
  (testing "explicit true value is respected"
    (let [config {:issuer                      "https://test.example.com"
                  :authorization-endpoint      "https://test.example.com/authorize"
                  :token-endpoint              "https://test.example.com/token"
                  :jwks-uri                    "https://test.example.com/jwks"
                  :request-parameter-supported true}
          result (discovery/openid-configuration config)]
      (is (= true (:request_parameter_supported result))))))

(deftest discovery-claims-parameter-supported-test
  (testing "claims_parameter_supported defaults to false"
    (let [config {:issuer                 "https://test.example.com"
                  :authorization-endpoint "https://test.example.com/authorize"
                  :token-endpoint         "https://test.example.com/token"
                  :jwks-uri               "https://test.example.com/jwks"}
          result (discovery/openid-configuration config)]
      (is (= false (:claims_parameter_supported result))))))

(deftest discovery-custom-claims-parameter-supported-test
  (testing "explicit true value is respected"
    (let [config {:issuer                     "https://test.example.com"
                  :authorization-endpoint     "https://test.example.com/authorize"
                  :token-endpoint             "https://test.example.com/token"
                  :jwks-uri                   "https://test.example.com/jwks"
                  :claims-parameter-supported true}
          result (discovery/openid-configuration config)]
      (is (= true (:claims_parameter_supported result))))))
