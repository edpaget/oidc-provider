(ns oidc-provider.resource-metadata-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.resource-metadata :as rm]))

(def base-config
  {:resource              "https://api.example.com"
   :authorization-servers ["https://auth.example.com"]})

(deftest resource-metadata-required-fields-test
  (testing "includes resource and authorization_servers in output"
    (let [result (rm/resource-metadata base-config)]
      (is (= "https://api.example.com" (:resource result)))
      (is (= ["https://auth.example.com"] (:authorization_servers result))))))

(deftest resource-metadata-defaults-test
  (testing "bearer_methods_supported defaults to header"
    (let [result (rm/resource-metadata base-config)]
      (is (= ["header"] (:bearer_methods_supported result))))))

(deftest resource-metadata-optional-fields-test
  (testing "optional fields included when provided"
    (let [result (rm/resource-metadata (assoc base-config
                                              :scopes-supported ["read" "write"]
                                              :bearer-methods-supported ["header" "body"]
                                              :resource-documentation "https://docs.example.com"))]
      (is (= ["read" "write"] (:scopes_supported result)))
      (is (= ["header" "body"] (:bearer_methods_supported result)))
      (is (= "https://docs.example.com" (:resource_documentation result))))))

(deftest resource-metadata-validation-test
  (testing "invalid input throws"
    (is (thrown? AssertionError (rm/resource-metadata {})))
    (is (thrown? AssertionError (rm/resource-metadata {:resource "https://api.example.com"})))))
