(ns oidc-provider.dev-server
  "Development Ring server wiring all OIDC provider endpoints.

  Starts a Jetty server on port 9090 with discovery, JWKS, token,
  registration, revocation, and authorization endpoints."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [oidc-provider.core :as provider]
   [oidc-provider.protocol :as proto]
   [oidc-provider.token :as token]
   [ring.adapter.jetty :as jetty]
   [ring.middleware.keyword-params :refer [wrap-keyword-params]]
   [ring.middleware.params :refer [wrap-params]]))

(set! *warn-on-reflection* true)

(defrecord SimpleClaimsProvider []
  proto/ClaimsProvider
  (get-claims [_ user-id _scope]
    {:sub user-id}))

(defn- json-response
  "Builds a Ring response map with JSON content type."
  [status body]
  {:status  status
   :headers {"Content-Type" "application/json"}
   :body    (json/generate-string body)})

(defn- error-response
  "Builds a JSON error response from an `ExceptionInfo`."
  [^clojure.lang.ExceptionInfo e]
  (let [data (ex-data e)]
    (json-response (or (:status data) 400)
                   {"error"             (or (:error data) "invalid_request")
                    "error_description" (.getMessage e)})))

(defn- create-app-provider
  "Creates a provider configured for the dev server."
  []
  (let [base-url "http://localhost:9090"
        rsa-key  (token/generate-rsa-key)]
    (provider/create-provider
     {:issuer                 base-url
      :authorization-endpoint (str base-url "/authorize")
      :token-endpoint         (str base-url "/token")
      :jwks-uri               (str base-url "/jwks")
      :registration-endpoint  (str base-url "/register")
      :revocation-endpoint    (str base-url "/revoke")
      :signing-key            rsa-key
      :claims-provider        (->SimpleClaimsProvider)})))

(defn- token-handler
  "Handles POST /token requests."
  [provider request]
  (try
    (let [result (provider/token-request
                  provider
                  (:params request)
                  (get-in request [:headers "authorization"]))]
      (json-response 200 result))
    (catch clojure.lang.ExceptionInfo e
      (error-response e))))

(defn- authorize-handler
  "Handles GET /authorize requests. Parses the authorization request
  but does not auto-approve — phase 2 will add that."
  [provider request]
  (try
    (let [parsed (provider/parse-authorization-request provider (:params request))]
      (json-response 200 {"status"  "authorization_pending"
                          "request" parsed}))
    (catch clojure.lang.ExceptionInfo e
      (error-response e))))

(defn- register-route?
  "Returns true when the URI targets the registration endpoint."
  [uri]
  (or (= uri "/register")
      (str/starts-with? uri "/register/")))

(defn- routes
  "Creates a Ring handler dispatching to OIDC endpoints."
  [provider]
  (let [reg-handler    (provider/registration-handler provider)
        revoke-handler (provider/revocation-handler provider)]
    (fn [{:keys [uri request-method] :as request}]
      (cond
        (and (= uri "/.well-known/openid-configuration") (= request-method :get))
        (json-response 200 (provider/discovery-metadata provider))

        (and (= uri "/jwks") (= request-method :get))
        (json-response 200 (provider/jwks provider))

        (and (= uri "/token") (= request-method :post))
        (token-handler provider request)

        (and (= uri "/authorize") (= request-method :get))
        (authorize-handler provider request)

        (register-route? uri)
        (reg-handler request)

        (and (= uri "/revoke") (= request-method :post))
        (revoke-handler request)

        :else
        (json-response 404 {"error" "not_found"})))))

(defn create-app
  "Creates the Ring application with middleware."
  [provider]
  (-> (routes provider)
      wrap-keyword-params
      wrap-params))

(defn -main
  "Starts the dev OIDC provider server on port 9090."
  [& _args]
  (let [provider (create-app-provider)
        app      (create-app provider)]
    (println "Starting OIDC provider dev server on http://localhost:9090")
    (jetty/run-jetty app {:port 9090 :join? true})))
