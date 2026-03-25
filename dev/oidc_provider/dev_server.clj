(ns oidc-provider.dev-server
  "Development Ring server for conformance suite testing.

  Starts a Jetty server on port 9090 with all OIDC endpoints wired.
  Authorization requests are auto-approved for a hardcoded test user
  (no login UI). A pre-registered test client (`test-client` /
  `test-secret`) is available on startup."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [oidc-provider.core :as provider]
   [oidc-provider.protocol :as proto]
   [oidc-provider.token :as token]
   [oidc-provider.util :as util]
   [ring.adapter.jetty :as jetty]
   [ring.middleware.keyword-params :refer [wrap-keyword-params]]
   [ring.middleware.params :refer [wrap-params]]))

(set! *warn-on-reflection* true)

(def ^:private test-user-id
  "User-id used for every auto-approved authorization request."
  "test-user")

(defrecord ^{:doc "Claims provider returning hardcoded test user claims,
  filtered by requested scope."} TestClaimsProvider []
  proto/ClaimsProvider
  (get-claims [_ user-id scope]
    (cond-> {:sub user-id}
      (some #{"profile"} scope)
      (assoc :name               "Test User"
             :given_name         "Test"
             :family_name        "User"
             :preferred_username "testuser")
      (some #{"email"} scope)
      (assoc :email          "test@example.com"
             :email_verified true))))

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
      :userinfo-endpoint      (str base-url "/userinfo")
      :registration-endpoint  (str base-url "/register")
      :revocation-endpoint    (str base-url "/revoke")
      :signing-key            rsa-key
      :claims-provider        (->TestClaimsProvider)
      :allow-http-issuer      true})))

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
  "Handles GET /authorize requests. Validates the authorization request
  and immediately approves it for the hardcoded test user, returning a
  302 redirect with an authorization code."
  [provider request]
  (try
    (let [parsed      (provider/parse-authorization-request provider (:params request))
          redirect-url (provider/authorize provider parsed test-user-id)]
      {:status  302
       :headers {"Location" redirect-url}
       :body    ""})
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
  (let [reg-handler      (provider/registration-handler provider)
        revoke-handler   (provider/revocation-handler provider)
        userinfo-handler (provider/userinfo-handler provider)]
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

        (= uri "/userinfo")
        (userinfo-handler request)

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

(defn- register-test-client
  "Pre-registers a test client with known credentials."
  [provider]
  (provider/register-client
   provider
   {:client-id                  "test-client"
    :client-type                "confidential"
    :client-secret-hash         (util/hash-client-secret "test-secret")
    :redirect-uris              ["https://example.com/callback"]
    :grant-types                ["authorization_code" "refresh_token"]
    :response-types             ["code"]
    :scopes                     ["openid" "profile" "email"]
    :token-endpoint-auth-method "client_secret_basic"}))

(defn -main
  "Starts the dev OIDC provider server on port 9090."
  [& _args]
  (let [provider (create-app-provider)
        _        (register-test-client provider)
        app      (create-app provider)]
    (println "Starting OIDC provider dev server on http://localhost:9090")
    (println "Test client: client_id=test-client client_secret=test-secret")
    (jetty/run-jetty app {:port 9090 :join? true})))
