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

(def ^:private conformance-callback
  "Redirect URI used by the conformance suite."
  "https://localhost.emobix.co.uk:8443/test/a/oidc-provider/callback")

(defn- create-app-provider
  "Creates a provider configured for the dev server. The base URL defaults
  to `http://localhost:9090` but can be overridden via `BASE_URL` or `PORT`
  environment variables. Use `BASE_URL=http://host.docker.internal:9090`
  when the conformance suite runs in Docker."
  []
  (let [port     (or (System/getenv "PORT") "9090")
        base-url (or (System/getenv "BASE_URL") (str "http://localhost:" port))
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

(defn- register-test-clients
  "Pre-registers two test clients with known credentials. The conformance
  suite requires two separate clients for its test scenarios."
  [provider]
  (let [redirect-uris ["https://example.com/callback" conformance-callback]]
    (provider/register-client
     provider
     {:client-id                  "test-client"
      :client-type                "confidential"
      :client-secret-hash         (util/hash-client-secret "test-secret")
      :redirect-uris              redirect-uris
      :grant-types                ["authorization_code" "refresh_token"]
      :response-types             ["code"]
      :scopes                     ["openid" "profile" "email"]
      :token-endpoint-auth-method "client_secret_basic"})
    (provider/register-client
     provider
     {:client-id                  "test-client-2"
      :client-type                "confidential"
      :client-secret-hash         (util/hash-client-secret "test-secret-2")
      :redirect-uris              redirect-uris
      :grant-types                ["authorization_code" "refresh_token"]
      :response-types             ["code"]
      :scopes                     ["openid" "profile" "email"]
      :token-endpoint-auth-method "client_secret_basic"})))

(defn -main
  "Starts the dev OIDC provider server. Port defaults to 9090 and can be
  overridden via the `PORT` environment variable."
  [& _args]
  (let [port     (Integer/parseInt (or (System/getenv "PORT") "9090"))
        provider (create-app-provider)
        _        (register-test-clients provider)
        app      (create-app provider)]
    (println (str "Starting OIDC provider dev server on http://localhost:" port))
    (println "Test clients: test-client/test-secret, test-client-2/test-secret-2")
    (jetty/run-jetty app {:port port :join? true})))
