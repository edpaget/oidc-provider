(ns oidc-provider.dev-server
  "Development Ring server for conformance suite testing.

  Starts a Jetty server on port 9090 with all OIDC endpoints wired.
  Authorization requests are auto-approved for a hardcoded test user
  (no login UI). A pre-registered test client (`test-client` /
  `test-secret`) is available on startup."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [oidc-provider.authorization :as authz]
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
             :email_verified true)
      (some #{"phone"} scope)
      (assoc :phone_number          "+1-555-555-1234"
             :phone_number_verified true)
      (some #{"address"} scope)
      (assoc :address {:street_address "123 Test Street"
                       :locality       "Testville"
                       :region         "TS"
                       :postal_code    "12345"
                       :country        "US"}))))

(defn- json-response
  "Builds a Ring response map with JSON content type."
  [status body]
  {:status  status
   :headers {"Content-Type" "application/json"}
   :body    (json/generate-string body)})

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
      :scopes-supported       ["openid" "profile" "email" "address" "phone" "offline_access"]
      :claims-supported       ["sub" "name" "given_name" "family_name"
                                "preferred_username" "email" "email_verified"
                                "phone_number" "phone_number_verified" "address"]
      :signing-key            rsa-key
      :claims-provider        (->TestClaimsProvider)
      :allow-http-issuer      true})))


;; ---------------------------------------------------------------------------
;; Session management
;; ---------------------------------------------------------------------------

(def ^:private auth-state
  "Server-side authentication state. Tracks the current auth-time (epoch seconds)
  for the test user. `nil` means unauthenticated. Playwright creates fresh browser
  contexts without cookies, so we track state server-side rather than via cookies."
  (atom nil))

(defn- current-auth-time
  "Returns the current auth-time, or nil if unauthenticated."
  []
  @auth-state)

(defn- authenticate!
  "Creates a fresh authentication with current time. Returns the new auth-time."
  []
  (let [now (quot (System/currentTimeMillis) 1000)]
    (reset! auth-state now)
    now))

(defn- authorize-handler
  "Handles GET /authorize requests. Manages authentication state for prompt and
  max_age conformance, then auto-approves for the test user."
  [provider request]
  (try
    (let [parsed        (provider/parse-authorization-request provider (:params request))
          prompt-values (:prompt-values parsed)
          max-age       (:max-age parsed)
          clock         (get-in provider [:provider-config :clock])
          auth-time     (if (contains? prompt-values :login)
                          (authenticate!)
                          (current-auth-time))]
      (if-let [err (authz/validate-prompt-none parsed (some? auth-time)
                                               (:provider-config provider))]
        {:status  302
         :headers {"Location" (authz/build-redirect-url err)}
         :body    ""}
        (let [auth-time (if (or (nil? auth-time)
                                (and max-age
                                     (not (authz/validate-max-age max-age auth-time clock))))
                          (authenticate!)
                          auth-time)
              redirect-url (provider/authorize provider parsed test-user-id auth-time)]
          {:status  302
           :headers {"Location" redirect-url}
           :body    ""})))
    (catch clojure.lang.ExceptionInfo e
      (provider/authorization-error-response provider e))))

(defn- register-route?
  "Returns true when the URI targets the registration endpoint."
  [uri]
  (or (= uri "/register")
      (str/starts-with? uri "/register/")))

(defn- routes
  "Creates a Ring handler dispatching to OIDC endpoints."
  [provider]
  (fn [{:keys [uri request-method] :as request}]
    (cond
      (and (= uri "/.well-known/openid-configuration") (= request-method :get))
      (json-response 200 (provider/discovery-metadata provider))

      (and (= uri "/jwks") (= request-method :get))
      (json-response 200 (provider/jwks provider))

      (and (= uri "/token") (= request-method :post))
      (provider/token-response provider request)

      (and (= uri "/authorize") (= request-method :get))
      (authorize-handler provider request)

      (= uri "/userinfo")
      (provider/userinfo-response provider request)

      (register-route? uri)
      (provider/registration-response provider request)

      (and (= uri "/revoke") (= request-method :post))
      (provider/revocation-response provider request)

      (and (= uri "/reset") (= request-method :post))
      (do (reset! auth-state nil)
          {:status 204 :headers {} :body ""})

      :else
      (json-response 404 {"error" "not_found"}))))

(defn- wrap-json-response
  "Middleware that serializes Clojure map response bodies to JSON strings
  and sets the Content-Type header."
  [handler]
  (fn [request]
    (let [response (handler request)]
      (if (map? (:body response))
        (-> response
            (update :body json/generate-string)
            (assoc-in [:headers "Content-Type"] "application/json"))
        response))))

(defn- wrap-json-request
  "Middleware that parses JSON request bodies into keyword maps. Only
  applies to requests with a JSON content type."
  [handler]
  (fn [request]
    (if (and (:body request)
             (some-> (get-in request [:headers "content-type"])
                     (str/includes? "json")))
      (let [body-str (slurp (:body request))
            parsed   (when-not (str/blank? body-str)
                       (json/parse-string body-str true))]
        (handler (assoc request :body parsed)))
      (handler request))))

(defn create-app
  "Creates the Ring application with middleware."
  [provider]
  (-> (routes provider)
      wrap-json-response
      wrap-json-request
      wrap-keyword-params
      wrap-params))

(defn- register-test-clients
  "Pre-registers three test clients with known credentials. The conformance
  suite requires separate clients for different auth method test variants."
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
      :scopes                     ["openid" "profile" "email" "address" "phone" "offline_access"]
      :token-endpoint-auth-method "client_secret_basic"})
    (provider/register-client
     provider
     {:client-id                  "test-client-2"
      :client-type                "confidential"
      :client-secret-hash         (util/hash-client-secret "test-secret-2")
      :redirect-uris              redirect-uris
      :grant-types                ["authorization_code" "refresh_token"]
      :response-types             ["code"]
      :scopes                     ["openid" "profile" "email" "address" "phone" "offline_access"]
      :token-endpoint-auth-method "client_secret_basic"})
    (provider/register-client
     provider
     {:client-id                  "test-client-post"
      :client-type                "confidential"
      :client-secret-hash         (util/hash-client-secret "test-secret-post")
      :redirect-uris              redirect-uris
      :grant-types                ["authorization_code" "refresh_token"]
      :response-types             ["code"]
      :scopes                     ["openid" "profile" "email" "address" "phone" "offline_access"]
      :token-endpoint-auth-method "client_secret_post"})))

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
