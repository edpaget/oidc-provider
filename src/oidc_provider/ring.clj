(ns oidc-provider.ring
  "Ring handlers for OAuth2 endpoints.

  Provides [[token-handler]] for the token endpoint (RFC 6749 §3.2),
  [[registration-handler]] for dynamic client registration (RFC 7591/7592),
  [[revocation-handler]] for token revocation (RFC 7009), and
  [[userinfo-handler]] for the UserInfo endpoint (OIDC Core §5.3)."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [oidc-provider.error :as error]
   [oidc-provider.protocol :as proto]
   [oidc-provider.registration :as reg]
   [oidc-provider.revocation :as revocation]
   [oidc-provider.token-endpoint :as token-ep])
  (:import
   [java.time Clock]))

(set! *warn-on-reflection* true)

(defn- extract-bearer-token
  "Extracts the Bearer token from the Authorization header, or returns nil."
  [request]
  (when-let [auth (get-in request [:headers "authorization"])]
    (when (str/starts-with? auth "Bearer ")
      (subs auth 7))))

(defn- parse-json-body
  "Parses the request body as JSON. Returns nil on missing body or parse failure."
  [request]
  (try
    (some-> (:body request) slurp (json/parse-string true))
    (catch com.fasterxml.jackson.core.JsonParseException _ nil)))

(defn- json-response
  "Builds a Ring response with JSON content type."
  [status body]
  {:status  status
   :headers {"Content-Type" "application/json"}
   :body    (json/generate-string body)})

(def ^:private no-cache-headers
  {"Content-Type"  "application/json"
   "Cache-Control" "no-store"
   "Pragma"        "no-cache"})

(def ^:private auth-failure-headers
  (assoc no-cache-headers "WWW-Authenticate" "Bearer"))

(defn- extract-client-id
  "Extracts the last non-empty path segment from the URI."
  [uri]
  (->> (str/split uri #"/")
       (remove str/blank?)
       last))

(defn- handle-post
  "Handles POST registration requests."
  [request client-store opts]
  (let [parsed (parse-json-body request)]
    (if-not parsed
      (json-response 400 {"error"             "invalid_client_metadata"
                          "error_description" "Missing or malformed JSON body"})
      (try
        (let [result (reg/handle-registration-request parsed client-store opts)]
          (json-response 201 result))
        (catch clojure.lang.ExceptionInfo e
          (json-response 400 {"error"             "invalid_client_metadata"
                              "error_description" (or (:error_description (ex-data e))
                                                      "invalid_client_metadata")}))))))

(defn- handle-get
  "Handles GET client read requests."
  [request client-store]
  (let [token (extract-bearer-token request)]
    (if-not token
      (json-response 401 {"error" "invalid_token"})
      (try
        (let [client-id (extract-client-id (:uri request))]
          (json-response 200 (reg/handle-client-read client-store client-id token)))
        (catch clojure.lang.ExceptionInfo _
          (json-response 401 {"error" "invalid_token"}))))))

(defn registration-handler
  "Creates a Ring handler for dynamic client registration.

  Takes a `client-store` implementing [[oidc-provider.protocol/ClientStore]] and
  an optional `opts` map passed through to
  [[oidc-provider.registration/handle-registration-request]]. Supported keys are
  `:clock` (a `java.time.Clock`) and `:registration-endpoint` (a base URL string).
  Returns a Ring handler function that dispatches POST for registration
  and GET for client configuration reads. To gate registration access,
  use application-level middleware."
  ([client-store]
   (registration-handler client-store {}))
  ([client-store opts]
   (fn [request]
     (case (:request-method request)
       :post (handle-post request client-store opts)
       :get  (handle-get request client-store)
       {:status  405
        :headers {"Allow" "GET, POST" "Content-Type" "application/json"}
        :body    (json/generate-string {"error" "method_not_allowed"})}))))

(defn revocation-handler
  "Creates a Ring handler for RFC 7009 token revocation.

  Takes `client-store` and `token-store`. Only accepts POST requests; returns
  405 for other methods."
  [client-store token-store]
  (fn [request]
    (if (not= :post (:request-method request))
      {:status  405
       :headers {"Allow" "POST" "Content-Type" "application/json"}
       :body    (json/generate-string {"error" "method_not_allowed"})}
      (let [content-type (get-in request [:headers "content-type"])]
        (if-not (and content-type (str/starts-with? content-type "application/x-www-form-urlencoded"))
          {:status  415
           :headers {"Content-Type" "application/json"
                     "Accept"       "application/x-www-form-urlencoded"}
           :body    (json/generate-string {"error"             "invalid_request"
                                           "error_description" "Content-Type must be application/x-www-form-urlencoded"})}
          (try
            (let [auth-header (get-in request [:headers "authorization"])]
              (revocation/handle-revocation-request
               (:params request) auth-header client-store token-store)
              {:status 200})
            (catch clojure.lang.ExceptionInfo e
              (if (error/request-error? (:type (ex-data e)))
                {:status  400
                 :headers no-cache-headers
                 :body    (json/generate-string
                           {:error             (ex-message e)
                            :error_description (:error_description (ex-data e))})}
                {:status  401
                 :headers auth-failure-headers
                 :body    (json/generate-string {:error "invalid_client"})}))))))))

(defn token-handler
  "Creates a Ring handler for the OAuth2 token endpoint (RFC 6749 §3.2).

  Takes a `provider` instance created by [[oidc-provider.core/create-provider]].
  Only accepts POST requests with `application/x-www-form-urlencoded` content
  type. Success responses include `Cache-Control: no-store` and `Pragma: no-cache`
  headers per RFC 6749 §5.1."
  [provider]
  (let [{:keys [provider-config client-store code-store
                token-store claims-provider]}           provider]
    (fn [request]
      (if (not= :post (:request-method request))
        {:status  405
         :headers {"Allow" "POST" "Content-Type" "application/json"}
         :body    (json/generate-string {"error" "method_not_allowed"})}
        (let [content-type (get-in request [:headers "content-type"])]
          (if-not (and content-type (str/starts-with? content-type "application/x-www-form-urlencoded"))
            {:status  415
             :headers {"Content-Type" "application/json"
                       "Accept"       "application/x-www-form-urlencoded"}
             :body    (json/generate-string {"error"             "invalid_request"
                                             "error_description" "Content-Type must be application/x-www-form-urlencoded"})}
            (try
              (let [auth-header (get-in request [:headers "authorization"])
                    result      (token-ep/handle-token-request
                                 (:params request) auth-header
                                 provider-config client-store
                                 code-store token-store claims-provider)]
                {:status  200
                 :headers no-cache-headers
                 :body    (json/generate-string result)})
              (catch clojure.lang.ExceptionInfo e
                {:status  400
                 :headers no-cache-headers
                 :body    (json/generate-string
                           (cond-> {:error (or (:error (ex-data e)) "invalid_request")}
                             (ex-message e) (assoc :error_description (ex-message e))))}))))))))

(defn- bearer-unauthorized
  "Returns a 401 response with `WWW-Authenticate: Bearer` header and optional
  error code. Per RFC 6750 §3.1 the error is omitted when no token was
  presented."
  ([]
   {:status  401
    :headers {"WWW-Authenticate" "Bearer"
              "Content-Type"     "application/json"}
    :body    ""})
  ([error-code]
   {:status  401
    :headers {"WWW-Authenticate" (str "Bearer error=\"" error-code "\"")
              "Content-Type"     "application/json"}
    :body    (json/generate-string {"error" error-code})}))

(defn userinfo-handler
  "Creates a Ring handler for the OIDC UserInfo endpoint (OIDC Core §5.3).

  Takes `token-store`, `claims-provider`, and `clock`. Accepts GET and POST
  requests with a Bearer token in the Authorization header. Looks up the
  access token, validates expiry, retrieves user claims filtered by the
  token's scope, and returns them as JSON."
  [token-store claims-provider ^Clock clock]
  (fn [request]
    (let [method     (:request-method request)
          token      (when (#{:get :post} method) (extract-bearer-token request))
          token-data (when token (proto/get-access-token token-store token))
          expired?   (when token-data (> (.millis clock) (:expiry token-data)))]
      (cond
        (not (#{:get :post} method))
        {:status  405
         :headers {"Allow" "GET, POST" "Content-Type" "application/json"}
         :body    (json/generate-string {"error" "method_not_allowed"})}

        (not token)
        (bearer-unauthorized)

        (or (not token-data) expired?)
        (bearer-unauthorized "invalid_token")

        :else
        (json-response 200 (proto/get-claims claims-provider
                                             (:user-id token-data)
                                             (:scope token-data)))))))
