(ns oidc-provider.ring
  "Ring handlers for OAuth2 Dynamic Client Registration (RFC 7591/7592) and
  Token Revocation (RFC 7009).

  Provides [[registration-handler]] for client registration and
  [[revocation-handler]] for token revocation."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [oidc-provider.registration :as reg]
   [oidc-provider.revocation :as revocation]))

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
    (some-> (:body request) slurp (json/parse-string))
    (catch com.fasterxml.jackson.core.JsonParseException _ nil)))

(defn- json-response
  "Builds a Ring response with JSON content type."
  [status body]
  {:status  status
   :headers {"Content-Type" "application/json"}
   :body    (json/generate-string body)})

(defn- extract-client-id
  "Extracts the last non-empty path segment from the URI."
  [uri]
  (->> (str/split uri #"/")
       (remove str/blank?)
       last))

(defn- handle-post
  "Handles POST registration requests."
  [request client-store]
  (let [parsed (parse-json-body request)]
    (if-not parsed
      (json-response 400 {"error"             "invalid_client_metadata"
                          "error_description" "Missing or malformed JSON body"})
      (try
        (let [result (reg/handle-registration-request parsed client-store)]
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
      (let [client-id (extract-client-id (:uri request))
            result    (reg/handle-client-read client-store client-id token)]
        (json-response (:status result) (:body result))))))

(defn registration-handler
  "Creates a Ring handler for dynamic client registration.

  Takes a `client-store` implementing [[oidc-provider.protocol/ClientStore]].
  Returns a Ring handler function that dispatches POST for registration
  and GET for client configuration reads. To gate registration access,
  use application-level middleware."
  [client-store]
  (fn [request]
    (case (:request-method request)
      :post (handle-post request client-store)
      :get  (handle-get request client-store)
      {:status  405
       :headers {"Allow" "GET, POST" "Content-Type" "application/json"}
       :body    (json/generate-string {"error" "method_not_allowed"})})))

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
          (let [auth-header (get-in request [:headers "authorization"])
                result      (revocation/handle-revocation-request
                             (:params request) auth-header
                             client-store token-store)]
            (cond-> result
              (:body result) (update :body json/generate-string))))))))
