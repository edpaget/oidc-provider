(ns oidc-provider.ring
  "Ring handler for OAuth2 Dynamic Client Registration (RFC 7591/7592).

  Provides [[registration-handler]] which returns a Ring handler supporting
  POST for client registration and GET for client configuration reads."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [oidc-provider.registration :as reg]
   [oidc-provider.util :as util]))

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
  [request client-store initial-access-token]
  (if (and initial-access-token
           (let [token (extract-bearer-token request)]
             (not (and token (util/constant-time-eq? token initial-access-token)))))
    (json-response 401 {"error" "invalid_token"})
    (let [parsed (parse-json-body request)]
      (if-not parsed
        (json-response 400 {"error"             "invalid_client_metadata"
                            "error_description" "Missing or malformed JSON body"})
        (try
          (let [result (reg/handle-registration-request parsed client-store)]
            (json-response 201 result))
          (catch clojure.lang.ExceptionInfo e
            (json-response 400 {"error"             "invalid_client_metadata"
                                "error_description" (.getMessage e)})))))))

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

  Takes a `client-store` implementing [[oidc-provider.protocol/ClientStore]]
  and optional keyword arguments. When `:initial-access-token` is provided,
  POST requests require a matching Bearer token for gated registration.

  Returns a Ring handler function that dispatches POST for registration
  and GET for client configuration reads."
  [client-store & {:keys [initial-access-token]}]
  (fn [request]
    (case (:request-method request)
      :post (handle-post request client-store initial-access-token)
      :get  (handle-get request client-store)
      {:status  405
       :headers {"Allow" "GET, POST" "Content-Type" "application/json"}
       :body    (json/generate-string {"error" "method_not_allowed"})})))
