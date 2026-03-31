(ns oidc-provider.registration
  "Dynamic client registration per RFC 7591.

  Provides [[handle-registration-request]] for processing client registration
  requests and [[registration-error-response]] for formatting error responses.
  Accepts keyword maps and converts to kebab-case for internal storage
  via [[oidc-provider.protocol/ClientStore]]."
  (:require
   [cheshire.core :as json]
   [clojure.set :as set]
   [clojure.string :as str]
   [malli.core :as m]
   [oidc-provider.protocol :as proto]
   [oidc-provider.token :as token]
   [oidc-provider.util :as util])
  (:import
   (java.net URI URISyntaxException)
   (java.time Clock Instant)))

(set! *warn-on-reflection* true)

(def RegistrationRequest
  "Malli schema for an RFC 7591 client registration request."
  [:map
   [:redirect_uris [:vector {:min 1} :string]]
   [:grant_types {:optional true} [:vector [:enum "authorization_code" "refresh_token" "client_credentials"]]]
   [:response_types {:optional true} [:vector [:enum "code" "token" "id_token"]]]
   [:client_name {:optional true} :string]
   [:token_endpoint_auth_method {:optional true} [:enum "client_secret_basic" "client_secret_post" "none"]]
   [:scope {:optional true} :string]
   [:client_uri {:optional true} :string]
   [:logo_uri {:optional true} :string]
   [:contacts {:optional true} [:vector :string]]
   [:application_type {:optional true} [:enum "web" "native"]]])

(def RegistrationResponse
  "Malli schema for an RFC 7591 client registration response."
  [:map
   [:client_id :string]
   [:registration_access_token :string]
   [:client_secret {:optional true} :string]
   [:client_name {:optional true} :string]
   [:scope {:optional true} :string]
   [:redirect_uris [:vector :string]]
   [:grant_types [:vector :string]]
   [:response_types [:vector :string]]
   [:token_endpoint_auth_method :string]
   [:client_uri {:optional true} :string]
   [:logo_uri {:optional true} :string]
   [:contacts {:optional true} [:vector :string]]
   [:application_type :string]
   [:client_secret_expires_at {:optional true} :int]
   [:client_id_issued_at {:optional true} :int]
   [:registration_client_uri {:optional true} :string]])

(defn- apply-defaults
  "Merges RFC 7591 defaults into a registration request."
  [request]
  (cond-> request
    (not (:grant_types request))                (assoc :grant_types ["authorization_code"])
    (not (:response_types request))             (assoc :response_types ["code"])
    (not (:token_endpoint_auth_method request)) (assoc :token_endpoint_auth_method "client_secret_basic")
    (not (:application_type request))           (assoc :application_type "web")))

(defn- valid-https-uri?
  "Returns true when `uri-str` is an absolute HTTPS URI."
  [uri-str]
  (try
    (let [uri (URI. ^String uri-str)]
      (and (.isAbsolute uri)
           (some? (.getHost uri))
           (= "https" (some-> (.getScheme uri) str/lower-case))))
    (catch URISyntaxException _ false)))

(defn- validate-metadata-uris
  "Validates that `client_uri` and `logo_uri`, when present, are absolute HTTPS URIs."
  [request]
  (when-let [client-uri (:client_uri request)]
    (when-not (valid-https-uri? client-uri)
      (throw (ex-info "invalid_client_metadata"
                      {:error_description (str "Invalid client_uri: " (util/truncate client-uri 200))}))))
  (when-let [logo-uri (:logo_uri request)]
    (when-not (valid-https-uri? logo-uri)
      (throw (ex-info "invalid_client_metadata"
                      {:error_description (str "Invalid logo_uri: " (util/truncate logo-uri 200))})))))

(defn- validate-redirect-uris
  "Validates redirect URIs based on `application_type`: `\"web\"` requires HTTPS only,
  `\"native\"` allows HTTPS, HTTP on loopback, or custom URI schemes."
  [request]
  (let [validator (if (= "native" (:application_type request))
                    util/valid-native-redirect-uri?
                    util/valid-web-redirect-uri?)]
    (doseq [uri (:redirect_uris request)]
      (when-not (validator uri)
        (throw (ex-info "invalid_client_metadata"
                        {:error_description (str "Invalid redirect URI: " (util/truncate uri 200))}))))))

(defn- validate-grant-response-consistency
  "Validates that `grant_types` and `response_types` are consistent per RFC 7591."
  [request]
  (let [grant-types    (set (:grant_types request))
        response-types (set (:response_types request))]
    (when (and (contains? grant-types "authorization_code")
               (not (contains? response-types "code")))
      (throw (ex-info "invalid_client_metadata"
                      {:error_description "grant_types contains authorization_code but response_types is missing code"})))
    (when (and (contains? grant-types "implicit")
               (empty? (set/intersection response-types #{"token" "id_token"})))
      (throw (ex-info "invalid_client_metadata"
                      {:error_description "grant_types contains implicit but response_types is missing token or id_token"})))
    (when (and (contains? response-types "code")
               (not (contains? grant-types "authorization_code")))
      (throw (ex-info "invalid_client_metadata"
                      {:error_description "response_types contains code but grant_types is missing authorization_code"})))))

(defn- validate-request
  "Runs semantic validations on a defaulted registration request."
  [request]
  (validate-redirect-uris request)
  (validate-metadata-uris request)
  (validate-grant-response-consistency request)
  request)

(defn- request->client-config
  "Converts a registration request to a kebab-case `ClientConfig` map."
  [request]
  (let [auth-method (:token_endpoint_auth_method request)
        scope-str   (:scope request)
        scopes      (if scope-str (vec (str/split scope-str #" ")) [])]
    (cond-> {:client-id                  (util/generate-client-id)
             :client-type                (if (= auth-method "none") "public" "confidential")
             :redirect-uris              (:redirect_uris request)
             :grant-types                (:grant_types request)
             :response-types             (:response_types request)
             :scopes                     scopes
             :token-endpoint-auth-method auth-method
             :application-type           (:application_type request)
             :registration-access-token  (token/generate-access-token)}

      (:client_name request) (assoc :client-name (:client_name request))
      (:client_uri request) (assoc :client-uri (:client_uri request))
      (:logo_uri request) (assoc :logo-uri (:logo_uri request))
      (:contacts request) (assoc :contacts (:contacts request)))))

(defn- client-config->response
  "Converts a stored kebab-case client config to a registration response."
  [client]
  (cond-> {:client_id                  (:client-id client)
           :redirect_uris              (:redirect-uris client)
           :grant_types                (:grant-types client)
           :response_types             (:response-types client)
           :token_endpoint_auth_method (:token-endpoint-auth-method client)
           :application_type           (:application-type client)}
    (:client-name client)   (assoc :client_name (:client-name client))
    (seq (:scopes client))  (assoc :scope (str/join " " (:scopes client)))
    (:client-uri client)    (assoc :client_uri (:client-uri client))
    (:logo-uri client)      (assoc :logo_uri (:logo-uri client))
    (:contacts client)      (assoc :contacts (:contacts client))))

(defn handle-registration-request
  "Processes a dynamic client registration request per RFC 7591.

  Takes a `request` map with keyword keys, a `client-store` implementing
  [[oidc-provider.protocol/ClientStore]], and an optional `opts` map. The `opts`
  map supports `:clock` (a `java.time.Clock`, defaults to UTC) for generating
  `client_id_issued_at`, and `:registration-endpoint` (a base URL string) for
  constructing `registration_client_uri` per RFC 7592.

  Throws `ex-info` with `\"invalid_client_metadata\"` message on validation errors."
  ([request client-store]
   (handle-registration-request request client-store {}))
  ([request client-store opts]
   (when-not (m/validate RegistrationRequest request)
     (throw (ex-info "invalid_client_metadata"
                     {:errors (m/explain RegistrationRequest request)})))
   (let [config       (-> request apply-defaults validate-request request->client-config)
         reg-token    (:registration-access-token config)
         secret       (when (not= (:token-endpoint-auth-method config) "none")
                        (util/generate-client-secret))
         to-store     (cond-> (assoc config :registration-access-token
                                     (util/hash-client-secret reg-token))
                        secret (assoc :client-secret-hash (util/hash-client-secret secret)))
         stored       (proto/register-client client-store to-store)
         ^Clock clock (or (:clock opts) (Clock/systemUTC))
         issued-at    (.getEpochSecond (Instant/now clock))
         client-id    (:client-id stored)
         reg-ep       (:registration-endpoint opts)]
     (cond-> (-> (client-config->response stored)
                 (assoc :registration_access_token reg-token)
                 (assoc :client_id_issued_at issued-at))
       secret (assoc :client_secret secret
                     :client_secret_expires_at 0)
       reg-ep (assoc :registration_client_uri (str reg-ep "/" client-id))))))

(defn handle-client-read
  "Handles RFC 7592 client read requests.

  Takes the `store` implementing [[oidc-provider.protocol/ClientStore]],
  `client-id`, and the bearer `access-token` presented by the caller.
  Returns the client configuration if the token is valid, or a 401 error
  response otherwise. The stored registration access token is a PBKDF2 hash;
  verification uses [[oidc-provider.util/verify-client-secret]]."
  [store client-id access-token]
  (let [client (proto/get-client store client-id)]
    (if (and client
             (try
               (util/verify-client-secret access-token (:registration-access-token client))
               (catch Exception _ false)))
      {:status 200 :body (client-config->response client)}
      {:status 401 :body {:error "invalid_token"}})))

(defn registration-error-response
  "Creates an RFC 7591 error response.

  Takes an `error` code string and `error-description` string. Returns a Ring
  response map with JSON body."
  [error error-description]
  {:status  400
   :headers {"Content-Type" "application/json"}
   :body    (json/generate-string
             (cond-> {:error error}
               error-description (assoc :error_description error-description)))})
