(ns oidc-provider.registration
  "Dynamic client registration per RFC 7591 and client configuration management
  per RFC 7592.

  Provides [[handle-registration-request]] for processing client registration
  requests, [[handle-client-read]] for reading client configuration,
  [[handle-client-update]] for replacing client metadata, and
  [[handle-client-delete]] for deregistration. Accepts keyword maps and converts
  to kebab-case for internal storage via [[oidc-provider.protocol/ClientStore]]."
  (:require
   [clojure.set :as set]
   [clojure.string :as str]
   [malli.core :as m]
   [oidc-provider.error :as error]
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
                      {:type              ::error/invalid-client-metadata
                       :error_description (str "Invalid client_uri: " (util/truncate client-uri 200))}))))
  (when-let [logo-uri (:logo_uri request)]
    (when-not (valid-https-uri? logo-uri)
      (throw (ex-info "invalid_client_metadata"
                      {:type              ::error/invalid-client-metadata
                       :error_description (str "Invalid logo_uri: " (util/truncate logo-uri 200))})))))

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
                        {:type              ::error/invalid-client-metadata
                         :error_description (str "Invalid redirect URI: " (util/truncate uri 200))}))))))

(defn- validate-grant-response-consistency
  "Validates that `grant_types` and `response_types` are consistent per RFC 7591."
  [request]
  (let [grant-types    (set (:grant_types request))
        response-types (set (:response_types request))]
    (when (and (contains? grant-types "authorization_code")
               (not (contains? response-types "code")))
      (throw (ex-info "invalid_client_metadata"
                      {:type              ::error/invalid-client-metadata
                       :error_description "grant_types contains authorization_code but response_types is missing code"})))
    (when (and (contains? grant-types "implicit")
               (empty? (set/intersection response-types #{"token" "id_token"})))
      (throw (ex-info "invalid_client_metadata"
                      {:type              ::error/invalid-client-metadata
                       :error_description "grant_types contains implicit but response_types is missing token or id_token"})))
    (when (and (contains? response-types "code")
               (not (contains? grant-types "authorization_code")))
      (throw (ex-info "invalid_client_metadata"
                      {:type              ::error/invalid-client-metadata
                       :error_description "response_types contains code but grant_types is missing authorization_code"})))))

(defn- validate-request
  "Runs semantic validations on a defaulted registration request."
  [request]
  (validate-redirect-uris request)
  (validate-metadata-uris request)
  (validate-grant-response-consistency request)
  request)

(defn- request->client-config
  "Converts a registration request to a kebab-case `ClientConfig` map.
  When no scope is provided and `default-scopes` is given, uses those
  as the client's allowed scopes per RFC 7591 §2."
  [request default-scopes]
  (let [auth-method (:token_endpoint_auth_method request)
        scope-str   (:scope request)
        scopes      (cond
                      scope-str      (vec (str/split scope-str #" "))
                      default-scopes (vec default-scopes)
                      :else          [])]
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
  `client_id_issued_at`, `:registration-endpoint` (a base URL string) for
  constructing `registration_client_uri` per RFC 7592, and `:scopes-supported`
  (a sequence of scope strings) used as the default scopes when the client
  omits the `scope` field per RFC 7591 §2.

  Throws `ex-info` with `\"invalid_client_metadata\"` message on validation errors."
  ([request client-store]
   (handle-registration-request request client-store {}))
  ([request client-store opts]
   (when-not (m/validate RegistrationRequest request)
     (throw (ex-info "invalid_client_metadata"
                     {:type   ::error/invalid-client-metadata
                      :errors (m/explain RegistrationRequest request)})))
   (let [config       (-> request apply-defaults validate-request
                          (request->client-config (:scopes-supported opts)))
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

(defn- authenticate-client
  "Retrieves and authenticates a client by verifying the bearer token against the
  stored registration access token hash. Returns the client config on success.
  Throws `ex-info` with `\"invalid_token\"` on failure."
  [store client-id access-token]
  (let [client (proto/get-client store client-id)]
    (if (and client
             (try
               (util/verify-client-secret access-token (:registration-access-token client))
               (catch Exception _ false)))
      client
      (throw (ex-info "invalid_token" {:type ::error/invalid-token})))))

(defn- update-request->client-config
  "Converts an update request to a kebab-case config, preserving immutable fields
  from the `existing` client (client-id, credentials, registration access token)."
  [request existing]
  (let [auth-method (:token_endpoint_auth_method request)
        public?     (= auth-method "none")
        scope-str   (:scope request)
        scopes      (if scope-str (vec (str/split scope-str #" ")) [])]
    (cond-> {:client-id                  (:client-id existing)
             :client-type                (if public? "public" "confidential")
             :redirect-uris              (:redirect_uris request)
             :grant-types                (:grant_types request)
             :response-types             (:response_types request)
             :scopes                     scopes
             :token-endpoint-auth-method auth-method
             :application-type           (:application_type request)
             :registration-access-token  (:registration-access-token existing)
             :client-secret-hash         (when-not public? (:client-secret-hash existing))}
      (:client_name request) (assoc :client-name (:client_name request))
      (:client_uri request)  (assoc :client-uri (:client_uri request))
      (:logo_uri request)    (assoc :logo-uri (:logo_uri request))
      (:contacts request)    (assoc :contacts (:contacts request)))))

(m/=> handle-client-read [:=> [:cat :any :string :string] :map])

(defn handle-client-read
  "Handles RFC 7592 client read requests.

  Takes the `store` implementing [[oidc-provider.protocol/ClientStore]],
  `client-id`, and the bearer `access-token` presented by the caller.
  Returns the client configuration map if the token is valid.
  Throws `ex-info` with `\"invalid_token\"` when the client is unknown or the
  token does not match."
  [store client-id access-token]
  (client-config->response (authenticate-client store client-id access-token)))

(m/=> handle-client-update [:=> [:cat :any :string :string :map] :map])

(defn handle-client-update
  "Handles RFC 7592 §2.2 client update requests.

  Takes the `store`, `client-id`, bearer `access-token`, and the updated
  metadata `request` map with keyword keys. The request is a full replacement
  of mutable metadata; immutable fields (`client_id`, `client_secret`,
  `registration_access_token`) are ignored per RFC 7592 §2.2.
  Returns the updated client configuration map.
  Throws `ex-info` with `\"invalid_token\"` on auth failure or
  `\"invalid_client_metadata\"` on validation errors."
  [store client-id access-token request]
  (let [existing (authenticate-client store client-id access-token)]
    (when-not (m/validate RegistrationRequest request)
      (throw (ex-info "invalid_client_metadata"
                      {:type   ::error/invalid-client-metadata
                       :errors (m/explain RegistrationRequest request)})))
    (let [defaulted (apply-defaults request)
          _         (validate-request defaulted)
          updated   (update-request->client-config defaulted existing)
          stored    (proto/update-client store client-id updated)]
      (client-config->response stored))))

(m/=> handle-client-delete [:=> [:cat :any :string :string] :nil])

(defn handle-client-delete
  "Handles RFC 7592 §2.3 client delete (deregistration) requests.

  Takes the `store`, `client-id`, and bearer `access-token`. Authenticates the
  request and removes the client from the store. Returns nil on success.
  Throws `ex-info` with `\"invalid_token\"` on auth failure."
  [store client-id access-token]
  (authenticate-client store client-id access-token)
  (proto/delete-client store client-id)
  nil)

