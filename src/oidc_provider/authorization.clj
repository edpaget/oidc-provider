(ns oidc-provider.authorization
  "Authorization endpoint implementation for OAuth2/OIDC."
  (:require
   [clojure.string :as str]
   [malli.core :as m]
   [oidc-provider.error :as error]
   [oidc-provider.protocol :as proto]
   [oidc-provider.token :as token])
  (:import
   [com.nimbusds.oauth2.sdk OAuth2Error ParseException]
   [com.nimbusds.openid.connect.sdk OIDCError Prompt Prompt$Type]))

(set! *warn-on-reflection* true)

(def AuthorizationRequest
  "Malli schema for authorization request parameters."
  [:map
   [:response_type :string]
   [:client_id :string]
   [:redirect_uri :string]
   [:scope {:optional true} :string]
   [:state {:optional true} :string]
   [:nonce {:optional true} :string]
   [:prompt {:optional true} :string]
   [:max_age {:optional true} [:or :string pos-int?]]
   [:ui_locales {:optional true} :string]
   [:code_challenge {:optional true} :string]
   [:code_challenge_method {:optional true} [:enum "S256"]]
   [:resource {:optional true} [:or :string [:vector :string]]]
   [:request {:optional true} :string]
   [:request_uri {:optional true} :string]])

(def AuthorizationResponse
  "Malli schema for authorization response."
  [:map
   [:redirect-uri :string]
   [:params :map]])

(defn- normalize-resource
  "Normalizes the `:resource` param to a vector. Ring's `wrap-params` produces a
  string for a single value and a vector for multiples."
  [params]
  (if-let [r (:resource params)]
    (assoc params :resource (if (string? r) [r] (vec r)))
    params))

(defn- validate-redirect-uri
  [client redirect-uri]
  (when-not (some #{redirect-uri} (:redirect-uris client))
    (throw (ex-info "Invalid redirect_uri"
                    {:redirect-uri redirect-uri
                     :allowed      (:redirect-uris client)
                     :type         ::error/invalid-request
                     :error        (.getCode OAuth2Error/INVALID_REQUEST)
                     :redirect     false}))))

(defn- validate-response-type
  [client response-type]
  (when-not (some #{response-type} (:response-types client))
    (throw (ex-info "Unsupported response_type"
                    {:response-type response-type
                     :supported     (:response-types client)
                     :type          ::error/unsupported-response-type
                     :error         (.getCode OAuth2Error/UNSUPPORTED_RESPONSE_TYPE)}))))

(defn- validate-scope
  [client scope-str]
  (let [requested-scopes (when scope-str (str/split scope-str #" "))
        client-scopes    (:scopes client)]
    (when (some (fn [scope] (not (some #{scope} client-scopes))) requested-scopes)
      (throw (ex-info "Invalid scope"
                      {:requested requested-scopes
                       :allowed   client-scopes
                       :type      ::error/invalid-scope
                       :error     (.getCode OAuth2Error/INVALID_SCOPE)})))))

(defn- validate-pkce-params
  [params]
  (cond
    (and (:code_challenge_method params) (not (:code_challenge params)))
    (throw (ex-info "Invalid request: code_challenge_method requires code_challenge"
                    {:type  ::error/invalid-request
                     :error (.getCode OAuth2Error/INVALID_REQUEST)}))

    (and (:code_challenge params) (not (:code_challenge_method params)))
    (assoc params :code_challenge_method "S256")

    :else params))

(def ^:private prompt-type->keyword
  "Maps Nimbus `Prompt$Type` enum values to keywords."
  {Prompt$Type/NONE           :none
   Prompt$Type/LOGIN          :login
   Prompt$Type/CONSENT        :consent
   Prompt$Type/SELECT_ACCOUNT :select-account})

(defn- parse-prompt
  "Parses a `prompt` parameter string using Nimbus `Prompt/parse`. Returns a set
  of keywords (e.g., `#{:login :consent}`). Throws `invalid_request` when the
  value is malformed or contains an invalid combination like `none login`."
  [prompt-str]
  (try
    (let [^Prompt prompt (Prompt/parse ^String prompt-str)]
      (into #{} (map prompt-type->keyword) prompt))
    (catch ParseException _
      (throw (ex-info "Invalid prompt parameter"
                      {:type  ::error/invalid-request
                       :error (.getCode OAuth2Error/INVALID_REQUEST)})))))

(defn- parse-max-age
  "Parses a `max_age` parameter value to a non-negative long. The value may be a
  string (from query params) or an integer. Throws `invalid_request` when the
  value is not a valid non-negative integer."
  [max-age-val]
  (let [v (parse-long (str max-age-val))]
    (when (or (nil? v) (neg? v))
      (throw (ex-info "Invalid max_age parameter"
                      {:type  ::error/invalid-request
                       :error (.getCode OAuth2Error/INVALID_REQUEST)})))
    v))

(defn- validate-public-client-pkce
  [client params]
  (when (and (= (:client-type client) "public")
             (not (:code_challenge params)))
    (throw (ex-info "Public clients must use PKCE"
                    {:type  ::error/invalid-request
                     :error (.getCode OAuth2Error/INVALID_REQUEST)}))))

(defn parse-authorization-request
  "Validates a pre-parsed authorization request.

   Takes a `params` map with keyword keys (as produced by Ring's `wrap-params` and
   `wrap-keyword-params` middleware) and a `client-store` implementing
   [[oidc-provider.protocol/ClientStore]]. Validates against [[AuthorizationRequest]],
   looks up the client, and validates the redirect URI, response type, scopes, PKCE,
   and resource indicator parameters. Returns the validated request map.

   The `:resource` parameter may be a string (single value) or a vector (multiple
   values); it is normalized to a vector. When the request has no `:resource` parameter
   and the client has a `:default-resource` configured, the default is applied
   automatically. When `prompt` is present, its value is parsed and validated per
   OIDC Core §3.1.2.1 and the result is included as `:prompt-values` — a set of
   keywords (e.g., `#{:login :consent}`). Throws `ex-info` on validation errors or
   if the client is unknown."
  [params client-store]
  (when-not (m/validate AuthorizationRequest params)
    (throw (ex-info "Invalid authorization request"
                    {:errors   (m/explain AuthorizationRequest params)
                     :type     ::error/invalid-request
                     :error    (.getCode OAuth2Error/INVALID_REQUEST)
                     :redirect false})))
  (let [params    (-> params validate-pkce-params normalize-resource)
        client-id (:client_id params)
        client    (proto/get-client client-store client-id)]
    (when-not client
      (throw (ex-info "Unknown client"
                      {:client-id client-id
                       :type      ::error/invalid-request
                       :error     (.getCode OAuth2Error/INVALID_REQUEST)
                       :redirect  false})))
    (validate-redirect-uri client (:redirect_uri params))
    (when (or (:request params) (:request_uri params))
      (throw (ex-info "Request objects are not supported"
                      {:type         ::error/invalid-request
                       :error        "request_not_supported"
                       :redirect_uri (:redirect_uri params)
                       :state        (:state params)})))
    (let [params (if (and (nil? (:resource params))
                          (:default-resource client))
                   (assoc params :resource (:default-resource client))
                   params)]
      (try
        (validate-response-type client (:response_type params))
        (when (:scope params)
          (validate-scope client (:scope params)))
        (validate-public-client-pkce client params)
        (when-let [resources (:resource params)]
          (proto/validate-resource-indicators resources))
        (let [params (if (and (:scope params)
                              (not (some #{"refresh_token"} (:grant-types client))))
                       (let [filtered (str/join " " (remove #{"offline_access"}
                                                            (str/split (:scope params) #" ")))]
                         (if (str/blank? filtered)
                           (dissoc params :scope)
                           (assoc params :scope filtered)))
                       params)]
          (cond-> params
            (:prompt params)  (assoc :prompt-values (parse-prompt (:prompt params)))
            (:max_age params) (assoc :max-age (parse-max-age (:max_age params)))))
        (catch clojure.lang.ExceptionInfo e
          (throw (ex-info (ex-message e)
                          (cond-> (assoc (ex-data e)
                                         :redirect_uri (:redirect_uri params))
                            (:state params) (assoc :state (:state params))))))))))

(m/=> parse-authorization-request [:=> [:cat :map :any] :map])

(defn handle-authorization-approval
  "Handles user approval of authorization request.

   Takes a parsed authorization request (from [[parse-authorization-request]]), the
   user ID of the approving user, provider configuration, an AuthorizationCodeStore,
   and an optional `auth-time` (epoch seconds) indicating when the user last
   authenticated. When `:max-age` was present in the authorization request, the host
   application should supply `auth-time` so that the `auth_time` claim appears in
   the resulting ID token per OIDC Core §3.1.2.1. Returns an authorization response
   map containing the redirect URI and response parameters (including the code and
   optional state). Currently supports response_type \"code\"; throws ex-info for
   unsupported response types."
  ([parsed-request user-id provider-config code-store]
   (handle-authorization-approval parsed-request user-id provider-config code-store nil))
  ([{:keys [response_type client_id redirect_uri scope state nonce
            code_challenge code_challenge_method resource]}
    user-id
    provider-config
    code-store
    auth-time]
   (if (= response_type "code")
     (let [code   (token/generate-authorization-code)
           expiry (+ (.millis ^java.time.Clock (:clock provider-config))
                     (* 1000 (or (:authorization-code-ttl-seconds provider-config) 600)))
           scopes (when scope (vec (str/split scope #" ")))]
       (proto/save-authorization-code code-store code user-id client_id
                                      redirect_uri scopes nonce expiry
                                      code_challenge code_challenge_method resource
                                      auth-time)
       {:redirect-uri redirect_uri
        :params       (cond-> {:code code}
                        (:issuer provider-config) (assoc :iss (:issuer provider-config))
                        state (assoc :state state))})
     (throw (ex-info "Unsupported response_type"
                     {:response-type response_type})))))

(m/=> handle-authorization-approval [:function
                                     [:=> [:cat :map :string :map :any] :map]
                                     [:=> [:cat :map :string :map :any [:maybe :int]] :map]])

(defn handle-authorization-denial
  "Handles user denial of authorization request.

   Takes a parsed authorization request, an OAuth2 error code (defaults to
   \"access_denied\" if not provided), a human-readable error description, and
   provider configuration. Includes the `iss` response parameter per RFC 9207.
   Returns the response map with the error, optional error description, and
   optional state parameter."
  [{:keys [redirect_uri state]} error-code error-description provider-config]
  {:redirect-uri redirect_uri
   :params       (cond-> {:error (or error-code "access_denied")}
                   (:issuer provider-config) (assoc :iss (:issuer provider-config))
                   error-description (assoc :error_description error-description)
                   state (assoc :state state))})

(m/=> handle-authorization-denial [:=> [:cat :map [:maybe :string] [:maybe :string] :map] :map])

(defn validate-prompt-none
  "Checks whether `prompt=none` was requested and the user is not authenticated.

   Host applications should call this after resolving the user's authentication
   state. If `:prompt-values` contains `:none` and `authenticated?` is false,
   returns an error redirect response map with a `login_required` error code per
   OIDC Core §3.1.2.6. Returns `nil` when no error applies — the host app should
   proceed normally."
  [{:keys [redirect_uri state prompt-values]} authenticated? provider-config]
  (when (and (contains? prompt-values :none) (not authenticated?))
    {:redirect-uri redirect_uri
     :params       (cond-> {:error (.getCode OIDCError/LOGIN_REQUIRED)}
                     (:issuer provider-config) (assoc :iss (:issuer provider-config))
                     state (assoc :state state))}))

(m/=> validate-prompt-none [:=> [:cat :map :boolean :map] [:maybe :map]])

(defn validate-max-age
  "Checks whether the user's authentication is still fresh per OIDC Core §3.1.2.1.

   Takes `max-age-seconds` from the authorization request, `auth-time-seconds`
   (epoch seconds when the user last authenticated), and a `java.time.Clock`.
   Returns `true` if the elapsed time since authentication is within `max-age`,
   `false` if re-authentication is required."
  [max-age-seconds auth-time-seconds ^java.time.Clock clock]
  (<= (- (quot (.millis clock) 1000) auth-time-seconds) max-age-seconds))

(m/=> validate-max-age [:=> [:cat :int :int :any] :boolean])

(defn build-redirect-url
  "Builds the redirect URL with query parameters.

   Takes an authorization response map (from [[handle-authorization-approval]] or
   [[handle-authorization-denial]]) containing a redirect URI and parameters. URL-encodes
   the parameters and appends them to the redirect URI as query parameters, properly
   handling whether the URI already contains a query string. Returns the complete
   redirect URL string."
  [{:keys [redirect-uri params]}]
  (let [query-string (->> params
                          (map (fn [[k v]] (str (name k) "=" (java.net.URLEncoder/encode (str v) "UTF-8"))))
                          (str/join "&"))]
    (str redirect-uri
         (if (str/includes? redirect-uri "?") "&" "?")
         query-string)))

(m/=> build-redirect-url [:=> [:cat :map] :string])
