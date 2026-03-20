(ns oidc-provider.client-metadata
  "Client ID Metadata Document resolution per draft-ietf-oauth-client-id-metadata-document.

  When a client's `client_id` is an HTTPS URL, this namespace resolves it to a JSON
  metadata document containing the client's configuration (redirect URIs, name, etc.),
  enabling verification without pre-registration.

  Use [[create-metadata-resolving-store]] to wrap an existing
  [[oidc-provider.protocol/ClientStore]] with metadata document resolution. URL-based
  client IDs that are not found in the inner store are fetched, validated, and cached
  automatically. Metadata clients are always treated as public (no `client_secret`)."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [malli.core :as m]
   [oidc-provider.protocol :as proto]
   [oidc-provider.util :as util])
  (:import
   (java.io ByteArrayOutputStream InputStream)
   (java.net InetAddress URI)
   (java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers)
   (java.time Clock Duration Instant)))

(set! *warn-on-reflection* true)

(def ClientMetadataDocument
  "Malli schema for a Client ID Metadata Document."
  [:map
   [:client_id :string]
   [:redirect_uris [:vector {:min 1} :string]]
   [:grant_types {:optional true} [:vector [:enum "authorization_code" "refresh_token" "client_credentials"]]]
   [:response_types {:optional true} [:vector [:enum "code" "token" "id_token"]]]
   [:client_name {:optional true} :string]
   [:token_endpoint_auth_method {:optional true} [:enum "client_secret_basic" "client_secret_post" "none"]]
   [:scope {:optional true} :string]
   [:client_uri {:optional true} :string]
   [:logo_uri {:optional true} :string]
   [:contacts {:optional true} [:vector :string]]])

(m/=> url-client-id? [:=> [:cat :string] :boolean])

(defn url-client-id?
  "Returns true when `client-id` is an HTTPS URL, indicating it should be resolved
  as a Client ID Metadata Document."
  [client-id]
  (and (str/starts-with? client-id "https://")
       (try
         (let [uri (URI. ^String client-id)]
           (and (.isAbsolute uri) (some? (.getHost uri))))
         (catch Exception _ false))))

(m/=> validate-metadata-document [:=> [:cat :map :string] :map])

(defn validate-metadata-document
  "Validates a metadata document against [[ClientMetadataDocument]] schema and verifies
  that the `client_id` field matches the `fetch-url` the document was retrieved from.

  Returns the document on success. Throws `ex-info` on validation failure or
  `client_id` mismatch."
  [document fetch-url]
  (when-not (m/validate ClientMetadataDocument document)
    (throw (ex-info "invalid metadata document"
                    {:error  "invalid_client_metadata"
                     :errors (m/explain ClientMetadataDocument document)})))
  (doseq [uri (:redirect_uris document)]
    (when-not (util/valid-redirect-uri-https-only? uri)
      (throw (ex-info "invalid redirect URI"
                      {:error             "invalid_client_metadata"
                       :error_description (str "Invalid redirect URI: " (util/truncate uri 200))}))))
  (when-not (= (or (:token_endpoint_auth_method document) "none") "none")
    (throw (ex-info "unsupported token_endpoint_auth_method"
                    {:error             "invalid_client_metadata"
                     :error_description "Metadata documents only support token_endpoint_auth_method \"none\""})))
  (when (some #{"client_credentials"} (:grant_types document))
    (throw (ex-info "client_credentials not allowed for metadata document clients"
                    {:error             "invalid_client_metadata"
                     :error_description "Metadata document clients are public and cannot use client_credentials grant"})))
  (when (not= (:client_id document) fetch-url)
    (throw (ex-info "client_id mismatch"
                    {:error    "invalid_client_metadata"
                     :expected fetch-url
                     :actual   (:client_id document)})))
  document)

(m/=> metadata-document->client-config [:=> [:cat :map] :map])

(defn metadata-document->client-config
  "Converts a wire-format metadata document to a kebab-case `ClientConfig` map.

  Always sets `:client-type` to `\"public\"` since metadata document clients cannot
  have a `client_secret`. Applies RFC 7591 defaults for missing `grant_types`,
  `response_types`, and `token_endpoint_auth_method`."
  [document]
  (let [scope-str (:scope document)
        scopes    (if scope-str (vec (str/split scope-str #" ")) [])]
    (cond-> {:client-id                  (:client_id document)
             :client-type                "public"
             :redirect-uris              (:redirect_uris document)
             :grant-types                (or (:grant_types document) ["authorization_code"])
             :response-types             (or (:response_types document) ["code"])
             :scopes                     scopes
             :token-endpoint-auth-method (or (:token_endpoint_auth_method document) "none")}
      (:client_name document) (assoc :client-name (:client_name document))
      (:client_uri document)  (assoc :client-uri (:client_uri document))
      (:logo_uri document)    (assoc :logo-uri (:logo_uri document))
      (:contacts document)    (assoc :contacts (:contacts document)))))

(defn cache-get
  "Returns the cached `ClientConfig` for `url` if present and not expired, else nil."
  [cache-atom url ttl-seconds ^Clock clock]
  (when-let [{:keys [client-config ^Instant fetched-at]} (get @cache-atom url)]
    (let [now      (.instant clock)
          age-secs (.getSeconds (Duration/between fetched-at now))]
      (when (< age-secs ttl-seconds)
        client-config))))

(defn cache-put
  "Stores a `ClientConfig` in the cache for `url` with the current timestamp."
  [cache-atom url client-config ^Clock clock]
  (swap! cache-atom assoc url {:client-config client-config
                               :fetched-at    (.instant clock)}))

(m/=> private-address? [:=> [:cat :string] :boolean])

(defn private-address?
  "Returns `true` when `hostname` resolves to a private, loopback, or link-local IP address.

  Checks all A and AAAA records returned by DNS resolution using JDK methods
  `isLoopbackAddress`, `isLinkLocalAddress`, and `isSiteLocalAddress`, which cover
  `127.0.0.0/8`, `::1`, `169.254.0.0/16`, `fe80::/10`, RFC 1918, and RFC 4193 ranges."
  [hostname]
  (try
    (let [addresses (InetAddress/getAllByName hostname)]
      (boolean
       (some (fn [^InetAddress addr]
               (or (.isLoopbackAddress addr)
                   (.isLinkLocalAddress addr)
                   (.isSiteLocalAddress addr)))
             addresses)))
    (catch Exception _ false)))

(def ^:private default-timeout-ms 5000)
(def ^:private default-max-body-bytes 524288)
(def ^:private default-cache-ttl-seconds 300)

(defn- read-bounded
  "Reads up to `max-bytes` from `input-stream`, returning the result as a UTF-8 String.
  Throws `ex-info` if the stream contains more than `max-bytes`."
  [^InputStream input-stream max-bytes url]
  (let [buf (byte-array 8192)
        out (ByteArrayOutputStream.)]
    (try
      (loop [total 0]
        (let [n (.read input-stream buf)]
          (when (pos? n)
            (let [new-total (+ total n)]
              (when (> new-total max-bytes)
                (throw (ex-info "metadata document too large"
                                {:url url :max max-bytes})))
              (.write out buf 0 n)
              (recur new-total)))))
      (.toString out "UTF-8")
      (finally
        (.close input-stream)))))

(m/=> fetch-metadata-document [:=> [:cat :string :map] [:maybe :map]])

(defn fetch-metadata-document
  "Fetches a Client ID Metadata Document from `url` via HTTP GET.

  Uses `java.net.http.HttpClient` with `Accept: application/json`, configurable
  timeout (`:fetch-timeout-ms`, default 5000), and max body size (`:max-body-bytes`,
  default 512KB). Redirect policy is `NEVER`. The response body is read in a streaming
  fashion with the size limit enforced during read, preventing memory exhaustion from
  oversized responses. Returns the parsed JSON map on success, or throws on failure."
  [url {:keys [fetch-timeout-ms max-body-bytes]
        :or   {fetch-timeout-ms default-timeout-ms
               max-body-bytes   default-max-body-bytes}}]
  (let [host (.getHost (URI. ^String url))]
    (when (private-address? host)
      (throw (ex-info "fetch blocked: private address"
                      {:url url :host host}))))
  (let [client   (-> (HttpClient/newBuilder)
                     (.followRedirects java.net.http.HttpClient$Redirect/NEVER)
                     (.connectTimeout (Duration/ofMillis fetch-timeout-ms))
                     (.build))
        request  (-> (HttpRequest/newBuilder)
                     (.uri (URI. ^String url))
                     (.header "Accept" "application/json")
                     (.timeout (Duration/ofMillis fetch-timeout-ms))
                     (.GET)
                     (.build))
        response (.send client request (HttpResponse$BodyHandlers/ofInputStream))]
    (when (not= 200 (.statusCode response))
      (throw (ex-info "metadata fetch failed"
                      {:status (.statusCode response) :url url})))
    (json/parse-string (read-bounded (.body response) max-body-bytes url) true)))

(defn- resolve-client-metadata
  "Resolves a URL-based client ID to a `ClientConfig`.

  Checks the cache first, then fetches, validates, and converts the metadata document.
  Returns `ClientConfig` or nil on any failure."
  [cache-atom url {:keys [cache-ttl-seconds clock fetch-fn]           :as opts
                   :or   {cache-ttl-seconds default-cache-ttl-seconds
                          clock             (Clock/systemUTC)}}]
  (or (cache-get cache-atom url cache-ttl-seconds clock)
      (try
        (let [fetch-opts (select-keys opts [:fetch-timeout-ms :max-body-bytes])
              fetch      (or fetch-fn #(fetch-metadata-document % fetch-opts))
              document   (fetch url)
              _          (validate-metadata-document document url)
              config     (metadata-document->client-config document)]
          (cache-put cache-atom url config clock)
          config)
        (catch Exception _
          nil))))

(defrecord MetadataResolvingClientStore [inner cache opts]
  proto/ClientStore
  (get-client [_ client-id]
    (or (proto/get-client inner client-id)
        (when (url-client-id? client-id)
          (resolve-client-metadata cache client-id opts))))

  (register-client [_ client-config]
    (proto/register-client inner client-config))

  (update-client [_ client-id updated-config]
    (proto/update-client inner client-id updated-config)))

(m/=> create-metadata-resolving-store [:=> [:cat :any :map] [:fn #(satisfies? proto/ClientStore %)]])

(defn create-metadata-resolving-store
  "Creates a [[MetadataResolvingClientStore]] that wraps `inner-store` with Client ID
  Metadata Document resolution.

  For non-URL client IDs, delegates directly to `inner-store`. For HTTPS URL client IDs
  not found in the inner store, fetches the metadata document from the URL, validates it,
  and returns the resulting `ClientConfig`.

  The default fetch function blocks requests to private, loopback, and link-local addresses
  to prevent SSRF. Supply a custom `:fetch-fn` to override this behavior.

  Options:

  - `:fetch-fn` — `(fn [url] metadata-map)`, overrides the default HTTP fetch including SSRF protection
  - `:cache-ttl-seconds` — how long to cache resolved metadata (default: 300)
  - `:fetch-timeout-ms` — HTTP request timeout (default: 5000)
  - `:max-body-bytes` — maximum metadata document size (default: 524288)
  - `:clock` — `java.time.Clock` instance for testable time (default: system UTC)"
  [inner-store opts]
  (->MetadataResolvingClientStore inner-store (atom {}) opts))
