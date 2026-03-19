(ns oidc-provider.client-metadata-test
  (:require
   [cheshire.core :as json]
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.client-metadata :as cm]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store])
  (:import
   (java.time Clock Instant ZoneOffset)))

(def ^:private test-url "https://app.example.com/.well-known/oauth-client")

(def ^:private valid-metadata
  {"client_id"      test-url
   "redirect_uris"  ["https://app.example.com/callback"]
   "client_name"    "Example App"
   "grant_types"    ["authorization_code"]
   "response_types" ["code"]})

(deftest url-client-id-recognizes-https-test
  (testing "HTTPS URLs are recognized as URL client IDs"
    (is (true? (cm/url-client-id? "https://example.com/client")))
    (is (true? (cm/url-client-id? "https://app.example.com/.well-known/oauth-client")))))

(deftest url-client-id-rejects-non-urls-test
  (testing "plain strings and HTTP URLs are not URL client IDs"
    (is (false? (cm/url-client-id? "my-client-id")))
    (is (false? (cm/url-client-id? "http://example.com/client")))
    (is (false? (cm/url-client-id? "")))
    (is (false? (cm/url-client-id? "ftp://example.com/client")))))

(deftest validate-metadata-document-valid-test
  (testing "valid metadata document passes validation"
    (is (= valid-metadata (cm/validate-metadata-document valid-metadata test-url)))))

(deftest validate-metadata-document-client-id-mismatch-test
  (testing "throws when client_id does not match the fetch URL"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"client_id mismatch"
         (cm/validate-metadata-document
          (assoc valid-metadata "client_id" "https://evil.example.com/client")
          test-url)))))

(deftest validate-metadata-document-rejects-http-redirect-uri-test
  (testing "throws when redirect_uris contains a non-localhost HTTP URI"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"invalid redirect URI"
         (cm/validate-metadata-document
          (assoc valid-metadata "redirect_uris" ["http://evil.example.com/callback"])
          test-url)))))

(deftest validate-metadata-document-rejects-http-loopback-redirect-uri-test
  (testing "throws when redirect_uris contains HTTP loopback URIs"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"invalid redirect URI"
         (cm/validate-metadata-document
          (assoc valid-metadata "redirect_uris" ["http://localhost/callback"])
          test-url)))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"invalid redirect URI"
         (cm/validate-metadata-document
          (assoc valid-metadata "redirect_uris" ["http://127.0.0.1/callback"])
          test-url)))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"invalid redirect URI"
         (cm/validate-metadata-document
          (assoc valid-metadata "redirect_uris" ["http://[::1]/callback"])
          test-url)))))

(deftest validate-metadata-document-rejects-secret-based-auth-method-test
  (testing "throws when token_endpoint_auth_method is not none"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"unsupported token_endpoint_auth_method"
         (cm/validate-metadata-document
          (assoc valid-metadata "token_endpoint_auth_method" "client_secret_basic")
          test-url)))))

(deftest validate-metadata-document-rejects-client-credentials-test
  (testing "throws when grant_types includes client_credentials for public metadata client"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"client_credentials not allowed"
         (cm/validate-metadata-document
          (assoc valid-metadata "grant_types" ["authorization_code" "client_credentials"])
          test-url)))))

(deftest validate-metadata-document-missing-redirect-uris-test
  (testing "throws when redirect_uris is missing"
    (is (thrown? clojure.lang.ExceptionInfo
                 (cm/validate-metadata-document
                  (dissoc valid-metadata "redirect_uris")
                  test-url)))))

(deftest metadata-document->client-config-maps-fields-test
  (testing "converts wire format to kebab-case ClientConfig with all fields"
    (let [doc    (assoc valid-metadata
                        "scope" "openid profile"
                        "client_uri" "https://app.example.com"
                        "logo_uri" "https://app.example.com/logo.png"
                        "contacts" ["admin@example.com"]
                        "token_endpoint_auth_method" "none")
          config (cm/metadata-document->client-config doc)]
      (is (= test-url (:client-id config)))
      (is (= "public" (:client-type config)))
      (is (= ["https://app.example.com/callback"] (:redirect-uris config)))
      (is (= ["authorization_code"] (:grant-types config)))
      (is (= ["code"] (:response-types config)))
      (is (= ["openid" "profile"] (:scopes config))))))

(deftest metadata-document->client-config-defaults-test
  (testing "applies RFC 7591 defaults for missing grant_types and response_types"
    (let [doc    {"client_id"     test-url
                  "redirect_uris" ["https://app.example.com/callback"]}
          config (cm/metadata-document->client-config doc)]
      (is (= ["authorization_code"] (:grant-types config)))
      (is (= ["code"] (:response-types config)))
      (is (= "none" (:token-endpoint-auth-method config))))))

(deftest metadata-document->client-config-always-public-test
  (testing "client-type is always public regardless of auth method in document"
    (let [doc    (assoc valid-metadata "token_endpoint_auth_method" "client_secret_basic")
          config (cm/metadata-document->client-config doc)]
      (is (= "public" (:client-type config))))))

(def ^:private fixed-clock (Clock/fixed (Instant/parse "2026-03-16T00:00:00Z") ZoneOffset/UTC))

(deftest cache-miss-returns-nil-test
  (testing "cache miss returns nil"
    (let [cache (atom {})]
      (is (nil? (cm/cache-get cache "https://example.com/client" 300 fixed-clock))))))

(deftest cache-hit-within-ttl-test
  (testing "cache hit within TTL returns config"
    (let [cache  (atom {})
          config {:client-id test-url :client-type "public"}]
      (cm/cache-put cache test-url config fixed-clock)
      (is (= config (cm/cache-get cache test-url 300 fixed-clock))))))

(deftest cache-expired-returns-nil-test
  (testing "expired cache entry returns nil"
    (let [cache     (atom {})
          config    {:client-id test-url :client-type "public"}
          old-clock (Clock/fixed (Instant/parse "2026-03-15T00:00:00Z") ZoneOffset/UTC)]
      (cm/cache-put cache test-url config old-clock)
      (is (nil? (cm/cache-get cache test-url 300 fixed-clock))))))

(deftest decorator-delegates-non-url-client-id-test
  (testing "non-URL client-id delegates to inner store"
    (let [inner  (store/create-client-store
                  [{:client-id      "my-client"
                    :client-type    "confidential"
                    :redirect-uris  ["https://app.example.com/callback"]
                    :grant-types    ["authorization_code"]
                    :response-types ["code"]
                    :scopes         ["openid"]}])
          mstore (cm/create-metadata-resolving-store
                  inner
                  {:fetch-fn (fn [_] (throw (ex-info "should not be called" {})))})]
      (is (= "my-client" (:client-id (proto/get-client mstore "my-client")))))))

(deftest decorator-resolves-url-client-id-test
  (testing "URL client-id resolves via fetch-fn and returns ClientConfig"
    (let [inner  (store/create-client-store)
          mstore (cm/create-metadata-resolving-store
                  inner
                  {:fetch-fn (fn [_url] valid-metadata)
                   :clock    fixed-clock})]
      (is (= test-url (:client-id (proto/get-client mstore test-url)))))))

(deftest decorator-caches-resolved-client-test
  (testing "fetch-fn is called only once for repeated lookups"
    (let [call-count (atom 0)
          inner      (store/create-client-store)
          mstore     (cm/create-metadata-resolving-store
                      inner
                      {:fetch-fn (fn [_url]
                                   (swap! call-count inc)
                                   valid-metadata)
                       :clock    fixed-clock})]
      (proto/get-client mstore test-url)
      (proto/get-client mstore test-url)
      (is (= 1 @call-count)))))

(deftest decorator-fetch-failure-returns-nil-test
  (testing "fetch failure returns nil"
    (let [inner  (store/create-client-store)
          mstore (cm/create-metadata-resolving-store
                  inner
                  {:fetch-fn (fn [_url] (throw (ex-info "network error" {})))
                   :clock    fixed-clock})]
      (is (nil? (proto/get-client mstore test-url))))))

(deftest decorator-inner-store-takes-precedence-test
  (testing "inner store result takes precedence over metadata fetch"
    (let [inner  (store/create-client-store
                  [{:client-id      test-url
                    :client-type    "confidential"
                    :redirect-uris  ["https://inner.example.com/callback"]
                    :grant-types    ["authorization_code"]
                    :response-types ["code"]
                    :scopes         ["openid"]}])
          mstore (cm/create-metadata-resolving-store
                  inner
                  {:fetch-fn (fn [_url] (throw (ex-info "should not be called" {})))
                   :clock    fixed-clock})]
      (is (= "confidential" (:client-type (proto/get-client mstore test-url)))))))

(deftest decorator-delegates-register-client-test
  (testing "register-client delegates to inner store"
    (let [inner  (store/create-client-store)
          mstore (cm/create-metadata-resolving-store inner {})
          config {:client-id      "new-client"
                  :client-type    "public"
                  :redirect-uris  ["https://app.example.com/callback"]
                  :grant-types    ["authorization_code"]
                  :response-types ["code"]
                  :scopes         []}]
      (is (= "new-client" (:client-id (proto/register-client mstore config)))))))

(deftest decorator-delegates-update-client-test
  (testing "update-client delegates to inner store"
    (let [inner   (store/create-client-store
                   [{:client-id      "existing"
                     :client-type    "public"
                     :redirect-uris  ["https://app.example.com/callback"]
                     :grant-types    ["authorization_code"]
                     :response-types ["code"]
                     :scopes         []}])
          mstore  (cm/create-metadata-resolving-store inner {})
          updated (proto/update-client mstore "existing" {:client-name "Updated"})]
      (is (= "Updated" (:client-name updated))))))

(deftest private-address-detects-loopback-test
  (testing "loopback addresses are detected as private"
    (is (true? (cm/private-address? "127.0.0.1")))
    (is (true? (cm/private-address? "localhost")))))

(deftest private-address-detects-rfc1918-test
  (testing "RFC 1918 private addresses are detected"
    (is (true? (cm/private-address? "10.0.0.1")))
    (is (true? (cm/private-address? "192.168.1.1")))
    (is (true? (cm/private-address? "172.16.0.1")))))

(deftest fetch-metadata-document-blocks-private-address-test
  (testing "fetch-metadata-document throws for private addresses"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"private address"
         (cm/fetch-metadata-document "https://127.0.0.1/.well-known/oauth-client" {})))))

(deftest fetch-metadata-document-rejects-oversized-response-test
  (testing "throws when response body exceeds max-body-bytes during streaming read"
    (let [large-body (json/generate-string (assoc valid-metadata "padding" (apply str (repeat 1000 "x"))))
          server     (doto (com.sun.net.httpserver.HttpServer/create
                            (java.net.InetSocketAddress. 0) 0)
                       (.createContext "/.well-known/oauth-client"
                                       (reify com.sun.net.httpserver.HttpHandler
                                         (handle [_ exchange]
                                           (let [body (.getBytes ^String large-body "UTF-8")]
                                             (.sendResponseHeaders exchange 200 (count body))
                                             (doto (.getResponseBody exchange)
                                               (.write body)
                                               (.close))))))
                       (.start))
          port       (.getPort (.getAddress server))]
      (try
        (let [local-url (str "http://localhost:" port "/.well-known/oauth-client")
              client    (-> (java.net.http.HttpClient/newBuilder)
                            (.followRedirects java.net.http.HttpClient$Redirect/NEVER)
                            (.build))
              request   (-> (java.net.http.HttpRequest/newBuilder)
                            (.uri (java.net.URI. ^String local-url))
                            (.header "Accept" "application/json")
                            (.GET)
                            (.build))
              response  (.send client request (java.net.http.HttpResponse$BodyHandlers/ofInputStream))]
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo #"metadata document too large"
               (#'cm/read-bounded (.body response) 64 local-url))))
        (finally
          (.stop server 0))))))

(deftest fetch-metadata-document-accepts-response-within-limit-test
  (testing "accepts response body within max-body-bytes during streaming read"
    (let [server (doto (com.sun.net.httpserver.HttpServer/create
                        (java.net.InetSocketAddress. 0) 0)
                   (.createContext "/.well-known/oauth-client"
                                   (reify com.sun.net.httpserver.HttpHandler
                                     (handle [_ exchange]
                                       (let [body (.getBytes (json/generate-string valid-metadata) "UTF-8")]
                                         (.sendResponseHeaders exchange 200 (count body))
                                         (doto (.getResponseBody exchange)
                                           (.write body)
                                           (.close))))))
                   (.start))
          port   (.getPort (.getAddress server))]
      (try
        (let [local-url (str "http://localhost:" port "/.well-known/oauth-client")
              client    (-> (java.net.http.HttpClient/newBuilder)
                            (.followRedirects java.net.http.HttpClient$Redirect/NEVER)
                            (.build))
              request   (-> (java.net.http.HttpRequest/newBuilder)
                            (.uri (java.net.URI. ^String local-url))
                            (.header "Accept" "application/json")
                            (.GET)
                            (.build))
              response  (.send client request (java.net.http.HttpResponse$BodyHandlers/ofInputStream))
              result    (json/parse-string (#'cm/read-bounded (.body response) 524288 local-url))]
          (is (= test-url (get result "client_id")))
          (is (= ["https://app.example.com/callback"] (get result "redirect_uris"))))
        (finally
          (.stop server 0))))))

(deftest fetch-metadata-document-http-server-test
  (testing "resolves metadata from a local HTTP server via custom fetch-fn"
    (let [server (doto (com.sun.net.httpserver.HttpServer/create
                        (java.net.InetSocketAddress. 0) 0)
                   (.createContext "/.well-known/oauth-client"
                                   (reify com.sun.net.httpserver.HttpHandler
                                     (handle [_ exchange]
                                       (let [body (.getBytes (json/generate-string valid-metadata) "UTF-8")]
                                         (.sendResponseHeaders exchange 200 (count body))
                                         (doto (.getResponseBody exchange)
                                           (.write body)
                                           (.close))))))
                   (.start))
          port   (.getPort (.getAddress server))]
      (try
        (let [local-url (str "http://localhost:" port "/.well-known/oauth-client")
              inner     (store/create-client-store)
              fetch-fn  (fn [_url]
                          (let [client   (-> (java.net.http.HttpClient/newBuilder)
                                             (.followRedirects java.net.http.HttpClient$Redirect/NEVER)
                                             (.build))
                                request  (-> (java.net.http.HttpRequest/newBuilder)
                                             (.uri (java.net.URI. local-url))
                                             (.header "Accept" "application/json")
                                             (.GET)
                                             (.build))
                                response (.send client request (java.net.http.HttpResponse$BodyHandlers/ofString))]
                            (json/parse-string (.body response))))
              mstore    (cm/create-metadata-resolving-store
                         inner
                         {:fetch-fn fetch-fn :clock fixed-clock})
              result    (proto/get-client mstore test-url)]
          (is (= test-url (:client-id result)))
          (is (= ["https://app.example.com/callback"] (:redirect-uris result))))
        (finally
          (.stop server 0))))))
