(ns oidc-provider.conformance
  "Conformance suite test runner.

  Drives the OpenID Foundation Conformance Suite REST API to create and
  run a Basic OP test plan, then reports results. Expects the conformance
  suite to be running (see `docker-compose.yml`)."
  (:require
   [cheshire.core :as json])
  (:import
   [java.net URI]
   [java.net.http HttpClient HttpClient$Version HttpRequest
                  HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
   [java.security SecureRandom]
   [java.security.cert X509Certificate]
   [java.time Duration]
   [javax.net.ssl SSLContext TrustManager X509TrustManager]))

(set! *warn-on-reflection* true)

(def ^:private plan-name
  "oidcc-basic-certification-test-plan")

(def ^:private plan-variant
  {"server_metadata"     "discovery"
   "client_registration" "static_client"})

(defn- trusting-ssl-context
  "Creates an SSLContext that trusts all certificates. Required for the
  conformance suite's self-signed localhost certificate."
  ^SSLContext []
  (let [trust-all (into-array TrustManager
                              [(reify X509TrustManager
                                 (checkClientTrusted [_ _ _])
                                 (checkServerTrusted [_ _ _])
                                 (getAcceptedIssuers [_]
                                   (into-array X509Certificate [])))])
        ctx       (SSLContext/getInstance "TLS")]
    (.init ctx nil trust-all (SecureRandom.))
    ctx))

(defn- create-http-client
  "Creates an HttpClient that skips TLS verification, including hostname
  checks. Required for the conformance suite's self-signed cert."
  ^HttpClient []
  (System/setProperty "jdk.internal.httpclient.disableHostnameVerification" "true")
  (-> (HttpClient/newBuilder)
      (.sslContext (trusting-ssl-context))
      (.version HttpClient$Version/HTTP_1_1)
      (.connectTimeout (Duration/ofSeconds 30))
      (.build)))

(defn- build-request
  "Builds an HttpRequest for the given method, URI, and optional JSON body."
  (^HttpRequest [method ^String uri]
   (build-request method uri nil))
  (^HttpRequest [method ^String uri body]
   (let [builder (-> (HttpRequest/newBuilder)
                     (.uri (URI/create uri))
                     (.timeout (Duration/ofSeconds 120))
                     (.header "Accept" "application/json"))]
     (case method
       :get  (.GET builder)
       :post (if body
               (do (.header builder "Content-Type" "application/json")
                   (.POST builder (HttpRequest$BodyPublishers/ofString (json/generate-string body))))
               (.POST builder (HttpRequest$BodyPublishers/noBody))))
     (.build builder))))

(defn- send-request
  "Sends an HTTP request and returns the parsed JSON response body."
  [^HttpClient client ^HttpRequest request]
  (let [response (.send client request (HttpResponse$BodyHandlers/ofString))
        status   (.statusCode response)
        body-str (.body response)]
    (when (>= status 400)
      (throw (ex-info (str "HTTP " status ": " body-str)
                      {:status status :body body-str})))
    (when-not (empty? ^String body-str)
      (json/parse-string body-str true))))

(defn- create-plan
  "Creates a test plan and returns the plan map with `:id` and `:modules`."
  [^HttpClient client ^String base-url config]
  (let [variant-json (json/generate-string plan-variant)
        uri          (str base-url "/api/plan"
                         "?planName=" plan-name
                         "&variant=" (java.net.URLEncoder/encode ^String variant-json "UTF-8"))
        request      (build-request :post uri config)]
    (send-request client request)))

(defn- create-test-from-plan
  "Creates a test module instance from a plan. The `module-variant` is
  the per-module variant map from the plan (includes response_type etc.).
  The runner endpoint takes all parameters as query params with no body."
  [^HttpClient client ^String base-url plan-id module-name module-variant]
  (let [variant-json (json/generate-string module-variant)
        uri          (str base-url "/api/runner"
                         "?test=" (java.net.URLEncoder/encode ^String module-name "UTF-8")
                         "&plan=" plan-id
                         "&variant=" (java.net.URLEncoder/encode ^String variant-json "UTF-8"))
        request      (build-request :post uri)]
    (send-request client request)))

(defn- start-test
  "Starts a test module by ID."
  [^HttpClient client ^String base-url ^String module-id]
  (let [request (build-request :post (str base-url "/api/runner/" module-id))]
    (send-request client request)))

(defn- get-test-info
  "Returns status info for a test module."
  [^HttpClient client ^String base-url ^String module-id]
  (let [request (build-request :get (str base-url "/api/info/" module-id))]
    (send-request client request)))

(defn- get-test-log
  "Returns the log entries for a test module."
  [^HttpClient client ^String base-url ^String module-id]
  (let [request (build-request :get (str base-url "/api/log/" module-id))]
    (send-request client request)))

(defn- find-redirect-url
  "Extracts the authorization redirect URL from the test module logs."
  [^HttpClient client ^String base-url ^String module-id]
  (let [logs (get-test-log client base-url module-id)]
    (->> logs
         (keep :redirect_to_authorization_endpoint)
         first)))

(defn- extract-implicit-url
  "Extracts the implicit callback POST URL from the conformance suite's
  callback HTML page JavaScript."
  [^String html]
  (when-let [m (re-find #"xhr\.open\('POST',\s*\"([^\"]+)\"" html)]
    (.replace ^String (second m) "\\/" "/")))

(defn- wait-for-states
  "Polls until the test module reaches one of the given statuses or times
  out. Returns the info map when a target status is reached."
  [^HttpClient client ^String base-url ^String module-id target-statuses timeout-ms]
  (let [start    (System/currentTimeMillis)
        targets  (set target-statuses)]
    (loop []
      (let [info   (get-test-info client base-url module-id)
            status (:status info)]
        (cond
          (targets status) info
          (= status "INTERRUPTED")
          (throw (ex-info (str "Test INTERRUPTED") {:module-id module-id}))
          (> (- (System/currentTimeMillis) start) timeout-ms)
          (throw (ex-info (str "Timeout (current: " status ")")
                          {:module-id module-id :status status}))
          :else (do (Thread/sleep 1000) (recur)))))))

(defn- rewrite-host-url
  "Rewrites `host.docker.internal` URLs to `localhost` so the browser
  simulation can reach the dev server from the host machine."
  ^String [^String url]
  (.replace url "host.docker.internal" "localhost"))

(defn- simulate-browser
  "When a test is WAITING, simulates the browser flow:
  1. GET the authorization URL on our provider (auto-approves → 302)
  2. GET the conformance suite callback URL (returns HTML with JS)
  3. Extract the implicit POST URL from the JS
  4. POST to it to signal the authorization flow is complete"
  [^HttpClient _client ^String base-url ^String module-id]
  (let [auth-url (or (find-redirect-url _client base-url module-id)
                     (throw (ex-info "No authorization redirect URL found"
                                     {:module-id module-id})))
        http     (-> (HttpClient/newBuilder)
                     (.sslContext (trusting-ssl-context))
                     (.version HttpClient$Version/HTTP_1_1)
                     (.connectTimeout (Duration/ofSeconds 30))
                     (.build))
        auth-resp (.send http (build-request :get (rewrite-host-url auth-url))
                         (HttpResponse$BodyHandlers/ofString))]
    (when (= 302 (.statusCode auth-resp))
      (let [callback-url (-> auth-resp .headers (.firstValue "location") .get)
            cb-resp      (.send http (build-request :get callback-url)
                                (HttpResponse$BodyHandlers/ofString))
            implicit-url (extract-implicit-url (.body cb-resp))]
        (when implicit-url
          (let [post-req (-> (HttpRequest/newBuilder)
                            (.uri (URI/create implicit-url))
                            (.timeout (Duration/ofSeconds 30))
                            (.header "Content-Type" "text/plain")
                            (.POST (HttpRequest$BodyPublishers/ofString ""))
                            (.build))]
            (.send http post-req (HttpResponse$BodyHandlers/ofString))))))))

(defn- run-module
  "Runs a single test module following the conformance suite lifecycle:
  create → wait for CONFIGURED/WAITING/FINISHED → start if CONFIGURED →
  simulate browser if WAITING → wait for FINISHED."
  [^HttpClient client ^String base-url plan-id module-name module-variant]
  (let [module    (create-test-from-plan client base-url plan-id module-name module-variant)
        module-id (:id module)
        info      (wait-for-states client base-url module-id
                                   ["CONFIGURED" "WAITING" "FINISHED"] 60000)]
    (when (= (:status info) "CONFIGURED")
      (start-test client base-url module-id)
      (wait-for-states client base-url module-id ["WAITING" "FINISHED"] 60000))
    (when (= (:status (get-test-info client base-url module-id)) "WAITING")
      (simulate-browser client base-url module-id))
    (wait-for-states client base-url module-id ["FINISHED"] 300000)))

(defn- print-results
  "Prints a summary of test results and returns the count of failures."
  [results]
  (let [grouped (group-by :result results)]
    (println)
    (println "=== Conformance Test Results ===")
    (println (str "Total: " (count results)
                  "  Passed: " (count (get grouped "PASSED" []))
                  "  Warning: " (count (get grouped "WARNING" []))
                  "  Review: " (count (get grouped "REVIEW" []))
                  "  Failed: " (count (get grouped "FAILED" []))
                  "  Skipped: " (count (get grouped "SKIPPED" []))))
    (println)
    (doseq [r (sort-by :name results)]
      (println (format "  %-8s %s" (:result r) (:name r))))
    (count (get grouped "FAILED" []))))

(defn run-basic-op
  "Runs the Basic OP conformance test plan. Returns the number of failures."
  [{:keys [base-url config-file]}]
  (let [base-url (or base-url
                     (System/getenv "CONFORMANCE_SERVER")
                     "https://localhost.emobix.co.uk:8443")
        config   (json/parse-string (slurp (or config-file "conformance/basic-op-config.json")) true)
        client   (create-http-client)]
    (println (str "Conformance server: " base-url))
    (println (str "Creating test plan: " plan-name))
    (let [plan    (create-plan client base-url config)
          plan-id (:id plan)
          modules (:modules plan)]
      (println (str "Plan created: " plan-id " (" (count modules) " modules)"))
      (println)
      (let [results (reduce
                     (fn [acc {:keys [testModule variant]}]
                       (print (str "  Running: " testModule "... "))
                       (flush)
                       (try
                         (let [info (run-module client base-url plan-id testModule variant)]
                           (println (:result info))
                           (conj acc {:name testModule :result (:result info)}))
                         (catch Exception e
                           (println (str "ERROR: " (or (.getMessage e) (str e))))
                           (conj acc {:name testModule :result "FAILED"}))))
                     []
                     modules)]
        (print-results results)))))

(defn -main
  "Runs the Basic OP conformance tests against the conformance suite."
  [& _args]
  (let [failures (run-basic-op {})]
    (System/exit (if (zero? failures) 0 1))))
