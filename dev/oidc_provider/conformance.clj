(ns oidc-provider.conformance
  "Conformance suite test runner.

  Drives the OpenID Foundation Conformance Suite REST API to create and
  run a Basic OP test plan, using Playwright for headless browser
  automation. Expects the conformance suite to be running (see
  `docker-compose.yml`)."
  (:require
   [cheshire.core :as json])
  (:import
   [com.microsoft.playwright Browser Browser$NewContextOptions
                             BrowserType$LaunchOptions Page$WaitForSelectorOptions
                             Playwright]
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

;; ---------------------------------------------------------------------------
;; HTTP client for conformance suite REST API
;; ---------------------------------------------------------------------------

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
  "Creates an HttpClient that skips TLS verification. Hostname
  verification is disabled via the JVM flag
  `-Djdk.internal.httpclient.disableHostnameVerification=true`
  set in the `:conformance` alias."
  ^HttpClient []
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

;; ---------------------------------------------------------------------------
;; Conformance suite REST API operations
;; ---------------------------------------------------------------------------

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

(defn- wait-for-states
  "Polls until the test module reaches one of the given statuses or times
  out. Returns the info map when a target status is reached."
  [^HttpClient client ^String base-url ^String module-id target-statuses timeout-ms]
  (let [start   (System/currentTimeMillis)
        targets (set target-statuses)]
    (loop []
      (let [info   (get-test-info client base-url module-id)
            status (:status info)]
        (cond
          (targets status) info
          (= status "INTERRUPTED")
          (throw (ex-info "Test INTERRUPTED" {:module-id module-id}))
          (> (- (System/currentTimeMillis) start) timeout-ms)
          (throw (ex-info (str "Timeout (current: " status ")")
                          {:module-id module-id :status status}))
          :else (do (Thread/sleep 1000) (recur)))))))

;; ---------------------------------------------------------------------------
;; Playwright browser automation
;; ---------------------------------------------------------------------------

(defn- create-browser
  "Creates a headless Chromium browser instance via Playwright."
  ^Browser [^Playwright pw]
  (-> (.chromium pw)
      (.launch (-> (BrowserType$LaunchOptions.)
                   (.setHeadless true)))))

(defn- find-redirect-url
  "Extracts the most recent authorization redirect URL from the test
  module logs."
  [^HttpClient client ^String base-url ^String module-id]
  (let [logs (get-test-log client base-url module-id)]
    (->> logs
         (keep :redirect_to_authorization_endpoint)
         last)))

(defn- rewrite-host-url
  "Rewrites `host.docker.internal` URLs to `localhost` so the browser
  running on the host can reach the dev server."
  ^String [^String url]
  (.replace url "host.docker.internal" "localhost"))

(defn- simulate-browser
  "Opens a headless browser page, navigates to the authorization URL,
  and waits for the conformance suite callback JS to signal completion.
  Returns true if the page completed, false if no redirect URL was found."
  [^Browser browser ^HttpClient client ^String base-url ^String module-id]
  (if-let [auth-url (find-redirect-url client base-url module-id)]
    (let [context (.newContext browser
                              (-> (Browser$NewContextOptions.)
                                  (.setIgnoreHTTPSErrors true)))
          page    (.newPage context)]
      (try
        (.navigate page (rewrite-host-url auth-url))
        (.waitForSelector page "#submission_complete"
                          (-> (Page$WaitForSelectorOptions.)
                              (.setTimeout 30000)))
        true
        (catch Exception e
          (binding [*out* *err*]
            (println (str "    Browser: " (.getMessage e))))
          false)
        (finally
          (.close context))))
    false))

;; ---------------------------------------------------------------------------
;; Test execution
;; ---------------------------------------------------------------------------

(defn- run-module
  "Runs a single test module following the conformance suite lifecycle:
  create → wait for CONFIGURED/WAITING/FINISHED → start if CONFIGURED →
  simulate browser each time the test enters WAITING → wait for FINISHED."
  [^Browser browser ^HttpClient client ^String base-url plan-id module-name module-variant]
  (let [module    (create-test-from-plan client base-url plan-id module-name module-variant)
        module-id (:id module)
        info      (wait-for-states client base-url module-id
                                   ["CONFIGURED" "WAITING" "FINISHED"] 60000)]
    (when (= (:status info) "CONFIGURED")
      (start-test client base-url module-id))
    (loop [attempts 0]
      (let [current (wait-for-states client base-url module-id
                                     ["WAITING" "FINISHED"] 60000)]
        (cond
          (= (:status current) "FINISHED")
          current

          (>= attempts 5)
          (wait-for-states client base-url module-id ["FINISHED"] 10000)

          :else
          (do (simulate-browser browser client base-url module-id)
              (recur (inc attempts))))))))

(defn- load-test-list
  "Loads a JSON file mapping test names to descriptions. Returns a set
  of test names, or an empty set if the file doesn't exist."
  [^String path]
  (try
    (let [m (json/parse-string (slurp path))]
      (set (remove #(= "_comment" %) (keys m))))
    (catch java.io.FileNotFoundException _ #{})))

(defn- print-results
  "Prints a summary of test results and returns the number of unexpected
  failures (failures not in the expected-failures set)."
  [results expected-failures]
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
      (let [expected? (expected-failures (:name r))
            marker    (if (and expected? (= "FAILED" (:result r))) " (expected)" "")]
        (println (format "  %-8s %s%s" (:result r) (:name r) marker))))
    (let [unexpected (filter #(and (= "FAILED" (:result %))
                                   (not (expected-failures (:name %))))
                             results)]
      (when (seq unexpected)
        (println)
        (println (str (count unexpected) " UNEXPECTED failure(s):"
                      (apply str (map #(str "\n    " (:name %)) unexpected)))))
      (count unexpected))))

(defn run-basic-op
  "Runs the Basic OP conformance test plan. Returns the number of
  unexpected failures. Tests in `expected-skips.json` are not run.
  Tests in `expected-failures.json` run but don't count as failures."
  [{:keys [base-url config-file]}]
  (let [base-url          (or base-url
                              (System/getenv "CONFORMANCE_SERVER")
                              "https://localhost.emobix.co.uk:8443")
        config            (json/parse-string (slurp (or config-file "conformance/basic-op-config.json")) true)
        skips             (load-test-list "conformance/expected-skips.json")
        expected-failures (load-test-list "conformance/expected-failures.json")
        client            (create-http-client)]
    (println (str "Conformance server: " base-url))
    (when (seq skips)
      (println (str "Skipping " (count skips) " tests (see conformance/expected-skips.json)")))
    (println (str "Creating test plan: " plan-name))
    (with-open [pw (Playwright/create)]
      (let [browser (create-browser pw)
            plan    (create-plan client base-url config)
            plan-id (:id plan)
            modules (:modules plan)]
        (println (str "Plan created: " plan-id " (" (count modules) " modules)"))
        (println)
        (try
          (let [results (reduce
                         (fn [acc {:keys [testModule variant]}]
                           (if (skips testModule)
                             (do (println (str "  Skipping: " testModule))
                                 (conj acc {:name testModule :result "SKIPPED"}))
                             (do (print (str "  Running: " testModule "... "))
                                 (flush)
                                 (try
                                   (let [info (run-module browser client base-url plan-id testModule variant)]
                                     (println (:result info))
                                     (conj acc {:name testModule :result (:result info)}))
                                   (catch Exception e
                                     (println (str "ERROR: " (or (.getMessage e) (str e))))
                                     (conj acc {:name testModule :result "FAILED"}))))))
                         []
                         modules)]
            (print-results results expected-failures))
          (finally
            (.close browser)))))))

(defn -main
  "Runs the Basic OP conformance tests against the conformance suite."
  [& _args]
  (let [failures (run-basic-op {})]
    (System/exit (if (zero? failures) 0 1))))
