(ns build
  (:require [clojure.tools.build.api :as b]
            [clojure.string :as str]))

(def lib 'io.github.edwardpaget/oidc-provider)
(def version (str/trim (slurp "VERSION")))
(def class-dir "target/classes")
(def jar-file (format "target/%s-%s.jar" (name lib) version))
(def basis (delay (b/create-basis {:project "deps.edn"})))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar [_]
  (clean nil)
  (b/write-pom {:class-dir class-dir
                :lib lib
                :version version
                :basis @basis
                :src-dirs ["src"]
                :scm {:url "https://github.com/edwardpaget/oidc-provider"
                      :connection "scm:git:git://github.com/edwardpaget/oidc-provider.git"
                      :developerConnection "scm:git:ssh://git@github.com/edwardpaget/oidc-provider.git"
                      :tag version}
                :pom-data [[:licenses
                            [:license
                             [:name "Apache-2.0"]
                             [:url "https://www.apache.org/licenses/LICENSE-2.0"]]]]})
  (b/copy-dir {:src-dirs ["src"]
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file jar-file}))

(defn install [_]
  (jar nil)
  (b/install {:basis @basis
              :lib lib
              :version version
              :jar-file jar-file
              :class-dir class-dir}))
