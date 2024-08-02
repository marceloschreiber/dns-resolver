(defproject dns-resolver "0.1.0-SNAPSHOT"
  :description "Learning DNS by reading RFCs and implementing a resolver"
  :license {:name "MIT", :url "https://opensource.org/license/MIT"}
  :dependencies [[org.clojure/clojure "1.11.3"]]
  :repl-options {:init-ns dns-resolver.core}
  :profiles {:dev {:dependencies [[lambdaisland/kaocha "1.91.1392"]]}}
  :aliases {"kaocha" ["run" "-m" "kaocha.runner"]})
