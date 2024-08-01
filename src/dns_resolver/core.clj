(ns dns-resolver.core)

(def type-values
  "A map of TYPES to their values and meanings.
   See https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2 for a complete list."
  [{:type :A, :value 1, :meaning "a host address"}
   {:type :NS, :value 2, :meaning "an authoritative name server"}
   {:type :CNAME, :value 5, :meaning "the canonical name for an alias"}])

(def class-values
  "A map of CLASS values to their values and meanings.
   See https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4 for a complete list."
  [{:class :IN, :value 1, :meaning "the Internet"}])

(defn- generate-random-query-id
  "Generate a random 16-bit ID for a DNS query."
  []
  (rand-int (Math/pow 2 16)))
