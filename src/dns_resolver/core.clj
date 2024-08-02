(ns dns-resolver.core
  (:import [java.nio ByteBuffer]))

(def type-values
  "A map of TYPES to their values and meanings.
   For a complete list see [ref:type-values]"
  [{:type :A, :value 1, :meaning "a host address"}
   {:type :NS, :value 2, :meaning "an authoritative name server"}
   {:type :CNAME, :value 5, :meaning "the canonical name for an alias"}])

(def class-values
  "A map of CLASS values to their values and meanings.
   For a complete list see [ref:class-values]."
  [{:class :IN, :value 1, :meaning "the Internet"}])

(defn generate-random-query-id
  "Generate a random 16-bit ID for a DNS query.
   For more info see [ref:header-id]."
  []
  (rand-int (Math/pow 2 16)))

(defn generate-query-header
  "Generate a query header for a DNS query.
   For more info about the format see [ref:header-section-format]."
  [{:keys [id recursion-desired?], :or {recursion-desired? true}}]
  (let [buffer (ByteBuffer/allocate 12)
        flags (if recursion-desired? 0x0100 0x0000)]
    (.putShort buffer id) ;;ID
    (.putShort buffer flags) ;; FLAGS
    (.putShort buffer 1) ;; QDCOUNT
    (.putShort buffer 0) ;; ANCOUNT
    (.putShort buffer 0) ;; NSCOUNT
    (.putShort buffer 0) ;; ARCOUNT
    (.array buffer)))
