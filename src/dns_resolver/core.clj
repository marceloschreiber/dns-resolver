(ns dns-resolver.core
  (:require [clojure.string :as str])
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

(defn unsigned-bytes->hex
  "Convert a sequence of bytes to a hex string."
  [bytes-seq]
  (->> bytes-seq
       (map #(format "%02X" %))
       (apply str)))

(defn generate-random-query-id
  "Generate a random 16-bit ID for a DNS query.
   For more info see [ref:header-id]."
  []
  (rand-int (Math/pow 2 16)))

(defn check-value-within-limits
  "Check if a value is within the limits of a given unsigned number of bits."
  [value bits]
  (when (or (< value 0) (>= value (Math/pow 2 bits)))
    (throw (ex-info "Value out of bounds" {:value value, :bits bits}))))

(defn write-unsigned-16
  "Write an unsigned 16-bit integer to a byte array.
   Array must be at least 2 bytes long and the value must be within the 16-bit limit."
  [array index value]
  (check-value-within-limits value 16)
  (aset array index (bit-shift-right (bit-and value 0xFF00) 8))
  (aset array (inc index) (bit-and value 0x00FF)))

(defn generate-query-header-section
  "Generate a query header for a DNS query.
   For more info about the format see [ref:header-section-format]."
  [{:keys [id recursion-desired?], :or {recursion-desired? true}}]
  (let [array (int-array 12)
        flags (if recursion-desired? 0x0100 0x0000)]
    (write-unsigned-16 array 0 id)
    (write-unsigned-16 array 2 flags)
    (write-unsigned-16 array 4 1) ;; QDCOUNT
    (write-unsigned-16 array 6 0) ;; ANCOUNT
    (write-unsigned-16 array 8 0) ;; NSCOUNT
    (write-unsigned-16 array 10 0) ;; ARCOUNT
    array))

(defn compress-domain-name
  "Encode a DNS message.
   For more info see [ref:message-compression]."
  [domain-name]
  (let [labels (str/split domain-name #"\.")
        buffer (ByteBuffer/allocate (+ (count labels) ;; ach label has a length byte
                                       (apply + (map count labels)) ;; the length of each label
                                       1))] ;; end delimiter which is a 0 byte
    (doseq [label labels]
      (.put buffer (byte (count label)))
      (.put buffer (.getBytes label)))
    (.put buffer (byte 0))
    (.array buffer)))
