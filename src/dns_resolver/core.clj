(ns dns-resolver.core
  (:require [clojure.string :as str])
  (:import [java.nio ByteBuffer]
           [java.net DatagramSocket DatagramPacket InetAddress]))

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

(defn find-first-by-key
  "Find the first element in a sequence that has a key with a given value."
  [key value coll]
  (first (filter #(= value (key %)) coll)))

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

(defn read-unsigned-16
  "Read an unsigned 16-bit integer from a byte array.
   Array must be 2 bytes long."
  [array]
  (let [first-byte (bit-and 0xFF (first array))
        second-byte (bit-and 0xFF (second array))]
    (bit-or (bit-shift-left first-byte 8) second-byte)))

(defn read-unsigned-32
  "Read an unsigned 32-bit integer from a byte array.
   Array must be 4 bytes long."
  [array]
  (let [first-byte  (bit-and 0xFF (nth array 0))
        second-byte (bit-and 0xFF (nth array 1))
        third-byte  (bit-and 0xFF (nth array 2))
        fourth-byte (bit-and 0xFF (nth array 3))]
    (bit-or (bit-shift-left first-byte 24)
            (bit-shift-left second-byte 16)
            (bit-shift-left third-byte 8)
            fourth-byte)))

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

(defn generate-question-section
  "Generate a question section for a DNS query.
   For more info see [ref:question-section]."
  [domain-name]
  (let [compressed-domain-name (compress-domain-name domain-name)
        type-and-class         (int-array 4)
        a-type-value           (:value (find-first-by-key :type :A type-values))
        in-class-value         (:value (find-first-by-key :class :IN class-values))]
    (write-unsigned-16 type-and-class 0 a-type-value)
    (write-unsigned-16 type-and-class 2 in-class-value)
    (concat compressed-domain-name type-and-class)))

(defn generate-dns-query
  "Generate a DNS query message."
  [domain-name]
  (let [id       (generate-random-query-id)
        header   (generate-query-header-section {:id                 id
                                                 :recursion-desired? true})
        question (generate-question-section domain-name)]
    {:id       id
     :header   header
     :question question
     :query    (concat header question)}))

(defn pointer?
  "Check if a byte is a pointer."
  [b]
  (every? #(bit-test b %) [7 6]))

(defn join-bytes
  [& b]
  (->> b
       (map-indexed (fn [i x]
                      (bit-shift-left x (* 8 (- (count b) i 1)))))
       (apply bit-or)))

(defn decode-label
  "Dumb implementation of a label decoder."
  [msg]
  (->> msg
       (drop 1)
       (map char)
       (map (fn [c]
              (if (Character/isLetterOrDigit c)
                c
                \.)))
       (apply str)))

(defn byte-to-unsigned-int [b]
  (bit-and b 0xFF))

(defn send-and-receive
  "Send a DNS query and receive the response."
  [domain-name]
  (let [{:keys [id question query]} (generate-dns-query domain-name)]
    (with-open [socket (DatagramSocket.)]
      (let [data           (byte-array (map unchecked-byte query))
            request-packed (DatagramPacket. data
                                            (count data)
                                            (InetAddress/getByName "8.8.8.8")
                                            53)]
        (.send socket request-packed)
        (loop []
          (let [buffer   (byte-array 1024)
                response (DatagramPacket. buffer (count buffer))]
            (.receive socket response)
            (let [received-msg (.getData response)
                  parsed-id    (->> received-msg
                                    (take 2)
                                    read-unsigned-16)]
              (if (= parsed-id id)
                (let [answer (->> received-msg
                                  (drop 12)
                                  (drop (count question)))]
                  (if (pointer? (first answer))
                    (let [joined-pointers (join-bytes (first answer) (second answer))
                          offset          (bit-and joined-pointers 0x3FFF)
                          label           (->> received-msg
                                               (drop offset)
                                               (take-while #(not= 0 %))
                                               decode-label)
                          rest-of-msg     (drop 2 answer)
                          type            (->> rest-of-msg
                                               (take 2)
                                               read-unsigned-16)
                          class           (->> rest-of-msg
                                               (drop 2)
                                               (take 2)
                                               read-unsigned-16)
                          ttl             (->> rest-of-msg
                                               (drop 4)
                                               (take 4)
                                               read-unsigned-32)
                          ip              (->> rest-of-msg
                                               (drop 10)
                                               (take 4)
                                               (map byte-to-unsigned-int)
                                               (str/join \.))]
                      {:label label
                       :type  (:type (find-first-by-key :value type type-values))
                       :class (:class (find-first-by-key :value class class-values))
                       :ttl   ttl
                       :ip    ip})
                    (throw (ex-info "Not implemented" {:received-msg received-msg}))))
                (recur)))))))))

(send-and-receive "marcelofernandes.dev")
