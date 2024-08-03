(ns dns-resolver.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [dns-resolver.core :as sut]))

(defmacro catch-thrown-info [f]
  `(try
     ~f
     (catch
      clojure.lang.ExceptionInfo e#
       {:msg (ex-message e#) :data (ex-data e#)})))

(deftest unsigned-bytes->hex-test
  (is (= "FF0082" (sut/unsigned-bytes->hex [0xFF 0x00 0x82]))))

(deftest check-value-within-limits-test
  (testing "Don't throw when value is within limits"
    (is (nil? (sut/check-value-within-limits 0 8)))
    (is (nil? (sut/check-value-within-limits 255 8)))
    (is (nil? (sut/check-value-within-limits 65535 16))))

  (testing "Throw when value is out of bounds"
    (testing "Negative value"
      (is (= {:msg "Value out of bounds", :data {:value -1, :bits 8}}
             (catch-thrown-info (sut/check-value-within-limits -1 8)))))

    (testing "Over the upper limit"
      (is (= {:msg "Value out of bounds", :data {:value 256, :bits 8}}
             (catch-thrown-info (sut/check-value-within-limits 256 8)))))))

(deftest write-unsigned-16-test
  (testing "Write 16-bit value to a byte array"
    (testing "Write 0"
      (let [array (int-array 2)]
        (sut/write-unsigned-16 array 0 0)
        (is (= [0 0] (into [] array)))))

    (testing "Write 255"
      (let [array (int-array 2)]
        (sut/write-unsigned-16 array 0 255)
        (is (= [0 255] (into [] array)))))

    (testing "Write 256"
      (let [array (int-array 2)]
        (sut/write-unsigned-16 array 0 256)
        (is (= [1 0] (into [] array)))))

    (testing "Write 65535"
      (let [array (int-array 2)]
        (sut/write-unsigned-16 array 0 65535)
        (is (= [255 255] (into [] array)))))))

(deftest generate-query-header-section-test
  (testing "When recursion enabled the flags should have the RD bit set"
    (let [header (sut/generate-query-header-section {:id 255 :recursion-desired? true})]
      (is (= [0 255 ;; ID
              1 0 ;; Flags
              0 1 ;; QDCOUNT
              0 0 ;; ANCOUNT
              0 0 ;; NSCOUNT
              0 0 ;; ARCOUNT
              ]
             (into [] header)))))

  (testing "When recursion disabled the flags should be 0"
    (let [header (sut/generate-query-header-section {:id 65535 :recursion-desired? false})]
      (is (= [255 255 ;; ID
              0 0 ;; Flags
              0 1 ;; QDCOUNT
              0 0 ;; ANCOUNT
              0 0 ;; NSCOUNT
              0 0 ;; ARCOUNT
              ]
             (into [] header))))))
