(ns dns-resolver.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [dns-resolver.core :as sut]))

(deftest generate-query-header-test
  (testing "When recursion-desired? is false"
    (is (= (vec (byte-array [0 1 0 0 0 1 0 0 0 0 0 0]))
           (vec (sut/generate-query-header {:id 1 :recursion-desired? false})))))

  (testing "When recursion-desired? is true"
    (is (= (vec (byte-array [0 1 1 0 0 1 0 0 0 0 0 0]))
           (vec (sut/generate-query-header {:id 1 :recursion-desired? true})))))

  (testing "By default recursion-desired? is true"
    (is (= (vec (byte-array [0 1 1 0 0 1 0 0 0 0 0 0]))
           (vec (sut/generate-query-header {:id 1}))))))
