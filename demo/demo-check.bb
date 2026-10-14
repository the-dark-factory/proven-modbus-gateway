#!/usr/bin/env bb
;; demo-check.bb -- the lovelace-mb W4 DEMO CHECK (test fixture, built-not-proved; R-MB-1).
;; Usage:  bb demo-check.bb [--direct] TRANSCRIPT.tsv PLC-WRITES.tsv SCRIPT.txt
;; Gateway mode (default): for every script step, in order,
;;   (1) the transcript outcome matches the expected column: ok (any ok) | ok v,v (exact values) | exc NN | silent;
;;   (2) for a WRITE step (wb wr wbs wrs mwr, or raw FC 5/6/15/16/22/23), checked from the PLC's own write log:
;;       an expected-ok write is in the log, a refused write is NOT (multiset per (fc, address, values): the log's
;;       count of a key must equal the number of expected-ok steps with that key);
;;   and the log holds no write that no script step asked for. One PASS/FAIL line per step, a summary, exit 0 only
;;   when every line passes.
;; --direct (self-test, no gateway): expectations are NOT judged; each step shows what the bare PLC did and whether
;;   the write reached it. Exit 0 when every write libmodbus acknowledged is in the PLC log (the log is live).
(require '[clojure.string :as str])

(def args *command-line-args*)
(def direct? (some #{"--direct"} args))
(def files (remove #{"--direct"} args))
(when (not= 3 (count files))
  (binding [*out* *err*] (println "usage: bb demo-check.bb [--direct] TRANSCRIPT.tsv PLC-WRITES.tsv SCRIPT.txt"))
  (System/exit 2))
(def tpath (nth files 0))
(def lpath (nth files 1))
(def spath (nth files 2))

(defn tsv [path]
  (let [[h & rows] (str/split-lines (slurp path))
        cols (str/split h #"\t")]
    (mapv #(zipmap cols (str/split % #"\t" -1)) rows)))

(def script-steps
  (->> (str/split-lines (slurp spath))
       (map str/trim)
       (remove #(or (str/blank? %) (str/starts-with? % "#")))
       (mapv #(let [[n p r e] (map str/trim (str/split % #"\|"))] {:name n :port p :request r :expect e}))))

(def transcript (tsv tpath))
(def plc-log
  (if (.exists (java.io.File. lpath))
    (->> (str/split-lines (slurp lpath))
         (remove str/blank?)
         (mapv #(let [[ms conn tid unit fc addr vals result] (str/split % #"\t" -1)]
                  {:fc (parse-long fc) :addr (parse-long addr) :values vals :result result})))
    []))

(defn num [s] (if (str/starts-with? (str/lower-case s) "0x") (Long/parseLong (subs s 2) 16) (parse-long s)))
(defn hex4 [v] (format "0x%04x" v))

(defn raw-key [hex]
  (let [h (str/replace hex #"\s" "")
        b (mapv #(Integer/parseInt (apply str %) 16) (partition 2 h))
        be16 (fn [i] (+ (* 256 (b i)) (b (inc i))))
        n (count b)]
    (when (>= n 8)
      (case (b 7)
        5 (when (>= n 12) (let [v (be16 10)]
                            [5 (be16 8) (case v 0xFF00 "1" 0 "0" (hex4 v))]))
        6 (when (>= n 12) [6 (be16 8) (str (be16 10))])
        16 (when (>= n 13) [16 (be16 8) (str/join "," (for [i (range (be16 10)) :let [p (+ 13 (* 2 i))] :when (< (inc p) n)] (be16 p)))])
        22 (when (>= n 14) [22 (be16 8) (str "and=" (hex4 (be16 10)) ",or=" (hex4 (be16 12)))])
        nil))))

(defn write-key
  "[fc addr values] for a write request in the script's syntax, as plc-sim logs it; nil for a non-write."
  [request]
  (let [[verb & xs] (str/split request #"\s+")]
    (case verb
      "wb"  [5 (num (first xs)) (if (zero? (num (second xs))) "0" "1")]
      "wr"  [6 (num (first xs)) (str (num (second xs)))]
      "wbs" [15 (num (first xs)) (str/join "," (map #(if (zero? (num %)) 0 1) (str/split (second xs) #",")))]
      "wrs" [16 (num (first xs)) (str/join "," (map num (str/split (second xs) #",")))]
      "mwr" [22 (num (first xs)) (str "and=" (hex4 (num (second xs))) ",or=" (hex4 (num (nth xs 2))))]
      "raw" (raw-key (str/join "" xs))
      nil)))

(def log-count (frequencies (map (juxt :fc :addr :values) plc-log)))
(def expect-ok? #(str/starts-with? % "ok"))
(def passed-count (frequencies (for [s script-steps :let [k (write-key (:request s))] :when (and k (expect-ok? (:expect s)))] k)))

(defn outcome-ok? [expect outcome]
  (cond (= expect "-") true
        (= expect "ok") (str/starts-with? outcome "ok")
        :else (= expect outcome)))

(def results (atom []))
(defn report! [pass? line] (swap! results conj pass?) (println (str (if pass? "PASS " "FAIL ") line)))

(println (str "demo-check: " (if direct? "DIRECT self-test (no gateway; expectations NOT judged)" "gateway demo")
              " -- " (count script-steps) " script steps, " (count transcript) " transcript rows, "
              (count plc-log) " PLC write-log lines"))

(when (not= (map :name script-steps) (map #(get % "step") transcript))
  (report! false "transcript steps differ from the script's steps (missing, extra or reordered)"))

(doseq [[s t] (map vector script-steps transcript)
        :let [outcome (get t "outcome" "?")
              k (write-key (:request s))
              in-log (get log-count k 0)
              want (get passed-count k 0)
              plc-note (cond (nil? k) ""
                             :else (str "  plc-log " (if (pos? in-log) (str "HAS " k " x" in-log) (str "lacks " k))))]]
  (if direct?
    (println (format "     %-26s %-40s -> %-16s%s" (:name s) (:request s) outcome
                     (cond (nil? k) ""
                           (pos? in-log) (str "  REACHED PLC" (when-not (expect-ok? (:expect s)) "  <- the gateway must refuse this"))
                           :else "  not executed")))
    (let [o-ok (outcome-ok? (:expect s) outcome)
          p-ok (or (nil? k) (= in-log want))]
      (report! (and o-ok p-ok)
               (format "%-26s expect %-12s got %-16s%s%s" (:name s) (:expect s) outcome plc-note
                       (cond (not p-ok) (if (expect-ok? (:expect s))
                                          (str "  (PLC log has " in-log ", passed steps " want ")")
                                          "  <- a REFUSED write reached the PLC")
                             :else ""))))))

(def script-keys (set (keep #(write-key (:request %)) script-steps)))
(def strays (remove script-keys (keys log-count)))

(if direct?
  (let [ws (filter #(write-key (:request %)) script-steps)
        reached (filter #(pos? (get log-count (write-key (:request %)) 0)) ws)
        forbidden (remove #(expect-ok? (:expect %)) reached)
        acked-missing (filter #(and (= "ok" (get % "outcome")) (write-key (get % "request"))
                                    (zero? (get log-count (write-key (get % "request")) 0)))
                              transcript)]
    (println (format "SELF-TEST: %d write steps sent straight to the PLC; %d reached it, %d of them writes the gateway must REFUSE."
                     (count ws) (count reached) (count forbidden)))
    (println "           The bare PLC obeys them all -- which is exactly why the gateway exists.")
    (doseq [t acked-missing] (println "FAIL acknowledged by the PLC but missing from its write log:" (get t "step")))
    (System/exit (if (empty? acked-missing) 0 1)))
  (do
    (doseq [k strays] (report! false (str "PLC write log has a write no script step asked for: " k " x" (log-count k))))
    (let [n (count @results) f (count (remove true? @results))]
      (println (format "SUMMARY: %d checks, %d PASS, %d FAIL -- %s" n (- n f) f (if (zero? f) "DEMO PASSES" "DEMO FAILS")))
      (System/exit (if (zero? f) 0 1)))))
