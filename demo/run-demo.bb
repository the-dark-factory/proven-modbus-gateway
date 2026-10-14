#!/usr/bin/env bb
;; run-demo.bb -- the lovelace-mb ONE-COMMAND DEMO runner (test instrument, never product; R-MB-1, R-MB-5).
;; It ORCHESTRATES ONLY (seat decision 2026-10-03 09:07). The single verdict is the existing demo-check.bb: its output
;; and its exit code are passed straight through, unchanged. This runner judges nothing.
;;
;;   bb demo/run-demo.bb          (from expand-lovelace-libmodbus/; any cwd works)
;;
;; Order:
;;   1. locate the five gateway edges' LANE OUTPUT in their wu dirs (~/dev/ada-factory/wu-lovelace-mb-<edge>): the binary
;;      the lane built from the lane-spliced source named in provenance-<R>.json. If that binary is missing or older than
;;      the source, the lane-spliced source + its carried .ads + edge.gpr are copied into demo/run/edges/<edge>/ and built
;;      there with gprbuild (lane env). Nothing is written into a wu dir; no Ada is written here.
;;   2. site-loader: demo/site-water-works.txt -> demo/run/site.dump.
;;   3. plc-sim (libmodbus, unmodified) on 127.0.0.1:1502, then the gateway as ONE OS pipeline on loopback:
;;        mb_master_listener_main DUMP 127.0.0.1 5029 | mb_policy_gate_main DUMP
;;          | mb_plc_forwarder_main DUMP 127.0.0.1 1502 | mb_master_replier_main 5029 EVENTS
;;      (5020 = SCADA slot 1, 5021 = historian slot 2, 5029 = the listener's return port; R-MB-20).
;;   4. demo-master over demo/script.txt (29 steps), writing demo/run/transcript.tsv.
;;   5. tear everything down (always: also on an error, an exception or Ctrl-C), then run demo-check.bb on the transcript
;;      and plc-sim's own write log. Its output is printed as is; its exit code is this runner's exit code.
;; If the demo cannot be set up (an edge has no lane output, a port is taken, a process does not start) the runner prints
;; the reason, tears down, and exits 3 without running demo-check. Usage error: exit 2.
;; Outputs (overwritten each run): demo/run/ -- site.dump, plc-writes.tsv, transcript.tsv, events.tsv, *.err, master.out.
;; Env: MB_FACTORY (default ~/dev/ada-factory).
(require '[babashka.process :refer [process shell pipeline pb]]
         '[babashka.fs :as fs]
         '[clojure.string :as str]
         '[clojure.java.io :as io]
         '[cheshire.core :as json])

(when (seq *command-line-args*)
  (binding [*out* *err*] (println "usage: bb run-demo.bb"))
  (System/exit 2))

(def home (System/getProperty "user.home"))
(def demo (str (fs/parent (fs/absolutize *file*))))
(def factory (or (System/getenv "MB_FACTORY") (str home "/dev/ada-factory")))
(def run (str demo "/run"))
(def chain-names ["master-listener" "policy-gate" "plc-forwarder" "master-replier"])

(defn say [& xs] (println (str/join " " xs)) (flush))
(defn stop! [& why] (throw (ex-info (str/join " " why) {:setup true})))

;; ---------------------------------------------------------------- 1. lane output
(defn lane-env []
  (merge (into {} (System/getenv))
         {"PATH" (str home "/.alire/bin:" (System/getenv "PATH")) "MACOSX_DEPLOYMENT_TARGET" "26.0"}))

(defn edge-binary [edge]
  (let [d (str factory "/wu-lovelace-mb-" edge)
        prov (->> (fs/glob d "provenance-*.json") (sort-by #(fs/file-time->millis (fs/last-modified-time %))) last)]
    (when-not prov (stop! "no lane output for" edge "(no provenance-*.json in" d ")"))
    (let [p (json/parse-string (slurp (str prov)) true)
          src (:source p)
          lane-bin (str d "/" (str/replace src #"\.adb$" ""))
          mtime #(fs/file-time->millis (fs/last-modified-time %))]
      (if (and (fs/executable? lane-bin) (>= (mtime lane-bin) (mtime (fs/path d src))))
        (do (say (format "edge %-16s lane round %s binary  %s" edge (:round p) lane-bin)) lane-bin)
        (let [b (str run "/edges/" edge)]
          (fs/create-dirs b)
          (doseq [f (concat [(fs/path d src) (fs/path d "edge.gpr")] (fs/glob d "*.ads"))] (fs/copy f b {:replace-existing true}))
          (let [r (shell {:dir b :continue true :out :string :err :string :extra-env (lane-env)} "gprbuild" "-P" "edge.gpr" "-p" "-q")]
            (spit (str b "/build.out") (str (:out r) (:err r)))
            (when-not (zero? (:exit r)) (stop! "gprbuild of" edge "exited" (:exit r) "(see" (str b "/build.out)")))
            (say (format "edge %-16s built here from lane round %s source  %s" edge (:round p) (str d "/" src)))
            (str b "/" (str/replace src #"\.adb$" ""))))))))

;; ---------------------------------------------------------------- processes and teardown
(def procs (atom []))
(defn alive? [p] (.isAlive ^Process (:proc p)))
(defn wait-gone [p ms]
  (let [t (+ (System/currentTimeMillis) ms)]
    (loop [] (when (and (alive? p) (< (System/currentTimeMillis) t)) (Thread/sleep 25) (recur)))))

(def torn-down (atom false))
(defn teardown!
  "Stop everything started: the listener first (the rest of the pipeline then ends on end of input), any stage still
  running after 2 s, then plc-sim; SIGKILL whatever outlives 3 s more."
  []
  (when (compare-and-set! torn-down false true)
    (let [by-name (into {} @procs)
          term (fn [n] (when-let [p (by-name n)] (when (alive? p) (.destroy ^Process (:proc p)))))]
      (term "master-listener")
      (doseq [n (rest chain-names)] (when-let [p (by-name n)] (wait-gone p 2000) (term n)))
      (term "plc-sim")
      (doseq [[_ p] @procs] (wait-gone p 3000) (when (alive? p) (.destroyForcibly ^Process (:proc p)) (wait-gone p 2000)))
      (let [left (for [[n p] @procs :when (alive? p)] n)]
        (say (if (empty? left) "teardown: all processes stopped" (str "teardown: still running: " (str/join "," left))))))))

(.addShutdownHook (Runtime/getRuntime) (Thread. ^Runnable (fn [] (teardown!))))

(defn port-taken? [port]
  (try (with-open [s (java.net.ServerSocket.)]
         (.bind s (java.net.InetSocketAddress. "127.0.0.1" (int port))) false)
       (catch Exception _ true)))
(defn wait-for [ms ready?]
  (let [t (+ (System/currentTimeMillis) ms)]
    (loop [] (cond (ready?) true (> (System/currentTimeMillis) t) false :else (do (Thread/sleep 25) (recur))))))
(defn has? [f s] (and (fs/exists? f) (str/includes? (slurp f) s)))

;; ---------------------------------------------------------------- the run
(defn setup-and-drive! []
  (say "lovelace-mb demo: simulated water works (R-MB-19) behind the gateway on loopback; run dir" run)
  (fs/delete-tree run)
  (fs/create-dirs run)
  (doseq [x ["mb_plc_sim" "mb_demo_master"]]
    (when-not (fs/executable? (str demo "/" x)) (stop! "fixture" x "missing: build it with  make -C demo")))
  (let [bins (into {} (for [e (cons "site-loader" chain-names)] [e (edge-binary e)]))
        f #(io/file run %)
        dump (str run "/site.dump")
        r (shell {:continue true :out :string :err :string} (bins "site-loader") (str demo "/site-water-works.txt"))]
    (spit dump (:out r))
    (when-not (zero? (:exit r)) (stop! "site-loader exited" (:exit r) (:err r)))
    (say "site dump:" (last (str/split-lines (:out r))))
    (when-let [taken (seq (filter port-taken? [1502 5020 5021 5029]))]
      (stop! "port(s) already in use on 127.0.0.1:" (str/join "," taken)))
    (let [plc (process [(str demo "/mb_plc_sim") "--port" "1502" "--log" (str run "/plc-writes.tsv")]
                       {:err (f "plc.err") :out (f "plc.out")})]
      (swap! procs conj ["plc-sim" plc])
      (when-not (wait-for 5000 #(has? (f "plc.err") "listening on")) (stop! "plc-sim did not start (see run/plc.err)"))
      (say "plc-sim (libmodbus, unmodified) listening on 127.0.0.1:1502")
      (let [chain (pipeline (pb [(bins "master-listener") dump "127.0.0.1" "5029"] {:err (f "listener.err")})
                            (pb [(bins "policy-gate") dump] {:err (f "gate.err")})
                            (pb [(bins "plc-forwarder") dump "127.0.0.1" "1502"] {:err (f "forwarder.err")})
                            (pb [(bins "master-replier") "5029" (str run "/events.tsv")] {:err (f "replier.err") :out (f "replier.out")}))]
        (swap! procs into (map vector chain-names chain))
        (when-not (and (wait-for 5000 #(and (has? (f "listener.err") "listening on 127.0.0.1:5020")
                                            (has? (f "listener.err") "listening on 127.0.0.1:5021")))
                       (wait-for 6000 #(has? (f "events.tsv") "started")))
          (stop! "the gateway did not come up (see run/listener.err, run/replier.err)"))
        (say "gateway up: listener | policy-gate | forwarder | replier on 5020 (SCADA), 5021 (historian)")
        (say "demo-master: 29 script steps, about 20 s (one 10.5 s pause, two 2 s silences) ...")
        (let [m (shell {:continue true :out :string :err :string}
                       (str demo "/mb_demo_master") "--script" (str demo "/script.txt") "--out" (str run "/transcript.tsv")
                       "--timeout-ms" "2000" "127.0.0.1")]
          (spit (f "master.out") (str (:out m) (:err m)))
          (say "demo-master exit" (:exit m))
          (when-let [gone (seq (for [[n p] (map vector chain-names chain) :when (not (alive? p))] n))]
            (say "note: gateway stage(s) no longer running after the script:" (str/join "," gone))))
        (Thread/sleep 300)))))

(defn -main []
  (let [setup-error (try (setup-and-drive!) nil
                         (catch clojure.lang.ExceptionInfo e (ex-message e))
                         (catch Exception e (str e))
                         (finally (teardown!)))]
    (if setup-error
      (do (say "demo not run to the check:" setup-error) (System/exit 3))
      (let [c (shell {:continue true :out :inherit :err :inherit} "bb" (str demo "/demo-check.bb")
                     (str run "/transcript.tsv") (str run "/plc-writes.tsv") (str demo "/script.txt"))]
        (System/exit (:exit c))))))

(-main)
