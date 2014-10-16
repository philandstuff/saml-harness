(ns saml-harness.keys
  (:require [clojure.java.io :as io])
  (:import java.security.KeyFactory
           java.security.spec.PKCS8EncodedKeySpec
           [org.apache.commons.io IOUtils]))

(def keyfile "filename.pk8")

(defn private-key-bytes [keyfilename]
  (IOUtils/toByteArray
   (io/input-stream
    keyfilename)))

(def kf (KeyFactory/getInstance "RSA"))

(def private-key (.generatePrivate kf (PKCS8EncodedKeySpec. (private-key-bytes keyfile))))
