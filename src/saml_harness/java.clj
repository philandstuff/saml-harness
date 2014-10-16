(ns saml-harness.java
  (:require [saml-harness.keys :as keys])
  (:import [javax.xml.crypto.dsig
            CanonicalizationMethod DigestMethod
            SignatureMethod Transform XMLSignatureFactory]
           [javax.xml.crypto.dsig.dom DOMSignContext]
           [javax.xml.parsers DocumentBuilderFactory]))

(def dbf (doto (DocumentBuilderFactory/newInstance)
           (.setNamespaceAware true)))

(def builder (.newDocumentBuilder dbf))

(def xsf (XMLSignatureFactory/getInstance "DOM"))

(def r (.newReference xsf
                      ""
                      (.newDigestMethod xsf DigestMethod/SHA1 nil)
                      [(.newTransform xsf Transform/ENVELOPED nil)]
                      nil
                      nil))

(def si (.newSignedInfo xsf
                        (.newCanonicalizationMethod
                         xsf
                         CanonicalizationMethod/INCLUSIVE
                         nil)
                        (.newSignatureMethod
                         xsf
                         SignatureMethod/RSA_SHA1
                         nil)
                        [r]))

(def sig (.newXMLSignature xsf si nil))

(defn sign! [element]
  (.sign sig (DOMSignContext. keys/private-key element)))
