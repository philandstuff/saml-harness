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

(defn make-reference [uri-str]
  (.newReference xsf
                 uri-str
                 (.newDigestMethod xsf DigestMethod/SHA1 nil)
                 [(.newTransform xsf Transform/ENVELOPED nil)
                  ;;(.newTransform xsf CanonicalizationMethod/EXCLUSIVE nil)
                  ]
                 nil
                 nil))

(defn make-signed-info [uri-str]
  (.newSignedInfo xsf
                  (.newCanonicalizationMethod
                   xsf
                   CanonicalizationMethod/EXCLUSIVE
                   nil)
                  (.newSignatureMethod
                   xsf
                   SignatureMethod/RSA_SHA1
                   nil)
                  [(make-reference uri-str)]))

(defn sig [uri-str] (.newXMLSignature xsf (make-signed-info uri-str) nil))

(defn sign! [element uri-str]
  (.sign (sig uri-str) (DOMSignContext. keys/private-key element)))
