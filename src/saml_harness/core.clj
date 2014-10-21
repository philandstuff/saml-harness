(ns saml-harness.core
  (:require [clj-http.core :as http]
            [clj-http.util :as util]
            [clojure.string :as str]
            [saml-harness.java :as java])
  (:import [java.io StringWriter]
           [javax.xml.transform TransformerFactory]
           [javax.xml.transform.dom DOMSource]
           [javax.xml.transform.stream StreamResult]
           [org.joda.time DateTime]
           [org.opensaml Configuration]
           [org.opensaml.saml2.core AuthnRequest Issuer NameIDType]))

;xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
;xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
;xmlns:ds="http://www.w3.org/2000/09/xmldsig#"

(org.opensaml.DefaultBootstrap/bootstrap)

(def saml-bf (Configuration/getBuilderFactory))

(defn make-issuer []
  (doto (-> (.getBuilder saml-bf Issuer/DEFAULT_ELEMENT_NAME)
            (.buildObject))
    (.setFormat NameIDType/ENTITY)
    (.setValue "http://www.test-rp.gov.uk/SAML2/MD")))

(defn make-authn-request []
  (doto (-> (.getBuilder saml-bf AuthnRequest/DEFAULT_ELEMENT_NAME)
            (.buildObject))
    (.setDestination "http://localhost:50220/SAML2/SSO")
    (.setForceAuthn false)
    (.setID (str "_" (java.util.UUID/randomUUID)))
    (.setIssuer (make-issuer))
    (.setIssueInstant (DateTime.))
    (.setProtocolBinding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    ))

(def trans (.newTransformer (TransformerFactory/newInstance)))

(defn saml->elem [samlobj]
  (let [req        samlobj
        marshaller (.getMarshaller (Configuration/getMarshallerFactory) req)]
    (.marshall marshaller req)))

(defn elem->string [doc]
  (let [sw (StringWriter.)]
    (.transform trans (DOMSource. doc) (StreamResult. sw))
    (str sw)))

(comment
  (-> (make-authn-request)
      saml->elem
      elem->string)
  )

(defn fetch-metadata []
  (http/request
   {:request-method :get
    :uri "localhost:50220/SAML2/metadata/sp"
    :scheme "http"
    :debug true}))

(comment
  (slurp (:body (fetch-metadata)))
  )

(defn signed-authn-req [authn-req]
  (let [xml-authn-req-elem (saml->elem authn-req)
        ref-uri (str "#" (.getID authn-req))
        ]
    (.setIdAttribute xml-authn-req-elem "ID" true)
    (java/sign! xml-authn-req-elem ref-uri)
    xml-authn-req-elem))

(defn build-saml-request-post-body [^String request]
  (into-array Byte/TYPE (concat
                         ;TODO: Charset
                         "SAMLRequest="
                         (util/url-encode (util/base64-encode (.getBytes request)))
                         "&RelayState=baz")))

(defn post-saml-request [^String request]
  (http/request
   {:request-method :post
    :uri "localhost:50220/SAML2/SSO"
    :scheme "http"
    :debug true
    :headers {"Content-Type" "application/x-www-form-urlencoded"}
    :body (build-saml-request-post-body request)}))

(comment
  (update-in (post-saml-request (str/join (concat "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xml>" (repeat 1500 "x") "</xml>"))) [:body] slurp)

  (let [unsigned-req (make-authn-request)
        _ (println (-> unsigned-req saml->elem elem->string))
        req (signed-authn-req unsigned-req)
        strreq (elem->string req)]
    (println strreq)
    )

  (let [req (signed-authn-req (make-authn-request))
        strreq (elem->string req)]
    (println strreq)
    (post-saml-request strreq))

  (let [req (saml->elem (make-authn-request))]
    (java/sign! req)
    (println (elem->string req))
    )

  )
