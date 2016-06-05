(in-package :cl-user)


(defpackage #:cl-async-oauth/util
  (:nicknames #:oauth/util)
  (:use #:cl)
  (:export #:get-unix-time
           #:random-string
           #:alist-to-oauth-header-string
           #:sort-alist-for-signing
           #:get-alist-value
           #:get-deep-alist-value))


(defpackage #:cl-async-oauth
  (:nicknames #:oauth)
  (:use #:cl #:cl-async-oauth/util)
  (:export #:session

           #:consumer-key
           #:consumer-secret
           #:signature-method
           #:token
           #:token-secret
           #:last-nonce
           #:version
           #:resource-base-url
           
           #:make-session
           #:get-credentials
           #:sign

           #:oauth-request 
           #:request-token
           #:build-authorization-url
           #:access-token
           #:build-resource-url
           #:request
           #:streaming-request))


(defpackage #:cl-async-oauth/api-test
  (:use #:cl #:cl-async-oauth #:blackbird)
  (:export #:mk-sess
           #:do-request-token
           #:do-build-authorization-url
           #:do-access-token
           #:do-request
           #:do-streaming-request))
