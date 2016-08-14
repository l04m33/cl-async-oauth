(in-package #:cl-async-oauth)


(define-condition missing-credentials-error (error)
  ((name
     :initarg :name
     :reader missing-credentials-name))
  (:report (lambda (c s)
             (print-unreadable-object (c s :type t :identity t)
               (format s "~a" (missing-credentials-name c)))))
  (:documentation "Indicate the absence of credentials from a session object."))


(defclass session ()
  ((consumer-key
     :initform (error 'missing-credentials-error :name "consumer-key")
     :initarg :consumer-key
     :accessor consumer-key)
   (consumer-secret
     :initform (error 'missing-credentials-error :name "consumer-secret")
     :initarg :consumer-secret
     :accessor consumer-secret)
   (signature-method
     :initform "HMAC-SHA1"
     :initarg :signature-method
     :accessor signature-method)
   (token
     :initform nil
     :initarg :token
     :accessor token)
   (token-secret
     :initform nil
     :initarg :token-secret
     :accessor token-secret)
   (last-nonce
     :initform nil
     :initarg :last-nonce
     :accessor last-nonce)
   (version
     :initform "1.0"
     :initarg :version
     :accessor version)
   (resource-base-url
     :initform ""
     :initarg :resource-base-url
     :accessor resource-base-url)))


(defun make-session (&rest args)
  (apply #'make-instance 'session args))


(defgeneric get-credentials (this))
(defgeneric sign (this method url param-list))
(defgeneric oauth-request (this url extra-oauth-params &key method))
(defgeneric request-token (this url cb-url &key method))
(defgeneric build-authorization-url (this url))
(defgeneric access-token (this url oauth-verifier &key method))
(defgeneric build-resource-url (this url))
(defgeneric request (this url &key method params))
(defgeneric streaming-request (this url &key method params body-cb))


(defmethod get-credentials ((this session))
  (let* ((nonce (random-string 32))
         (cred-list (list (cons "oauth_consumer_key" (consumer-key this))
                          (cons "oauth_nonce" nonce)
                          (cons "oauth_signature_method" (signature-method this))
                          (cons "oauth_timestamp" (write-to-string (get-unix-time)))
                          (cons "oauth_version" (version this)))))
    (setf (last-nonce this) nonce)
    (if (token this)
      (cons (cons "oauth_token" (token this)) cred-list)
      cred-list)))


(defmethod sign ((this session) method url param-list)
  (let* ((upper-method (string-upcase method))
         (encoded-url (quri.encode:url-encode url))
         (sorted-param-list (sort-alist-for-signing (copy-list param-list)))
         (param-string (quri.encode:url-encode-params sorted-param-list))
         (encoded-param-string (quri.encode:url-encode param-string))
         (base-string (format nil "~A&~A&~A"
                              upper-method
                              encoded-url
                              encoded-param-string))

         (encoded-consumer-secret (quri.encode:url-encode (consumer-secret this)))
         (encoded-token-secret (if (token-secret this)
                          (quri.encode:url-encode (token-secret this))
                          ""))
         (signing-key (format nil "~A&~A"
                              encoded-consumer-secret encoded-token-secret))
         
         (hmac (ironclad:make-hmac
                 (babel:string-to-octets signing-key) 'ironclad:sha1)))

    (ironclad:update-hmac hmac (babel:string-to-octets base-string))
    (cl-base64:usb8-array-to-base64-string (ironclad:hmac-digest hmac))))


(defmethod oauth-request ((this session) url extra-oauth-params &key (method :post))
  (let* ((cred-list (get-credentials this))
         (oauth-params (concatenate 'list cred-list extra-oauth-params))
         (signature (sign this (symbol-name method) url oauth-params))
         (full-oauth-params (cons (cons "oauth_signature" signature) oauth-params))
         (oauth-header (format nil "OAuth ~A" (alist-to-oauth-header-string full-oauth-params))))
    (blackbird-syntax:multiple-promise-bind
        (body status headers)
        (carrier:request url
                         :method method
                         :headers (list :authorization oauth-header)
                         :return-body t)
      (if (eql status 200)
        (let* ((decoded-body (quri.decode:url-decode-params body))
               (oauth-token (get-alist-value "oauth_token" decoded-body))
               (oauth-token-secret (get-alist-value "oauth_token_secret" decoded-body)))
          (when (and oauth-token oauth-token-secret)
            (setf (token this) oauth-token)
            (setf (token-secret this) oauth-token-secret))
          (list status decoded-body headers))
        (if (> (length body) 0)
          (list status (babel:octets-to-string body) headers)
          (list status nil headers))))))


(defmethod request-token ((this session) url cb-url &key (method :post))
  (oauth-request this url
                 (list (cons "oauth_callback" cb-url))
                 :method method))


(defmethod build-authorization-url ((this session) url)
  (let* ((oauth-token (token this))
         (uri (quri.uri:uri url)))
    (setf (quri.uri.http:uri-query-params uri)
          (list (cons "oauth_token" oauth-token)))
    (with-output-to-string (out)
      (quri:render-uri uri out))))


(defmethod access-token ((this session) url oauth-verifier &key (method :post))
  (oauth-request this url
                 (list (cons "oauth_verifier" oauth-verifier))
                 :method method))


(defmethod build-resource-url ((this session) url)
  (cond
    ((and (>= (length url) 8) (equal (subseq url 0 8) "https://")) url)
    ((and (>= (length url) 7) (equal (subseq url 0 7) "http://")) url)
    ((and (>= (length url) 1) (equal (subseq url 0 1) "/"))
     (let ((uri (quri.uri:uri (resource-base-url this))))
       (setf (quri.uri:uri-path uri) url)
       (quri:render-uri uri)))
    (t
     (format nil "~A~A" (resource-base-url this) url))))


(defmethod request ((this session) url &key (method :get) params)
  (let* ((real-url (build-resource-url this url))
         (cred-list (get-credentials this))
         (param-cred-list (concatenate 'list cred-list params))
         (signature (sign this (symbol-name method) real-url param-cred-list))
         (full-cred-list (cons (cons "oauth_signature" signature) cred-list))
         (oauth-header (format nil "OAuth ~A" (alist-to-oauth-header-string full-cred-list))))
    (blackbird-syntax:multiple-promise-bind
        (body status headers)
        (if (eql method :post)
          (carrier:request real-url
                           :method method
                           :headers (list :content-type "application/x-www-form-urlencoded"
                                          :authorization oauth-header )
                           :body (quri.encode:url-encode-params params)
                           :return-body t)
          (let ((uri (quri.uri:uri real-url)))
            (setf (quri.uri.http:uri-query-params uri) params)
            (carrier:request (quri:render-uri uri)
                             :method method
                             :headers (list :authorization oauth-header)
                             :return-body t)))
        (if (> (length body) 0)
          (list status (json:decode-json-from-string (babel:octets-to-string body)) headers)
          (list status nil headers)))))


(defmethod streaming-request ((this session) url &key (method :get) params body-cb)
  (let* ((real-url (build-resource-url this url))
         (cred-list (get-credentials this))
         (param-cred-list (concatenate 'list cred-list params))
         (signature (sign this (symbol-name method) real-url param-cred-list))
         (full-cred-list (cons (cons "oauth_signature" signature) cred-list))
         (oauth-header (format nil "OAuth ~A" (alist-to-oauth-header-string full-cred-list))))
    (blackbird-syntax:multiple-promise-bind
        (empty-body status headers)
        (if (eql method :post)
          (carrier:request real-url
                           :method method
                           :headers (list :content-type "application/x-www-form-urlencoded"
                                          :authorization oauth-header )
                           :body (quri.encode:url-encode-params params)
                           :body-callback body-cb
                           :return-body nil)
          (let ((uri (quri.uri:uri real-url)))
            (setf (quri.uri.http:uri-query-params uri) params)
            (carrier:request (quri:render-uri uri)
                             :method method
                             :headers (list :authorization oauth-header)
                             :body-callback body-cb
                             :return-body nil)))
        (declare (ignore empty-body))
        (list status nil headers))))
