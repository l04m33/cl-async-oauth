(asdf:defsystem #:cl-async-oauth
  :description "OAuth implementation for cl-async"
  :author "Kay Z. <l04m33@gmail.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on (#:carrier
               #:cl-json
               #:cl-async
               #:blackbird
               #:babel
               #:quri
               #:cl-base64
               #:ironclad)
  :components ((:module "src"
                :pathname "src"
                :components ((:file "package")
                             (:file "util" :depends-on ("package"))
                             (:file "session" :depends-on ("package" "util"))
                             (:file "api-test" :depends-on ("package" "session"))))))
