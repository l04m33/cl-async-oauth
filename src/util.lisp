(in-package #:cl-async-oauth/util)


(defun get-unix-time ()
  (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0)))


(defun random-string (length)
  (with-output-to-string (stream)
    (let* ((chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
           (range (length chars)))
      (loop repeat length
            do (princ (aref chars (random range)) stream)))))


(defun alist-to-oauth-header-string (alist)
  (with-output-to-string (out)
    (loop for first = t then nil
          for (name . value) in alist
          unless first do (format out ", ")
          do (format out "~A=\"~A\""
                     (quri.encode:url-encode name)
                     (quri.encode:url-encode value)))))


(defun alist-signing-sorter (e1 e2)
  (let ((key1 (car e1))
        (val1 (cdr e1))
        (key2 (car e2))
        (val2 (cdr e2)))
    (cond
      ((string< key1 key2) t)
      ((string> key1 key2) nil)
      (t
       (if (string< val1 val2) t nil)))))


(defun sort-alist-for-signing (alist)
  (sort alist #'alist-signing-sorter))


(defun get-alist-value (key alist)
  (let ((kv-pair (assoc key alist :test 'equal)))
    (if kv-pair
      (cdr kv-pair)
      nil)))


(defun get-deep-alist-value (alist &rest keys)
  (loop for k in keys
        for s = (cdr (assoc k alist)) then (cdr (assoc k s))
        finally (return s)))
