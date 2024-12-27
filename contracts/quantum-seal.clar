;; Quantum-Resistant Document Sealing System
;; Initial implementation with core functionality

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-not-owner (err u100))
(define-constant err-already-sealed (err u101))
(define-constant err-document-not-found (err u102))

;; Data Maps
(define-map sealed-documents
    {document-hash: (buff 32)}
    {
        owner: principal,
        timestamp: uint,
        status: (string-ascii 10)
    }
)

(define-map document-metadata
    {document-hash: (buff 32)}
    {
        title: (string-ascii 64),
        description: (string-ascii 256),
        category: (string-ascii 32)
    }
)

;; Public Functions
(define-public (seal-document 
    (document-hash (buff 32))
    (title (string-ascii 64))
    (description (string-ascii 256))
    (category (string-ascii 32)))
    
    (let
        ((caller tx-sender))
        
        ;; Check if document already exists
        (asserts! (is-none (get-sealed-document document-hash))
            err-already-sealed)
        
        ;; Insert document data
        (asserts! (map-insert sealed-documents
            {document-hash: document-hash}
            {
                owner: caller,
                timestamp: block-height,
                status: "active"
            })
            (err u103)) ;; Failed to insert document data
        
        ;; Insert metadata
        (asserts! (map-insert document-metadata
            {document-hash: document-hash}
            {
                title: title,
                description: description,
                category: category
            })
            (err u104)) ;; Failed to insert metadata
        
        (ok true)
    )
)

;; Read-Only Functions
(define-read-only (get-sealed-document (document-hash (buff 32)))
    (map-get? sealed-documents {document-hash: document-hash})
)

(define-read-only (get-document-metadata (document-hash (buff 32)))
    (map-get? document-metadata {document-hash: document-hash})
)

;; Authorization Check
(define-private (is-owner (document-hash (buff 32)))
    (let ((doc-data (unwrap! (get-sealed-document document-hash)
            false)))
        (is-eq tx-sender (get owner doc-data))
    )
)
