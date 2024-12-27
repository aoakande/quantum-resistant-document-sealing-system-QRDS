;; Quantum-Resistant Document Sealing System
;; A future-proof document verification system built on Stacks

;; Error Constants
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-ALREADY-EXISTS (err u402))
(define-constant ERR-NOT-FOUND (err u404))
(define-constant ERR-INVALID-SIGNATURE (err u403))
(define-constant ERR-BATCH-LIMIT-EXCEEDED (err u405))
(define-constant ERR-INVALID-STATUS (err u406))

;; Event Constants
(define-constant EVENT-DOCUMENT-SEALED "document-sealed")
(define-constant EVENT-BATCH-SEALED "batch-sealed")
(define-constant EVENT-STATUS-UPDATED "status-updated")
(define-constant EVENT-OWNERSHIP-TRANSFERRED "ownership-transferred")

;; Other Constants
(define-constant MAX-BATCH-SIZE u10)
(define-constant VALID-STATUS (list "active" "revoked" "expired"))

;; Data Variables
(define-data-var contract-owner principal tx-sender)
(define-data-var last-document-id uint u0)
(define-data-var last-batch-id uint u0)

;; Data Maps
(define-map documents
    {id: uint}  ;; Using uint ID for efficient indexing
    {
        hash: (buff 32),
        owner: principal,
        timestamp: uint,
        status: (string-ascii 10),
        signature: {
            value: (buff 512),      ;; Quantum-resistant signature size
            merkle-root: (buff 32),
            public-key: (buff 256)  ;; Post-quantum public key
        }
    }
)

(define-map document-metadata
    {id: uint}
    {
        title: (string-ascii 64),
        description: (string-ascii 256),
        category: (string-ascii 32),
        merkle-path: (list 32 (buff 32))  ;; Merkle proof path
    }
)

(define-map batch-records
    {batch-id: uint}
    {
        document-ids: (list 100 uint),
        timestamp: uint,
        status: (string-ascii 10),
        owner: principal
    }
)

;; Authorization Functions
(define-private (is-contract-owner)
    (is-eq tx-sender (var-get contract-owner)))

(define-private (is-document-owner (id uint))
    (match (map-get? documents {id: id})
        doc (is-eq tx-sender (get owner doc))
        false))

(define-private (is-valid-status (status (string-ascii 10)))
    (is-some (index-of VALID-STATUS status)))

;; Core Document Functions
(define-public (seal-document
    (document-hash (buff 32))
    (title (string-ascii 64))
    (description (string-ascii 256))
    (category (string-ascii 32))
    (signature (buff 512))
    (merkle-root (buff 32))
    (public-key (buff 256))
    (merkle-path (list 32 (buff 32))))
    
    (let
        ((new-id (+ (var-get last-document-id) u1)))
        
        ;; Store document data
        (asserts! (map-insert documents
            {id: new-id}
            {
                hash: document-hash,
                owner: tx-sender,
                timestamp: block-height,
                status: "active",
                signature: {
                    value: signature,
                    merkle-root: merkle-root,
                    public-key: public-key
                }
            })
            ERR-ALREADY-EXISTS)
        
        ;; Store metadata
        (asserts! (map-insert document-metadata
            {id: new-id}
            {
                title: title,
                description: description,
                category: category,
                merkle-path: merkle-path
            })
            ERR-ALREADY-EXISTS)
        
        ;; Update last document ID
        (var-set last-document-id new-id)
        
        ;; Print event
        (print {
            event: EVENT-DOCUMENT-SEALED,
            document-id: new-id,
            hash: document-hash,
            owner: tx-sender
        })
        
        (ok new-id)
    ))

;; Batch Processing Functions
(define-public (seal-document-batch
    (documents (list 10 {
        hash: (buff 32),
        title: (string-ascii 64),
        description: (string-ascii 256),
        category: (string-ascii 32),
        signature: (buff 512),
        merkle-root: (buff 32),
        public-key: (buff 256),
        merkle-path: (list 32 (buff 32))
    })))
    
    (let
        ((batch-id (+ (var-get last-batch-id) u1))
         (document-ids (list)))
        
        ;; Check batch size
        (asserts! (<= (len documents) MAX-BATCH-SIZE)
            ERR-BATCH-LIMIT-EXCEEDED)
        
        ;; Process each document
        (map process-batch-document documents)
        
        ;; Store batch record
        (asserts! (map-insert batch-records
            {batch-id: batch-id}
            {
                document-ids: document-ids,
                timestamp: block-height,
                status: "sealed",
                owner: tx-sender
            })
            ERR-ALREADY-EXISTS)
        
        ;; Update batch counter
        (var-set last-batch-id batch-id)
        
        ;; Print event
        (print {
            event: EVENT-BATCH-SEALED,
            batch-id: batch-id,
            count: (len documents),
            owner: tx-sender
        })
        
        (ok batch-id)))

;; Helper function for batch processing
(define-private (process-batch-document (doc {
    hash: (buff 32),
    title: (string-ascii 64),
    description: (string-ascii 256),
    category: (string-ascii 32),
    signature: (buff 512),
    merkle-root: (buff 32),
    public-key: (buff 256),
    merkle-path: (list 32 (buff 32))}))
    
    (let
        ((new-id (+ (var-get last-document-id) u1)))
        
        ;; Store document
        (map-insert documents
            {id: new-id}
            {
                hash: (get hash doc),
                owner: tx-sender,
                timestamp: block-height,
                status: "active",
                signature: {
                    value: (get signature doc),
                    merkle-root: (get merkle-root doc),
                    public-key: (get public-key doc)
                }
            })
            
        ;; Store metadata
        (map-insert document-metadata
            {id: new-id}
            {
                title: (get title doc),
                description: (get description doc),
                category: (get category doc),
                merkle-path: (get merkle-path doc)
            })
        
        ;; Update document counter
        (var-set last-document-id new-id)
        
        ;; Print event
        (print {
            event: EVENT-DOCUMENT-SEALED,
            document-id: new-id,
            hash: (get hash doc),
            owner: tx-sender
        })
        
        new-id))

;; Document Management Functions
(define-public (update-document-status
    (id uint)
    (new-status (string-ascii 10)))
    
    (begin
        (asserts! (is-document-owner id) ERR-NOT-AUTHORIZED)
        (asserts! (is-valid-status new-status) ERR-INVALID-STATUS)
        (match (map-get? documents {id: id})
            doc (begin
                (map-set documents
                    {id: id}
                    (merge doc {status: new-status}))
                (print {
                    event: EVENT-STATUS-UPDATED,
                    document-id: id,
                    new-status: new-status,
                    owner: tx-sender
                })
                (ok true))
            ERR-NOT-FOUND)))

(define-public (transfer-document-ownership
    (id uint)
    (new-owner principal))
    
    (begin
        (asserts! (is-document-owner id) ERR-NOT-AUTHORIZED)
        (match (map-get? documents {id: id})
            doc (begin
                (map-set documents
                    {id: id}
                    (merge doc {owner: new-owner}))
                (print {
                    event: EVENT-OWNERSHIP-TRANSFERRED,
                    document-id: id,
                    previous-owner: tx-sender,
                    new-owner: new-owner
                })
                (ok true))
            ERR-NOT-FOUND)))

;; Read-Only Functions
(define-read-only (get-document (id uint))
    (map-get? documents {id: id}))

(define-read-only (get-metadata (id uint))
    (map-get? document-metadata {id: id}))

(define-read-only (verify-signature
    (id uint)
    (provided-signature (buff 512)))
    
    (match (map-get? documents {id: id})
        doc (ok (is-eq (get value (get signature doc)) provided-signature))
        ERR-NOT-FOUND))

(define-read-only (verify-merkle-proof
    (id uint)
    (leaf (buff 32)))
    
    (let
        ((doc (unwrap! (map-get? documents {id: id}) ERR-NOT-FOUND))
         (metadata (unwrap! (map-get? document-metadata {id: id}) ERR-NOT-FOUND)))
        
        ;; Verify if leaf exists in Merkle path
        (ok (is-some (index-of (get merkle-path metadata) leaf)))))

(define-read-only (get-batch (batch-id uint))
    (map-get? batch-records {batch-id: batch-id}))

(define-read-only (get-batch-documents (batch-id uint))
    (match (map-get? batch-records {batch-id: batch-id})
        batch (ok (map get-document (get document-ids batch)))
        ERR-NOT-FOUND))

;; Administrative Functions
(define-public (set-contract-owner (new-owner principal))
    (begin
        (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
        (ok (var-set contract-owner new-owner))))
