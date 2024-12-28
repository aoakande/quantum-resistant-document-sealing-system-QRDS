import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v1.5.4/index.ts';
import { assertEquals, assert } from 'https://deno.land/std@0.178.0/testing/asserts.ts';

// Test Constants
const documentHash = '0x0102030405060708091011121314151617181920212223242526272829303132';
const merkleRoot = '0x0102030405060708091011121314151617181920212223242526272829303132';
const signature = '0x01020304050607080910111213141516171819202122232425262728293031320102030405060708091011121314151617181920212223242526272829303132';
const publicKey = '0x0102030405060708091011121314151617181920212223242526272829303132';
const merklePath = [merkleRoot];

Clarinet.test({
    name: "Should seal a new document successfully",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get("deployer")!;

        const block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "seal-document", [
                types.buff32(documentHash),
                types.ascii("Test Document"),
                types.ascii("Test Description"),
                types.ascii("Test"),
                types.buff512(signature),
                types.buff32(merkleRoot),
                types.buff256(publicKey),
                types.list(merklePath.map(m => types.buff32(m)))
            ], deployer.address)
        ]);

        // Assert successful response
        assertEquals(block.receipts.length, 1);
        assertEquals(block.height, 2);
        assertEquals(block.receipts[0].result.expectOk(), "u1");
    },
});

Clarinet.test({
    name: "Should not allow duplicate document sealing",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get("deployer")!;

        let block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "seal-document", [
                types.buff32(documentHash),
                types.ascii("Test Document"),
                types.ascii("Test Description"),
                types.ascii("Test"),
                types.buff512(signature),
                types.buff32(merkleRoot),
                types.buff256(publicKey),
                types.list(merklePath.map(m => types.buff32(m)))
            ], deployer.address)
        ]);

        // First sealing should succeed
        assertEquals(block.receipts[0].result.expectOk(), "u1");

        // Attempt to seal same document again
        block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "seal-document", [
                types.buff32(documentHash),
                types.ascii("Test Document"),
                types.ascii("Test Description"),
                types.ascii("Test"),
                types.buff512(signature),
                types.buff32(merkleRoot),
                types.buff256(publicKey),
                types.list(merklePath.map(m => types.buff32(m)))
            ], deployer.address)
        ]);

        // Should fail with ERR-ALREADY-EXISTS
        block.receipts[0].result.expectErr().expectUint(402);
    },
});

Clarinet.test({
    name: "Should update document status correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get("deployer")!;

        // First seal a document
        let block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "seal-document", [
                types.buff32(documentHash),
                types.ascii("Test Document"),
                types.ascii("Test Description"),
                types.ascii("Test"),
                types.buff512(signature),
                types.buff32(merkleRoot),
                types.buff256(publicKey),
                types.list(merklePath.map(m => types.buff32(m)))
            ], deployer.address)
        ]);

        // Update status to revoked
        block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "update-document-status", [
                types.uint(1),
                types.ascii("revoked")
            ], deployer.address)
        ]);

        // Check status update succeeded
        assertEquals(block.receipts[0].result.expectOk(), true);

        // Verify new status
        const getDoc = chain.callReadOnlyFn(
            "quantum-seal",
            "get-document",
            [types.uint(1)],
            deployer.address
        );

        const docData = getDoc.result.expectSome().expectTuple();
        assertEquals(docData.status, "revoked");
    },
});

Clarinet.test({
    name: "Should handle invalid status updates correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get("deployer")!;

        // First seal a document
        let block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "seal-document", [
                types.buff32(documentHash),
                types.ascii("Test Document"),
                types.ascii("Test Description"),
                types.ascii("Test"),
                types.buff512(signature),
                types.buff32(merkleRoot),
                types.buff256(publicKey),
                types.list(merklePath.map(m => types.buff32(m)))
            ], deployer.address)
        ]);

        // Attempt invalid status update
        block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "update-document-status", [
                types.uint(1),
                types.ascii("invalid")
            ], deployer.address)
        ]);

        // Should fail with ERR-INVALID-STATUS
        block.receipts[0].result.expectErr().expectUint(406);
    },
});

Clarinet.test({
    name: "Should verify signatures correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get("deployer")!;

        // First seal a document
        let block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "seal-document", [
                types.buff32(documentHash),
                types.ascii("Test Document"),
                types.ascii("Test Description"),
                types.ascii("Test"),
                types.buff512(signature),
                types.buff32(merkleRoot),
                types.buff256(publicKey),
                types.list(merklePath.map(m => types.buff32(m)))
            ], deployer.address)
        ]);

        // Verify correct signature
        const verifyCorrect = chain.callReadOnlyFn(
            "quantum-seal",
            "verify-signature",
            [types.uint(1), types.buff512(signature)],
            deployer.address
        );

        // Should return true for correct signature
        assertEquals(verifyCorrect.result.expectOk(), true);

        // Verify incorrect signature
        const wrongSignature = '0x' + '00'.repeat(512);
        const verifyWrong = chain.callReadOnlyFn(
            "quantum-seal",
            "verify-signature",
            [types.uint(1), types.buff512(wrongSignature)],
            deployer.address
        );

        // Should return false for incorrect signature
        assertEquals(verifyWrong.result.expectOk(), false);
    },
});

Clarinet.test({
    name: "Should process document batches correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get("deployer")!;

        const batchDocuments = [
            {
                hash: documentHash,
                title: "Batch Doc 1",
                description: "Batch Description 1",
                category: "Test",
                signature: signature,
                merkleRoot: merkleRoot,
                publicKey: publicKey,
                merklePath: merklePath
            },
            {
                hash: documentHash,
                title: "Batch Doc 2",
                description: "Batch Description 2",
                category: "Test",
                signature: signature,
                merkleRoot: merkleRoot,
                publicKey: publicKey,
                merklePath: merklePath
            }
        ];

        const block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "seal-document-batch", [
                types.list(batchDocuments.map(doc => ({
                    hash: types.buff32(doc.hash),
                    title: types.ascii(doc.title),
                    description: types.ascii(doc.description),
                    category: types.ascii(doc.category),
                    signature: types.buff512(doc.signature),
                    merkleRoot: types.buff32(doc.merkleRoot),
                    publicKey: types.buff256(doc.publicKey),
                    merklePath: types.list(doc.merklePath.map(m => types.buff32(m)))
                })))
            ], deployer.address)
        ]);

        // Verify batch sealing succeeded
        assertEquals(block.receipts[0].result.expectOk(), "u1");

        // Verify batch record exists
        const getBatch = chain.callReadOnlyFn(
            "quantum-seal",
            "get-batch",
            [types.uint(1)],
            deployer.address
        );

        const batchData = getBatch.result.expectSome().expectTuple();
        assertEquals(batchData.status, "sealed");
    },
});

Clarinet.test({
    name: "Should enforce ownership correctly",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get("deployer")!;
        const wallet1 = accounts.get("wallet_1")!;

        // Seal document as deployer
        let block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "seal-document", [
                types.buff32(documentHash),
                types.ascii("Test Document"),
                types.ascii("Test Description"),
                types.ascii("Test"),
                types.buff512(signature),
                types.buff32(merkleRoot),
                types.buff256(publicKey),
                types.list(merklePath.map(m => types.buff32(m)))
            ], deployer.address)
        ]);

        // Attempt status update as non-owner
        block = chain.mineBlock([
            Tx.contractCall("quantum-seal", "update-document-status", [
                types.uint(1),
                types.ascii("revoked")
            ], wallet1.address)
        ]);

        // Should fail with ERR-NOT-AUTHORIZED
        block.receipts[0].result.expectErr().expectUint(401);
    },
});
