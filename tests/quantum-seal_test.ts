import { describe, it, expect } from "vitest";
import { Cl } from "@stacks/transactions";

describe("quantum-seal", () => {
  const accounts = simnet.getAccounts();
  const deployer = accounts.get("deployer")!;
  const wallet1 = accounts.get("wallet_1")!;

  // Helper to create properly sized buffers
  const createBuffer = (size: number) => "00".repeat(size);

  // Test data with correct sizes
  const testDoc = {
    hash: createBuffer(32),          // 32 bytes
    signature: createBuffer(512),    // 512 bytes
    merkleRoot: createBuffer(32),    // 32 bytes
    publicKey: createBuffer(256),    // 256 bytes
    title: "Test Document",
    description: "Test Description",
    category: "Test"
  };

  // Core sealing functionality
  it("seals a new document", () => {
    const block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testDoc.hash),
        Cl.ascii(testDoc.title),
        Cl.ascii(testDoc.description),
        Cl.ascii(testDoc.category),
        Cl.buff(testDoc.signature),
        Cl.buff(testDoc.merkleRoot),
        Cl.buff(testDoc.publicKey),
        Cl.list([Cl.buff(testDoc.merkleRoot)])
      ],
      deployer
    );

    block.result.expectOk().expectUint(1);
  });

  // Document status management
  it("allows owner to update document status", () => {
    // First seal a document
    let block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testDoc.hash),
        Cl.ascii(testDoc.title),
        Cl.ascii(testDoc.description),
        Cl.ascii(testDoc.category),
        Cl.buff(testDoc.signature),
        Cl.buff(testDoc.merkleRoot),
        Cl.buff(testDoc.publicKey),
        Cl.list([Cl.buff(testDoc.merkleRoot)])
      ],
      deployer
    );

    // Then update its status
    block = simnet.callPublicFn(
      "quantum-seal",
      "update-document-status",
      [Cl.uint(1), Cl.ascii("revoked")],
      deployer
    );

    block.result.expectOk().expectBool(true);
  });

  // Access control
  it("prevents non-owners from updating status", () => {
    // First seal a document as deployer
    let block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testDoc.hash),
        Cl.ascii(testDoc.title),
        Cl.ascii(testDoc.description),
        Cl.ascii(testDoc.category),
        Cl.buff(testDoc.signature),
        Cl.buff(testDoc.merkleRoot),
        Cl.buff(testDoc.publicKey),
        Cl.list([Cl.buff(testDoc.merkleRoot)])
      ],
      deployer
    );

    // Try to update as different user
    block = simnet.callPublicFn(
      "quantum-seal",
      "update-document-status",
      [Cl.uint(1), Cl.ascii("revoked")],
      wallet1
    );

    block.result.expectErr().expectUint(401); // ERR-NOT-AUTHORIZED
  });

  // Signature verification
  it("verifies valid signatures", () => {
    // First seal a document
    let block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testDoc.hash),
        Cl.ascii(testDoc.title),
        Cl.ascii(testDoc.description),
        Cl.ascii(testDoc.category),
        Cl.buff(testDoc.signature),
        Cl.buff(testDoc.merkleRoot),
        Cl.buff(testDoc.publicKey),
        Cl.list([Cl.buff(testDoc.merkleRoot)])
      ],
      deployer
    );

    // Verify with correct signature
    const verify = simnet.callReadOnlyFn(
      "quantum-seal",
      "verify-signature",
      [Cl.uint(1), Cl.buff(testDoc.signature)],
      deployer
    );

    verify.result.expectOk().expectBool(true);
  });

  // Document retrieval
  it("retrieves sealed document data", () => {
    // First seal a document
    let block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testDoc.hash),
        Cl.ascii(testDoc.title),
        Cl.ascii(testDoc.description),
        Cl.ascii(testDoc.category),
        Cl.buff(testDoc.signature),
        Cl.buff(testDoc.merkleRoot),
        Cl.buff(testDoc.publicKey),
        Cl.list([Cl.buff(testDoc.merkleRoot)])
      ],
      deployer
    );

    // Retrieve document
    const docResponse = simnet.callReadOnlyFn(
      "quantum-seal",
      "get-document",
      [Cl.uint(1)],
      deployer
    );

    const doc = docResponse.result.expectSome().expectTuple();
    expect(doc.status).toBe("active");
  });
});
