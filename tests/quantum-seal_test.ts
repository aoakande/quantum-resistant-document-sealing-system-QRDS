import { describe, it, expect } from "vitest";
import { Cl } from "@stacks/transactions";

describe("quantum-seal", () => {
  // Get test accounts
  const accounts = simnet.getAccounts();
  const deployer = accounts.get("deployer")!;
  const wallet1 = accounts.get("wallet_1")!;

  // Helper function to create exact-size buffers
  function createBuffer(size: number): string {
    return Array(size * 2).fill('0').join('');  // Each byte needs 2 hex chars
  }

  // Create properly sized test data
  const testHash = createBuffer(32);       // 32 bytes
  const testSignature = createBuffer(512); // 512 bytes
  const testPublicKey = createBuffer(256); // 256 bytes
  const testMerkleRoot = createBuffer(32); // 32 bytes

  it("successfully seals a document", () => {
    const block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testHash),
        Cl.ascii("Test Document"),
        Cl.ascii("Test Description"),
        Cl.ascii("Test"),
        Cl.buff(testSignature),
        Cl.buff(testMerkleRoot),
        Cl.buff(testPublicKey),
        Cl.list([Cl.buff(testMerkleRoot)])
      ],
      deployer
    );

    // Check the result
    expect(block.result).toBeOk(Cl.uint(1));

    // Verify document was stored correctly
    const docResponse = simnet.callReadOnlyFn(
      "quantum-seal",
      "get-document",
      [Cl.uint(1)],
      deployer
    );

    const doc = docResponse.result.expectSome().expectTuple();
    expect(doc.hash).toBe(testHash);
    expect(doc.status).toBe("active");
  });

  it("prevents duplicate document sealing", () => {
    // First sealing
    let block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testHash),
        Cl.ascii("Test Document"),
        Cl.ascii("Test Description"),
        Cl.ascii("Test"),
        Cl.buff(testSignature),
        Cl.buff(testMerkleRoot),
        Cl.buff(testPublicKey),
        Cl.list([Cl.buff(testMerkleRoot)])
      ],
      deployer
    );

    expect(block.result).toBeOk(Cl.uint(1));

    // Try to seal same document again
    block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testHash),
        Cl.ascii("Test Document"),
        Cl.ascii("Test Description"),
        Cl.ascii("Test"),
        Cl.buff(testSignature),
        Cl.buff(testMerkleRoot),
        Cl.buff(testPublicKey),
        Cl.list([Cl.buff(testMerkleRoot)])
      ],
      deployer
    );

    expect(block.result).toBeErr(Cl.uint(402));
  });

  it("correctly updates document status", () => {
    // First seal a document
    let block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testHash),
        Cl.ascii("Test Document"),
        Cl.ascii("Test Description"),
        Cl.ascii("Test"),
        Cl.buff(testSignature),
        Cl.buff(testMerkleRoot),
        Cl.buff(testPublicKey),
        Cl.list([Cl.buff(testMerkleRoot)])
      ],
      deployer
    );

    expect(block.result).toBeOk(Cl.uint(1));

    // Update status
    block = simnet.callPublicFn(
      "quantum-seal",
      "update-document-status",
      [Cl.uint(1), Cl.ascii("revoked")],
      deployer
    );

    expect(block.result).toBeOk(Cl.bool(true));

    // Verify status using read-only function
    const docResponse = simnet.callReadOnlyFn(
      "quantum-seal",
      "get-document",
      [Cl.uint(1)],
      deployer
    );

    const doc = docResponse.result.expectSome().expectTuple();
    expect(doc.status).toBe("revoked");
  });

  it("enforces owner-only status updates", () => {
    // First seal a document as deployer
    let block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testHash),
        Cl.ascii("Test Document"),
        Cl.ascii("Test Description"),
        Cl.ascii("Test"),
        Cl.buff(testSignature),
        Cl.buff(testMerkleRoot),
        Cl.buff(testPublicKey),
        Cl.list([Cl.buff(testMerkleRoot)])
      ],
      deployer
    );

    expect(block.result).toBeOk(Cl.uint(1));

    // Try to update status as different user
    block = simnet.callPublicFn(
      "quantum-seal",
      "update-document-status",
      [Cl.uint(1), Cl.ascii("revoked")],
      wallet1
    );

    expect(block.result).toBeErr(Cl.uint(401)); // ERR-NOT-AUTHORIZED
  });

  it("verifies signatures correctly", () => {
    // First seal a document
    let block = simnet.callPublicFn(
      "quantum-seal",
      "seal-document",
      [
        Cl.buff(testHash),
        Cl.ascii("Test Document"),
        Cl.ascii("Test Description"),
        Cl.ascii("Test"),
        Cl.buff(testSignature),
        Cl.buff(testMerkleRoot),
        Cl.buff(testPublicKey),
        Cl.list([Cl.buff(testMerkleRoot)])
      ],
      deployer
    );

    expect(block.result).toBeOk(Cl.uint(1));

    // Verify with correct signature
    const verifyCorrect = simnet.callReadOnlyFn(
      "quantum-seal",
      "verify-signature",
      [Cl.uint(1), Cl.buff(testSignature)],
      deployer
    );

    expect(verifyCorrect.result).toBeOk(Cl.bool(true));

    // Verify with incorrect signature
    const wrongSignature = createBuffer(512);  // Different 512-byte signature
    const verifyWrong = simnet.callReadOnlyFn(
      "quantum-seal",
      "verify-signature",
      [Cl.uint(1), Cl.buff(wrongSignature)],
      deployer
    );

    expect(verifyWrong.result).toBeOk(Cl.bool(false));
  });
});
