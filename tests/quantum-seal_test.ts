import { describe, it, expect } from "vitest";
import { Cl } from "@stacks/transactions";

describe("quantum-seal", () => {
  // Get test accounts
  const accounts = simnet.getAccounts();
  const deployer = accounts.get("deployer")!;

  // Create 32-byte test values
  const testHash = "0".repeat(64);          // 32 bytes for hash
  const testSignature = "0".repeat(1024);   // 512 bytes for signature
  const testPublicKey = "0".repeat(512);    // 256 bytes for public key
  const testMerkleRoot = "0".repeat(64);    // 32 bytes for merkle root

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

    expect(block.result).toBeOk(Cl.uint(1));
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

    // Update status
    block = simnet.callPublicFn(
      "quantum-seal",
      "update-document-status",
      [Cl.uint(1), Cl.ascii("revoked")],
      deployer
    );

    expect(block.result).toBeOk(Cl.bool(true));

    // Verify status
    const docData = simnet.getDataVar("quantum-seal", "document-records", { id: 1 });
    const status = docData?.status;
    expect(status).toBe("revoked");
  });
});
