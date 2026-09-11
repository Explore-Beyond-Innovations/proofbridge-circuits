// Generates real fixtures for the deposit circuit using the proofbridge_mmr SDK: one tree holding
// leaves of every domain (leaf i has domain i % 5), and a Prover file per domain claiming a real leaf.
// Prover.toml = domain 1 (ad-side deposit); Prover_d{0,2,3,4}.toml the rest; plus an untagged-root sidecar. Run via the SDK's ts-node
// (see test-sdk-e2e.sh / adversarial-tests.sh). Imports the SDK by relative path so it needs no
// node_modules of its own.
import {
  DOMAIN_TAG,
  MemoryStore,
  MerkleMountainRange,
  Poseidon2Hasher,
  encodeLeaf,
} from "../../../packages/proofbridge_mmr/src";
import * as fs from "fs";
import * as path from "path";

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const toBuf = (x: bigint) => Buffer.from(x.toString(16).padStart(64, "0"), "hex");
const bufToBig = (b: Buffer) => BigInt("0x" + b.toString("hex"));
const fieldMod = (x: bigint) => ((x % P) + P) % P;
const DOMAIN = bufToBig(DOMAIN_TAG);
const CIRCUIT = path.join(__dirname, "..", "..", "deposits");

async function main() {
  const hasher = new Poseidon2Hasher();
  const mmr = new MerkleMountainRange("fixture", new MemoryStore(), hasher);
  await mmr.init();

  // each leaf payload = poseidon2(orderHash, domain) via the SDK's encodeLeaf; numeric domains so this
  // runs against any published SDK
  const orderFields: bigint[] = [];
  for (let i = 1; i <= 10; i++) {
    const oh = fieldMod(BigInt(i) * 0x9e3779b97f4a7c15n + 0x1234567n); // distinct test order hash
    orderFields.push(oh);
    await mmr.append(encodeLeaf(oh, i % 5, hasher));
  }

  const secret = fieldMod(0xa11ce5ec2e7000feedface1234567890abcdef00n);
  const sHex = secret.toString(16).padStart(64, "0");
  const a = BigInt("0x" + sHex.slice(0, 32) + "00".repeat(16));
  const b = BigInt("0x" + "00".repeat(16) + sHex.slice(32));

  const pad = (arr: string[], n: number, fill = "0x0") =>
    arr.concat(Array(n - arr.length).fill(fill)).slice(0, n);
  const padB = (arr: boolean[], n: number) =>
    arr.concat(Array(n - arr.length).fill(false)).slice(0, n);
  const padN = (arr: number[], n: number) =>
    arr.concat(Array(n - arr.length).fill(0)).slice(0, n);

  let untagged = "";
  for (let domain = 0; domain < 5; domain++) {
    // leaves 5,6,2,3,4 carry domains 0,1,2,3,4: all in the first mountain (chosen_peak 0)
    const leaf = [5, 6, 2, 3, 4][domain];
    const proof = await mmr.getMerkleProof(mmr.getLeafIndex(leaf));
    const orderHash = orderFields[leaf - 1];

    // recompute the root to sanity-check parity and to derive the untagged sidecar
    const size = BigInt(proof.elementsCount);
    let acc: Buffer = toBuf(BigInt(proof.peaks[0]));
    for (const pk of proof.peaks.slice(1)) acc = hasher.hash([acc, toBuf(BigInt(pk))]) as Buffer;
    const taggedRoot =
      "0x" + bufToBig(hasher.hash([toBuf(DOMAIN), toBuf(size), acc])).toString(16).padStart(64, "0");
    if (taggedRoot !== proof.root) throw new Error(`root parity: ${taggedRoot} != ${proof.root}`);
    untagged = "0x" + bufToBig(hasher.hash([toBuf(size), acc])).toString(16).padStart(64, "0");

    // ad side: H(a, orderHash); order side: H(orderHash, b); events: none
    const nullifier =
      domain === 1 ? bufToBig(hasher.hash([toBuf(a), toBuf(orderHash)]))
      : domain === 0 ? bufToBig(hasher.hash([toBuf(orderHash), toBuf(b)]))
      : 0n;

    const toml = `
nullifier_hash = "0x${nullifier.toString(16)}"
order_hash = "0x${orderHash.toString(16)}"
target_root = "${taggedRoot}"
leaf_domain = "${domain}"
width = "${proof.width}"
secret = "0x${secret.toString(16)}"
leaf_index = "${proof.elementIndex}"
path_len = "${proof.siblings.length}"
siblings = [${pad(proof.siblings, 32).map((s) => `"${s}"`).join(", ")}]
sib_is_left = [${padB(proof.directions, 32).map(String).join(", ")}]
parent_index = [${padN(proof.parentIndices, 32).map((x) => `"${x}"`).join(", ")}]
peaks = [${pad(proof.peaks, 32).map((s) => `"${s}"`).join(", ")}]
peaks_len = "${proof.peaks.length}"
chosen_peak = "${proof.chosenPeak}"
`.trim();
    fs.writeFileSync(path.join(CIRCUIT, domain === 1 ? "Prover.toml" : `Prover_d${domain}.toml`), toml + "\n");
  }
  fs.writeFileSync(path.join(CIRCUIT, "untagged_root.txt"), untagged + "\n");
  console.log("wrote Prover.toml (domain 1) + Prover_d{0,2,3,4}.toml");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
