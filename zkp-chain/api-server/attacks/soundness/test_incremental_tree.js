// test_incremental_tree.js — the chaincode's incremental voter-tree root must
// equal a full rebuild (and the client's tree) after every registration,
// including the lazy migration from a pre-existing commitment list.
const path = require("path");
const h = require("./harness");

(async () => {
  const contract = h.loadContract();
  const { ctx, state } = h.makeLedger();
  let failures = 0;
  const leaves = [];
  for (let i = 0; i < 37; i++) {
    const c = h.fieldStr(BigInt(i * 7919 + 1) * 1000003n);
    leaves.push(c);
    await h.quiet(() => contract.register(ctx, `nid-${i}`, c));
    const inc = (await contract._treeState(ctx, "face")).root;
    const full = (await contract.buildMerkleTreeOnChain(leaves)).toString();
    const client = (await h.buildTree(leaves)).root.toString();
    if (inc !== full || inc !== client) { failures++; console.log(`FAIL after ${i + 1} leaves`); }
  }
  // Lazy migration: drop the tree state, keep the list, rebuild on demand
  state.delete("MERKLE_FACE");
  const migrated = (await contract._treeState(ctx, "face")).root;
  if (migrated !== (await contract.buildMerkleTreeOnChain(leaves)).toString()) { failures++; console.log("FAIL migration"); }
  // ...and keep appending after migration
  leaves.push("424242");
  await h.quiet(() => contract.register(ctx, "nid-x", "424242"));
  if ((await contract._treeState(ctx, "face")).root !== (await contract.buildMerkleTreeOnChain(leaves)).toString()) {
    failures++; console.log("FAIL append after migration");
  }
  console.log(failures ? `${failures} failure(s)` : "PASS incremental root == full rebuild == client tree (38 leaves + migration)");
  process.exit(failures ? 1 : 0);
})();
