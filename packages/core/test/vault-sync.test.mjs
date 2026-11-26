import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createVaultSeed,
  syncInceptionFromNode,
  unlockIdentity,
} from "../dist/vault.js";

test("on-chain-only sync uses the confirmed KEL tip for payout", async () => {
  const mnemonic = createVaultSeed(128);
  const secondFactor = "test-sf";
  const username = "alice";
  const k0 = unlockIdentity(mnemonic, secondFactor, username, { mainDepth: 0 });
  const k1 = unlockIdentity(mnemonic, secondFactor, username, { mainDepth: 1 });
  const k2 = unlockIdentity(mnemonic, secondFactor, username, { mainDepth: 2 });
  const k3 = unlockIdentity(mnemonic, secondFactor, username, { mainDepth: 3 });

  const urls = [];
  const fetch = async (input) => {
    const url = String(input);
    urls.push(url);
    if (url.includes("/identity-inception-status")) {
      return new Response(
        JSON.stringify({
          status: true,
          incepted: true,
          has_kel: true,
          kel_depth: 3,
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    if (url.includes("/key-event-log")) {
      return new Response(
        JSON.stringify({
          status: true,
          key_event_log: [
            {
              counter: 0,
              prev_public_key_hash: "",
              public_key_hash: k0.k0.address,
              prerotated_key_hash: k1.tipSigner.address,
            },
            {
              counter: 1,
              prev_public_key_hash: k0.k0.address,
              public_key_hash: k1.tipSigner.address,
              prerotated_key_hash: k2.tipSigner.address,
            },
            {
              counter: 2,
              prev_public_key_hash: k1.tipSigner.address,
              public_key_hash: k2.tipSigner.address,
              prerotated_key_hash: k3.tipSigner.address,
              mempool: true,
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    return new Response("{}", { status: 404 });
  };

  const synced = await syncInceptionFromNode(
    { baseUrl: "https://node.example", fetch },
    k0,
    { onchainOnly: true }
  );

  assert.equal(synced.aligned, true);
  assert.equal(synced.identity.mainDepth, 2);
  assert.equal(synced.identity.tipSigner.address, k2.tipSigner.address);
  assert.notEqual(synced.identity.tipSigner.address, k3.tipSigner.address);
  assert.ok(urls.length >= 2);
  for (const url of urls) assert.match(url, /onchain_only=1/);
});
