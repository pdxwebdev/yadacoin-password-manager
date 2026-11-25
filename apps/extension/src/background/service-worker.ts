/**
 * MV3 service worker — vault sign-in/rotate for harness pages via content script.
 * Password home SP is resolved automatically (no user Node URL).
 */
import {
  baseReceiveAddress,
  signUsdcPermit,
  baseTokenBalance,
  unwrapWyda,
  bytesToHex,
  hashPassword,
  hexToBytes,
  LEGACY_KEYS,
  materialFromPrivCc,
  nodeUrlToWebSocketUrl,
  normalizeNodeBaseUrl,
  normalizeSiteId,
  passwordAuthPresenceProof,
  postAuthSessionResult,
  registerSite,
  resyncSiteFromNode,
  resyncVaultFromNode,
  resolvePasswordHome,
  rotateSitePassword,
  sealToRatchetPub,
  sealToX25519,
  siteForSignIn,
  syncInceptionFromNode,
  broadcastTxns,
  buildInceptionTxn,
  createVaultSeed,
  identityAfterInception,
  isAlreadyInceptedError,
  unlockIdentity,
  vaultIdFromData,
  websocketPeerIdentity,
  VaultStore,
  type PasswordAuthRequestPayload,
  type SiteRegistration,
  type StoredSite,
  type StoredVault,
  type VaultIdentity,
} from "@yadacoin/password-core";
import { createExtensionVaultBackend } from "../shared/vault-backend.js";
import { announceFile } from "../shared/announce.js";
import { rememberHome, resolveHomeApiBase } from "../shared/home.js";

const store = new VaultStore(createExtensionVaultBackend());
let migrated = false;

async function ensureMigrated(): Promise<void> {
  if (migrated) return;
  await store.migrateLegacy(LEGACY_KEYS.extension);
  migrated = true;
}

function storeSite(site: SiteRegistration): StoredSite {
  return {
    siteId: site.siteId,
    branchPeer: site.branchPeer,
    counter: site.counter,
    tipPrevPkh: site.tipPrevPkh,
    branchInceptionPkh: site.branchInceptionPkh,
    tipPriv: bytesToHex(site.tip.privateKey),
    tipCc: bytesToHex(site.tip.chainCode),
    currentPassword: site.currentPassword,
    nextPassword: site.nextPassword,
    kp0Priv: bytesToHex(site.kp0.privateKey),
    kp0Cc: bytesToHex(site.kp0.chainCode),
  };
}

function siteFromStored(s: StoredSite): SiteRegistration {
  return {
    siteId: s.siteId,
    branchPeer: s.branchPeer,
    kp0: materialFromPrivCc(hexToBytes(s.kp0Priv), hexToBytes(s.kp0Cc)),
    tip: materialFromPrivCc(hexToBytes(s.tipPriv), hexToBytes(s.tipCc)),
    counter: s.counter,
    tipPrevPkh: s.tipPrevPkh,
    currentPassword: s.currentPassword,
    nextPassword: s.nextPassword,
    branchInceptionPkh: s.branchInceptionPkh,
  };
}

async function loadVault(): Promise<StoredVault | null> {
  await ensureMigrated();
  const entry = await store.getActiveVault();
  return entry?.data ?? null;
}

async function saveVault(v: StoredVault): Promise<void> {
  await ensureMigrated();
  const id = vaultIdFromData(v);
  await store.updateVaultData(id, v);
  await store.setActiveVaultId(id);
}

/** Home SP API base for this vault + page origin. */
async function apiBase(pageOrigin?: string): Promise<string> {
  const v = await loadVault();
  return resolveHomeApiBase({
    username: v?.username || "",
    pageOrigin,
    cachedHome: v?.nodeUrl && pageOrigin && v.nodeUrl.replace(/\/+$/, "").toLowerCase() === pageOrigin.replace(/\/+$/, "").toLowerCase()
      ? undefined
      : v?.nodeUrl,
    requestPermission: false,
  });
}

/**
 * Soft-refresh inception fields from the home SP. Never blocks register/sign-in.
 */
async function refreshInception(
  v: StoredVault,
  baseUrl: string
): Promise<StoredVault> {
  const base = normalizeNodeBaseUrl(baseUrl);
  if (!base) return v;

  let next: StoredVault = v.nodeUrl === base ? v : { ...v, nodeUrl: base };

  try {
    const identity: VaultIdentity = unlockIdentity(
      v.mnemonic,
      v.secondFactor,
      v.username,
      {
        identityType: v.identityType,
        mainDepth: v.mainDepth,
        tipPrevPkh: v.tipPrevPkh,
      }
    );
    const synced = await syncInceptionFromNode({ baseUrl: base }, identity);
    if (synced.inceptionDone) {
      next = {
        ...next,
        inceptionDone: true,
        mainDepth: synced.identity.mainDepth,
        tipPrevPkh: synced.identity.tipPrevPkh,
      };
    }
  } catch {
    /* proceed — register/sign-in will surface real node errors */
  }

  if (
    next.inceptionDone !== v.inceptionDone ||
    next.mainDepth !== v.mainDepth ||
    next.tipPrevPkh !== v.tipPrevPkh ||
    next.nodeUrl !== v.nodeUrl
  ) {
    await saveVault(next);
  }
  return next;
}

/**
 * Broadcast inception for a stored vault if it is not on the home SP yet.
 * Resolves home, refreshes from the node, and broadcasts the inception txn.
 * The signed txn is also sent to the return-node origin (where the user will
 * sign in) so that node's mempool sees the identity without waiting for
 * block propagation. Returns the (possibly updated) vault plus a
 * human-readable error when no node accepted the broadcast.
 */
async function broadcastInceptionFor(
  v: StoredVault,
  pageOrigin?: string,
  returnUrl?: string
): Promise<{ vault: StoredVault; error: string }> {
  try {
    const base = await resolveHomeApiBase({
      username: v.username,
      pageOrigin,
      cachedHome: v.nodeUrl,
      requestPermission: false,
    });
    if (!base) return { vault: v, error: "could not resolve password home SP" };
    let next = await refreshInception(v, base);
    if (next.inceptionDone) return { vault: next, error: "" };
    const identity = unlockIdentity(next.mnemonic, next.secondFactor, next.username, {
      identityType: next.identityType,
      mainDepth: next.mainDepth,
      tipPrevPkh: next.tipPrevPkh,
    });
    const txn = buildInceptionTxn(identity);
    let inceptionHome = "";
    try {
      const route = await resolvePasswordHome(
        base,
        v.username,
        identity.usernameSignature
      );
      inceptionHome = normalizeNodeBaseUrl(route?.node_http_base || "");
    } catch {
      /* home not resolvable yet */
    }
    const targets: string[] = [];
    const addTarget = (raw?: string) => {
      const originBase = normalizeNodeBaseUrl(raw || "");
      if (!originBase || !/^https?:\/\//i.test(originBase)) return;
      if (!targets.some((t) => sameNode(t, originBase))) targets.push(originBase);
    };
    addTarget(PURCHASE_HOME);
    addTarget(inceptionHome);
    addTarget(base);
    addTarget(returnUrl);
    const results = await Promise.all(
      targets.map(async (target) => {
        try {
          const res = await broadcastTxns({ baseUrl: target }, txn);
          return { target, res, error: "" };
        } catch (e) {
          return { target, res: null, error: e instanceof Error ? e.message : String(e) };
        }
      })
    );
    const accepted = results.find(
      (r) => r.res && (r.res.ok || isAlreadyInceptedError(r.res.body?.message))
    );
    if (accepted) {
      // The pre-inception home pick often falls back to the page/return node
      // because the identity is not announced yet. Once the inception lands,
      // resolve again and push the same txn to the real home SP so it has the
      // identity before the browser/page starts an auth session there.
      let finalHome = "";
      const resolveFrom = accepted.target || base;
      for (let i = 0; i < 6; i += 1) {
        try {
          const route = await resolvePasswordHome(resolveFrom, v.username);
          const candidate = normalizeNodeBaseUrl(route?.node_http_base || "");
          if (route?.status && candidate) {
            finalHome = candidate;
            break;
          }
        } catch {
          /* announcement not visible yet */
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      if (finalHome && !targets.some((t) => sameNode(t, finalHome))) {
        try {
          await broadcastTxns({ baseUrl: finalHome }, txn);
        } catch {
          /* already incepted or home unreachable */
        }
      }
      const homeBase = finalHome || inceptionHome || base;
      const after = identityAfterInception(identity);
      next = {
        ...next,
        nodeUrl: homeBase,
        mainDepth: after.mainDepth,
        tipPrevPkh: after.tipPrevPkh,
        inceptionDone: true,
      };
      await saveVault(next);
      return { vault: next, error: "" };
    }
    next = { ...next, nodeUrl: base };
    await saveVault(next);
    const failed = results.find((r) => r.res) || results.find((r) => r.error);
    const message = failed?.res
      ? String(
          failed.res.body?.message ||
            failed.res.body?.error?.message ||
            `inception failed (${failed.res.status})`
        )
      : failed?.error || "inception broadcast failed";
    return { vault: next, error: message };
  } catch (e) {
    return { vault: v, error: e instanceof Error ? e.message : String(e) };
  }
}

const EXT_VERSION = "0.1.41";
/** Purchases run through Center Identity, so it must see the inception too. */
const PURCHASE_HOME = "https://centeridentity.com";

function sameNode(a: string, b: string): boolean {
  return a.replace(/\/+$/, "").toLowerCase() === b.replace(/\/+$/, "").toLowerCase();
}

let siaWait: Promise<void> | null = null;

type UploadJob = {
  requestId: string;
  appKey: string;
  fileB64: string;
  mime: string;
  thumbB64: string;
};

let uploadJob: UploadJob | null = null;
let uploadDone: ((value: Record<string, unknown>) => void) | null = null;
let uploadSender: chrome.runtime.MessageSender | null = null;

function takeUploadJob(): UploadJob | null {
  const job = uploadJob;
  uploadJob = null;
  return job;
}

function finishUploadJob(result: Record<string, unknown>): void {
  const done = uploadDone;
  uploadDone = null;
  done?.(result);
}

async function uploadInPage(
  sender: chrome.runtime.MessageSender,
  requestId: string,
  job: UploadJob
): Promise<Record<string, unknown>> {
  uploadJob = job;
  uploadSender = sender;
  const result = new Promise<Record<string, unknown>>((resolve, reject) => {
    const timer = setTimeout(() => {
      uploadJob = null;
      uploadDone = null;
      reject(new Error("Sia upload timed out"));
    }, 20 * 60 * 1000);
    uploadDone = (value) => {
      clearTimeout(timer);
      if (value.ok === false) reject(new Error(String(value.message || "upload failed")));
      else resolve(value);
    };
  });
  reportProgress(sender, requestId, "Uploading to Sia");
  await chrome.windows.create({
    url: chrome.runtime.getURL("upload.html"),
    type: "popup",
    width: 420,
    height: 220,
    focused: true,
  });
  return result;
}

async function storeFromPage(
  message: Record<string, unknown>,
  sender: chrome.runtime.MessageSender
): Promise<Record<string, unknown>> {
  const requestId = String(message.requestId || "");
  const origin = String(message.origin || "").toLowerCase();
  if (!requestId || !origin.startsWith("http")) throw new Error("invalid upload request");
  const title = String(message.title || "").trim();
  if (!title) throw new Error("title is required");
  const fileB64 = String(message.fileB64 || "");
  if (!fileB64) throw new Error("file bytes missing");
  let v = await loadVault();
  if (!v?.mnemonic) throw new Error("no vault");
  if (!v.siaAppKey) {
    await requestSiaKey();
    const next = await loadVault();
    if (!next?.siaAppKey) throw new Error("Sia app key was not saved");
    v.siaAppKey = next.siaAppKey;
  }
  const baseUrl = await apiBase(origin);
  reportProgress(sender, requestId, "Checking the key event log");
  const seeded = unlockIdentity(v.mnemonic, v.secondFactor, v.username, {
    identityType: v.identityType,
    mainDepth: v.mainDepth,
    tipPrevPkh: v.tipPrevPkh,
  });
  const synced = await syncInceptionFromNode({ baseUrl }, seeded);
  if (!synced.aligned) {
    throw new Error(synced.alignError || "Refusing to sign: key event tip is not this vault");
  }
  const uploaded = await uploadInPage(sender, requestId, {
    requestId,
    appKey: v.siaAppKey,
    fileB64,
    mime: String(message.mime || ""),
    thumbB64: String(message.thumbB64 || ""),
  });
  const thumbnail_file_id = String(uploaded.thumbnail_file_id || "");
  const thumbnail_share_url = String(uploaded.thumbnail_share_url || "");
  const file = Uint8Array.from(atob(fileB64), (c) => c.charCodeAt(0));
  if (synced.identity.tipSigner.address === synced.identity.k0.address && synced.identity.mainDepth > 1) {
    throw new Error("Refusing to sign: tip signer is still the inception key");
  }
  v = {
    ...v,
    inceptionDone: true,
    mainDepth: synced.identity.mainDepth,
    tipPrevPkh: synced.identity.tipPrevPkh,
    nodeUrl: baseUrl,
  };
  await saveVault(v);
  const txns = announceFile(synced.identity, {
    title,
    description: String(message.description || ""),
    filename: String(message.filename || ""),
    mime: String(message.mime || ""),
    size: file.length,
    type: String(message.kind || ""),
    file_id: String(uploaded.file_id || ""),
    share_url: String(uploaded.share_url || ""),
    thumbnail_file_id,
    thumbnail_share_url,
  });
  const res = await broadcastTxns({ baseUrl }, txns);
  if (!res.ok) throw new Error(res.body?.message || `announce failed (${res.status})`);
  await saveVault({ ...v, mainDepth: v.mainDepth + 2, nodeUrl: baseUrl });
  return {
    ok: true,
    file_id: uploaded.file_id,
    share_url: uploaded.share_url,
    thumbnail_file_id,
    thumbnail_share_url,
    transaction_id: txns[0]?.id || "",
    message: "announced",
  };
}

function requestSiaKey(): Promise<void> {
  if (siaWait) return siaWait;
  siaWait = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      chrome.runtime.onMessage.removeListener(onMsg);
      reject(new Error("Sia approval timed out"));
    }, 180000);
    function onMsg(msg: { type?: string; ok?: boolean; message?: string }) {
      if (!msg || msg.type !== "YADA_SIA_KEY_READY") return;
      clearTimeout(timer);
      chrome.runtime.onMessage.removeListener(onMsg);
      if (!msg.ok) reject(new Error(msg.message || "Sia connection failed"));
      else resolve(undefined);
    }
    chrome.runtime.onMessage.addListener(onMsg);
    void chrome.windows.create({
      url: chrome.runtime.getURL("sia.html"),
      type: "popup",
      width: 420,
      height: 240,
      focused: true,
    });
  }).finally(() => {
    siaWait = null;
  });
  return siaWait!;
}

let approveInFlight: string | null = null;
let approveTail: Promise<void> = Promise.resolve();

async function approveAuthRequest(
  p: PasswordAuthRequestPayload,
  pendingNodeUrl: string,
  pageOrigin: string,
  verificationCode = "",
  rpToken = ""
): Promise<{ ok: boolean; message: string; action?: string }> {
  if (!p?.session_id) return { ok: false, message: "no pending request" };
  if (approveInFlight === p.session_id) {
    return { ok: true, message: "Already approving", action: p.action };
  }
  approveInFlight = p.session_id;
  await chrome.storage.local.set({ yadaApproveBusy: p.session_id });
  try {
    const v = await loadVault();
    if (!v) throw new Error("no vault");
    const nodeUrl =
      pendingNodeUrl.replace(/\/+$/, "") ||
      (p.home_node || "").replace(/\/+$/, "") ||
      (await apiBase(pageOrigin || undefined));
    const identity: VaultIdentity = unlockIdentity(v.mnemonic, v.secondFactor, v.username, {
      identityType: v.identityType,
      mainDepth: v.mainDepth,
      tipPrevPkh: v.tipPrevPkh,
    });
    let siteKey = p.site || "";
    if (siteKey.startsWith("http://") || siteKey.startsWith("https://")) {
      siteKey = normalizeSiteId(siteKey);
    }
    const action = (p.action || "signin").toLowerCase();

    if (action === "storage") {
      const boxPub = String(p.boxPub || "").trim();
      if (!/^[0-9a-fA-F]{64}$/.test(boxPub)) {
        throw new Error("storage request has no page key");
      }
      if (!v.siaAppKey) {
        await requestSiaKey();
        const next = await loadVault();
        if (!next?.siaAppKey) throw new Error("Sia app key was not saved");
        v.siaAppKey = next.siaAppKey;
      }
      const siaBox = await sealToX25519(v.siaAppKey, boxPub);
      await postAuthSessionResult(nodeUrl, p.session_id, {
        result_token: p.result_token,
        ok: true,
        action: "storage",
        nonce: p.nonce,
        siaBox,
        message: "storage key returned",
      });
      await chrome.storage.local.remove(["yadaPendingAuth", "yadaPendingHome", "yadaApproveBusy"]);
      await chrome.action.setBadgeText({ text: "" });
      return { ok: true, message: "Storage key returned to the page", action };
    }

    if (action === "client") {
      const asked = (p.username || "").replace(/^@/, "").toLowerCase();
      const mine = (v.username || "").replace(/^@/, "").toLowerCase();
      if (asked && mine && asked !== mine) {
        throw new Error("username does not match this vault");
      }
      const address = baseReceiveAddress(v.mnemonic);
      const identityId = vaultIdFromData(v);
      const resultBody = {
        result_token: p.result_token,
        ok: true,
        action: "client",
        nonce: p.nonce,
        username: (v.username || "").replace(/^@/, ""),
        identity: identityId,
        baseAddress: address,
        message: "client identity returned",
      };
      await postAuthSessionResult(nodeUrl, p.session_id, resultBody);
      await chrome.storage.local.remove(["yadaPendingAuth", "yadaPendingHome", "yadaApproveBusy"]);
      await chrome.action.setBadgeText({ text: "" });
      return { ok: true, message: "Identity returned to the page", action };
    }

    if (action === "status") {
      await postAuthSessionResult(nodeUrl, p.session_id, {
        result_token: p.result_token,
        ok: true,
        action: "status",
        nonce: p.nonce,
        message: "status ok",
        registered: !!v.sites?.[siteKey],
        counter: v.sites?.[siteKey]?.counter ?? null,
      });
      await chrome.storage.local.remove(["yadaPendingAuth", "yadaPendingHome", "yadaApproveBusy"]);
      await chrome.action.setBadgeText({ text: "" });
      return { ok: true, message: "Status approved", action };
    }

    const rotateBase =
      action === "operator" && siteKey.startsWith("http") ? siteKey : nodeUrl;
    const siteReg = await siteForSignIn({ baseUrl: rotateBase }, identity, siteKey);
    const rotated = await rotateSitePassword(
      { baseUrl: rotateBase },
      identity,
      siteReg,
      undefined,
      { expectedHash: p.expectedHash || undefined }
    );
    v.sites[siteKey] = storeSite(rotated.site);
    await saveVault(v);
    const password = rotated.site.currentPassword;
    const counter = rotated.site.counter;
    const nextHash = hashPassword(rotated.site.nextPassword);
    const sealTo =
      action === "operator"
        ? pendingNodeUrl || (siteKey.startsWith("http") ? siteKey : nodeUrl)
        : nodeUrl;
    const pubRes = await fetch(
      sealTo.replace(/\/+$/, "") +
        "/password-rotation/ratchet-pub?username_signature=" +
        encodeURIComponent(identity.usernameSignature),
      { headers: { Accept: "application/json" } }
    );
    const pubData = await pubRes.json().catch(() => ({}));
    if (!pubRes.ok || !pubData.public_key) {
      throw new Error(
        pubData.message || "refusing to send a plaintext password — no ratchet public key"
      );
    }
    const passwordEnc = await sealToRatchetPub(
      JSON.stringify({ p: password, b: p.bind_id || "" }),
      pubData.public_key
    );
    const resultBody = {
      result_token: p.result_token,
      verification_code: verificationCode,
      // Same-browser proof: only the requesting tab received this token.
      ...(rpToken ? { rp_token: rpToken } : {}),
      ok: true,
      action: action === "operator" ? "operator" : action === "register" ? "register" : "signin",
      nonce: p.nonce,
      password_enc: passwordEnc,
      nextPasswordHash: nextHash,
      counter,
      registered: true,
      message:
        action === "operator"
          ? `operator approved · counter ${counter}`
          : `approved · counter ${counter}`,
    };
    const home = (p.home_node || "").replace(/\/+$/, "");
    const page = (pageOrigin || "").replace(/\/+$/, "");
    const ordered = [page, pendingNodeUrl, home, siteKey.startsWith("http") ? siteKey : "", nodeUrl]
      .map((b) => b.replace(/\/+$/, ""))
      .filter(Boolean)
      .filter((b, i, all) => all.findIndex((x) => sameNode(x, b)) === i);
    let posted = false;
    let firstErr = "";
    const primary = ordered[0] || nodeUrl;
    try {
      await postAuthSessionResult(primary, p.session_id, resultBody);
      posted = true;
    } catch (e) {
      firstErr = e instanceof Error ? e.message : String(e);
    }
    if (!posted) {
      for (const base of ordered.slice(1)) {
        try {
          await postAuthSessionResult(base, p.session_id, resultBody);
          posted = true;
          break;
        } catch (e) {
          firstErr = e instanceof Error ? e.message : String(e);
        }
      }
    }
    if (!posted) {
      throw new Error(firstErr || "could not deliver approval to the sign-in node");
    }
    await chrome.storage.local.remove(["yadaPendingAuth", "yadaPendingHome"]);
    await chrome.action.setBadgeText({ text: "" });
    approveTail = Promise.all(
      ordered
        .filter((b) => !sameNode(b, primary))
        .map((base) => postAuthSessionResult(base, p.session_id, resultBody).catch(() => {}))
    ).then(() => {});
    return {
      ok: true,
      action,
      message:
        action === "operator"
          ? "Operator request approved — wallet can finish unlock"
          : "Request approved",
    };
  } finally {
    await chrome.storage.local.remove("yadaApproveBusy");
  }
}

async function reportUnwrap(
  detail: { wallet_address: string; yadacoin_address: string; burn: string },
  notify = true
): Promise<void> {
  const base = await apiBase();
  await fetch(base.replace(/\/+$/, "") + "/crypto-onramp/unwrap-done", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(detail),
  }).catch(() => undefined);
  if (notify) notifyOnramp("YADA_UNWRAP_DONE", detail);
}

function notifyOnramp(type: string, detail: Record<string, string> = {}): void {
  void chrome.tabs.query({}).then((tabs) => {
    for (const tab of tabs) {
      if (tab.id == null || !tab.url || !tab.url.includes("/crypto-onramp")) continue;
      chrome.tabs.sendMessage(tab.id, { type, ...detail }, () => {
        void chrome.runtime.lastError;
      });
    }
  });
}

function reportProgress(
  sender: chrome.runtime.MessageSender,
  requestId: unknown,
  message: string
): void {
  const tabId = sender.tab && sender.tab.id;
  if (tabId == null || requestId == null || requestId === "") return;
  chrome.tabs.sendMessage(
    tabId,
    { type: "YADA_PASSWORD_PROGRESS", requestId, message },
    () => {
      void chrome.runtime.lastError;
    }
  );
}

let authWs: WebSocket | null = null;
let authWsKey = "";
let forcedAuthHome: { username: string; base: string } | null = null;
let forcedAuthHomeLoaded = false;

async function loadForcedAuthHome(): Promise<void> {
  if (forcedAuthHomeLoaded) return;
  forcedAuthHomeLoaded = true;
  try {
    const stored = await chrome.storage.local.get("yadaAuthHome");
    const row = stored.yadaAuthHome as { username?: string; home?: string } | undefined;
    const base = normalizeNodeBaseUrl(String(row?.home || ""));
    if (row?.username && base) forcedAuthHome = { username: row.username, base };
  } catch {
    /* ignore */
  }
}

async function activePageOrigin(): Promise<string> {
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const url = tabs.find((t) => t.url && /^https?:/i.test(t.url))?.url || "";
    if (!url) return "";
    return new URL(url).origin.toLowerCase();
  } catch {
    return "";
  }
}

async function connectAuthSocket(baseUrl: string): Promise<void> {
  const v = await loadVault();
  if (!v?.inceptionDone || !v.username) return;
  const base = normalizeNodeBaseUrl(baseUrl);
  if (!base) return;
  const identity = unlockIdentity(v.mnemonic, v.secondFactor, v.username, {
    identityType: v.identityType,
    mainDepth: v.mainDepth,
    tipPrevPkh: v.tipPrevPkh,
  });
  const peer = websocketPeerIdentity(identity);
  const key = `${base}|${peer.public_key}`;
  if (
    authWs &&
    authWsKey === key &&
    (authWs.readyState === WebSocket.OPEN ||
      authWs.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }
  if (authWs) {
    try {
      authWs.onclose = null;
      authWs.close();
    } catch {
      /* ignore */
    }
    authWs = null;
  }
  const wsUrl = nodeUrlToWebSocketUrl(base);
  if (!wsUrl) return;
  authWsKey = key;
  const ws = new WebSocket(wsUrl);
  authWs = ws;
  let rpcId = 1;
  const send = (method: string, params: Record<string, unknown> = {}) => {
    if (ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ id: rpcId++, jsonrpc: "2.0", method, params }));
  };
  ws.onopen = () => {
    send("connect", { identity: peer });
  };
  ws.onmessage = (ev) => {
    let msg: { method?: string; params?: PasswordAuthRequestPayload; result?: { pending?: PasswordAuthRequestPayload[] } };
    try {
      msg = JSON.parse(String(ev.data || ""));
    } catch {
      return;
    }
    if (msg.method === "connect_confirm") {
      send(
        "join_password_auth",
        passwordAuthPresenceProof(identity.username, identity.k0.privateKey)
      );
      return;
    }
    const payload = (msg.params || msg.result) as
      | PasswordAuthRequestPayload
      | { pending?: PasswordAuthRequestPayload[] }
      | undefined;
    if (msg.method === "join_password_auth_confirm") {
      const row = (payload as { pending?: PasswordAuthRequestPayload[] } | undefined)?.pending?.[0];
      if (row) {
        void chrome.storage.local.set({ yadaPendingAuth: row, yadaPendingHome: base });
        void chrome.action.setBadgeText({ text: "1" });
      }
      return;
    }
    if (msg.method === "password_auth_request" && payload && "session_id" in payload) {
      void chrome.storage.local.set({ yadaPendingAuth: payload, yadaPendingHome: base });
      void chrome.action.setBadgeText({ text: "1" });
    }
    if (msg.method === "wyda_swap_request" && payload && "session_id" in payload) {
      if ((payload as { permit_signed?: boolean }).permit_signed) return;
      void chrome.storage.local.set({ yadaPendingSwap: payload });
    }
  };
  ws.onclose = () => {
    if (authWs === ws) authWs = null;
  };
}

async function connectAuthHome(): Promise<void> {
  await loadForcedAuthHome();
  const v = await loadVault();
  if (!v?.inceptionDone || !v.username) return;
  const username = v.username.replace(/^@/, "");
  const forced =
    forcedAuthHome &&
    forcedAuthHome.username.toLowerCase() === username.toLowerCase()
      ? forcedAuthHome.base
      : "";
  let base = forced;
  if (!base) {
    const pageOrigin = await activePageOrigin();
    base = await resolveHomeApiBase({
      username: v.username,
      pageOrigin: pageOrigin || undefined,
      cachedHome:
        v.nodeUrl && pageOrigin && v.nodeUrl.replace(/\/+$/, "").toLowerCase() === pageOrigin
          ? undefined
          : v.nodeUrl,
      requestPermission: false,
    });
  }
  if (!base) return;
  await connectAuthSocket(base);
}

chrome.runtime.onInstalled.addListener(() => {
  console.info("Yada Password extension installed", EXT_VERSION);
  void ensureMigrated();
  void import("../shared/home.js").then((m) => m.refreshTopologyCache()).catch(() => {});
  chrome.alarms.create("yada-auth-home", { periodInMinutes: 1 });
  void connectAuthHome().catch(() => {});
  void pollPendingSwap().catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create("yada-auth-home", { periodInMinutes: 1 });
  void connectAuthHome().catch(() => {});
  void pollPendingSwap().catch(() => {});
});

async function pollPendingSwap(): Promise<void> {
  const v = await loadVault();
  if (!v?.mnemonic) return;
  const wallet = baseReceiveAddress(v.mnemonic);
  const username = (v.username || "").replace(/^@/, "");
  const url =
    "http://localhost:8111/crypto-onramp/pending-swap?username=" +
    encodeURIComponent(username) +
    "&wallet=" +
    encodeURIComponent(wallet);
  const res = await fetch(url);
  if (!res.ok) return;
  const data = (await res.json()) as { swaps?: { session_id?: string; source_amount?: string; wallet_address?: string; permit_signed?: boolean }[] };
  const row = (data.swaps || []).find((item) => item?.session_id && !item.permit_signed);
  if (!row?.session_id) return;
  const done = await chrome.storage.local.get("yadaFulfilledSwaps");
  const ids = Array.isArray(done.yadaFulfilledSwaps) ? done.yadaFulfilledSwaps : [];
  if (ids.includes(row.session_id)) return;
  await chrome.storage.local.set({ yadaPendingSwap: row, yadaOnrampOrigin: "http://localhost:8111" });
  await chrome.action.setBadgeText({ text: "1" });
  const open = chrome.action.openPopup;
  if (open) await open().catch(() => undefined);
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== "yada-auth-home") return;
  void connectAuthHome().catch(() => {});
  void pollPendingSwap().catch(() => {});
});
void pollPendingSwap().catch(() => {});

chrome.runtime.onConnect.addListener(() => {});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") return false;

  if (message.type === "YADA_STORE_PENDING_SWAP") {
    void chrome.storage.local.set({
      yadaPendingSwap: {
        session_id: message.session_id,
        source_amount: message.source_amount,
        wallet_address: message.wallet_address,
      },
      yadaOnrampOrigin: message.origin,
    });
    void chrome.action.setBadgeText({ text: "1" });
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === "YADA_USE_AUTH_HOME") {
    void (async () => {
      const home = normalizeNodeBaseUrl(String(message.home || ""));
      if (!home) {
        sendResponse({ ok: false, message: "invalid home node" });
        return;
      }
      try {
        const v = await loadVault();
        if (v?.username) {
          const username = v.username.replace(/^@/, "");
          forcedAuthHome = { username, base: home };
          forcedAuthHomeLoaded = true;
          rememberHome(username, home);
          await chrome.storage.local.set({ yadaAuthHome: { username, home } });
        }
        await connectAuthSocket(home);
        sendResponse({ ok: true, home });
      } catch (e) {
        sendResponse({ ok: false, message: e instanceof Error ? e.message : String(e) });
      }
    })();
    return true;
  }

  if (message.type === "YADA_REGISTER_SITE") {
    void (async () => {
      const say = (text: string) => reportProgress(sender, message.requestId, text);
      try {
        say("Resolving password home…");
        const origin = String(message.origin || "").toLowerCase();
        if (!origin.startsWith("http")) {
          sendResponse({ ok: false, message: "invalid origin" });
          return;
        }
        const baseUrl = await apiBase(origin);
        if (!baseUrl) {
          sendResponse({
            ok: false,
            extVersion: EXT_VERSION,
            message: "could not resolve password home SP",
          });
          return;
        }
        let v = await loadVault();
        if (!v) {
          sendResponse({ ok: false, message: "no vault" });
          return;
        }
        say("Syncing the key event log…");
        v = await refreshInception(v, baseUrl);
        say("Registering this origin on the node…");
        const identity: VaultIdentity = unlockIdentity(
          v.mnemonic,
          v.secondFactor,
          v.username,
          {
            identityType: v.identityType,
            mainDepth: v.mainDepth,
            tipPrevPkh: v.tipPrevPkh,
          }
        );
        const result = await registerSite({ baseUrl }, identity, origin);
        v.mainDepth = result.identity.mainDepth;
        v.tipPrevPkh = result.identity.tipPrevPkh;
        v.nodeUrl = baseUrl;
        v.sites[result.site.branchPeer] = storeSite(result.site);
        say("Saving vault…");
        await saveVault(v);
        sendResponse({
          ok: true,
          extVersion: EXT_VERSION,
          homeNode: baseUrl,
          registered: true,
          counter: result.site.counter,
          password: result.site.currentPassword,
          passwordHash: hashPassword(result.site.currentPassword),
          nextPasswordHash: hashPassword(result.site.nextPassword),
          message: `registered · counter ${result.site.counter}`,
        });
      } catch (e) {
        sendResponse({
          ok: false,
          extVersion: EXT_VERSION,
          message: e instanceof Error ? e.message : String(e),
        });
      }
    })();
    return true;
  }

  if (message.type === "YADA_SWAP_USDC") {
    void (async () => {
      try {
        const v = await loadVault();
        if (!v?.mnemonic) {
          sendResponse({ ok: false, message: "no vault" });
          return;
        }
        const permit = await signUsdcPermit(v.mnemonic, (message as { source_amount?: string }).source_amount);
        await chrome.storage.local.remove("yadaPendingSwap");
        const done = await chrome.storage.local.get("yadaFulfilledSwaps");
        const ids = Array.isArray(done.yadaFulfilledSwaps) ? done.yadaFulfilledSwaps : [];
        const sessionId = (message as { sessionId?: string }).sessionId;
        if (sessionId && !ids.includes(sessionId)) ids.push(sessionId);
        await chrome.storage.local.set({ yadaFulfilledSwaps: ids.slice(-100) });
        const identity = unlockIdentity(v.mnemonic, v.secondFactor, v.username, {
          identityType: v.identityType,
          mainDepth: v.mainDepth,
          tipPrevPkh: v.tipPrevPkh,
        });
        const saved = {
          ...permit,
          session_id: sessionId || "",
          wallet_address: permit.owner,
          yadacoin_address: identity.tipSigner.address,
          source_amount: (message as { source_amount?: string }).source_amount || "",
        };
        const storedOrigin = await chrome.storage.local.get("yadaOnrampOrigin");
        const bases = new Set([
          "http://127.0.0.1:8111",
          "http://localhost:8111",
          String(storedOrigin.yadaOnrampOrigin || "").replace(/\/+$/, ""),
          (await apiBase()).replace(/\/+$/, ""),
        ]);
        await Promise.all([...bases].filter((base) => base.startsWith("http")).map((base) =>
          fetch(base + "/crypto-onramp/pending-swap", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(saved),
          }).catch(() => undefined)
        ));
        notifyOnramp("YADA_SWAP_DONE", saved);
        sendResponse({ ok: true, ...permit, yadacoin_address: identity.tipSigner.address });
      } catch (e) {
        sendResponse({ ok: false, message: e instanceof Error ? e.message : String(e) });
      }
    })();
    return true;
  }

  if (message.type === "YADA_BASE_USDC") {
    void (async () => {
      try {
        const v = await loadVault();
        if (!v?.mnemonic) {
          sendResponse({ ok: false });
          return;
        }
        sendResponse({ ok: true, usdc: await baseTokenBalance(v.mnemonic, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") });
      } catch (e) {
        sendResponse({ ok: false, message: e instanceof Error ? e.message : String(e) });
      }
    })();
    return true;
  }

  if (message.type === "YADA_PREPARE_UNWRAP") {
    void (async () => {
      try {
        const v = await loadVault();
        if (!v?.mnemonic) {
          sendResponse({ ok: false });
          return;
        }
        const seeded = unlockIdentity(v.mnemonic, v.secondFactor, v.username, {
          identityType: v.identityType,
          mainDepth: v.mainDepth,
          tipPrevPkh: v.tipPrevPkh,
        });
        await chrome.storage.local.set({
          yadaPendingUnwrap: {
            amount: "WYDA balance",
            yadacoin_address: seeded.tipSigner.address,
            wallet_address: baseReceiveAddress(v.mnemonic),
          },
        });
        sendResponse({ ok: true });
      } catch (e) {
        sendResponse({ ok: false, message: e instanceof Error ? e.message : String(e) });
      }
    })();
    return true;
  }

  if (message.type === "YADA_UNWRAP_YDA") {
    void (async () => {
      try {
        let v = await loadVault();
        if (!v?.mnemonic) throw new Error("no vault");
        const baseUrl = await apiBase();
        const seeded = unlockIdentity(v.mnemonic, v.secondFactor, v.username, {
          identityType: v.identityType,
          mainDepth: v.mainDepth,
          tipPrevPkh: v.tipPrevPkh,
        });
        const synced = await syncInceptionFromNode({ baseUrl }, seeded);
        if (!synced.aligned) throw new Error(synced.alignError || "key event tip is not this vault");
        const yadacoinAddress = synced.identity.tipSigner.address;
        const burned = await unwrapWyda(v.mnemonic, yadacoinAddress);
        await chrome.storage.local.set({
          yadaLastUnwrap: {
            wallet_address: baseReceiveAddress(v.mnemonic),
            yadacoin_address: yadacoinAddress,
            burn: burned.burn,
            at: Date.now(),
          },
        });
        await chrome.storage.local.remove("yadaPendingUnwrap");
        await reportUnwrap({
          wallet_address: baseReceiveAddress(v.mnemonic),
          yadacoin_address: yadacoinAddress,
          burn: burned.burn,
        });
        sendResponse({
          ok: true,
          burn: burned.burn,
          request: "",
          amount: burned.amount,
          yadacoin_address: yadacoinAddress,
        });
      } catch (e) {
        sendResponse({ ok: false, message: e instanceof Error ? e.message : String(e) });
      }
    })();
    return true;
  }

  if (message.type === "YADA_PAYOUT_STATUS") {
    void chrome.storage.local.get(["yadaPendingUnwrap", "yadaLastUnwrap"]).then((stored) => {
      sendResponse({
        ok: true,
        pendingUnwrap: stored.yadaPendingUnwrap || null,
        lastUnwrap: stored.yadaLastUnwrap || null,
      });
    });
    return true;
  }

  if (message.type === "YADA_CLIENT_IDENTITY") {
    void (async () => {
      try {
        let v = await loadVault();
        if (!v?.mnemonic) {
          sendResponse({ ok: false, message: "no vault", extVersion: EXT_VERSION, canCreateVault: true });
          return;
        }
        const address = baseReceiveAddress(v.mnemonic);
        sendResponse({
          ok: true,
          username: (v.username || "").replace(/^@/, ""),
          identity: vaultIdFromData(v),
          baseAddress: address,
          inceptionDone: !!v.inceptionDone,
          extVersion: EXT_VERSION,
          canCreateVault: true,
        });
        void connectAuthHome().catch(() => {});
      } catch (e) {
        sendResponse({
          ok: false,
          message: e instanceof Error ? e.message : String(e),
          extVersion: EXT_VERSION,
          canCreateVault: true,
        });
      }
    })();
    return true;
  }

  if (message.type === "YADA_CREATE_VAULT") {
    void (async () => {
      try {
        const username = String(message.username || "").trim().replace(/^@/, "");
        const secondFactor = String(message.secondFactor || "");
        if (!username) throw new Error("username required");
        if (!secondFactor) throw new Error("master password required");
        const existing = await loadVault();
        if (existing?.mnemonic) {
          const origin = String(message.origin || "");
          const returnUrl = String(message.returnUrl || "");
          const done = existing.inceptionDone
            ? { vault: existing, error: "" }
            : await broadcastInceptionFor(existing, origin, returnUrl);
          sendResponse({
            ok: true,
            existing: true,
            username: (existing.username || "").replace(/^@/, ""),
            baseAddress: baseReceiveAddress(existing.mnemonic),
            inceptionDone: !!done.vault.inceptionDone,
            inceptionError: done.error,
          });
          void connectAuthHome().catch(() => {});
          return;
        }
        const mnemonic = createVaultSeed(128);
        const identity: VaultIdentity = unlockIdentity(mnemonic, secondFactor, username);
        const vaultId = identity.k0.address;
        let stored: StoredVault = {
          mnemonic,
          secondFactor,
          username,
          identityType: "social",
          mainDepth: 0,
          tipPrevPkh: "",
          inceptionDone: false,
          sites: {},
        };
        await store.saveVault(vaultId, stored, { name: username });
        await store.setActiveVaultId(vaultId);
        const incepted = await broadcastInceptionFor(
          stored,
          String(message.origin || ""),
          String(message.returnUrl || "")
        );
        stored = incepted.vault;
        sendResponse({
          ok: true,
          existing: false,
          username,
          baseAddress: baseReceiveAddress(mnemonic),
          mnemonic,
          inceptionDone: !!stored.inceptionDone,
          inceptionError: incepted.error,
        });
        void connectAuthHome().catch(() => {});
      } catch (e) {
        sendResponse({
          ok: false,
          message: e instanceof Error ? e.message : String(e),
          extVersion: EXT_VERSION,
          canCreateVault: true,
        });
      }
    })();
    return true;
  }

  if (message.type === "YADA_INCEPT_VAULT") {
    void (async () => {
      try {
        const v = await loadVault();
        if (!v?.mnemonic) {
          sendResponse({ ok: false, message: "no vault" });
          return;
        }
        if (v.inceptionDone) {
          sendResponse({ ok: true, inceptionDone: true, username: (v.username || "").replace(/^@/, "") });
          void connectAuthHome().catch(() => {});
          return;
        }
        const done = await broadcastInceptionFor(
          v,
          String(message.origin || ""),
          String(message.returnUrl || "")
        );
        sendResponse({
          ok: true,
          inceptionDone: !!done.vault.inceptionDone,
          inceptionError: done.error,
          username: (done.vault.username || "").replace(/^@/, ""),
          baseAddress: baseReceiveAddress(done.vault.mnemonic),
        });
        void connectAuthHome().catch(() => {});
      } catch (e) {
        sendResponse({ ok: false, message: e instanceof Error ? e.message : String(e) });
      }
    })();
    return true;
  }

  if (message.type === "YADA_SIGNIN_ROTATE") {
    void (async () => {
      const say = (text: string) => reportProgress(sender, message.requestId, text);
      try {
        say("Resolving password home…");
        const origin = String(message.origin || "").toLowerCase();
        if (!origin.startsWith("http")) {
          sendResponse({ ok: false, message: "invalid origin" });
          return;
        }
        const baseUrl = await apiBase(origin);
        if (!baseUrl) {
          sendResponse({
            ok: false,
            extVersion: EXT_VERSION,
            message: "could not resolve password home SP",
          });
          return;
        }
        say("Unlocking vault…");
        let v = await loadVault();
        if (!v) {
          sendResponse({ ok: false, message: "no vault" });
          return;
        }
        say("Syncing the key event log…");
        v = await refreshInception(v, baseUrl);
        const identity: VaultIdentity = unlockIdentity(
          v.mnemonic,
          v.secondFactor,
          v.username,
          {
            identityType: v.identityType,
            mainDepth: v.mainDepth,
            tipPrevPkh: v.tipPrevPkh,
          }
        );
        let stored = v.sites[origin];
        let site: SiteRegistration;
        if (!stored) {
          say("Resyncing this origin from the node…");
          site = await resyncSiteFromNode({ baseUrl }, identity, origin);
        } else {
          say("Loading this origin…");
          site = siteFromStored(stored);
        }
        say("Rotating the password on the node…");
        const result = await rotateSitePassword({ baseUrl }, identity, site);
        v.sites[origin] = storeSite(result.site);
        v.nodeUrl = baseUrl;
        say("Saving vault…");
        await saveVault(v);
        sendResponse({
          ok: true,
          extVersion: EXT_VERSION,
          homeNode: baseUrl,
          authenticated: true,
          rotated: true,
          counter: result.site.counter,
          password: result.site.currentPassword,
          passwordHash: hashPassword(result.site.currentPassword),
          nextPasswordHash: hashPassword(result.site.nextPassword),
          message: `signed in & rotated to counter ${result.site.counter}`,
        });
      } catch (e) {
        sendResponse({
          ok: false,
          extVersion: EXT_VERSION,
          message: e instanceof Error ? e.message : String(e),
        });
      }
    })();
    return true;
  }

  if (message.type === "YADA_RESYNC_SITE") {
    void (async () => {
      const say = (text: string) => reportProgress(sender, message.requestId, text);
      try {
        say("Resolving password home…");
        const origin = String(message.origin || "").toLowerCase();
        if (!origin.startsWith("http")) {
          sendResponse({ ok: false, message: "invalid origin" });
          return;
        }
        const baseUrl = await apiBase(origin);
        if (!baseUrl) {
          sendResponse({
            ok: false,
            extVersion: EXT_VERSION,
            message: "could not resolve password home SP",
          });
          return;
        }
        say("Unlocking vault…");
        let v = await loadVault();
        if (!v) {
          sendResponse({ ok: false, message: "no vault" });
          return;
        }
        say("Syncing the key event log…");
        v = await refreshInception(v, baseUrl);
        const identity: VaultIdentity = unlockIdentity(
          v.mnemonic,
          v.secondFactor,
          v.username,
          {
            identityType: v.identityType,
            mainDepth: v.mainDepth,
            tipPrevPkh: v.tipPrevPkh,
          }
        );
        const sites: Record<string, SiteRegistration> = {};
        for (const [k, s] of Object.entries(v.sites || {})) {
          sites[k] = siteFromStored(s);
        }
        say("Resyncing vault from the node…");
        const full = await resyncVaultFromNode({ baseUrl }, identity, sites);
        let site = full.sites[origin];
        if (!site) {
          site = await resyncSiteFromNode({ baseUrl }, full.identity, origin);
          full.sites[origin] = site;
        }
        const nextSites: Record<string, StoredSite> = {};
        for (const [k, s] of Object.entries(full.sites)) {
          nextSites[k] = storeSite(s);
        }
        const nextVault: StoredVault = {
          ...v,
          nodeUrl: baseUrl,
          mainDepth: full.identity.mainDepth,
          tipPrevPkh: full.identity.tipPrevPkh,
          inceptionDone: full.kelDepth > 0,
          sites: nextSites,
        };
        say("Saving vault…");
        await saveVault(nextVault);
        sendResponse({
          ok: true,
          extVersion: EXT_VERSION,
          homeNode: baseUrl,
          resynced: true,
          counter: site.counter,
          message: `resynced · counter ${site.counter}`,
        });
      } catch (e) {
        sendResponse({
          ok: false,
          extVersion: EXT_VERSION,
          message: e instanceof Error ? e.message : String(e),
        });
      }
    })();
    return true;
  }

  if (message.type === "YADA_APPROVE_AUTH") {
    return (async () => {
      try {
        const p = message.request as PasswordAuthRequestPayload;
        const pendingNodeUrl = String(message.pendingNodeUrl || "");
        const pageOrigin = String(message.pageOrigin || "");
        const verificationCode = String(message.verificationCode || "");
        const rpToken = String(message.rpToken || "");
        const result = await approveAuthRequest(
          p,
          pendingNodeUrl,
          pageOrigin,
          verificationCode,
          rpToken
        );
        await approveTail;
        return result;
      } catch (e) {
        return {
          ok: false,
          message: e instanceof Error ? e.message : String(e),
        };
      } finally {
        approveInFlight = null;
      }
    })();
  }

  if (message.type === "YADA_UPLOAD_PROGRESS") {
    if (uploadSender) reportProgress(uploadSender, message.requestId, String(message.message || ""));
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === "YADA_UPLOAD_TAKE") {
    const job = takeUploadJob();
    sendResponse(job ? { ok: true, ...job } : { ok: false, message: "no upload waiting" });
    return false;
  }

  if (message.type === "YADA_UPLOAD_DONE") {
    finishUploadJob(message);
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === "YADA_STORE_FILE") {
    void (async () => {
      try {
        const result = await storeFromPage(message, sender);
        sendResponse(result);
      } catch (e) {
        sendResponse({ ok: false, message: e instanceof Error ? e.message : String(e) });
      }
    })();
    return true;
  }

  if (message.type === "YADA_SITE_STATUS") {
    void (async () => {
      const origin = String(message.origin || "").toLowerCase();
      const v = await loadVault();
      const stored = v?.sites?.[origin];
      sendResponse({
        ok: true,
        extVersion: EXT_VERSION,
        registered: !!stored,
        counter: stored?.counter ?? null,
      });
    })();
    return true;
  }

  return false;
});

void chrome.storage.local.get("yadaLastUnwrap").then((stored) => {
  const last = stored.yadaLastUnwrap as { wallet_address?: string; yadacoin_address?: string; burn?: string } | undefined;
  if (!last?.burn || !last.wallet_address) return;
  return reportUnwrap({
    wallet_address: last.wallet_address,
    yadacoin_address: last.yadacoin_address || "",
    burn: last.burn,
  }, false);
});

void connectAuthHome().catch(() => {});
