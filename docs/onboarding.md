# Onboarding

How to connect claude.ai to your Matrix account on `kampong.social`.

---

## Prerequisites

- A `kampong.social` Matrix account.
- Cross-signing set up in Element X (Settings → Security → Set up
  secure backup). You'll need the recovery key it shows you.
- A claude.ai account with access to custom connectors.

---

## Step 1 – Add the connector in claude.ai

1. Open claude.ai → Settings → Connectors → Add custom connector.
2. Enter the URL: `https://matrix-mcp.kampong.social/mcp`
3. Click Connect.

Claude.ai will discover the MAS authorization server, register itself
as a client via DCR, and redirect you to `id.kampong.social` to log in
and approve the scopes.

Approve the `openid`, Matrix C-S API (`urn:matrix:…`), and device scopes
when prompted. These let matrix-mcp read/write your rooms on your behalf.

---

## Step 2 – Unlock E2EE via /setup

After connecting, call the `verify_status` tool from claude.ai. It will
tell you if E2EE is already active. On first connection it won't be.

To unlock E2EE:

1. Open `https://matrix-mcp.kampong.social/setup` in a browser.
2. Click "Sign in" – you're redirected to `id.kampong.social`.
3. After signing in, you're redirected back to the recovery key form.
4. Paste your Matrix Secret Storage recovery key (the 48-character
   string starting with `Esso…` that Element X showed you when you first
   enabled secure backup).
5. Click "Unlock E2EE".

The success page confirms that matrix-mcp imported your cross-signing
keys. It also starts downloading your megolm key backup in the background
(up to 200 rooms, ~1–2 minutes for a busy account).

---

## Step 3 – Verify

Back in claude.ai, call `verify_status`. Within ~30 s of completing
/setup it should return:

```json
{
  "cross_signed": true,
  "user_has_master_key": true,
  "message": "matrix-mcp device is cross-signed; E2EE rooms are accessible."
}
```

If it still says `cross_signed: false`, wait another 30 s and try again.
The sync loop runs continuously; it picks up the updated key state on
the next cycle.

---

## What happens to your recovery key

The recovery key is transmitted once to matrix-mcp over HTTPS and is
never stored or logged. Only the derived cross-signing private keys are
persisted, encrypted on disk with a per-user key derived from a
server-wide secret.

The recovery key itself is processed entirely server-side by the
`client.encryption().recovery().recover()` call. It does not appear
in claude.ai's chat history.

---

## Re-running /setup

The `/setup` flow is idempotent. If you:
- Changed your Matrix Secret Storage recovery key in Element X,
- Got a new phone and set up a new secure backup,
- Or just want to re-verify,

…visit `/setup` again and paste the new recovery key. The old
cross-signing state is replaced.

---

## Optional: check Element X

After running `/setup`, a new device named something like
`MATRIXMCPCONNECTOR` should appear in Element X under
Settings → Devices. It will be marked as verified.

If you see it marked as unverified, call `verify_status` from claude.ai
and check the message – it will explain what's needed.
