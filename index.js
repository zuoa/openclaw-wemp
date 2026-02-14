import { createHash } from "node:crypto";
import {
  createReplyPrefixOptions,
  emptyPluginConfigSchema,
  isRequestBodyLimitError,
  normalizePluginHttpPath,
  promptAccountId,
  readRequestBodyWithLimit,
  registerPluginHttpRoute,
  requestBodyErrorToText
} from "openclaw/plugin-sdk";

const PLUGIN_ID = "wemp";
const CHANNEL_ID = "wemp";
const DEFAULT_ACCOUNT_ID = "default";
const DEFAULT_WEBHOOK_PATH = "/wemp";
const WEBHOOK_MAX_BODY_BYTES = 1024 * 1024;
const WEBHOOK_BODY_TIMEOUT_MS = 30_000;
const VALID_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i;
const INVALID_CHARS_RE = /[^a-z0-9_-]+/g;
const LEADING_DASH_RE = /^-+/;
const TRAILING_DASH_RE = /-+$/;

function toStringValue(value, fallback = "") {
  if (typeof value === "string") return value;
  if (value == null) return fallback;
  return String(value);
}

function nowMessageId(prefix = "wemp") {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function toSafeErrorText(err) {
  if (err instanceof Error) return err.message;
  return toStringValue(err, "unknown error");
}

function normalizeAccountIdValue(value) {
  const trimmed = toStringValue(value).trim();
  if (!trimmed) return DEFAULT_ACCOUNT_ID;
  if (VALID_ID_RE.test(trimmed)) return trimmed.toLowerCase();
  return (
    trimmed
      .toLowerCase()
      .replace(INVALID_CHARS_RE, "-")
      .replace(LEADING_DASH_RE, "")
      .replace(TRAILING_DASH_RE, "")
      .slice(0, 64) || DEFAULT_ACCOUNT_ID
  );
}

function normalizeWebhookPath(value) {
  const path = toStringValue(value).trim();
  if (!path) return DEFAULT_WEBHOOK_PATH;
  if (path.startsWith("/")) return path;
  return `/${path}`;
}

function parseXml(xml) {
  const pick = (tag) => {
    const open = `<${tag}>`;
    const close = `</${tag}>`;
    const start = xml.indexOf(open);
    if (start < 0) return "";
    const bodyStart = start + open.length;
    const end = xml.indexOf(close, bodyStart);
    if (end < 0) return "";

    let value = xml.slice(bodyStart, end);
    if (value.startsWith("<![CDATA[") && value.endsWith("]]>")) {
      const cdataPrefix = "<![CDATA[";
      const cdataSuffix = "]]>";
      value = value.slice(cdataPrefix.length, -cdataSuffix.length);
    }
    return value.trim();
  };

  return {
    toUserName: pick("ToUserName"),
    fromUserName: pick("FromUserName"),
    createTime: pick("CreateTime"),
    msgType: pick("MsgType"),
    content: pick("Content"),
    msgId: pick("MsgId"),
    event: pick("Event"),
    eventKey: pick("EventKey")
  };
}

function sha1(input) {
  return createHash("sha1").update(input).digest("hex");
}

function verifySignature({ token, signature, timestamp, nonce }) {
  if (!token || !signature || !timestamp || !nonce) return false;
  const source = [token, timestamp, nonce].sort().join("");
  return sha1(source) === signature;
}

function parseUrlQuery(urlText) {
  const source = toStringValue(urlText).trim();
  if (!source) return {};
  if (source.startsWith("?")) {
    return Object.fromEntries(new URLSearchParams(source).entries());
  }

  try {
    return Object.fromEntries(new URL(source).searchParams.entries());
  } catch {
    try {
      return Object.fromEntries(new URL(source, "http://localhost").searchParams.entries());
    } catch {
      return {};
    }
  }
}

function parseUnknownQuery(value) {
  if (value == null) return {};
  if (value instanceof URL) {
    return Object.fromEntries(value.searchParams.entries());
  }
  if (value instanceof URLSearchParams) {
    return Object.fromEntries(value.entries());
  }
  if (typeof value === "string") {
    return parseUrlQuery(value);
  }
  if (typeof value !== "object") return {};

  const fromSearchParams = value.searchParams;
  if (fromSearchParams instanceof URLSearchParams) {
    return Object.fromEntries(fromSearchParams.entries());
  }
  if (fromSearchParams instanceof URL) {
    return Object.fromEntries(fromSearchParams.searchParams.entries());
  }
  if (typeof fromSearchParams === "string") {
    const parsed = parseUrlQuery(fromSearchParams);
    if (Object.keys(parsed).length > 0) return parsed;
  }
  if (typeof value.url === "string") {
    const parsed = parseUrlQuery(value.url);
    if (Object.keys(parsed).length > 0) return parsed;
  }
  if (value.url instanceof URL) {
    return Object.fromEntries(value.url.searchParams.entries());
  }
  if (typeof value.nextUrl === "string") {
    const parsed = parseUrlQuery(value.nextUrl);
    if (Object.keys(parsed).length > 0) return parsed;
  }
  if (value.nextUrl instanceof URL) {
    return Object.fromEntries(value.nextUrl.searchParams.entries());
  }
  if (value.nextUrl?.searchParams instanceof URLSearchParams) {
    return Object.fromEntries(value.nextUrl.searchParams.entries());
  }

  const proto = Object.getPrototypeOf(value);
  const isPlainObject = proto === Object.prototype || proto === null;
  if (!isPlainObject) return {};
  const entries = Object.entries(value).filter(([, v]) => v != null);
  if (entries.length === 0) return {};
  return Object.fromEntries(entries.map(([k, v]) => [k, toStringValue(v)]));
}

function readQueryFromRequest(req) {
  if (!req || typeof req !== "object") return {};

  const candidates = [
    req.query,
    req.searchParams,
    req.nextUrl?.searchParams,
    req.nextUrl,
    req.url,
    req.originalUrl,
    req.href,
    req.request?.url
  ];

  for (const candidate of candidates) {
    const parsed = parseUnknownQuery(candidate);
    if (Object.keys(parsed).length > 0) return parsed;
  }
  return {};
}

function normalizeAccountConfig(raw) {
  const cfg = raw && typeof raw === "object" ? raw : {};
  return {
    enabled: cfg.enabled !== false,
    name: toStringValue(cfg.name),
    appId: toStringValue(cfg.appId),
    appSecret: toStringValue(cfg.appSecret),
    token: toStringValue(cfg.token),
    verifySignature: cfg.verifySignature !== false,
    webhookPath: toStringValue(cfg.webhookPath, DEFAULT_WEBHOOK_PATH)
  };
}

function pickChannelConfig(rootCfg) {
  const channels = rootCfg && typeof rootCfg === "object" ? rootCfg.channels : undefined;
  const raw = channels && typeof channels === "object" ? channels[CHANNEL_ID] : undefined;
  return raw && typeof raw === "object" ? raw : {};
}

function accountMapFromChannelConfig(channelCfg) {
  const accounts = channelCfg.accounts;
  if (!accounts || typeof accounts !== "object" || Array.isArray(accounts)) return null;
  return accounts;
}

function defaultAccountIdFromChannelConfig(channelCfg) {
  const accounts = accountMapFromChannelConfig(channelCfg);
  if (!accounts) return DEFAULT_ACCOUNT_ID;
  if (accounts[DEFAULT_ACCOUNT_ID]) return DEFAULT_ACCOUNT_ID;
  const ids = Object.keys(accounts);
  return ids[0] ?? DEFAULT_ACCOUNT_ID;
}

function mergeBaseAccountConfig(channelCfg, accountCfg) {
  const base = { ...channelCfg };
  delete base.accounts;
  return { ...base, ...(accountCfg && typeof accountCfg === "object" ? accountCfg : {}) };
}

function listAccountIdsFromRootConfig(rootCfg) {
  const channelCfg = pickChannelConfig(rootCfg);
  const accounts = accountMapFromChannelConfig(channelCfg);
  if (!accounts) return [DEFAULT_ACCOUNT_ID];

  const ids = Object.keys(accounts);
  if (ids.length === 0) return [DEFAULT_ACCOUNT_ID];
  return ids;
}

function resolveAccountFromRootConfig(rootCfg, accountId) {
  const channelCfg = pickChannelConfig(rootCfg);
  const accounts = accountMapFromChannelConfig(channelCfg);

  if (!accounts) {
    const normalized = normalizeAccountConfig(channelCfg);
    return {
      ...normalized,
      accountId: DEFAULT_ACCOUNT_ID,
      name: normalized.name || "default"
    };
  }

  const requestedId = toStringValue(accountId) || defaultAccountIdFromChannelConfig(channelCfg);
  const resolvedId = accounts[requestedId]
    ? requestedId
    : accounts[DEFAULT_ACCOUNT_ID]
      ? DEFAULT_ACCOUNT_ID
      : defaultAccountIdFromChannelConfig(channelCfg);

  const merged = mergeBaseAccountConfig(channelCfg, accounts[resolvedId]);
  const normalized = normalizeAccountConfig(merged);

  return {
    ...normalized,
    accountId: resolvedId,
    name: normalized.name || resolvedId
  };
}

function isAccountConfigured(account) {
  return Boolean(account.appId && account.appSecret && account.token);
}

function setAccountEnabledInConfig(rootCfg, accountId, enabled) {
  const cfg = rootCfg && typeof rootCfg === "object" ? rootCfg : {};
  const channelCfg = pickChannelConfig(cfg);
  const channels = cfg.channels && typeof cfg.channels === "object" ? cfg.channels : {};
  const accounts = accountMapFromChannelConfig(channelCfg);

  if (!accounts) {
    return {
      ...cfg,
      channels: {
        ...channels,
        [CHANNEL_ID]: {
          ...channelCfg,
          enabled
        }
      }
    };
  }

  const resolvedId = toStringValue(accountId) || defaultAccountIdFromChannelConfig(channelCfg);
  return {
    ...cfg,
    channels: {
      ...channels,
      [CHANNEL_ID]: {
        ...channelCfg,
        accounts: {
          ...accounts,
          [resolvedId]: {
            ...(accounts[resolvedId] && typeof accounts[resolvedId] === "object" ? accounts[resolvedId] : {}),
            enabled
          }
        }
      }
    }
  };
}

function deleteAccountFromConfig(rootCfg, accountId) {
  const cfg = rootCfg && typeof rootCfg === "object" ? rootCfg : {};
  const channelCfg = pickChannelConfig(cfg);
  const channels = cfg.channels && typeof cfg.channels === "object" ? cfg.channels : {};
  const accounts = accountMapFromChannelConfig(channelCfg);

  if (!accounts) {
    return {
      ...cfg,
      channels: {
        ...channels,
        [CHANNEL_ID]: {
          ...channelCfg,
          appId: "",
          appSecret: "",
          token: ""
        }
      }
    };
  }

  const resolvedId = toStringValue(accountId) || defaultAccountIdFromChannelConfig(channelCfg);
  const nextAccounts = { ...accounts };
  delete nextAccounts[resolvedId];

  return {
    ...cfg,
    channels: {
      ...channels,
      [CHANNEL_ID]: {
        ...channelCfg,
        accounts: nextAccounts
      }
    }
  };
}

function upsertAccountConfig(rootCfg, accountId, patch) {
  const cfg = rootCfg && typeof rootCfg === "object" ? rootCfg : {};
  const channels = cfg.channels && typeof cfg.channels === "object" ? cfg.channels : {};
  const channelCfg = pickChannelConfig(cfg);
  const normalizedId = normalizeAccountIdValue(accountId);
  const accounts = accountMapFromChannelConfig(channelCfg);

  if (!accounts && normalizedId === DEFAULT_ACCOUNT_ID) {
    return {
      ...cfg,
      channels: {
        ...channels,
        [CHANNEL_ID]: {
          ...channelCfg,
          ...patch
        }
      }
    };
  }

  const nextAccounts = { ...(accounts || {}) };
  const currentEntry =
    nextAccounts[normalizedId] && typeof nextAccounts[normalizedId] === "object"
      ? nextAccounts[normalizedId]
      : {};
  nextAccounts[normalizedId] = {
    ...currentEntry,
    ...patch
  };

  return {
    ...cfg,
    channels: {
      ...channels,
      [CHANNEL_ID]: {
        ...channelCfg,
        accounts: nextAccounts
      }
    }
  };
}

function pickSetupCredentials(input, existingAccount) {
  const appId = toStringValue(input?.botToken ?? input?.userId ?? existingAccount?.appId).trim();
  const appSecret = toStringValue(input?.appToken ?? input?.password ?? existingAccount?.appSecret).trim();
  const token = toStringValue(input?.token ?? existingAccount?.token).trim();

  let webhookPath = toStringValue(input?.webhookPath ?? existingAccount?.webhookPath).trim();
  if (!webhookPath) {
    const webhookUrl = toStringValue(input?.webhookUrl).trim();
    if (webhookUrl) {
      try {
        webhookPath = new URL(webhookUrl).pathname || DEFAULT_WEBHOOK_PATH;
      } catch {
        webhookPath = webhookUrl;
      }
    }
  }

  return {
    appId,
    appSecret,
    token,
    webhookPath: normalizeWebhookPath(webhookPath),
    name: toStringValue(input?.name ?? existingAccount?.name).trim(),
    enabled: true
  };
}

function buildSetupMissingFieldsMessage(values) {
  const missing = [];
  if (!values.appId) missing.push("appId");
  if (!values.appSecret) missing.push("appSecret");
  if (!values.token) missing.push("token");
  if (missing.length === 0) return null;
  return `wemp missing ${missing.join("/")}. Use interactive setup with 'openclaw channels add' (no flags) or 'openclaw configure --section channels', or pass --bot-token <appId> --app-token <appSecret> --token <wechatToken>.`;
}

function buildOnboardingStatus(rootCfg) {
  const accountIds = listAccountIdsFromRootConfig(rootCfg);
  const configuredCount = accountIds.filter((id) =>
    isAccountConfigured(resolveAccountFromRootConfig(rootCfg, id))
  ).length;
  const configured = configuredCount > 0;
  return {
    configured,
    statusLines: [
      configured
        ? `WeChat Official Account: configured (${configuredCount}/${accountIds.length} account${configuredCount > 1 ? "s" : ""})`
        : "WeChat Official Account: needs appId + appSecret + token"
    ],
    selectionHint: configured ? "configured" : "needs credentials",
    quickstartScore: configured ? 2 : 1
  };
}

async function fetchAccessToken(tokenState, account) {
  const now = Date.now();
  if (tokenState.accessToken && tokenState.accessTokenExpireAt > now + 30_000) {
    return tokenState.accessToken;
  }

  if (!account.appId || !account.appSecret) {
    throw new Error("wemp account missing appId/appSecret");
  }

  const url = new URL("https://api.weixin.qq.com/cgi-bin/token");
  url.searchParams.set("grant_type", "client_credential");
  url.searchParams.set("appid", account.appId);
  url.searchParams.set("secret", account.appSecret);

  const res = await fetch(url);
  const body = await res.json();
  if (!res.ok || body.errcode || !body.access_token) {
    throw new Error(`wemp access_token failed: ${body.errcode ?? res.status} ${body.errmsg ?? res.statusText}`);
  }

  const ttlMs = Math.max((body.expires_in ?? 7200) - 120, 300) * 1000;
  tokenState.accessToken = body.access_token;
  tokenState.accessTokenExpireAt = now + ttlMs;
  return tokenState.accessToken;
}

async function sendWechatText(tokenState, account, openId, text) {
  if (!openId) throw new Error("wemp sendText missing target openId");
  if (!text) throw new Error("wemp sendText missing text");

  const accessToken = await fetchAccessToken(tokenState, account);
  const url = new URL("https://api.weixin.qq.com/cgi-bin/message/custom/send");
  url.searchParams.set("access_token", accessToken);

  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      touser: openId,
      msgtype: "text",
      text: { content: text }
    })
  });

  const body = await res.json();
  if (!res.ok || body.errcode) {
    throw new Error(`wemp send failed: ${body.errcode ?? res.status} ${body.errmsg ?? res.statusText}`);
  }
}

function toInboundText(payload) {
  if (payload.msgType === "text") {
    return toStringValue(payload.content).trim();
  }
  if (payload.msgType === "event") {
    const event = toStringValue(payload.event, "unknown").trim();
    const key = toStringValue(payload.eventKey).trim();
    return key ? `[event:${event}] ${key}` : `[event:${event}]`;
  }
  return `[${toStringValue(payload.msgType, "unknown").trim() || "unknown"}]`;
}

function normalizeWechatTarget(raw) {
  const value = toStringValue(raw).trim();
  if (!value) return "";
  return value.replace(/^wechat:(?:user:)?/i, "");
}

function outboundTextFromPayload(payload) {
  const text = toStringValue(payload?.text).trim();
  if (text) return text;

  const mediaUrl = toStringValue(payload?.mediaUrl).trim();
  if (mediaUrl) return mediaUrl;

  if (Array.isArray(payload?.mediaUrls)) {
    const lines = payload.mediaUrls
      .map((item) => toStringValue(item).trim())
      .filter(Boolean);
    if (lines.length > 0) return lines.join("\n");
  }

  return "";
}

function sendTextResponse(res, statusCode, body) {
  res.statusCode = statusCode;
  res.setHeader("content-type", "text/plain; charset=utf-8");
  res.end(body);
}

function sendJsonResponse(res, statusCode, body) {
  res.statusCode = statusCode;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function createChannelPlugin(api) {
  const tokenStateByAccount = new Map();
  const webhookByAccount = new Map();

  const getTokenState = (accountId) => {
    const key = toStringValue(accountId, DEFAULT_ACCOUNT_ID);
    const existing = tokenStateByAccount.get(key);
    if (existing) return existing;

    const created = { accessToken: "", accessTokenExpireAt: 0 };
    tokenStateByAccount.set(key, created);
    return created;
  };

  const stopWebhook = (accountId) => {
    const key = toStringValue(accountId, DEFAULT_ACCOUNT_ID);
    const running = webhookByAccount.get(key);
    if (!running) return;
    try {
      running.unregister?.();
    } catch {}
    try {
      running.abortSignal?.removeEventListener?.("abort", running.abortHandler);
    } catch {}
    webhookByAccount.delete(key);
  };

  const dispatchInboundText = async ({ cfg, account, fromUser, text, messageId, log }) => {
    const route = api.runtime.channel.routing.resolveAgentRoute({
      cfg,
      channel: CHANNEL_ID,
      accountId: account.accountId,
      peer: {
        kind: "direct",
        id: fromUser
      }
    });

    api.runtime.channel.activity.record({
      channel: CHANNEL_ID,
      accountId: route.accountId,
      direction: "inbound"
    });

    const timestamp = Date.now();
    const conversationLabel = `wechat:${fromUser}`;
    const storePath = api.runtime.channel.session.resolveStorePath(cfg.session?.store, {
      agentId: route.agentId
    });

    const envelope = api.runtime.channel.reply.resolveEnvelopeFormatOptions(cfg);
    const previousTimestamp = api.runtime.channel.session.readSessionUpdatedAt({
      storePath,
      sessionKey: route.sessionKey
    });

    const body = api.runtime.channel.reply.formatInboundEnvelope({
      channel: "WeChat",
      from: conversationLabel,
      timestamp,
      body: text,
      chatType: "direct",
      sender: { id: fromUser },
      previousTimestamp,
      envelope
    });

    const ctxPayload = api.runtime.channel.reply.finalizeInboundContext({
      Body: body,
      BodyForAgent: text,
      RawBody: text,
      CommandBody: text,
      From: conversationLabel,
      To: conversationLabel,
      SessionKey: route.sessionKey,
      AccountId: route.accountId,
      ChatType: "direct",
      ConversationLabel: conversationLabel,
      SenderId: fromUser,
      Provider: CHANNEL_ID,
      Surface: CHANNEL_ID,
      MessageSid: messageId,
      Timestamp: timestamp,
      OriginatingChannel: CHANNEL_ID,
      OriginatingTo: conversationLabel
    });

    await api.runtime.channel.session.updateLastRoute({
      storePath,
      sessionKey: route.mainSessionKey ?? route.sessionKey,
      deliveryContext: {
        channel: CHANNEL_ID,
        to: fromUser,
        accountId: route.accountId
      },
      ctx: ctxPayload
    });

    void api.runtime.channel.session
      .recordSessionMetaFromInbound({
        storePath,
        sessionKey: ctxPayload.SessionKey ?? route.sessionKey,
        ctx: ctxPayload
      })
      .catch((err) => {
        log?.warn?.(`[${account.accountId}] failed to record session meta: ${toSafeErrorText(err)}`);
      });

    const { onModelSelected, ...prefixOptions } = createReplyPrefixOptions({
      cfg,
      agentId: route.agentId,
      channel: CHANNEL_ID,
      accountId: route.accountId
    });

    const dispatchResult = await api.runtime.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
      ctx: ctxPayload,
      cfg,
      dispatcherOptions: {
        ...prefixOptions,
        deliver: async (payload) => {
          const outboundText = outboundTextFromPayload(payload);
          if (!outboundText) return;

          const tokenState = getTokenState(account.accountId);
          await sendWechatText(tokenState, account, fromUser, outboundText);

          api.runtime.channel.activity.record({
            channel: CHANNEL_ID,
            accountId: route.accountId,
            direction: "outbound"
          });
        },
        onError: (err, info) => {
          log?.error?.(
            `[${account.accountId}] dispatch ${info.kind} failed: ${toSafeErrorText(err)}`
          );
        }
      },
      replyOptions: {
        onModelSelected
      }
    });

    if (!dispatchResult.queuedFinal) {
      log?.debug?.(`[${account.accountId}] no final reply produced for ${fromUser}`);
    }
  };

  const createWebhookHandler = ({ cfg, account, log }) => {
    return async (req, res) => {
      const method = toStringValue(req?.method, "GET").toUpperCase();
      const query = readQueryFromRequest(req);
      const signature = toStringValue(query.signature).trim();
      const timestamp = toStringValue(query.timestamp).trim();
      const nonce = toStringValue(query.nonce).trim();
      const echostr = toStringValue(query.echostr, "ok");

      if (account.verifySignature) {
        const ok = verifySignature({
          token: account.token,
          signature,
          timestamp,
          nonce
        });
        if (!ok) {
          sendTextResponse(res, 401, "invalid signature");
          return;
        }
      }

      if (method === "GET") {
        sendTextResponse(res, 200, echostr);
        return;
      }

      if (method !== "POST") {
        res.statusCode = 405;
        res.setHeader("allow", "GET, POST");
        sendTextResponse(res, 405, "method not allowed");
        return;
      }

      try {
        const rawXml = await readRequestBodyWithLimit(req, {
          maxBytes: WEBHOOK_MAX_BODY_BYTES,
          timeoutMs: WEBHOOK_BODY_TIMEOUT_MS
        });

        const payload = parseXml(toStringValue(rawXml));
        const fromUser = toStringValue(payload.fromUserName).trim();
        const text = toInboundText(payload);
        const messageId = toStringValue(payload.msgId, nowMessageId("wemp-inbound"));

        sendTextResponse(res, 200, "success");

        if (!fromUser || !text) {
          log?.warn?.(`[${account.accountId}] webhook payload missing sender/text`);
          return;
        }

        void dispatchInboundText({
          cfg,
          account,
          fromUser,
          text,
          messageId,
          log
        }).catch((err) => {
          log?.error?.(`[${account.accountId}] inbound dispatch failed: ${toSafeErrorText(err)}`);
        });
      } catch (err) {
        if (isRequestBodyLimitError(err, "PAYLOAD_TOO_LARGE")) {
          sendJsonResponse(res, 413, { error: "Payload too large" });
          return;
        }
        if (isRequestBodyLimitError(err, "REQUEST_BODY_TIMEOUT")) {
          sendJsonResponse(res, 408, { error: requestBodyErrorToText("REQUEST_BODY_TIMEOUT") });
          return;
        }

        log?.error?.(`[${account.accountId}] webhook error: ${toSafeErrorText(err)}`);
        if (!res.headersSent) {
          sendJsonResponse(res, 500, { error: "Internal server error" });
        }
      }
    };
  };

  return {
    id: CHANNEL_ID,
    meta: {
      id: CHANNEL_ID,
      label: "wemp (WeChat Official Account)",
      selectionLabel: "wemp (WeChat Official Account Webhook)",
      docsPath: "/channels/wemp",
      docsLabel: "wemp",
      blurb: "WeChat Official Account webhook channel for OpenClaw.",
      aliases: ["wechat", "wemp", "weixin", "公众号", "微信"],
      order: 1
    },
    capabilities: {
      chatTypes: ["direct"],
      media: false,
      threads: false,
      nativeCommands: false,
      blockStreaming: false
    },
    config: {
      listAccountIds: (cfg) => listAccountIdsFromRootConfig(cfg),
      resolveAccount: (cfg, accountId) => resolveAccountFromRootConfig(cfg, accountId),
      defaultAccountId: (cfg) => {
        const channelCfg = pickChannelConfig(cfg);
        return defaultAccountIdFromChannelConfig(channelCfg);
      },
      setAccountEnabled: ({ cfg, accountId, enabled }) =>
        setAccountEnabledInConfig(cfg, accountId, enabled),
      deleteAccount: ({ cfg, accountId }) => deleteAccountFromConfig(cfg, accountId),
      isEnabled: (account) => account.enabled !== false,
      disabledReason: () => "channel disabled",
      isConfigured: (account) => isAccountConfigured(account),
      unconfiguredReason: () => "wemp requires appId + appSecret + token",
      describeAccount: (account) => ({
        accountId: account.accountId,
        name: account.name,
        enabled: account.enabled,
        configured: isAccountConfigured(account),
        webhookPath: account.webhookPath,
        mode: "webhook"
      })
    },
    setup: {
      resolveAccountId: ({ accountId }) => normalizeAccountIdValue(accountId),
      applyAccountName: ({ cfg, accountId, name }) =>
        upsertAccountConfig(cfg, accountId, { name: toStringValue(name).trim() }),
      validateInput: ({ cfg, accountId, input }) => {
        const existing = resolveAccountFromRootConfig(cfg, accountId);
        const values = pickSetupCredentials(input, existing);
        return buildSetupMissingFieldsMessage(values);
      },
      applyAccountConfig: ({ cfg, accountId, input }) => {
        const existing = resolveAccountFromRootConfig(cfg, accountId);
        const values = pickSetupCredentials(input, existing);
        const patch = {
          enabled: true,
          appId: values.appId,
          appSecret: values.appSecret,
          token: values.token,
          webhookPath: values.webhookPath,
          verifySignature: existing.verifySignature !== false
        };
        if (values.name) patch.name = values.name;
        return upsertAccountConfig(cfg, accountId, patch);
      }
    },
    onboarding: {
      channel: CHANNEL_ID,
      getStatus: async ({ cfg }) => ({
        channel: CHANNEL_ID,
        ...buildOnboardingStatus(cfg)
      }),
      configure: async ({ cfg, prompter, accountOverrides, shouldPromptAccountIds }) => {
        const overrideId = toStringValue(accountOverrides?.[CHANNEL_ID]).trim();
        const defaultAccountId = defaultAccountIdFromChannelConfig(pickChannelConfig(cfg));
        let accountId = overrideId ? normalizeAccountIdValue(overrideId) : defaultAccountId;

        if (shouldPromptAccountIds) {
          accountId = await promptAccountId({
            cfg,
            prompter,
            label: "WeChat",
            currentId: accountId,
            listAccountIds: listAccountIdsFromRootConfig,
            defaultAccountId
          });
        }

        accountId = normalizeAccountIdValue(accountId);
        const existing = resolveAccountFromRootConfig(cfg, accountId);

        await prompter.note(
          [
            "Configure WeChat Official Account webhook credentials.",
            "You can update these later with `openclaw configure --section channels`.",
            "AppID / AppSecret come from 微信公众号后台 -> 开发 -> 基本配置。"
          ].join("\n"),
          "WeChat setup"
        );

        const nameInput = await prompter.text({
          message: "Account display name (optional)",
          initialValue: existing.name || accountId
        });
        const appIdInput = await prompter.text({
          message: "WeChat AppID",
          initialValue: existing.appId,
          validate: (value) => (toStringValue(value).trim() ? undefined : "Required")
        });
        const appSecretInput = await prompter.text({
          message: "WeChat AppSecret",
          initialValue: existing.appSecret,
          validate: (value) => (toStringValue(value).trim() ? undefined : "Required")
        });
        const tokenInput = await prompter.text({
          message: "Webhook Token (must match WeChat backend)",
          initialValue: existing.token,
          validate: (value) => (toStringValue(value).trim() ? undefined : "Required")
        });
        const webhookPathInput = await prompter.text({
          message: "Webhook path",
          initialValue: existing.webhookPath || DEFAULT_WEBHOOK_PATH,
          validate: (value) => (toStringValue(value).trim() ? undefined : "Required")
        });
        const verifySignature = await prompter.confirm({
          message: "Enable webhook signature verification?",
          initialValue: existing.verifySignature !== false
        });

        const next = upsertAccountConfig(cfg, accountId, {
          enabled: true,
          name: toStringValue(nameInput).trim() || accountId,
          appId: toStringValue(appIdInput).trim(),
          appSecret: toStringValue(appSecretInput).trim(),
          token: toStringValue(tokenInput).trim(),
          webhookPath: normalizeWebhookPath(webhookPathInput),
          verifySignature
        });

        return { cfg: next, accountId };
      },
      disable: (cfg) => {
        const channels = cfg?.channels && typeof cfg.channels === "object" ? cfg.channels : {};
        const channelCfg = pickChannelConfig(cfg);
        return {
          ...cfg,
          channels: {
            ...channels,
            [CHANNEL_ID]: {
              ...channelCfg,
              enabled: false
            }
          }
        };
      }
    },
    outbound: {
      deliveryMode: "direct",
      resolveTarget: ({ to }) => {
        const normalized = normalizeWechatTarget(to);
        if (!normalized) {
          return { ok: false, error: new Error("wemp missing target openId") };
        }
        return { ok: true, to: normalized };
      },
      sendText: async ({ cfg, to, text, accountId }) => {
        const target = normalizeWechatTarget(to);
        if (!target) throw new Error("wemp sendText missing target openId");

        const account = resolveAccountFromRootConfig(cfg, accountId);
        if (!isAccountConfigured(account)) {
          throw new Error("wemp account not configured (appId/appSecret/token required)");
        }

        const content = toStringValue(text).trim();
        if (!content) throw new Error("wemp sendText missing text");

        const tokenState = getTokenState(account.accountId);
        await sendWechatText(tokenState, account, target, content);

        api.runtime.channel.activity.record({
          channel: CHANNEL_ID,
          accountId: account.accountId,
          direction: "outbound"
        });

        return {
          channel: CHANNEL_ID,
          messageId: nowMessageId("wemp-outbound"),
          chatId: target,
          timestamp: Date.now()
        };
      },
      sendMedia: async ({ cfg, to, text, mediaUrl, accountId }) => {
        const contentLines = [toStringValue(text).trim(), toStringValue(mediaUrl).trim()].filter(Boolean);
        if (contentLines.length === 0) {
          throw new Error("wemp sendMedia requires text or mediaUrl");
        }
        const target = normalizeWechatTarget(to);
        if (!target) throw new Error("wemp sendMedia missing target openId");

        const account = resolveAccountFromRootConfig(cfg, accountId);
        if (!isAccountConfigured(account)) {
          throw new Error("wemp account not configured (appId/appSecret/token required)");
        }

        const tokenState = getTokenState(account.accountId);
        await sendWechatText(tokenState, account, target, contentLines.join("\n"));

        api.runtime.channel.activity.record({
          channel: CHANNEL_ID,
          accountId: account.accountId,
          direction: "outbound"
        });

        return {
          channel: CHANNEL_ID,
          messageId: nowMessageId("wemp-outbound"),
          chatId: target,
          timestamp: Date.now(),
          meta: { degradedMedia: true }
        };
      }
    },
    status: {
      defaultRuntime: {
        accountId: DEFAULT_ACCOUNT_ID,
        running: false,
        mode: "webhook",
        lastStartAt: null,
        lastStopAt: null,
        lastError: null
      },
      collectStatusIssues: (accounts) => {
        const issues = [];
        for (const account of accounts) {
          const accountId = account.accountId || DEFAULT_ACCOUNT_ID;
          if (!account.configured) {
            issues.push({
              channel: CHANNEL_ID,
              accountId,
              kind: "config",
              message: "wemp requires appId, appSecret, and token"
            });
          }
        }
        return issues;
      },
      buildChannelSummary: ({ snapshot }) => ({
        configured: snapshot.configured ?? false,
        running: snapshot.running ?? false,
        webhookPath: snapshot.webhookPath ?? null,
        mode: snapshot.mode ?? "webhook",
        lastError: snapshot.lastError ?? null,
        lastStartAt: snapshot.lastStartAt ?? null,
        lastStopAt: snapshot.lastStopAt ?? null,
        lastInboundAt: snapshot.lastInboundAt ?? null,
        lastOutboundAt: snapshot.lastOutboundAt ?? null
      }),
      buildAccountSnapshot: ({ account, runtime }) => ({
        accountId: account.accountId,
        name: account.name,
        enabled: account.enabled,
        configured: isAccountConfigured(account),
        running: runtime?.running ?? false,
        mode: "webhook",
        webhookPath: account.webhookPath,
        lastError: runtime?.lastError ?? null,
        lastStartAt: runtime?.lastStartAt ?? null,
        lastStopAt: runtime?.lastStopAt ?? null,
        lastInboundAt: runtime?.lastInboundAt ?? null,
        lastOutboundAt: runtime?.lastOutboundAt ?? null
      })
    },
    gateway: {
      startAccount: async (ctx) => {
        const account = ctx.account;
        const accountId = toStringValue(account.accountId, DEFAULT_ACCOUNT_ID);
        stopWebhook(accountId);

        if (!account.enabled) {
          ctx.setStatus({
            ...ctx.getStatus(),
            running: false,
            mode: "webhook",
            lastError: null
          });
          return { started: false, reason: "disabled" };
        }

        if (!isAccountConfigured(account)) {
          ctx.setStatus({
            ...ctx.getStatus(),
            accountId,
            running: false,
            mode: "webhook",
            lastError: "wemp account not configured (appId/appSecret/token required)"
          });
          return { started: false, reason: "unconfigured" };
        }

        const normalizedPath =
          normalizePluginHttpPath(account.webhookPath, DEFAULT_WEBHOOK_PATH) || DEFAULT_WEBHOOK_PATH;

        const handler = createWebhookHandler({
          cfg: ctx.cfg,
          account,
          log: ctx.log
        });

        const unregister = registerPluginHttpRoute({
          path: normalizedPath,
          pluginId: PLUGIN_ID,
          accountId,
          log: (message) => ctx.log?.debug?.(message),
          handler
        });

        const abortHandler = () => {
          stopWebhook(accountId);
          ctx.setStatus({
            ...ctx.getStatus(),
            running: false,
            mode: "webhook",
            lastStopAt: Date.now()
          });
        };

        ctx.abortSignal?.addEventListener?.("abort", abortHandler);

        webhookByAccount.set(accountId, {
          unregister,
          abortSignal: ctx.abortSignal,
          abortHandler,
          path: normalizedPath
        });

        ctx.setStatus({
          ...ctx.getStatus(),
          accountId,
          running: true,
          mode: "webhook",
          webhookPath: normalizedPath,
          lastStartAt: Date.now(),
          lastError: null
        });

        ctx.log?.info?.(`[${accountId}] wemp webhook listening on ${normalizedPath}`);
        return { started: true, webhookPath: normalizedPath };
      },
      stopAccount: async (ctx) => {
        const accountId = toStringValue(ctx.accountId, DEFAULT_ACCOUNT_ID);
        stopWebhook(accountId);
        ctx.setStatus({
          ...ctx.getStatus(),
          running: false,
          mode: "webhook",
          lastStopAt: Date.now()
        });
      }
    }
  };
}

const plugin = {
  id: PLUGIN_ID,
  name: "WeChat Official Account",
  description: "OpenClaw channel plugin for WeChat Official Account",
  configSchema: emptyPluginConfigSchema(),
  register(api) {
    api.registerChannel({ plugin: createChannelPlugin(api) });
  }
};

export default plugin;
