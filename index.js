import { createHash } from "node:crypto";

const CHANNEL_ID = "wemp";
const DEFAULT_WEBHOOK_PATH = "/wemp";

function toStringValue(value, fallback = "") {
  if (typeof value === "string") return value;
  if (value == null) return fallback;
  return String(value);
}

function parseXml(xml) {
  const pick = (tag) => {
    const re = new RegExp(`<${tag}><!\\[CDATA\\[(.*?)]]><\\/${tag}>|<${tag}>(.*?)<\\/${tag}>`, "s");
    const m = xml.match(re);
    return (m?.[1] ?? m?.[2] ?? "").trim();
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
  const source = [token, timestamp, nonce].sort().join("");
  return sha1(source) === signature;
}

function readQuery(input) {
  if (!input) return {};
  if (input instanceof URLSearchParams) {
    return Object.fromEntries(input.entries());
  }
  if (input instanceof URL) {
    return Object.fromEntries(input.searchParams.entries());
  }
  if (typeof input === "string") {
    const source = input.trim();
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
  if (typeof input === "object") {
    return input;
  }
  return {};
}

function normalizeConfig(raw) {
  const cfg = raw && typeof raw === "object" ? raw : {};
  return {
    enabled: cfg.enabled !== false,
    appId: toStringValue(cfg.appId),
    appSecret: toStringValue(cfg.appSecret),
    token: toStringValue(cfg.token),
    verifySignature: cfg.verifySignature !== false,
    webhookPath: toStringValue(cfg.webhookPath, DEFAULT_WEBHOOK_PATH)
  };
}

async function fetchAccessToken(state, cfg) {
  const now = Date.now();
  if (state.accessToken && state.accessTokenExpireAt > now + 30_000) {
    return state.accessToken;
  }

  const url = new URL("https://api.weixin.qq.com/cgi-bin/token");
  url.searchParams.set("grant_type", "client_credential");
  url.searchParams.set("appid", cfg.appId);
  url.searchParams.set("secret", cfg.appSecret);

  const res = await fetch(url);
  const body = await res.json();
  if (!res.ok || body.errcode || !body.access_token) {
    throw new Error(`wemp access_token failed: ${body.errcode ?? res.status} ${body.errmsg ?? res.statusText}`);
  }

  const ttlMs = Math.max((body.expires_in ?? 7200) - 120, 300) * 1000;
  state.accessToken = body.access_token;
  state.accessTokenExpireAt = now + ttlMs;
  return state.accessToken;
}

async function sendWechatText(state, cfg, openId, text) {
  const accessToken = await fetchAccessToken(state, cfg);
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

function readRequestBody(requestLike) {
  if (!requestLike) return "";
  if (typeof requestLike.rawBody === "string") return requestLike.rawBody;
  if (typeof requestLike.body === "string") return requestLike.body;
  if (typeof requestLike.text === "function") return requestLike.text();
  return "";
}

function getSendTextPayload(payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const threadId = p.threadId ?? p.chatId ?? p.targetId ?? p.userId;
  const text = p.text ?? p.message ?? p.content;
  return {
    threadId: toStringValue(threadId),
    text: toStringValue(text)
  };
}

function makeGatewayAdapter(api, state) {
  return ({ channelConfig, ctx }) => {
    const cfg = normalizeConfig(channelConfig);

    if (cfg.enabled && typeof ctx?.addRoutes === "function") {
      const routeHandler = async (routeCtx) => {
        const request = routeCtx?.request ?? routeCtx?.req ?? routeCtx;
        const method = toStringValue(request?.method, "GET").toUpperCase();
        const query = readQuery(request?.query ?? request?.searchParams ?? request?.url);
        const signature = toStringValue(query.signature);
        const timestamp = toStringValue(query.timestamp);
        const nonce = toStringValue(query.nonce);
        const echostr = toStringValue(query.echostr, "ok");

        if (cfg.verifySignature) {
          const ok = verifySignature({ token: cfg.token, signature, timestamp, nonce });
          if (!ok) return { status: 401, body: "invalid signature" };
        }

        if (method === "GET") {
          return { status: 200, body: echostr };
        }
        if (method !== "POST") {
          return { status: 405, body: "method not allowed" };
        }

        const rawXml = await readRequestBody(request);
        const payload = parseXml(toStringValue(rawXml));
        const fromUser = payload.fromUserName;
        const msgType = payload.msgType;
        let text = "";
        if (msgType === "text") text = payload.content;
        else if (msgType === "event") text = `[event:${payload.event || "unknown"}] ${payload.eventKey || ""}`.trim();
        else text = `[${msgType || "unknown"}]`;

        if (fromUser && text && typeof ctx.onUserText === "function") {
          await ctx.onUserText({
            threadId: fromUser,
            userId: fromUser,
            text
          });
        } else {
          api.logger?.warn?.("wemp webhook received message but cannot forward to OpenClaw");
        }

        return { status: 200, body: "success" };
      };

      ctx.addRoutes([
        { method: "GET", path: cfg.webhookPath, handler: routeHandler },
        { method: "POST", path: cfg.webhookPath, handler: routeHandler }
      ]);
    }

    return {
      async sendText(payload) {
        const { threadId, text } = getSendTextPayload(payload);
        if (!threadId) throw new Error("wemp sendText missing threadId");
        if (!text) throw new Error("wemp sendText missing text");
        await sendWechatText(state, cfg, threadId, text);
      }
    };
  };
}

const channelPlugin = (api) => ({
  id: CHANNEL_ID,
  meta: {
    id: CHANNEL_ID,
    label: "WeChat Official Account",
    selectionLabel: "WeChat Official Account (Webhook)",
    docsPath: "/channels/wechat-mp",
    blurb: "WeChat Official Account webhook channel for OpenClaw.",
    aliases: ["wechat", "wechat-mp"]
  },
  name: "WeChat Official Account",
  metadata: {
    name: "WeChat Official Account",
    version: "0.2.0",
    description: "OpenClaw channel plugin for WeChat Official Account"
  },
  configSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      enabled: { type: "boolean", default: true },
      appId: { type: "string" },
      appSecret: { type: "string" },
      token: { type: "string" },
      verifySignature: { type: "boolean", default: true },
      webhookPath: { type: "string", default: DEFAULT_WEBHOOK_PATH }
    },
    required: ["enabled", "appId", "appSecret", "token"]
  },
  capabilities: {
    sendText: true,
    receiveText: true
  },
  createGatewayAdapter: makeGatewayAdapter(api, {
    accessToken: "",
    accessTokenExpireAt: 0
  })
});

export default function register(api) {
  api.registerChannel({ plugin: channelPlugin(api) });
}
