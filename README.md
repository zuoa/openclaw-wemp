# @openclaw/wechat-mp

用于把微信公众号（服务号/订阅号）接入 OpenClaw Gateway 的渠道插件（官方 `registerChannel` 方式）。

## 插件安装（OpenClaw）

这是 **OpenClaw Gateway 插件**，请安装到你的 OpenClaw Gateway 项目中（不是在公众号后台安装）。

1. 获取插件源码（如果你还没有本地目录）

```bash
git clone https://github.com/zuoa/openclaw-wemp.git
```

2. 在 Gateway 环境安装本地插件（开发态推荐 `-l/--link`）

```bash
openclaw plugins install -l /path/to/openclaw-wemp
```

3. 重启 Gateway（插件在 Gateway 进程内加载，必须重启）

4. 检查插件状态

```bash
openclaw plugins list
openclaw plugins info wemp
openclaw plugins doctor
```

5. 配置渠道（推荐走向导）

```bash
openclaw configure --section channels
```

或：

```bash
openclaw channels add
```

- `openclaw channels add`（无参数）会进入交互式向导。
- `openclaw channels add --channel wemp` 是非交互模式，需要同时传完整凭证参数，否则会报 `missing appId/appSecret/token`。
- 也可以手工写入 `~/.openclaw/openclaw.json` 的 `channels.wemp`。


## 功能

- 微信回调 `GET` 验证（`signature/timestamp/nonce/echostr`）
- 微信回调 `POST` 消息接收（XML，明文模式）
- 文本/事件消息转发给 OpenClaw（`onUserText`）
- 通过微信公众号客服消息 API 发送文本
- `access_token` 内存缓存

## 插件结构

- `openclaw.plugin.json`
- `index.js`（`export default function register(api) { ... }`）
- `package.json` 中包含：
  - `"main": "index.js"`
  - `"openclaw.extensions": ["./index.js"]`

## OpenClaw 配置示例（JSON）

```json
{
  "channels": {
    "wemp": {
      "enabled": true,
      "appId": "wx1234567890",
      "appSecret": "your-app-secret",
      "token": "your-wechat-token",
      "verifySignature": true,
      "webhookPath": "/wemp"
    }
  }
}
```

说明：
- 这里的 key `wemp` 对应插件声明的 channel id。
- `webhookPath` 默认是 `/wemp`。

## 微信公众号后台配置

1. 进入公众号后台 -> 开发 -> 基本配置 -> 服务器配置。
2. URL 填 OpenClaw 网关地址 + `webhookPath`，例如：`https://your-domain.com/wemp`。
3. Token 必须与 `channels.wemp.token` 一致。
4. 消息加解密方式建议先用“明文模式”联调，稳定后再扩展安全模式。

## 当前限制

- 当前仅发送文本回复（客服消息 `msgtype=text`）。
- 未实现“安全模式”（AES）解密。
- 微信公众号 48 小时客服消息窗口规则由微信侧限制，超窗会被拒绝。
