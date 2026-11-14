# WorkBuddy 服务商 · 集成说明

Dylix 新增 WorkBuddy 模型服务商（腾讯 CodeBuddy 计划），支持官方**扫码登录**（外链授权页 + 轮询确认）、自动续期、账户级请求头与模型发现。

## 服务商

| ID | 名称 | 端点 | 说明 |
|---|---|---|---|
| `workbuddy` | WorkBuddy · CodeBuddy 中国区 | `https://copilot.tencent.com/v2` | 中国区计划账户 |
| `workbuddy-ai` | WorkBuddy AI · 国际版 | `https://www.workbuddy.ai/v2` | 国际版计划账户，账户不互通 |

两者使用同一套协议，各自独立登录、独立模型清单。

## 登录流程（扫码）

与 WorkBuddy 桌面客户端一致，没有回调地址与 client id，登录完成由轮询接口确认：

1. `POST /v2/plugin/auth/state?platform=<platform>`（携带 `X-No-Authorization` 等置空头）→ 返回 `state` 与授权页 `authUrl`（中国区 `login.codebuddy.cn`，国际版 `www.workbuddy.ai`；页面即扫码页）。
2. 授权页追加 `version=2.0.0` 与随机 `loginSessionId`，保留其余原始查询串（含 `%2B` 编码）。
3. 打开授权页（系统登录弹窗）。用户完成登录后：
4. 每秒轮询 `GET /v2/plugin/auth/token?state=…`，"未就绪"业务码 `11217`、408、429 继续等待；成功后取得 `accessToken / refreshToken / expiresAt / domain`。
5. 轮询 `GET /v2/plugin/login/account?state=…`（Bearer + `X-Domain`），"未就绪"码 `12151` 继续等；成功后取得 `uid`、昵称/手机号、企业 ID。
6. 凭据与账户信息（uid、domain、enterpriseId、accountName 等）仅存钥匙串，不写 UserDefaults、连接 JSON 或日志。等待窗口 5 分钟；连续三次网络故障终止轮询。

## 续期

`POST /v2/plugin/auth/token/refresh`，refresh token 走 `X-Refresh-Token` 头，body 为空 JSON；未轮换的 refresh token 保留旧值。refresh token 自身过期（`refreshExpiresAt`）则本机退出，需重新扫码。access token 提前 5 分钟视为过期，由现有并发刷新共用机制收敛。

## 请求约定

聊天走 `{endpoint}/v2/chat/completions`，OpenAI 兼容，但网关有准入约定：

- 头：`X-Product: SaaS`、`X-IDE-Type: WorkBuddy`、`X-IDE-Name/Version`（`5.5.6`）、`X-Requested-With: XMLHttpRequest`、`X-Agent-Intent/Purpose`；国际版另带 `X-Agent-Type: main`。
- `User-Agent: WorkBuddy/5.5.6`；陌生 UA 会被网关以 `10085`（请求不合法）拒绝。拉模型时 UA 为 `CLI/2.0.0 WorkBuddy/5.5.6`。
- 账户头：`X-User-Id`、`X-Domain`，企业账户另带 `X-Enterprise-Id` 与 `X-Tenant-Id`；缺了会按个人计划作答或计入无客户端用量。
- 体：首条消息必须是 system（否则报 "first message is not system prompt"，Dylix 会自动补默认 system 消息）；不发送 OpenAI 的 `stream_options` 等私有字段；思考档位走 `reasoning_effort`。

## 模型发现

模型清单不在 chat 前缀下，而在站点根 `GET /v3/config`（以 CLI 客户端身份请求）：应答中 `agents` 里名为 `cli` 的代理的 `models` 即客户端选择器清单，各模型的名称、上下文窗口、图片支持与思考档位取自 `data.models` 明细。能力初值仍为 unknown，清单声明不代替实测。

## 隐私与边界

- 凭据仅存钥匙串；诊断不保存响应正文、令牌或登录页内容。
- 无公开吊销接口：退出只清除本机凭据，远端会话如需撤销请在 CodeBuddy 官网账户管理完成。
- 本实现按 WorkBuddy 桌面客户端公开协议移植，与 kwwk（EYHN/kwwk）`WorkBuddyOAuth.swift` / `WorkBuddyWire.swift` 的行为对齐；服务端协议变化时以官方客户端为准。
