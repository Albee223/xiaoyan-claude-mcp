# 小研 Claude MCP

小研 Threads 營運中心的獨立遠端 MCP。提供 OAuth 2.1、PKCE、Daily Radar、草稿、審核、核准、排程與成效工具。

## 安全邊界

- 只有通過擁有者密碼的 OAuth 使用者能呼叫 MCP。
- 寫入內容必須依序經過草稿、送審、明確核准、排程。
- 不提供 Threads 發布或回覆工具，直到 Meta 授權完成。
- 小研網站資料仍保存在原本的 Sites D1，由專屬服務金鑰存取。

## 必要環境變數

- `OWNER_PASSWORD`
- `OAUTH_SIGNING_SECRET`
- `SITE_BASE_URL`
- `SITE_BYPASS_TOKEN`
- `SITE_SERVICE_KEY`
