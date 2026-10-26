# Shopify Checker API

Single-file async Shopify card checker. Koi hardcoded site/proxy nahi — sab URL se.

## Install
```bash
pip install -r requirements.txt
```

## Run
```bash
python app.py
```
Default port: **8083**. Env vars se badal sakta hai (niche dekho).

## Endpoints

### Single
```
GET /shopify?card=CARD|MM|YYYY|CVV&site=DOMAIN&proxy=host:port
```

Example:
```
http://127.0.0.1:8083/shopify?card=5178058551094413|06|2028|425&site=https://www.allbirds.com&proxy=1.2.3.4:8080
```

### Batch
```
POST /batch
Content-Type: application/json

{
  "site": "allbirds.com",
  "cards": ["4111...|12|2027|123", "5500...|01|2029|456"],
  "proxies": ["1.2.3.4:8080", "5.6.7.8:8080"]
}
```

## Optional query params (single endpoint)
| Param | Kaam |
|---|---|
| `proxy` | `host:port`, `user:pass@host:port`, `socks5://...`. Comma se multiple de sakta hai -> random pick |
| `variant` | apna variant id force karne ke liye |
| `key` | per-user concurrency limit alag rakhne ke liye |
| `first`,`last`,`email`,`phone`,`address1`,`city`,`state`,`zip`,`country` | address override |

## Response
```json
{
  "cc": "...",
  "Gateway": "shopify_payments",
  "Response": "ORDER_PLACED",
  "Price": 12.5,
  "Currency": "USD",
  "Status": true,
  "Proxy": "Live",
  "Time": "3.41s",
  "site": "https://www.allbirds.com"
}
```

## Config (env vars)
| Var | Default | Kaam |
|---|---|---|
| `PORT` | 8083 | server port |
| `GLOBAL_MAX_CONCUR` | 3000 | total concurrent |
| `PER_USER_CONCUR` | 1200 | per-key concurrent |
| `MAX_RETRIES` | 2 | retry count |
| `REQ_TOTAL_TIMEOUT` | 40 | request timeout (s) |
| `THREADS` | 200 | waitress threads |

Example:
```bash
PORT=9000 GLOBAL_MAX_CONCUR=5000 python app.py
```

## Notes
- `proxies.txt` optional hai (fallback pool). URL me proxy diya toh wahi use hoga.
- Proxy na diya toh direct connect.