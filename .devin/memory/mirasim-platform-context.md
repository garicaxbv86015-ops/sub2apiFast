---
name: mirasim-platform-context
description: Context on Mirasim client architecture and user relationship as its local app developer
type: project
---

---
name: mirasim-platform-context
description: Context on Mirasim client architecture and user relationship as its local app developer
type: project
---

The user is developing the local Mirasim application (/Applications/Mirasim.app). Mirasim acts as an AI client and relay proxy connecting to relay.mirasim.ai. Key protocol mechanisms include authentication against auth.mirasim.ai (browser OAuth at /auth/oauth/{provider}/login or email verification via /auth/code and /auth/verify returning access_token and refresh_token), device ticket exchange via /v1/device/session signed with ed25519 device keys (x-mirasim-* headers), 5-hour rolling usage windows inspected via /v1/limits, and strict quota gating where plan='none' halts cloud relaying to prevent personal account consumption. On the user's local machine, Mirasim app stores credentials and device keys at ~/.mirasim/setting.json (.auth.token, .device.privateKey) and ~/.mirasim/device.json (.deviceId).
