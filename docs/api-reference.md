# API Reference

All 17 MCP tools exposed by matrix-mcp at `/mcp`.

Tools use Streamable HTTP (JSON-RPC 2.0). Authentication: Bearer token
issued by MAS, passed in the `Authorization` header.

Rate limits: 60 reads/min, 30 writes/min per identity (defaults).
Returns error code `-32001` (`RATE_LIMITED`) when exceeded.

---

## whoami

Return the authenticated Matrix user id and device id.

**Category:** read  
**Params:** none

**Returns:**
```json
{
  "mxid": "@julian:kampong.social",
  "device_id": "MATRIXMCPCONNECTOR"
}
```

`device_id` may be `null` if MAS did not include it in the introspection
response and it could not be parsed from the scope string.

---

## list_joined_rooms

List Matrix rooms the authenticated user has joined.

**Category:** read  
**Params:** none

**Returns:**
```json
{
  "rooms": [
    {
      "room_id": "!abc:kampong.social",
      "display_name": "General",
      "topic": "General chat",
      "encrypted": true
    }
  ]
}
```

---

## read_recent_messages

Read recent events (newest first) from a Matrix room. The SDK decrypts
E2EE rooms if this device is cross-signed. Events that cannot be decrypted
return `status: "unable_to_decrypt"` with a null event body.

**Category:** read  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id, e.g. `!abc:kampong.social` |
| `limit` | integer | `20` | Max events to return. Capped at 50. |

**Returns:**
```json
{
  "events": [
    {
      "event_id": "$abc123:kampong.social",
      "sender": "@julian:kampong.social",
      "origin_server_ts": 1747267200000,
      "status": "decrypted",
      "event": { "type": "m.room.message", "content": { "body": "Hello" } },
      "in_reply_to": null,
      "is_thread_root": false,
      "thread_event_count": null
    }
  ]
}
```

`status` is one of `"plaintext"`, `"decrypted"`, `"unable_to_decrypt"`.

---

## read_thread

Read all events in a Matrix thread (MSC3440 / spec v1.4+), newest first.
Uses `GET /_matrix/client/v1/rooms/{room_id}/relations/{event_id}/m.thread`.
The root event itself is not included.

**Category:** read  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `root_event_id` | string | required | Event id of the thread root |
| `limit` | integer | `50` | Max events. Capped at 200. |

**Returns:** same shape as `read_recent_messages`

---

## send_text_message

Send a text message to a Matrix room. Body is rendered as Markdown for
`formatted_body`. E2EE rooms are encrypted automatically if this device
is cross-signed.

**Category:** write  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `body` | string | required | Message body (Markdown). Max 64 KiB. |

**Returns:**
```json
{ "event_id": "$newEvent:kampong.social" }
```

---

## verify_status

Report the cross-signing / verification status of this matrix-mcp device.

**Category:** read  
**Params:** none

**Returns:**
```json
{
  "cross_signed": true,
  "user_has_master_key": true,
  "message": "matrix-mcp device is cross-signed; E2EE rooms are accessible."
}
```

If `cross_signed` is false, `message` contains instructions for the user.

---

## room_info

Return metadata about a joined Matrix room. Only works for rooms the
caller is currently joined to.

**Category:** read  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |

**Returns:**
```json
{
  "room_id": "!abc:kampong.social",
  "display_name": "General",
  "name": "General",
  "topic": "General chat",
  "encrypted": true,
  "joined_members_count": 42,
  "active_members_count": 45,
  "my_power_level": 50,
  "is_room_creator": false
}
```

`my_power_level` is `null` for v12+ room creators (`is_room_creator: true`).

---

## room_members

List joined members of a Matrix room with display name, avatar, and
normalized power level.

**Category:** read  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `limit` | integer | `200` | Max members. Capped at 1000. |

**Returns:**
```json
{
  "members": [
    {
      "mxid": "@julian:kampong.social",
      "display_name": "Julian",
      "avatar_url": "mxc://kampong.social/abc",
      "power_level": 100
    }
  ],
  "total": 42
}
```

`total` is the room's actual joined-member count. If `members.len() < total`,
the response was truncated.

---

## get_unread_summary

Summarise rooms with unread messages, sorted by latest activity (newest
first).

**Category:** read  
**Params:** none

**Returns:**
```json
{
  "rooms": [
    {
      "room_id": "!abc:kampong.social",
      "display_name": "General",
      "encrypted": true,
      "unread_messages": 5,
      "unread_notifications": 2,
      "unread_mentions": 1,
      "latest_event_id": "$abc:kampong.social",
      "latest_sender": "@alice:kampong.social",
      "latest_origin_server_ts": 1747267200000
    }
  ],
  "total_unread_rooms": 3,
  "total_unread_messages": 12
}
```

---

## mark_read

Mark a room (or a specific event) as read by sending an unthreaded read
receipt.

**Category:** write  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `event_id` | string | `null` | Event to mark. If omitted, uses the room's latest event. |

**Returns:**
```json
{ "room_id": "!abc:kampong.social", "event_id": "$abc:kampong.social" }
```

---

## send_reaction

Add an emoji reaction to a Matrix event. Reactions are non-E2EE per
MSC2677 – the `key` is visible to everyone in the room.

**Category:** write  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `event_id` | string | required | Target event id |
| `key` | string | required | Reaction key, usually an emoji e.g. `"👍"` |

**Returns:**
```json
{ "event_id": "$reactionEvent:kampong.social" }
```

---

## redact_message

Redact (delete) a Matrix event. The homeserver enforces ACLs – if your
power level is below the room's `redact` threshold, you get an error.

**Category:** write  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `event_id` | string | required | Event to redact |
| `reason` | string | `null` | Optional reason |

**Returns:**
```json
{ "event_id": "$redactionEvent:kampong.social" }
```

---

## download_attachment

Download an attachment from a Matrix room event (`m.file`, `m.image`,
`m.audio`, or `m.video`) and return it as base64. The SDK handles
E2EE decryption transparently. Attachments larger than
`MATRIX_MCP_DOWNLOAD_MAX_BYTES` (default 5 MiB) are rejected before
any media I/O.

**Category:** read  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `event_id` | string | required | Event id of the attachment message |

**Returns:**
```json
{
  "content_type": "image/png",
  "size_bytes": 12345,
  "body_base64": "iVBORw0KGgo...",
  "filename": "screenshot.png"
}
```

---

## send_image_from_url

Fetch an image from a public HTTPS URL, upload it to the homeserver
media repo, and post it as `m.image`. URL must be HTTPS. Redirects
limited to 3 hops. Fetch timeout 15 s. Max size: `MATRIX_MCP_UPLOAD_MAX_BYTES`
(default 10 MiB).

**Category:** write  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `image_url` | string | required | HTTPS URL of the image |
| `caption` | string | `null` | Optional caption. If set, becomes `body`; URL basename becomes `filename`. |

**Returns:**
```json
{
  "event_id": "$imageEvent:kampong.social",
  "mxc_uri": "mxc://kampong.social/abc123"
}
```

---

## search_messages

Search Matrix room history using the homeserver's full-text search index
(`POST /_matrix/client/v3/search`). Results ordered by relevance. For
E2EE rooms `body` is always `null` – the homeserver cannot decrypt
ciphertext for indexing.

**Category:** read  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `query` | string | required | Full-text search query |
| `room_id` | string | `null` | Scope to one room. If omitted, searches all joined rooms. |
| `limit` | integer | `20` | Max results. Capped at 100. |

**Returns:**
```json
{
  "results": [
    {
      "event_id": "$abc:kampong.social",
      "room_id": "!abc:kampong.social",
      "sender": "@julian:kampong.social",
      "origin_server_ts": 1747267200000,
      "rank": 1.23,
      "body": "Hello world"
    }
  ],
  "total": 5
}
```

---

## join_room

Join a Matrix room by id or canonical alias. Returns the canonical room
id after joining.

**Category:** write  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id_or_alias` | string | required | Room id (`!abc:server`) or alias (`#name:server`) |

**Returns:**
```json
{ "room_id": "!abc:kampong.social" }
```

---

## leave_room

Leave a Matrix room.

**Category:** write  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |

**Returns:**
```json
{ "room_id": "!abc:kampong.social" }
```

---

## invite_user

Invite a Matrix user to a room. The homeserver enforces ACL (power level
vs. `invite` threshold).

**Category:** write  
**Params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `room_id` | string | required | Matrix room id |
| `mxid` | string | required | MXID to invite, e.g. `@alice:kampong.social` |

**Returns:**
```json
{
  "room_id": "!abc:kampong.social",
  "mxid": "@alice:kampong.social"
}
```
