---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

A lightweight proxy protocol over TLS. Each TCP+TLS connection carries one
logical proxy stream at a time but may be reused for subsequent streams; the
first eight frames of every stream are randomly padded to flatten initial
packet-length signatures.

### Structure

```json
{
  "type": "simpletls",
  "tag": "simpletls-in",

  ... // Listen Fields

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "tls": {}
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

==Required==

SimpleTLS users.

#### tls

==Required==

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).
