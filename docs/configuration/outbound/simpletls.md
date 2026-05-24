---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

A lightweight proxy protocol over TLS. Each TCP+TLS connection carries one
logical proxy stream at a time but may be reused for subsequent streams; the
first eight frames of every stream are randomly padded to flatten initial
packet-length signatures. UDP is tunnelled through UDP-over-TCP v2.

### Structure

```json
{
  "type": "simpletls",
  "tag": "simpletls-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "password": "8JCsPssfgS8tiRwiMlhARg==",
  "tls": {},

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### password

==Required==

The SimpleTLS password.

#### tls

==Required==

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
