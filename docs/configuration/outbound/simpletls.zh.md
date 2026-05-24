---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

基于 TLS 的轻量代理协议。每条 TCP+TLS 连接同时只承载一条逻辑代理流，但可被后续流复用；
每条流的前 8 个数据帧会被随机填充，用于打散初始数据包的长度特征。UDP 通过 UDP-over-TCP v2 承载。

### 结构

```json
{
  "type": "simpletls",
  "tag": "simpletls-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "password": "8JCsPssfgS8tiRwiMlhARg==",
  "tls": {},

  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### password

==必填==

SimpleTLS 密码。

#### tls

==必填==

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#出站)。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
