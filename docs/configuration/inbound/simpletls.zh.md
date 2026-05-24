---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

基于 TLS 的轻量代理协议。每条 TCP+TLS 连接同时只承载一条逻辑代理流，但可被后续流复用；
每条流的前 8 个数据帧会被随机填充，用于打散初始数据包的长度特征。

### 结构

```json
{
  "type": "simpletls",
  "tag": "simpletls-in",

  ... // 监听字段

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "tls": {}
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### users

==必填==

SimpleTLS 用户列表。

#### tls

==必填==

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#入站)。
