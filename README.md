# Live_Proxy_Api
BILIBILI的直播API中间层，反代并负载均衡直播流API与Cookie

## 功能
### API
 - API池(多个)
 - 负载均衡权重
 - 健康检查
### cookie
 - cookie池
 - 负载均衡权重
 - 健康检查
### 通知
 - 邮件
 - Webhook(在写了)


## 使用
1. config.yaml中填写你所使用的直播流反代API和Cookie
2. 启动脚本 `py Api.py`
3. 把所使用的录播软件的直播流API看需求改为下列地址
```
# 使用Cookie
http://localhost:5683/use_cookie/{代理池名称}
# 不使用Cookie
http://localhost:5683/no_cookie/{代理池名称}
```


## 联系
```
# 录播姬闲聊群 179319267
```
![qrcode_1708848596572](https://github.com/KNaiFen/Live_Proxy_Api/assets/39889850/9bdc28b8-645f-40d7-b24f-36fe0dd3e37f)
