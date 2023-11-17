# Live_Proxy_Api
BILIBILI的直播API中间层，反代并负载均衡直播流API与Cookie

## 功能
 - 多个代理池
 - 根据权重随机选择代理池内的一个反代API使用
 - 代理的健康检查功能
 - cookie池，随机选择cookie使用
 - cookie的健康检查功能


## 使用
1. config.yaml中填写你所使用的直播流反代API和你的Cookie
2. 启动脚本 `py Api.py`
3. 把你所使用的录播软件的直播流API改为 `http://localhost:5683/api_live_stream/{代理池名称}`