from fastapi import FastAPI, Request, HTTPException
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler
import logging
import httpx
import random
import os
import uvicorn
import requests
import re
import asyncio
import json
import yaml

# 路径
root_directory = os.path.dirname(os.path.abspath(__file__))


## 日志部分
# 创建目录
logs_directory = os.path.join(root_directory, 'logs')
Path(logs_directory).mkdir(parents=True, exist_ok=True)

# 配置日志格式
log_format = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# 创建文件处理器
log_file = os.path.join(logs_directory, 'LB.log')
file_handler = TimedRotatingFileHandler(log_file, when="D", interval=1, backupCount=30, encoding="utf-8")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_format)

# 创建流处理器，用于输出日志到控制台
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(log_format)

# 配置根日志记录器
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)

# 配置特定的日志记录器
log = logging.getLogger("Root")
log.setLevel(logging.INFO)
log.addHandler(stream_handler)


# 配置文件
with open(os.path.join(root_directory, 'config.yaml'), 'r') as file:
    config = yaml.safe_load(file)
INTERFACE_POOLS = config['INTERFACE_POOLS']
ORIGINAL_COOKIESTR_POOL = list(set(config['COOKIESTR_POOL']))
HEALTH_INTERFACE_POOLS = {pool_name: [] for pool_name in INTERFACE_POOLS}

app = FastAPI()

# 异步 接口检查请求
async def check_interface_health_async(url: str) -> bool:
    request_url = f"{url}/room/v1/Room/playUrl?cid=3&qn=10000&platform=web"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    for _ in range(2):
        try:
            with httpx.Client() as client:
                response = client.get(request_url, headers=headers)
            if response.status_code >= 200 and response.status_code < 300:
                return True
        except httpx.HTTPError:
            pass
        await asyncio.sleep(10)
    return False

# 异步 Cookie健康检查
async def check_cookie_health_async(cookie: str) -> bool:
    def is_login(cookie_str: str):
        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36 Edg/97.0.1072.69'
        url = 'https://api.bilibili.com/x/web-interface/nav'
        try:
            pattern = r'bili_jct=([0-9a-zA-Z]+);'
            csrf = re.search(pattern, cookie_str).group(1)
            headers = {'User-Agent': user_agent, 'Cookie': cookie_str}
            response = requests.get(url, headers=headers)
            data = response.json()
            return data['code'] == 0, data, cookie_str, csrf
        except:
            return False, _, _, _

    is_logged_in, _, _, _ = is_login(cookie)
    if is_logged_in:
        return True
    return False

# 异步 接口健康检查
async def interface_health_check_task():
    global HEALTH_INTERFACE_POOLS
    interface_health_status = {}
    for pool_name, pool in INTERFACE_POOLS.items():
        interface_health_status[pool_name] = {url['url']: {"success_count": 0, "is_healthy": True} for url in pool['INTERFACE_POOL']}
    
    while True:
        all_check_tasks = [(pool_name, url['url'], check_interface_health_async(url['url'])) 
                           for pool_name, pool in INTERFACE_POOLS.items()
                           for url in pool['INTERFACE_POOL']]
        check_results = await asyncio.gather(*[task for _, _, task in all_check_tasks])

        for (pool_name, url, _), result in zip(all_check_tasks, check_results):
            if result:
                interface_health_status[pool_name][url]["success_count"] += 1
                if interface_health_status[pool_name][url]["success_count"] >= 2:
                    interface_health_status[pool_name][url]["is_healthy"] = True
            else:
                interface_health_status[pool_name][url]["success_count"] = 0
                interface_health_status[pool_name][url]["is_healthy"] = False
        for pool_name in INTERFACE_POOLS:
            HEALTH_INTERFACE_POOLS[pool_name] = [url for url, status in interface_health_status[pool_name].items() if status["is_healthy"]]

        log.info("当前健康接口数: " + ", ".join(f"{pool}: {len(urls)}" for pool, urls in HEALTH_INTERFACE_POOLS.items()))
        await asyncio.sleep(180)

# 异步 执行Cookie的健康检查并管理
async def cookie_health_check_task():
    while True:
        healthy_cookiestr_pool = [cookie for cookie in ORIGINAL_COOKIESTR_POOL if await check_cookie_health_async(cookie)]
        log.info(f"当前健康 Cookie 数: {len(healthy_cookiestr_pool)}")
        await asyncio.sleep(12 * 3600)

# 启动健康检查协程
async def start_health_check_coroutines():
    await asyncio.gather(
        interface_health_check_task(),
        cookie_health_check_task()
    )

# 代理请求的接口
@app.get("/api_live/use_cookie/{pool_name}/{path:path}")
async def api_live(pool_name: str, path: str, request: Request):
    return await handle_proxy_request(pool_name, path, request, use_cookie=True)
@app.get("/api_live/no_cookie/{pool_name}/{path:path}")
async def api_live_no_cookie(pool_name: str, path: str, request: Request):
    return await handle_proxy_request(pool_name, path, request, use_cookie=False)

# 代理请求的通用函数
async def handle_proxy_request(pool_name: str, path: str, request: Request, use_cookie: bool):
    def weighted_choice(choices):
        total = sum(weight for _, weight in choices)
        r = random.uniform(0, total)
        upto = 0
        for choice, weight in choices:
            if upto + weight >= r:
                return choice
            upto += weight
        assert False, "Oops!"

    if pool_name not in HEALTH_INTERFACE_POOLS:
        raise HTTPException(status_code=404, detail="Pool not found")

    pool = INTERFACE_POOLS[pool_name]['INTERFACE_POOL']
    weighted_urls = [(url['url'], url['weight']) for url in pool if url['url'] in HEALTH_INTERFACE_POOLS[pool_name]]
    target_url = weighted_choice(weighted_urls) if weighted_urls else None
    chosen_cookie = random.choice(ORIGINAL_COOKIESTR_POOL) if ORIGINAL_COOKIESTR_POOL else None

    if not target_url:
        log.warning("没有可用的健康接口")
        raise HTTPException(status_code=400, detail="No healthy interfaces available")

    method = request.method
    headers = dict(request.headers)
    query_params = request.query_params
    body = await request.body()

    if use_cookie:
        if chosen_cookie:
            headers.pop('cookie', None)
            headers.pop('host', None)
            headers["Cookie"] = chosen_cookie
        else:
            headers.pop('host', None)
            headers["Cookie"] = ""
            log.warning("没有配置 Cookie 或 Cookie 已过期")
    else:
        headers.pop('cookie', None)
        headers.pop('host', None)
        headers["Cookie"] = ""

    async with httpx.AsyncClient() as client:
        try:
            log.info(f"Request: {target_url}/{path}")
            response = await client.request(
                method,
                f"{target_url}/{path}",
                headers=headers,
                params=query_params,
                content=body
            )
        except httpx.HTTPError as http_err:
            return {"Error": str(http_err)}
        
    try:
        data = json.loads(response.content.decode('utf-8', 'ignore'))
    except json.JSONDecodeError:
        log.error("JSON解析错误")
        raise HTTPException(status_code=500, detail="Invalid JSON response")
    return liveStreamProcess(data)

# 对请求返回的结果进行加工处理
def liveStreamProcess(date_json):
    return date_json

# 启动时事件处理
@app.on_event("startup")
async def on_startup():
    asyncio.create_task(start_health_check_coroutines())

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5683)
