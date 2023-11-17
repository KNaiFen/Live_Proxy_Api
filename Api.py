from fastapi import FastAPI, BackgroundTasks, Request, HTTPException
from loguru import logger
import httpx
import random
import os
import time
import uvicorn
import sys
import requests
import re
import asyncio
import json
import yaml

root_directory = os.path.dirname(os.path.abspath(__file__))

# Log
logger.remove()
logger.add(
    sys.stdout,
    colorize=True,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{message}</level>",
    backtrace=True,
    diagnose=True,
)
log = logger.bind(user="Root")

# 接口池和Cookie池
with open(os.path.join(root_directory, 'config.yaml'), 'r') as file:
    config = yaml.safe_load(file)
INTERFACE_POOLS = config['INTERFACE_POOLS']
ORIGINAL_COOKIESTR_POOL = list(set(config['COOKIESTR_POOL']))
healthy_interface_pools = {pool_name: [] for pool_name in INTERFACE_POOLS}

app = FastAPI()


async def check_interface_health_async(url: str) -> bool:
    '''实现 反代接口 的健康检查逻辑'''
    request_url = f"{url}/room/v1/Room/playUrl?cid=3&qn=10000&platform=web"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    for _ in range(2):  # 尝试两次
        try:
            with httpx.Client() as client:
                response = client.get(request_url, headers=headers)
            if response.status_code >= 200 and response.status_code < 300:
                return True
        except httpx.HTTPError:
            pass
        await asyncio.sleep(10)  # 等待10秒后再次尝试
    return False


async def check_cookie_health_async(cookie: str) -> bool:
    '''实现 Cookie 健康检查逻辑'''
    def is_login(cookie_str : str):
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


async def interface_health_check_task():
    '''执行 接口 的健康检查并管理'''
    global healthy_interface_pools
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
                if interface_health_status[pool_name][url]["success_count"] >= 3:
                    interface_health_status[pool_name][url]["is_healthy"] = True
            else:
                interface_health_status[pool_name][url]["success_count"] = 0
                interface_health_status[pool_name][url]["is_healthy"] = False
        for pool_name in INTERFACE_POOLS:
            healthy_interface_pools[pool_name] = [url for url, status in interface_health_status[pool_name].items() if status["is_healthy"]]

        log.info("当前健康接口数: " + ", ".join(f"{pool}: {len(urls)}" for pool, urls in healthy_interface_pools.items()))
        await asyncio.sleep(60)


async def cookie_health_check_task():
    '''执行 Cookie 的健康检查并管理'''
    global healthy_cookiestr_pool
    while True:
        healthy_cookiestr_pool = [cookie for cookie in ORIGINAL_COOKIESTR_POOL if await check_cookie_health_async(cookie)]
        log.info(f"当前健康 Cookie 数: {len(healthy_cookiestr_pool)}")
        await asyncio.sleep(12 * 3600)


async def start_health_check_coroutines():
    await asyncio.gather(
        interface_health_check_task(),
        cookie_health_check_task()
    )


@app.get("/api_live_stream/{pool_name}/{path:path}")
async def api_live_stream(pool_name: str, path: str, request: Request):
    def weighted_choice(choices):
        total = sum(weight for _, weight in choices)
        r = random.uniform(0, total)
        upto = 0
        for choice, weight in choices:
            if upto + weight >= r:
                return choice
            upto += weight
        assert False, "Oops!"

    if pool_name not in healthy_interface_pools:
        raise HTTPException(status_code=404, detail="Pool not found")

    pool = INTERFACE_POOLS[pool_name]['INTERFACE_POOL']
    weighted_urls = [(url['url'], url['weight']) for url in pool if url['url'] in healthy_interface_pools[pool_name]]
    target_url = weighted_choice(weighted_urls) if weighted_urls else None
    chosen_cookie = random.choice(ORIGINAL_COOKIESTR_POOL) if ORIGINAL_COOKIESTR_POOL else None

    if not target_url or not chosen_cookie:
        log.error(f"No healthy interfaces or cookies available")
        raise HTTPException(status_code=400, detail="No healthy interfaces or cookies available")

    method = request.method
    headers = dict(request.headers)
    query_params = request.query_params
    body = await request.body()

    headers.pop('cookie', None)
    headers.pop('host', None)
    headers["Cookie"] = chosen_cookie
    # log.info(headers)

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
        data = json.loads(response.content)
    except json.JSONDecodeError:
        log.error("Invalid JSON response")
        raise HTTPException(status_code=500, detail="Invalid JSON response")
    return liveStreamProcess(data)


def liveStreamProcess(date_json):
    '''对返回的JSON进行处理'''
    return date_json


@app.on_event("startup")
async def on_startup():
    asyncio.create_task(start_health_check_coroutines())


if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=5683)
