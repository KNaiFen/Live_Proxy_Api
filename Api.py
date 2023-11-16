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
    ORIGINAL_INTERFACE_POOL = config['INTERFACE_POOL']
    ORIGINAL_COOKIESTR_POOL = config['COOKIESTR_POOL']
healthy_interface_pool = []
healthy_cookiestr_pool = []

app = FastAPI()


async def check_interface_health_async(url: str) -> bool:
    '''实现 反代接口 的健康检查逻辑'''
    request_url = f"{url}/room/v1/Room/playUrl?cid=3&qn=10000&platform=web"
    try:
        with httpx.Client() as client:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            response = client.get(request_url, headers=headers)
        return response.status_code >= 200 and response.status_code < 300
    except httpx.HTTPError:
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
    global healthy_interface_pool
    while True:
        healthy_interface_pool = [url for url in ORIGINAL_INTERFACE_POOL if await check_interface_health_async(url)]
        log.info(f"当前健康 接口 数: {len(healthy_interface_pool)}")
        await asyncio.sleep(120)
async def cookie_health_check_task():
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


@app.get("/api_live_stream/{path:path}")
async def api_live_stream(path: str, request: Request):
    target_url = random.choice(healthy_interface_pool) if healthy_interface_pool else None
    chosen_cookie = random.choice(healthy_cookiestr_pool) if healthy_cookiestr_pool else None

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
