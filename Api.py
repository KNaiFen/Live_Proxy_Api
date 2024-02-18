from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import secrets
from datetime import datetime, timedelta
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

# 根路径
root_directory = os.path.dirname(os.path.abspath(__file__))

# 需要加密的接口的认证密匙
SECRET_KEY = "YourSecretKey"
# 统一UA
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36 Edg/97.0.1072.69"

### 日志部分
# 创建目录
logs_directory = os.path.join(root_directory, "logs")
Path(logs_directory).mkdir(parents=True, exist_ok=True)

# 配置日志格式
log_format = logging.Formatter(
    "%(asctime)s [%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)

# 创建文件处理器
log_file = os.path.join(logs_directory, "LB.log")
file_handler = TimedRotatingFileHandler(
    log_file, when="D", interval=1, backupCount=30, encoding="utf-8"
)
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


### 负载均衡API实现
# 配置文件
with open(os.path.join(root_directory, "config.yaml"), "r", encoding="utf-8") as file:
    config = yaml.safe_load(file)

INTERFACE_POOLS = config["INTERFACE_POOLS"]
ORIGINAL_COOKIESTR_POOL = config["COOKIESTR_POOL"]
HEALTH_INTERFACE_POOLS = {pool_name: [] for pool_name in INTERFACE_POOLS}
HEALTH_COOKIESTR_POOL = []

# 接口检查请求参数
DEFAULT_MAX_RETRIES = config.get("DEFAULT_MAX_RETRIES", 2)
DEFAULT_RETRY_INTERVAL = config.get("DEFAULT_RETRY_INTERVAL", 10)

# 健康检查的频率
INTERFACE_HEALTH_CHECK_INTERVAL = config.get("INTERFACE_HEALTH_CHECK_INTERVAL", 180)
COOKIE_HEALTH_CHECK_INTERVAL = config.get("INTERFACE_HEALTH_CHECK_INTERVAL", 1 * 3600)

# 提取 API 状态的用户名和密码
api_status_config = config.get("API_STATUS", {})
api_username = api_status_config.get("username", "default_username")
api_password = api_status_config.get("password", "default_password")

app = FastAPI()

# 设置基本认证
security = HTTPBasic()


# 认证函数
def basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, api_username)
    correct_password = secrets.compare_digest(credentials.password, api_password)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials


# 静态文件目录
app.mount("/static", StaticFiles(directory="static"), name="static")


# 主页路由，提供监控UI
@app.get("/api_status", dependencies=[Depends(basic_auth)])
async def api_status_page():
    return FileResponse("static/api_status.html")


# 异步 接口检查请求
async def check_interface_health_async(
    url: str,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_interval: int = DEFAULT_RETRY_INTERVAL,
) -> bool:
    global INTERFACE_HEALTH_DATA
    request_url = f"{url}/room/v1/Room/playUrl?cid=3&qn=10000&platform=web"
    headers = {"User-Agent": USER_AGENT}
    for _ in range(max_retries):
        try:
            INTERFACE_HEALTH_DATA[url]["total"] += 1
            async with httpx.AsyncClient() as client:
                response = await client.get(request_url, headers=headers, timeout=5)
            if response.status_code >= 200 and response.status_code < 300:
                INTERFACE_HEALTH_DATA[url]["total_success"] += 1
                return True
        except httpx.HTTPError as http_err:
            # log.error(f"Error: check_interface_health_async: {url}")
            pass
        except Exception as Error:
            # log.error(f"Error: {Error}")
            pass
        await asyncio.sleep(retry_interval)

    return False


# 异步 Cookie健康检查
async def check_cookie_health_async(cookie: str, cookie_name: str) -> bool:
    def is_login(cookie_str: str):
        url = "https://api.bilibili.com/x/web-interface/nav"
        try:
            pattern = r"bili_jct=([0-9a-zA-Z]+);"
            csrf = re.search(pattern, cookie_str).group(1)
            headers = {"User-Agent": USER_AGENT, "Cookie": cookie_str}
            response = requests.get(url, headers=headers)
            data = response.json()
            return data["code"] == 0, data, cookie_str, csrf
        except:
            return False, _, _, _

    is_logged_in, _, _, _ = is_login(cookie)
    if is_logged_in:
        return True
    log.warning(f"Cookie '{cookie_name}' 无效了")
    return False


# 异步 接口健康检查
async def interface_health_check_task():
    global HEALTH_INTERFACE_POOLS
    interface_health_status = {}
    for pool_name, pool in INTERFACE_POOLS.items():
        interface_health_status[pool_name] = {
            url["url"]: {"success_count": 0, "is_healthy": True}
            for url in pool["INTERFACE_POOL"]
        }

    while True:
        all_check_tasks = [
            (
                pool_name,
                url["url"],
                check_interface_health_async(
                    url["url"],
                    pool.get("max_retries", DEFAULT_MAX_RETRIES),
                    pool.get("retry_interval", DEFAULT_RETRY_INTERVAL),
                ),
            )
            for pool_name, pool in INTERFACE_POOLS.items()
            for url in pool["INTERFACE_POOL"]
        ]
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
            HEALTH_INTERFACE_POOLS[pool_name] = [
                url
                for url, status in interface_health_status[pool_name].items()
                if status["is_healthy"]
            ]

        log.info(
            "当前健康接口数: "
            + ", ".join(
                f"{pool}: {len(urls)}" for pool, urls in HEALTH_INTERFACE_POOLS.items()
            )
        )

        await asyncio.sleep(INTERFACE_HEALTH_CHECK_INTERVAL)


# 异步 执行Cookie的健康检查并管理
async def cookie_health_check_task():
    global HEALTH_COOKIESTR_POOL
    while True:
        healthy_cookies = []
        for cookie_name, cookies in ORIGINAL_COOKIESTR_POOL.items():
            for cookie_data in cookies:
                if await check_cookie_health_async(cookie_data["cookie"], cookie_name):
                    healthy_cookies.append(cookie_data["cookie"])

        HEALTH_COOKIESTR_POOL = healthy_cookies
        log.info(f"当前健康 Cookie 数: {len(HEALTH_COOKIESTR_POOL)}")
        await asyncio.sleep(COOKIE_HEALTH_CHECK_INTERVAL)


# 启动健康检查协程
async def start_health_check_coroutines():
    await asyncio.gather(interface_health_check_task(), cookie_health_check_task())


# 代理请求的接口
@app.get("/api_live/use_cookie/{pool_name}/{path:path}")
async def api_live(pool_name: str, path: str, request: Request):
    return await handle_proxy_request(pool_name, path, request, use_cookie=True)


@app.get("/api_live/no_cookie/{pool_name}/{path:path}")
async def api_live_no_cookie(pool_name: str, path: str, request: Request):
    return await handle_proxy_request(pool_name, path, request, use_cookie=False)


# 代理请求的通用函数
async def handle_proxy_request(
    pool_name: str, path: str, request: Request, use_cookie: bool
):
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

    update_request_stats(pool_name)

    pool = INTERFACE_POOLS[pool_name]["INTERFACE_POOL"]
    weighted_urls = [
        (url["url"], url["weight"])
        for url in pool
        if url["url"] in HEALTH_INTERFACE_POOLS[pool_name]
    ]
    target_url = weighted_choice(weighted_urls) if weighted_urls else None
    # chosen_cookie = random.choice(HEALTH_COOKIESTR_POOL) if HEALTH_COOKIESTR_POOL else None

    if not target_url:
        log.warning("没有可用的健康接口")
        raise HTTPException(status_code=400, detail="No healthy interfaces available")

    method = request.method
    headers = dict(request.headers)
    query_params = request.query_params
    body = await request.body()

    if use_cookie:
        weighted_healthy_cookies = [
            (cookie_data["cookie"], cookie_data["weight"])
            for user_cookies in ORIGINAL_COOKIESTR_POOL.values()
            for cookie_data in user_cookies
            if cookie_data["cookie"] in HEALTH_COOKIESTR_POOL
        ]
        chosen_cookie = (
            weighted_choice(weighted_healthy_cookies)
            if weighted_healthy_cookies
            else None
        )
        # log.info(f"选择Cookie: {chosen_cookie}")
        if chosen_cookie:
            headers.pop("cookie", None)
            headers.pop("host", None)
            headers["Cookie"] = chosen_cookie
        else:
            headers.pop("host", None)
            headers["Cookie"] = ""
            log.warning("没有配置 Cookie 或 Cookie 已过期")
    else:
        headers.pop("cookie", None)
        headers.pop("host", None)
        headers["Cookie"] = ""

    async with httpx.AsyncClient() as client:
        try:
            log.info(f"Request: {target_url}/{path}")
            response = await client.request(
                method,
                f"{target_url}/{path}",
                headers=headers,
                params=query_params,
                content=body,
            )
        except httpx.HTTPError as http_err:
            return {"Error": str(http_err)}

    try:
        data = json.loads(response.content.decode("utf-8", "ignore"))
    except json.JSONDecodeError:
        log.error("JSON解析错误")
        raise HTTPException(status_code=500, detail="Invalid JSON response")
    return liveStreamProcess(data)


# 对请求返回的结果进行加工处理
def liveStreamProcess(date_json):
    return date_json


### 监控相关
# 初始化 request_data
REQUEST_DATA = {
    pool_name: {
        "total_requests": 0,
        "recent_requests": 0,
        "recent_requests_timestamps": [],
        "creation_time": datetime.now(),
    }
    for pool_name in config["INTERFACE_POOLS"]
}

# 初始化接口健康数据
INTERFACE_HEALTH_DATA = {
    item["url"]: {"total": 0, "total_success": 0}
    for pool in config["INTERFACE_POOLS"].values()
    for item in pool["INTERFACE_POOL"]
}


# 清理 request_data 旧数据
async def cleanup_old_stats():
    while True:
        ten_minutes_ago = datetime.now() - timedelta(minutes=10)
        for data in REQUEST_DATA.values():
            data["recent_requests_timestamps"] = [
                t for t in data["recent_requests_timestamps"] if t > ten_minutes_ago
            ]
            recent_count = len(data["recent_requests_timestamps"]) * 10
            data["recent_requests"] = recent_count + data["recent_requests"] % 10
        await asyncio.sleep(60)


# 更新 request_data 请求数据
def update_request_stats(pool_name):
    now = datetime.now()
    data = REQUEST_DATA[pool_name]
    data["total_requests"] += 1
    data["recent_requests"] += 1

    if data["recent_requests"] % 10 == 0:
        data["recent_requests_timestamps"].append(now)


# 返回各个 反代API池 的调用次数和总调用次数
@app.get("/api_status/request_pools_count")
async def request_pools_count():
    # request_data 总体频率计算
    def calculate_total_frequency(pool_name):
        data = REQUEST_DATA[pool_name]
        duration = datetime.now() - data["creation_time"]
        total_frequency = data["total_requests"] / (
            duration.total_seconds() / 60
        )  # 每分钟请求次数
        return round(total_frequency, 1)

    pools_data = []
    for pool_name, data in REQUEST_DATA.items():
        total_frequency = calculate_total_frequency(pool_name)
        pool_stats = {
            pool_name: {
                "total_requests": data["total_requests"],
                "recent_requests": data["recent_requests"],
                "total_frequency_per_minute": total_frequency,
            }
        }
        pools_data.append(pool_stats)
    return {"pools_data": pools_data}


# 查询各个 反代API 健康率
@app.get("/api_status/request_health_data")
async def request_health_count(request: Request):
    auth_key = request.headers.get("Authorization")
    if auth_key != SECRET_KEY:
        raise HTTPException(status_code=404, detail="Unauthorized")

    health_data = []
    for url, data in INTERFACE_HEALTH_DATA.items():
        health_rate = (
            (data["total_success"] / data["total"]) if data["total"] > 0 else 0
        )
        health_data.append({url: {"health_rate": health_rate, "total": data["total"]}})
    return {"health_data": health_data}


# 查询各个 Cookie 健康情况
@app.get("/api_status/cookie_health_data")
async def cookie_health_count(request: Request):
    auth_key = request.headers.get("Authorization")
    if auth_key != SECRET_KEY:
        raise HTTPException(status_code=404, detail="Unauthorized")

    health_cookie = []
    no_health_cookie = []
    for user, cookie_data in ORIGINAL_COOKIESTR_POOL.items():
        try:
            user_health_cookies = []
            user_no_health_cookies = []

            # 检查每个用户的 cookie 是否在健康池中
            for cookie_item in cookie_data:
                if cookie_item["cookie"] in HEALTH_COOKIESTR_POOL:
                    user_health_cookies.append(
                        {"id": user, "cookie": cookie_item["cookie"]}
                    )
                else:
                    user_no_health_cookies.append(
                        {"id": user, "cookie": cookie_item["cookie"]}
                    )

            health_cookie.extend(user_health_cookies)
            no_health_cookie.extend(user_no_health_cookies)

        except Exception as Error:
            log.error(f"health_count: Error: {Error}")
            log.error(f"Problematic cookie: {user}")

    return {"health_cookie": health_cookie, "no_health_cookie": no_health_cookie}


# 当前总体健康情况
@app.get("/api_status/health_status_number")
async def health_status_number():
    request_status = {pool: len(urls) for pool, urls in HEALTH_INTERFACE_POOLS.items()}
    return {
        "request_status": request_status,
        "cookie_status": len(HEALTH_COOKIESTR_POOL),
    }


### 主线程启动
# 启动时事件处理
@app.on_event("startup")
async def on_startup():
    # 健康检查
    asyncio.create_task(start_health_check_coroutines())
    # 接口数据清理
    asyncio.create_task(cleanup_old_stats())


if __name__ == "__main__":
    uvicorn.run(app, host="10.0.0.101", port=5683)
