from fastapi import FastAPI, Request, HTTPException, Depends, status, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler
import uuid
import logging
import httpx
import random
import os
import uvicorn
import requests
import re
import asyncio
from http import HTTPStatus
import yaml
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formatdate

# 根路径
root_dir = os.path.dirname(os.path.abspath(__file__))

# 定义fastapi路由
app = FastAPI()

# 静态文件目录
app.mount("/static", StaticFiles(directory="static"), name="static")

### 配置部分
## 读取配置文件
config_file_path = os.path.join(root_dir, "config.yaml")
with open(config_file_path, "r", encoding="utf-8") as file:
    config = yaml.safe_load(file)

## 监听IP和端口
HOST = config.get("HOST", "127.0.0.1")
PORT = config.get("PORT", 5687)

# UA
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

# API状态页的用户名和密码
api_status_config = config.get("API_STATUS", {})
api_status_enable = api_status_config.get("enable", False)
api_username = api_status_config.get("username", "admin")
api_password = api_status_config.get("password", "admin")

# API的认证密匙
API_KEY = config.get("API_KEY")
if not API_KEY:
    raise ValueError("[配置] API_KEY 不允许为空，请检查配置文件.")


## 健康检查部分
CONFIG_HC = config.get("HEALTH_CHECK", {})
## API配置
# API健康检查 间隔(秒)，默认180秒
INTERFACE_HEALTH_CHECK_INTERVAL = CONFIG_HC.get("API", {}).get("INTERVAL", 180)
# API健康检查 错误 最大重试次数，默认2次
DEFAULT_MAX_RETRIES = CONFIG_HC.get("API", {}).get("MAX_RETRY", 2)
# API健康检查 错误 重试间隔时间(秒)，默认10秒
DEFAULT_RETRY_INTERVAL = CONFIG_HC.get("API", {}).get("MAX_RETRY_INTERVAL", 10)
## Cookie
# Cookie健康检查间隔(秒)，默认3600秒
COOKIE_HEALTH_CHECK_INTERVAL = CONFIG_HC.get("COOKIE", {}).get("INTERVAL", 1 * 3600)

## API与Cookie池
INTERFACE_POOLS = config["INTERFACE_POOLS"]
ORIGINAL_COOKIESTR_POOL = config["COOKIESTR_POOL"]
HEALTH_INTERFACE_POOLS = {pool_name: [] for pool_name in INTERFACE_POOLS}
HEALTH_COOKIESTR_POOL = []

## SMTP配置
CONFIG_SMTP = config.get("SMTP", {})
SMTP_ENABLE = CONFIG_SMTP.get("enable", False)
SENDER_EMAIL = CONFIG_SMTP.get("sender_email", "")
SENDER_PASSWORD = CONFIG_SMTP.get("sender_password", "")
RECEIVER_EMAIL = CONFIG_SMTP.get("receiver_email", "")
SMTP_SERVER = CONFIG_SMTP.get("smtp_server", "")
SMTP_SSL = CONFIG_SMTP.get("smtp_ssl", "")
SMTP_PORT = CONFIG_SMTP.get("smtp_port", "")

webhook_host = config.get("WEBHOOKHOST", "")

### 日志模块
def log():
    global logger
    # 检查是否已经配置了处理器
    if logging.getLogger().handlers:
        return logging.getLogger()

    # 获取目录
    script_directory = os.path.dirname(os.path.abspath(__file__))
    log_directory = os.path.join(script_directory, "logs")
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    # 日志格式
    log_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(processName)s - %(message)s"
    )

    # 日志名称和后缀
    default_log_file_name = "api"
    log_file_path = os.path.join(log_directory, default_log_file_name)

    # 创建日志文件处理器,每天分割日志文件
    log_file_handler = TimedRotatingFileHandler(
        log_file_path,
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8",
    )
    log_file_handler.suffix = "%Y-%m-%d.log"
    log_file_handler.setFormatter(log_formatter)

    # 创建并配置 logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(log_file_handler)

    return logger


logger = log()



# 合并日志与打印信息
def log_and_print(message, prefix="", level="INFO"):
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    # 日志
    logger = logging.getLogger()
    logger.log(level, message)
    # 打印
    print(prefix + message)

### 通知相关
## SMTP
'''
调用 
smtp("标题", "内容")
'''
def smtp(subject, body):
    if not SMTP_ENABLE:
        return

    # 构建邮件
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    # 连接SMTP服务器并发送邮件
    try:
        if SMTP_SSL:
            server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        else:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        logger.debug("[SMTP] 邮件发送成功")
        server.quit()
    except Exception as e:
        log_and_print(f"[SMTP] 邮件发送失败: {e}", "ERROR:     ", "ERROR")

# SMTP 启动测试
async def smtp_start_test():
    if SMTP_ENABLE:
        try:
            if SMTP_SSL:
                server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=5)
            else:
                server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=5)
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            log_and_print("[SMTP] 邮件通知功能已启用", "INFO:     ", "INFO")
            log_and_print("[SMTP] 邮箱登录成功", "INFO:     ", "INFO")
            server.quit()
        except Exception as e:
            log_and_print(f"[SMTP] 邮箱登录失败: {e}", "ERROR:     ", "ERROR")
    else:
        logger.debug("[SMTP] 邮件通知功能禁用")


## WEBHOOK
'''
调用
webhook({"message": "事件data"}, "事件类型")
'''
async def webhook(event_data: dict, event_type: str):
    try:
        if not webhook_host:
            return {"message": "Webhook 功能未启用"}

        headers = {"Content-Type": "application/json", "User-Agent": "API_COOKIE_LB"}

        # 构建 Webhook 请求数据
        payload = {
            "EventType": event_type,
            "EventTimestamp": str(datetime.now()),
            "EventId": str(uuid.uuid4()),
            "EventData": event_data
        }

        # 发送 Webhook 请求
        response = requests.post(webhook_host, json=payload, headers=headers)
        response.raise_for_status()
        return {"message": "Webhook 请求已成功发送"}
    except requests.RequestException as req_error:
        logger.error(f"[Webhook] 无法发送 Webhook 请求: {req_error}")
        return {"error": f"无法发送 Webhook 请求: {req_error}"}
    except Exception as e:
        logger.error(f"[Webhook] 发生未知错误: {e}")
        return {"error": f"发生未知错误: {e}"}



# 异步 API检查请求
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
            # logger.error(f"Error: check_interface_health_async: {url}")
            pass
        except Exception as Error:
            # logger.error(f"Error: {Error}")
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
        except Exception as e:
            log_and_print(
                f"[状态] 检查 Cookie 时出错: {e}' 无效了", "ERROR:     ", "ERROR"
            )
            return False, None, None, None

    is_logged_in, _, _, _ = is_login(cookie)
    if is_logged_in:
        return True
    else:
        log_and_print(f"[状态] Cookie '{cookie_name}' 无效了", "WARN:     ", "WARNING")
        smtp("[状态] Cookie失效警告", f"Cookie '{cookie_name}' 无效了，请及时处理。")
        await webhook({"message": f"[状态] Cookie '{cookie_name}' 无效了，请及时处理。"}, "ExpiryCookie")
        return False

# 异步 API健康检查
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

        log_and_print(
            "[状态] 当前健康 API 数: " + ", ".join(f"{pool}: {len(urls)}" for pool, urls in HEALTH_INTERFACE_POOLS.items()),
            "INFO:     ",
            "INFO",
        )
        await webhook({"message": "[状态] 当前健康 API 数: " + ", ".join(f"{pool}: {len(urls)}" for pool, urls in HEALTH_INTERFACE_POOLS.items())}, "HealthAPI")

        try:
            await asyncio.sleep(INTERFACE_HEALTH_CHECK_INTERVAL)
        except asyncio.CancelledError:
            logger.debug("API健康检查任务被取消")
            break

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
        log_and_print(
            f"[状态] 当前健康 Cookie 数: {len(HEALTH_COOKIESTR_POOL)}",
            "INFO:     ",
            "INFO",
        )
        await webhook({"message": f"[状态] 当前健康 Cookie 数: {len(HEALTH_COOKIESTR_POOL)}"}, "HealthCookie")


        try:
            await asyncio.sleep(COOKIE_HEALTH_CHECK_INTERVAL)
        except asyncio.CancelledError:
            logger.debug("Cookie健康检查任务被取消")
            break

# 启动健康检查协程
async def start_health_check_coroutines():
    await asyncio.gather(interface_health_check_task(), cookie_health_check_task())

# 代理请求的通用函数
async def handle_proxy_request(
    pool_name: str, path: str, request: Request, use_cookie: bool
) -> Response:
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
        raise HTTPException(status_code=404, detail="不存在的代理池")

    update_request_stats(pool_name)

    pool = INTERFACE_POOLS[pool_name]["INTERFACE_POOL"]
    weighted_urls = [
        (url["url"], url["weight"])
        for url in pool
        if url["url"] in HEALTH_INTERFACE_POOLS[pool_name]
    ]
    target_url = weighted_choice(weighted_urls) if weighted_urls else None
    if not target_url:
        log_and_print("[请求] 没有可用的健康API", "WARN:     ", "WARNING")
        smtp("[请求] 没有可用的健康API", "没有可用的健康API，请及时处理。")
        await webhook({"message": f"[请求] 没有可用的健康API"}, "ExpiryAPI")
        raise HTTPException(status_code=400, detail="没有可用的健康API")

    method = request.method
    headers = {
        k[5:].replace("_", "-").title(): v
        for k, v in request.headers.items()
        if k.startswith("HTTP_")
    }
    headers.pop("Host", None)
    headers.pop("Accept-Encoding", None)
    headers["User-Agent"] = USER_AGENT

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
        logger.debug(f"[请求] 选择Cookie: {chosen_cookie}")
        if chosen_cookie:
            headers.pop("Cookie", None)
            headers["Cookie"] = chosen_cookie
        else:
            headers.pop("Cookie", None)
            log_and_print(
                "[请求] 没有配置 Cookie 或 Cookie 已过期", "WARN:     ", "WARNING"
            )
            smtp("[请求] 没有Cookie", "没有配置 Cookie 或 Cookie 已过期")
            await webhook({"message": f"[请求] 没有配置 Cookie 或 Cookie 已过期"}, "ErrorCookie")
    else:
        headers.pop("Cookie", None)

    url = f"{target_url}/{path}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method,
                url,
                headers=headers,
                params=request.query_params,
                content=await request.body(),
            )
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response.headers,
            )
    except httpx.HTTPError as http_err:
        raise HTTPException(
            status_code=http_err.response.status_code, detail=str(http_err)
        )
    except Exception as e:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(e))

# 对请求返回的结果进行加工处理 (强制原画、优选cdn(未来可期))
def liveStreamProcess(date_json):
    return date_json


# 代理请求的API
@app.get("/use_cookie/{pool_name}/{path:path}")
async def api_live(pool_name: str, path: str, request: Request):
    return await handle_proxy_request(pool_name, path, request, use_cookie=True)

@app.get("/no_cookie/{pool_name}/{path:path}")
async def api_live_no_cookie(pool_name: str, path: str, request: Request):
    return await handle_proxy_request(pool_name, path, request, use_cookie=False)


### API相关
## 配置相关

## 测试相关
# 邮件发送测试
@app.get("/api/smtp/test")
async def api_smtp_test(request: Request):
    auth_key = request.headers.get("Authorization")
    if auth_key != API_KEY:
        raise HTTPException(status_code=401, detail="未授权")
    
    if not SMTP_ENABLE:
        return {"error": "SMTP 功能未启用"}
        
    subject = "测试邮件"
    body = "这是一封测试邮件。"
    try:
        smtp(subject, body)
        return {"message": "测试邮件已发送"}
    except Exception as e:
        return {"error": f"邮件发送失败: {str(e)}"}



## 监控相关
# BA认证函数
def basic_auth(credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    correct_username = secrets.compare_digest(credentials.username, api_username)
    correct_password = secrets.compare_digest(credentials.password, api_password)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="账号或密码不正确",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials


# API状态页
if api_status_enable:

    @app.get("/api_status", dependencies=[Depends(basic_auth)])
    async def api_status_page():
        return FileResponse("static/api_status.html")


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

# 初始化API健康数据
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

# 当前总体健康情况
@app.get("/api/status")
async def health_status_number():
    request_status = {pool: len(urls) for pool, urls in HEALTH_INTERFACE_POOLS.items()}
    return {
        "request_status": request_status,
        "cookie_status": len(HEALTH_COOKIESTR_POOL),
    }

# 返回各个 反代API池 的调用次数和总调用次数
@app.get("/api/status/request")
async def request():
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
@app.get("/api/status/api/health")
async def api_health(request: Request):
    auth_key = request.headers.get("Authorization")
    if auth_key != API_KEY:
        raise HTTPException(status_code=401, detail="未授权")
    health_data = []
    for url, data in INTERFACE_HEALTH_DATA.items():
        health_rate = (
            (data["total_success"] / data["total"]) if data["total"] > 0 else 0
        )
        health_data.append({url: {"health_rate": health_rate, "total": data["total"]}})
    return {"health_data": health_data}

# 查询各个 Cookie 健康情况
@app.get("/api/status/cookie/health")
async def cookie_health(request: Request):
    health_info = []

    for user, cookie_data in ORIGINAL_COOKIESTR_POOL.items():
        try:
            user_health_status = any(
                cookie_item["cookie"] in HEALTH_COOKIESTR_POOL
                for cookie_item in cookie_data
            )

            health_info.append({"id": user, "healthy": user_health_status})

        except Exception as Error:
            logger.error(f"health_count: Error: {Error}")
            logger.error(f"Problematic cookie: {user}")

    return health_info



### 主线程启动
@asynccontextmanager
async def lifespan(app: FastAPI):
    async def start():
        log_and_print("程序启动, 开始进行 API&Cookie 健康检查", "INFO:     ", "INFO")
        # 健康检查
        asyncio.create_task(start_health_check_coroutines())
        # API数据清理
        asyncio.create_task(cleanup_old_stats())
        # 测试 SMTP 功能是否可用
        await smtp_start_test()

    await start()
    yield
    log_and_print("程序关闭", "INFO:     ", "INFO")

app = FastAPI(lifespan=lifespan)


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
