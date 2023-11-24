from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Depends, Request

import requests

app = FastAPI()

# 静态文件
static = Jinja2Templates(directory="static")


URL = 'http://127.0.0.1:5683'
SECRET_KEY = "YourSecretKey"


@app.get("/status", response_class=HTMLResponse)
def show_status(request: Request):
    # 获取信息数据
    pools_result = requests.get(f"{URL}/api_status/request_pools_count")
    health_result = requests.get(f"{URL}/api_status/request_health_data", headers={'Authorization': SECRET_KEY})
    cookie_result = requests.get(f"{URL}/api_status/cookie_health_data", headers={'Authorization': SECRET_KEY})
    health_status_result = requests.get(f"{URL}/api_status/health_status_number")

    # 处理信息数据
    pools_data = pools_result.json().get('pools_data', [])
    health_data = health_result.json().get('health_data', [])
    health_cookies = cookie_result.json().get('health_cookie', [])
    no_health_cookies = cookie_result.json().get('no_health_cookie', [])
    request_status = health_status_result.json().get('request_status', {})
    cookie_status = health_status_result.json().get('cookie_status', 0)

    return static.TemplateResponse("status.html", {
        "request": request,
        "request_pools": pools_data,
        "request_health": health_data,
        "health_cookies": health_cookies,
        "no_health_cookies": no_health_cookies,
        "request_status": request_status,
        "cookie_status": cookie_status
    })


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=45678)
