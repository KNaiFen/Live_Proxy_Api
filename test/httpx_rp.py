import httpx

from http import HTTPStatus

from starlette.applications import Starlette
from starlette.responses import Response

app = Starlette()

async def proxy_app(request) -> Response:
    full_path = request.url.path
    url = f"https://api.live.bilibili.com/{full_path}"
    
    headers = {k[5:].replace('_', '-').title(): v for k, v in request.headers.items() if k.startswith('HTTP_')}
    headers.pop('Host', None)
    headers.pop('Accept-Encoding', None)
    headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=request.query_params)
            return Response(content=response.content, status_code=response.status_code, headers=response.headers)
    except Exception as e:
        return Response(content=str(e), status_code=HTTPStatus.INTERNAL_SERVER_ERROR)

app.add_route("/{path:path}", proxy_app, methods=["GET"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=6111)
