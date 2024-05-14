import gevent.monkey
gevent.monkey.patch_all()

import gevent
import gevent.pywsgi
import requests

def proxy_app(environ, start_response):
    full_path = environ['PATH_INFO']
    url = f"https://api.live.bilibili.com/{full_path}"
    headers = {k: v for k, v in environ.items() if k.startswith('HTTP_')}
    headers.pop('HTTP_HOST', None)
    headers.pop('HTTP_ACCEPT_ENCODING', None)
    headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'

    try:
        response = requests.get(url, headers=headers, params=environ['QUERY_STRING'])
        start_response(f"{response.status_code} {response.reason}", list(response.headers.items()))
        yield response.content
    except Exception as e:
        start_response("500 Internal Server Error", [])
        yield str(e).encode()

if __name__ == "__main__":
    server = gevent.pywsgi.WSGIServer(('127.0.0.1', 6111), proxy_app)
    server.serve_forever()
