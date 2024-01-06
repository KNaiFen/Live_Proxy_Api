import requests

URL = 'http://127.0.0.1:5683'
SECRET_KEY = "YourSecretKey"


# 查询各个 反代API池 的调用次数和总调用次数 
def query_request_pools_count(url):
    result = requests.get(f"{url}/api_status/request_pools_count")
    
    if result.status_code == 200:
        data = result.json()
        pools_data = data.get('pools_data', [])

        for pool_data in pools_data:
            for pool_name, stats in pool_data.items():
                total_requests = stats['total_requests']
                recent_requests = stats['recent_requests']
                frequency_per_minute = stats['total_frequency_per_minute']
                recent_frequency_per_minute = recent_requests / 10
                print(f"反代池: {pool_name:7} | 总次数: {total_requests:6} | 10MIN 内次数: {recent_requests:5} | 总频率: {frequency_per_minute:5.1f} 次/MIN | 10MIN 内频率: {recent_frequency_per_minute:4.1f} 次/MIN")

# 查询各个 反代API 健康率
def query_request_health_count(url):
    header = {'Authorization': SECRET_KEY}
    result = requests.get(f"{url}/api_status/request_health_data", headers=header)
    
    if result.status_code == 200:
        data = result.json()
        health_data = data.get('health_data', [])

        for entry in health_data:
            for api_url, stats in entry.items():
                health_rate = stats['health_rate'] * 100
                total_requests = stats['total']
                print(f"{api_url:35} | 健康率: {health_rate:5.1f}% | 检查次数: {total_requests}")

# 查询各个 COOKIE 健康率
def query_cookie_health_count(url):
    header = {'Authorization': SECRET_KEY}
    result = requests.get(f"{url}/api_status/cookie_health_data", headers=header)
    
    if result.status_code == 200:
        data = result.json()
        # print(f"data:{data}")
        health_cookies = data.get('health_cookie', [])
        no_health_cookies = data.get('no_health_cookie', [])

        print(f"健康Cookie数量: {len(health_cookies)}: ")
        for health_cookie in health_cookies:
            print(f"\nCookieID: {health_cookie['id']}\nCookie: {health_cookie['cookie']}")
        print(f"\n不健康Cookie数量: {len(no_health_cookies)}: ")
        for no_health_cookie in no_health_cookies:
            print(f"\nCookieID: {no_health_cookie['id']}\nCookie: {no_health_cookie['cookie']}")
        print()


# 查询当前总体健康情况
def query_health_status_number(url):
    result = requests.get(f"{url}/api_status/health_status_number")
    
    if result.status_code == 200:
        data = result.json()
        request_status = data.get('request_status', {})
        cookie_status = data.get('cookie_status', 0)

        print("当前各接口池的健康接口数量：")
        for pool_name, healthy_count in request_status.items():
            print(f"{pool_name:7}: {healthy_count}")
        print("当前健康Cookie数量：", cookie_status)


if __name__ == "__main__":
    def print_info():
        print(f"\n1: 查询各个 反代API池 的调用次数和总调用次数")
        print(f"2: 查询各个 反代API 健康率")
        print(f"3: 查询各个 Cookie 健康情况")
        print(f"4: 查询当前总体健康情况")
        print(f"99: 退出")
    print_info()
    INPUT = ''
    while(INPUT != '99'):
        INPUT = input("输入选项：")
        print()
        if INPUT == '1':
            query_request_pools_count(URL)
        elif INPUT == '2':
            query_request_health_count(URL)
        elif INPUT == '3':
            query_cookie_health_count(URL)
        elif INPUT == '4':
            query_health_status_number(URL)
        elif INPUT == '99':
            print("退出")
            break
        else:
            pass
        print_info()