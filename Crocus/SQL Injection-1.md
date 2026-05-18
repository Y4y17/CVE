# SQL Injection vulnerability
##### Vulnerability Location: DeviceInfoMapper.xml
##### Affected Range: Crocus V1.3.44
##### Vulnerability Cause: The DeviceInfoMapper.xml file contains an SQL injection vulnerability, specifically an orderby injection vulnerability, which uses ${}.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions; Obtain data from other databases; Stealing users' confidential information includes accounts, personal private information, transaction information, etc.
##### Link: https://cn.streamax.com/
# Vulnerability recurrence

Using delayed injection, the echo time is 5 seconds.

<img width="1085" height="614" alt="image" src="https://github.com/user-attachments/assets/8ddd44c5-abfb-4542-92b7-95aba2b021b6" />

 Using a script, the database username was obtained as root@localhost:

 <img width="849" height="525" alt="image" src="https://github.com/user-attachments/assets/78e35912-a51b-4e8c-8663-812e199d3085" />

# Code Analysis

The DeviceInfoMapper.xml file contains an SQL injection vulnerability, specifically an orderby injection vulnerability, which uses ${}.

<img width="953" height="551" alt="image" src="https://github.com/user-attachments/assets/dd0e8d94-661f-44f1-bcfd-448436b300a1" />

Follow up to the Mapper layer: IDeviceInfoMapper.java

<img width="915" height="269" alt="image" src="https://github.com/user-attachments/assets/9e97314c-cc34-4f40-a89a-098aa0036e8c" />

Continue upwards to the Service layer:

<img width="1170" height="598" alt="image" src="https://github.com/user-attachments/assets/f3f5e392-9af5-40b3-85fb-fe787b2e107d" />

As you can see, the `queryFromLast()` method calls `this.mapper.queryFromLast(item)`. The parameters passed to this method are validated using `CommonFunction.validate()`. Further investigation into this method reveals a check for SQL injection.

<img width="784" height="292" alt="image" src="https://github.com/user-attachments/assets/7c92f3ff-74ec-4c83-be3d-05f23b33a0b9" />

It was discovered that this method only checks whether the parameter value is empty!

<img width="1053" height="583" alt="image" src="https://github.com/user-attachments/assets/cce630bb-f8fa-455a-be1d-209a8a0accce" />

This vulnerability is a front-end vulnerability, located around lines 22-25 of CommandFilter.java:

<img width="606" height="398" alt="image" src="https://github.com/user-attachments/assets/7093a916-038b-4916-aa6e-dad4f9a9e906" />

This uses Java's `!=` for string comparison. `request.getParameter("Action")` returns a new String object, which is not the same object reference as the string literal "" in the code, so `action != ""` will always be true (as long as `action` is not null).



