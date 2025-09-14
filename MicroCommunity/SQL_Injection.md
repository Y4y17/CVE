# SQL Injection vulnerability
##### Vulnerability Location: /MicroCommunity/java110-db/src/main/resources/mapper/community/RepairServiceDaoImplMapper.xml
##### Affected Range: MicroCommunity v1.9
##### Vulnerability Cause: RepairName RepairServiceDaoImplMapper.xml file using the ${} to splice, ListAdminOwnerRepairsCmd.java parameter passing, no relevant filter at the same time, resulting in SQL injection vulnerabilities
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions; Obtain data from other databases; Stealing users' confidential information includes accounts, personal private information, transaction information, etc.
##### Link: https://gitee.com/wuxw7/MicroCommunity The manufacturer's website address: http://www.homecommunity.cn/
# Vulnerability recurrence

Log in to the backend using your account and password

<img width="1425" height="722" alt="image" src="https://github.com/user-attachments/assets/23e5e605-f47a-43cf-a483-33c8a84374da" />

Click on "Work Order", then click on "Community Repair Report", and capture the corresponding data package as follows

<img width="1828" height="715" alt="image" src="https://github.com/user-attachments/assets/11cd0e84-c919-4726-aa30-c0117453c0c0" />

Modify the parameter "repairName" to obtain the database name：

<img width="1784" height="839" alt="image" src="https://github.com/user-attachments/assets/a7541766-e4fa-4c50-a471-97657e69f697" />

The database name can be obtained.

# Code Analysis

Locating the source location: /service-community/SRC/main/java/com/java110/community/cmd/ownerRepair/ListAdminOwnerRepairsCmd.Java

<img width="1031" height="735" alt="image" src="https://github.com/user-attachments/assets/fafea2f6-7c64-4887-9b4b-d5493f0234cf" />

After debug code found problems in the cmd method, the code is as follows: int count = repairInnerServiceSMOImpl.queryRepairsCount(ownerRepairDto);
Continue to follow up:

<img width="1618" height="616" alt="image" src="https://github.com/user-attachments/assets/c310cac5-180e-46da-83f6-51585eb787c7" />

This class is a hallmark of the work of Spring AOP. This class is not the original instance of the interface implementation class, but a Proxy object created by Spring. Here, a suspicious calling method was found in the Method. So, an attempt was made to set a breakpoint in this method. debug directly jumped to the next breakpoint, and it was discovered that the code directly skipped the Proxy and successfully reached the breakpoint

<img width="1454" height="609" alt="image" src="https://github.com/user-attachments/assets/87895782-b3ef-4ab2-abde-817b82eb096b" />

Then, in the above code, it can be seen that the bean is converted into a map collection, and then the queryRepairCount of repairServiceDaoImpl is called, and then it continues to follow up:

<img width="1271" height="755" alt="image" src="https://github.com/user-attachments/assets/0119ffc4-4883-4e16-8416-568eb5501d06" />

Once the corresponding SQL mapping file is found, just use namespace="repairServiceDaoImpl" as the file name to search for it:

<img width="1172" height="226" alt="image" src="https://github.com/user-attachments/assets/0e83285d-98e2-4ab8-b97e-8ae9e6d15c05" />

After locating the specific file, directly search for id="queryRepairsCount" within the file. The content is as follows:

<img width="1139" height="595" alt="image" src="https://github.com/user-attachments/assets/381f54b4-9027-4635-ac28-7e1090e5e92f" />

Among them, and t.epair_name like '%${repairName}%' is concatenated by ${}!
In Mybatis, ${} is directly concatenated! Therefore, there is an SQL injection vulnerability here!
