# SQL注入漏洞
##### 漏洞位置: /api/v1/datacenterTable/getPageData
##### 影响范围: AiFlowy <= V2.1.2
##### 漏洞成因: DatacenterQuery.java 文件中的getPageData方法接收参数where，未经过过滤直接带入到SQL查询语句中，造成SQL注入漏洞。
##### 漏洞影响: 获取数据库访问权限，甚至获得DBA权限；获取其他数据库中的数据；
##### 官方链接: https://gitee.com/aiflowy/aiflowy
# 漏洞复现

漏洞出现在后台中的数据中枢功能点：

<img width="2433" height="570" alt="image" src="https://github.com/user-attachments/assets/c813de80-97e1-4499-ae8b-ff3302a8e36b" />

当传递参数where的值为1=1时：

<img width="2433" height="1179" alt="image" src="https://github.com/user-attachments/assets/0773eaf0-70ae-47d8-990e-d2c4bfcb91c1" />

当传递参数where的值为1=12时：

<img width="2433" height="739" alt="image" src="https://github.com/user-attachments/assets/ee36eb43-84d7-41b2-8773-c6eff3192e99" />

# 代码分析

利用动态调试进行分析：

<img width="2433" height="834" alt="image" src="https://github.com/user-attachments/assets/a969c200-a590-4ed0-8f9e-50e4a19d0acd" />

请求的是 getPageData，接收的参数是一个 DatacenterQuery 对象，跟进到这个类中观察：

<img width="1622" height="1265" alt="image" src="https://github.com/user-attachments/assets/6079cf86-5d8f-4ef3-864b-6121bca00a93" />

存在多个参数，比如 tableId、where 等，通过 GET 参数自动绑定！此时参数都是由用户完全控制的！

<img width="2433" height="976" alt="image" src="https://github.com/user-attachments/assets/347aba37-3b13-40e3-b36a-5a73a0f6d64f" />

<img width="2433" height="814" alt="image" src="https://github.com/user-attachments/assets/a2622a19-daff-465a-8fb6-b5fb05699fb8" />

断点下在 Controller 和 Service 层，跟进到 getPageData 方法中：

<img width="2306" height="1265" alt="image" src="https://github.com/user-attachments/assets/0d7ec475-85ed-454a-95f1-1f4676b8595c" />

这里先跟进到 count 参数处，在执行触发漏洞之前会先进行判断，判断 count 参数是不是 0，如果不是的话，才回继续往下执行，否则就直接 return。
所以这里需要满足 count 不为 0 才可以。那就跟进到 getCount 方法中：

<img width="2433" height="1222" alt="image" src="https://github.com/user-attachments/assets/fb96b525-8032-4f64-a176-fb6df5925e1c" />

可以先观察一下整个 SQL 语句，由于该项目采用的是 MyBatis-Flex。所以 SQL 语句并不会直接写在代码中！
这里的大概语句如下：

```sql
select count(*) from tb_dynamic_uu_387819835081773056 where tableid=387819835081773056 and 1=12
```

所以这里是没有查询到数据的，或者说当只见里这个表，而表里面没有数据的时候，count 的值就是 0。此时返回到上层调用的时候，count=0，if 语句就直接进入了，从而直接 return。

<img width="2301" height="1265" alt="image" src="https://github.com/user-attachments/assets/2e265ed6-a0bc-4b5e-ad8d-d2ba1715276a" />

当 count != 0 的时候，就不会进入 if 判断。继续往下走：

<img width="1966" height="1265" alt="image" src="https://github.com/user-attachments/assets/a062b915-8053-4ac4-9905-7683540e2c6b" />

当查询到表里面存在数据的时候，就会进入到下面的查询数据，通过 QueryWrapper 构建，跟进到 buildCondition 方法中：
看起来 wrapper.where 方法，实际上是存在安全问题的！

<img width="2433" height="1221" alt="image" src="https://github.com/user-attachments/assets/ed381591-61bc-4abe-a36f-b6e7112619ed" />


