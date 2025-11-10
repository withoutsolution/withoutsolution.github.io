---
title: "bruteforcingtools"
quote: tryhackme
categories:
  - 技术
  - 教程
tags: [tools, brute-forcing]
description: Brute Forcing Tools
sidebar: false
outline: deep
---

# Brute Forcing Tools

前缀目录

```bash
ffuf -w raft-small-words.txt -u http://10.10.36.45:1337/hmr_FUZZ -s
```
```bash
awk '{print "hmr_"$0}' raft-small-words.txt > hmr_prefixed_wordlist.txt
gobuster dir -u http://10.10.36.45:1337/ -w hmr_prefixed_wordlist.txt
```



## Gobuster

gobuster is an open-source offensive tool written in Golang. It enumerates web directories, DNS subdomains, vhosts, Amazon S3 buckets, and Google Cloud Storage by brute force, using specific wordlists and handling the incoming responses. Many security professionals use this tool for penetration testing, bug bounty hunting, and cyber security assessments. Looking at the phases of ethical hacking, we can place Gobuster between the reconnaissance and scanning phases.

```bash
gobuster dir -u http://10.10.114.42/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
```

<span style="font-size: 23px;">**Enumeration**</span>

**Enumeration** is the act of listing all the available resources, whether they are accessible or not. For example, Gobuster enumerates web directories.

<span style="font-size: 23px;">**Brute Force**</span>

**Brute force** is the act of trying every possibility until a match is found. It is like having ten keys and trying them all on a lock until one fits. Gobuster uses wordlists for this purpose.

### command

<span style="font-size: 23px;">**--help**</span>

```bash
root@host:~# gobuster --help
Usage:
  gobuster [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dir         Uses directory/file enumeration mode
  dns         Uses DNS subdomain enumeration mode
  fuzz        Uses fuzzing mode. Replaces the keyword FUZZ in the URL, Headers and the request body
  gcs         Uses gcs bucket enumeration mode
  help        Help about any command
  s3          Uses aws bucket enumeration mode
  tftp        Uses TFTP enumeration mode
  version     shows the current version
  vhost       Uses VHOST enumeration mode (you most probably want to use the IP address as the URL parameter)

Flags:
      --debug                 Enable debug output
      --delay duration        Time each thread waits between requests (e.g. 1500ms)
  -h, --help                  help for gobuster
      --no-color              Disable color output
      --no-error              Don't display errors
  -z, --no-progress           Don't display progress
  -o, --output string         Output file to write results to (defaults to stdout)
  -p, --pattern string        File containing replacement patterns
  -q, --quiet                 Don't print the banner and other noise
  -t, --threads int           Number of concurrent threads (default 10)
  -v, --verbose               Verbose output (errors)
  -w, --wordlist string       Path to the wordlist. Set to - to use STDIN.
      --wordlist-offset int   Resume from a given position in the wordlist (defaults to 0)

Use "gobuster [command] --help" for more information about a command.
```

The help page contains multiple sections:

- `Usage`: Shows the syntax on how to use the command.
- `Available Commands`: Multiple commands are available to aid us in enumerating directories, files, DNS subdomains, Google Cloud Storage buckets, and Amazon AWS S3 buckets.Like `dir`, `dns`, and `vhost` commands
- `Flags`: options we can configure to customize our commands. 

### Use Case

Gobuster 的一些常用选项包括：
- `-u`：指定目标 URL。
- `-w`：指定字典文件路径。
- `-t`：指定并发线程数。
- `-o`：指定输出文件路径。

示例用法：
```sh
gobuster dir -u http://example.com -w /path/to/wordlist.txt -t 50 -o output.txt
```
这个命令会使用 `/path/to/wordlist.txt` 中的单词列表对 `http://example.com` 进行目录和文件暴力破解，并将结果保存到 `output.txt` 文件中。

### Directory and File Enumeration

Gobuster has a `dir` mode, allowing users to enumerate website directories and their files. This mode is useful when you are performing a penetration test and would like to see what the directory structure of a website is and what files it contains. Often, directory structures of websites and web apps follow a particular convention, making them susceptible to Brute Force using wordlists.

Gobuster is powerful because it allows you to scan the website and return the status codes. These status codes immediately tell you if you, as an outside user, can request that directory or not.

<span style="font-size: 23px;">**Help**</span>

If you want a complete overview of what the Gobuster `dir` command can offer, you can look at the help page. Seeing the extensive help page for the dir command can somewhat be intimidating. So, we will focus on the most essential flags in this room. Type the following command to display the help: `gobuster dir --help`.

Many flags are used to fine-tune the `gobuster dir` command. It is out of scope to go over each one of them, but in the table below, we have listed the flags that cover most of the scenarios:

| Flag | Long Flag | Description |
| ---- | ---- | ---- |
| `-c` | `--cookies` | This flag configures a cookie to pass along each request, such as a session ID. |
| `-x` | `--extensions` | This flag specifies which file extensions you want to scan for. E.g., .php, .js |
| `-H` | `--headers` | This flag configures an entire header to pass along with each request. |
| `-k` | `--no-tls-validation` | This flag skips the process that checks the certificate when https is used. It often happens for CTF events or test rooms like the ones on THM a self - signed certificate is used. This causes an error during the TLS check. |
| `-n` | `--no-status` | You can set this flag when you don't want to see status codes of each response received. This helps keep the output on the screen clear. |
| `-p` | `password` | You can set this flag together with the --username flag to execute authenticated requests. This is handy when you have obtained credentials from a user. |
| `-s` | `--status-codes` | With this flag, you can configure which status codes of the received responses you want to display, such as 200, or a range like 300 - 400. |
| `-b` | `--status-codes-blacklist` | This flag allows you to configure which status codes of the received responses you don't want to display. Configuring this flag overrides the -s flag. |
| `-U` | `--username` | You can set this flag together with the `--password` flag to execute authenticated requests. This is handy when you have obtained credentials from a user. |
| `-r` | `--followredirect` | This flags configures Gobuster to follow the redirect that it received as a response to the sent request. A HTTP redirect status code (e.g., 301 or 302) is used to redirect the client to a different URL. | 

<span style="font-size: 23px;">**How To Use dir Mode**</span>

To run Gobuster in `dir` mode, use the following command format:

`gobuster dir -u "http://www.example.thm" -w /path/to/wordlist`

Notice that the command also includes the flags `-u` and `-w`, in addition to the `dir` keyword. These two flags are required for the Gobuster directory enumeration to work. Let us look at a practical example of how to enumerate directories and files with Gobuster `dir` mode:

`gobuster dir -u "http://www.example.thm" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r`

This command scans all the directories located at www.example.thm using the wordlist directory-list-2.3-medium.txt. Let’s look a bit closer at each part of the command:

- `gobuster dir`: Configures Gobuster to use the directory and file enumeration mode.
- `-u http://www.example.thm`:
  - The URL will be the base path where Gobuster starts looking. So, the URL  above is using the root web directory. For example, in a typical Apache installation on Linux, this is `/var/www/html`. So if you have a “resources” directory and you want to enumerate that directory, you’d set the URL as `http://www.example.thm/resources`. You can also think of this like `http://www.example.thm/path/to/folder`.
  - The URL must contain the protocol used, in this case, HTTP. This is important and required. If you pass the wrong protocol, the scan will fail.
  - In the host part of the URL, you can either fill in the IP or the HOSTNAME. However, it is important to mention that when using the IP, you may target a different website than intended. A web server can host multiple websites using one IP (this technique is also called virtual hosting). Use the HOSTNAME if you want to be sure.
  - Gobuster does not enumerate recursively. So, if the results show a directory path you are interested in, you will have to enumerate that specific directory.
- `-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` configures Gobuster to use the directory-list-2.3-medium.txt wordlist to enumerate. Each entry of the wordlist is appended to the configured URL.
- `-r` configures Gobuster to follow the redirect responses received from the sent requests. If a status code 301 was received, Gobuster will navigate to the redirect URL that is included in the response.

Let's look at a second example where we use the `-x` flag to specify what type of files we want to enumerate:

`gobuster dir -u "http://www.example.thm" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.js`

This command will look for directories located at http://example.thm using the wordlist directory-list-2.3-medium.txt. In addition to directory listing, this command also lists all the files that have a .php or .js extension.


### Subdomain Enumeration

The next mode we’ll focus on is the `dns` mode. This mode allows Gobuster to brute force subdomains. During a penetration test,  checking the subdomains of your target’s top domain is essential. Just because something is patched in the regular domain, it doesn't mean it is also patched in the subdomain. An opportunity to exploit a vulnerability in one of these subdomains may exist. For example, if TryHackMe owns tryhackme.thm and mobile.tryhackme.thm, there may be a vulnerability in mobile.tryhackme.thm that is not present in tryhackme.thm. That is why it is important to search for subdomains as well!

<span style="font-size: 23px;">**Help**</span>

If you want a complete overview of what the Gobuster dns command can offer, you can have a look at the help page. Seeing the extensive help page for the `dns` command can be intimidating. So, we will focus on the most important flags in this room. Type the following command to display the help: `gobuster dns --help`

The `dns` mode offers fewer flags than the `dir` mode. But these are more than enough to cover most DNS subdomain enumeration scenarios. Let us have a look at some of the commonly used flags:

| Flag | Long Flag | Description |
| ---- | ---- | ---- |
| `-c` | `--show-cname` | Show CNAME Records (cannot be used with the `-i` flag). |
| `-i` | `--show-ips` | Including this flag shows IP addresses that the domain and subdomains resolve to. |
| `-r` | `--resolver` | This flag configures a custom DNS server to use for resolving. |
| `-d` | `--domain` | This flag configures the domain you want to enumerate. | 

<span style="font-size: 23px;">**How to Use dns Mode**</span>

To run Gobuster in dns mode, use the following command syntax:
`gobuster dns -d example.thm -w /path/to/wordlist`

Notice that the command also includes the flags `-d` and `-w`, in addition to the `dns` keyword. These two flags are required for the Gobuster subdomain enumeration to work. Let us look at an example of how to enumerate  subdomains with Gobuster dns mode:

`gobuster dns -d example.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

- `gobuster dns` enumerates subdomains on the configured domain.
- `-d example.thm` sets the target to the example.thm domain.
- `-w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` sets the wordlist to subdomains-top1million-5000.txt. Gobuster uses each entry of this list to construct a new DNS query. If the first entry of this list is 'all', the query would be all.example.thm.

### Vhost Enumeration

The last and final mode we’ll focus on is the `vhost` mode. This mode allows Gobuster to brute force virtual hosts. Virtual hosts are different websites on the same machine. Sometimes, they look like subdomains, but don’t be deceived! Virtual hosts are IP-based and are running on the same server. Subdomains are set up in DNS. The difference between `vhost` and `dns` mode is in the way Gobuster scans:

- `vhost` mode will navigate to the URL created by combining the configured HOSTNAME (-u flag) with an entry of a wordlist.
- `dns` mode will do a DNS lookup to the FQDN created by combining the configured domain name (-d flag) with an entry of a wordlist.

<span style="font-size: 23px;">**Help**</span>

If you want a complete overview of what the Gobuster `vhost` command can offer, you can have a look at the help page. Seeing the extensive help page for the vhost command can be intimidating. So, we will focus on the most important flags in this room. Type the  following command to display the help: `gobuster vhost --help`

The `vhost` mode offers flags similar to those of the dir mode. Let us have a look at some of the commonly used flags:

| Short Flag | Long Flag | Description |
| ---- | ---- | ---- |
| `-u` | `--url` | Specifies the base URL (target domain) for brute-forcing virtual hostnames. |
|  | `--append-domain` | Appends the base domain to each word in the wordlist (e.g., word.example.com). |
| `-m` | `--method` | Specifies the HTTP method to use for the requests (e.g., GET, POST). |
|  | `--domain` | Appends a domain to each wordlist entry to form a valid hostname (useful if not provided explicitly). |
|  | `--exclude-length` | Excludes results based on the length of the response body (useful to filter out unwanted responses). |
| `-r` | `--follow-redirect` | Follows HTTP redirects (useful for cases where subdomains may redirect). | 

<span style="font-size: 23px;">**How To Use vhost Mode**</span>

To run Gobuster in `vhost` mode, type the following command:

`gobuster vhost -u "http://example.thm" -w /path/to/wordlist`

Notice that the command also includes the flags `-u` and `-w`, in addition to the `vhost` keyword. These two flags are required for the Gobuster vhost enumeration to work. Let us look at a practical example of how to enumerate virtual hosts with Gobuster `vhost` mode:

```bash
gobuster vhost -u "http://10.10.110.82" --domain example.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250-320 
```
Gobuster will send multiple requests, each time changing the `Host:` part of the request. The value of `Host:` in this example is www.example.thm. We can break this down into three parts:

- `www`: This is the subdomain. This is the part that Gobuster will fill in with each entry of the configured wordlist.
- `.example`: This is the second-level domain. You can configure this with the `--domain` flag (this needs to be configured together with the top-level domain).
- `.thm`: This is the top-level domain. You can configure this with the `--domain` flag (this needs to be configured together with the second-level domain).

Now that we know how Gobuster sends its request, let's break down the command and examine each flag more closely:

- `gobuster vhost` instructs Gobuster to enumerate virtual hosts.
- `-u "http://10.10.110.82"` sets the URL to browse to 10.10.110.82.
- `-w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` configures Gobuster to use the subdomains-top1million-5000.txt wordlist. Gobuster appends each entry in the wordlist to the configured domain. If no domain is explicitly configured with the `--domain` flag, Gobuster will extract it from the URL. E.g., test.example.thm, help.example.thm, etc. If any subdomains are found, Gobuster will report them to you in the terminal.
- `--domain example.thm` sets the top- and second-level domains in the Hostname: part of the request to example.thm.
- `--append-domain` appends the configured domain to each entry in the wordlist. If this flag is not configured, the set hostname would be www, blog, etc. This will cause the command to work incorrectly and display false positives.
- `--exclude-length` filters the responses we get from the sent web requests. With this flag, we can filter out the false positives. If you run the command without this flag, you will notice you will get a lot of false positives like "Found: Orion.example.thm Status: 404 [Size: 279]" or  "Found: pm.example.thm Status: 404 [Size: 276]". These false positives typically have a similar response size, so we can use this to filter out most false positives. We expect to get a 200 OK response back to have a true positive. There are, however, exceptions, but it is not in the scope of this room to go deeper into these.

### vhost和dns区别

Gobuster的 `vhost` 模式和 `dns` 模式主要区别在于它们扫描的目标和方式：

1.  **`dns` 模式 (DNS 子域名枚举):**
    * **目标：** 用于枚举DNS子域名。
    * **工作原理：** 它通过将一个基础域名（例如 `example.com`）与一个单词列表中的每个条目组合，形成潜在的子域名（例如 `admin.example.com`, `dev.example.com` 等），然后对这些组合的完整域名（FQDN）进行DNS查找。如果DNS解析成功，就说明找到了一个子域名。
    * **何时使用：** 当你需要发现一个顶级域名下可能存在的各种子域名时使用，这些子域名可能承载不同的服务或应用程序，甚至可能存在未打补丁的漏洞。

2.  **`vhost` 模式 (虚拟主机枚举):**
    * **目标：** 用于枚举目标Web服务器上的虚拟主机名。
    * **工作原理：** 虚拟主机允许单个IP地址或服务器托管多个域名。`vhost` 模式会向一个已知的IP地址或URL发送HTTP请求，并在请求的 `Host` 头中尝试单词列表中的每个条目作为虚拟主机名。服务器会根据 `Host` 头来决定响应哪个虚拟站点的内容。如果服务器响应了不同的内容或返回了特定的状态码（例如，200 OK 而不是 404 Not Found），则可能表明找到了一个虚拟主机。
    * **何时使用：** 当你知道一个Web服务器的IP地址，并想发现它可能托管了哪些不同的网站或应用程序时使用。这通常发生在目标服务器上存在多个站点但它们共享同一个IP地址的情况下。

**总结区别：**

* **`dns` 模式关注DNS解析，寻找的是真实的、在DNS中注册的子域名。**
* **`vhost` 模式关注HTTP请求，寻找的是在同一个服务器上通过HTTP `Host` 头区分的虚拟主机。** 它们可能看起来像子域，但其发现方式是基于Web服务器的配置，而不是DNS记录。

简而言之，`dns` 模式是在网络层面上进行发现（通过DNS查询），而 `vhost` 模式是在应用层面上进行发现（通过HTTP请求）。

```bash
# DNS mode
root@host:~# gobuster dns -d offensivetools.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     offensivetools.thm
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: www.offensivetools.thm

Found: forum.offensivetools.thm

Found: store.offensivetools.thm

Found: WWW.offensivetools.thm

Found: primary.offensivetools.thm

Progress: 4997 / 4998 (99.98%)
===============================================================
Finished
===============================================================

# Vhost mode
root@host:~# gobuster vhost -u "http://10.10.253.1" --domain  offensivetools.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250-320
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://10.10.253.1
[+] Method:           GET
[+] Threads:          10
[+] Wordlist:         /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:       gobuster/3.6
[+] Timeout:          10s
[+] Append Domain:    true
[+] Exclude Length:   278,287,305,307,308,256,260,273,272,275,286,299,320,253,262,263,311,252,257,296,312,316,251,255,270,292,309,310,259,276,293,279,289,318,271,300,302,304,254,258,284,303,314,250,280,291,274,294,306,315,282,298,313,285,295,301,261,265,267,319,266,283,297,277,281,288,290,317,264,268,269
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: forum.offensivetools.thm Status: 200 [Size: 2635]
Found: store.offensivetools.thm Status: 200 [Size: 3014]
Found: secret.offensivetools.thm Status: 200 [Size: 1550]
Found: WWW.offensivetools.thm Status: 200 [Size: 8806]
Progress: 4997 / 4998 (99.98%)
Found: www.offensivetools.thm Status: 200 [Size: 8806]
===============================================================
Finished
===============================================================

```
---

## FFUF

**[FFUF](https://github.com/ffuf/ffuf)** (**Fuzz Faster U Fool**) 是一个用于**模糊测试 (fuzzing)** 的命令行工具，主要用于**Web 应用程序的安全测试**。

简单来说，它的作用是：

* **快速发现隐藏的目录、文件、参数等：** 你可以给它一个 URL 和一个字典（wordlist），FFUF 会尝试将字典中的每个单词替换掉 URL 中的特定位置（通常用 `FUZZ` 标记），然后发送请求，根据响应来判断是否存在这些隐藏资源。
* **寻找潜在的漏洞：** 通过模糊测试，可以发现一些常见的漏洞，例如：
    * **目录遍历 (Directory Traversal)**
    * **文件包含 (File Inclusion)**
    * **SQL 注入 (SQL Injection)**
    * **跨站脚本 (Cross-Site Scripting, XSS)**
    * **参数枚举 (Parameter Enumeration)**
    * **子域名发现 (Subdomain Discovery)**

**FFUF 的主要特点：**

* **速度快：** FFUF 使用 Go 语言编写，性能非常高效。
* **高度可配置：** 提供丰富的命令行参数，可以灵活地控制模糊测试的行为，例如：
    * 指定 URL (`-u`) 和字典 (`-w`)
    * 添加 HTTP 请求头 (`-H`)
    * 切换请求方法 (GET/POST, `-X`)
    * 指定 POST 数据 (`-d`)
    * 过滤响应状态码 (`-mc`，如 `-mc 200,302` 只显示 200 和 302 状态码的响应)
    * 递归发现目录 (`-recursion`)
    * 添加文件扩展名 (`-e`)
    * 设置并发线程数 (`-t`)
    * 设置请求延迟 (`-p`)
    * 支持代理 (`-x`)
* **用途广泛：** 除了目录和文件发现，还可以用于认证测试、参数模糊、虚拟主机枚举等。

**基本用法示例：**

```bash
ffuf -w wordlist.txt -u http://example.com/FUZZ
```

这个命令会使用 `wordlist.txt` 中的单词替换 `http://example.com/FUZZ` 中的 `FUZZ`，然后发送请求。

总的来说，FFUF 是渗透测试人员和安全研究人员在进行 Web 应用程序内容发现和漏洞挖掘时一个非常实用的工具。

---

## dirb

`dirb` 也是一个**用于 Web 应用程序目录和文件暴力破解 (brute-forcing) 的命令行工具**，它在渗透测试和安全审计中非常常用。它的主要目的是通过尝试各种预定义的单词列表（字典）来发现 Web 服务器上可能存在的隐藏目录、文件和敏感信息。

**dirb 的主要功能：**

* **目录和文件发现：** 这是 dirb 最核心的功能。它会向目标 Web 服务器发送大量请求，尝试猜测目录和文件的名称，以发现那些没有在网站上明确链接但仍然可访问的资源。这包括：
    * **网站后台管理面板** (admin, manager, login)
    * **临时文件、备份文件** (.bak, .old, .zip, .tar.gz)
    * **配置文件** (.conf, .ini)
    * **日志文件** (.log)
    * **测试页面** (test, dev)
    * **默认安装文件** (install.php, setup.exe)
* **基于字典的攻击：** `dirb` 使用一个或多个字典文件来生成猜测的路径。这些字典通常包含了常见的文件名、目录名、Web 应用程序的默认路径等。
* **支持递归扫描：** 它可以递归地扫描发现的目录，进一步深入挖掘隐藏的资源。
* **文件扩展名支持：** 可以指定要尝试的文件扩展名（例如 `.php`, `.asp`, `.html`, `.txt` 等），以缩小搜索范围或提高效率。
* **HTTP 认证和代理支持：** 可以在需要认证的 Web 服务器上进行扫描，并支持通过代理进行请求。
* **过滤响应：** 可以根据 HTTP 状态码、响应大小等来过滤结果，只显示有用的信息。

**基本用法示例：**

```bash
dirb http://example.com /usr/share/wordlists/dirb/common.txt
```

这个命令会使用 `common.txt` 这个字典文件来扫描 `http://example.com` 上的目录和文件。


## 区别

FFUF、dirb 和 Gobuster 都是用于 Web 应用程序目录和文件暴力破解 (brute-forcing) 的工具，它们在渗透测试和安全审计中扮演着重要的角色。虽然它们的目标相似，但在设计、功能和性能上存在一些区别。

以下是它们的主要区别：

### 1. dirb

* **语言：** 使用 C 语言编写。
* **特点：**
    * 历史悠久，是目录暴力破解工具的先行者之一。
    * 功能相对简单，主要专注于目录和文件发现。
    * 在处理大型字典或需要高并发时，速度可能不如 Go 语言编写的工具。
    * 默认情况下，输出可能比较简洁。
* **适用场景：** 经典的目录爆破工具，对于简单的目标和快速检查仍然有效。

### 2. Gobuster

* **语言：** 使用 Go 语言编写。
* **特点：**
    * **速度快：** 由于 Go 语言的并发特性，Gobuster 在执行任务时通常比 dirb 更快、更高效。
    * **多模式支持：** 除了目录和文件爆破（`dir` 模式），Gobuster 还支持：
        * **子域名爆破 (`dns` 模式)：** 发现目标网站的子域名。
        * **VHost 爆破 (`vhost` 模式)：** 枚举虚拟主机。
        * **S3 bucket 爆破 (`s3` 模式)：** 发现 Amazon S3 存储桶。
        * **Google Cloud Storage bucket 爆破 (`gcs` 模式)。**
    * **简洁的输出：** 默认输出相对清晰，易于阅读。
    * **活跃开发：** 持续更新和维护。
* **适用场景：** 需要快速进行目录、子域名、VHost 等多种类型枚举的场景，是许多渗透测试人员的首选工具之一。

### 3. FFUF (Fuzz Faster U Fool)

* **语言：** 使用 Go 语言编写。
* **特点：**
    * **强大的模糊测试 (Fuzzing) 能力：** FFUF 不仅仅局限于目录和文件爆破，它是一个更通用的模糊测试引擎，可以用于：
        * **目录和文件发现：** 和 dirb、Gobuster 的核心功能一致。
        * **参数模糊 (Parameter Fuzzing)：** 模糊 HTTP 请求参数，寻找注入点等漏洞。
        * **HTTP 头模糊 (HTTP Header Fuzzing)：** 模糊 HTTP 请求头，测试各种头部字段。
        * **POST 数据模糊：** 模糊 POST 请求体中的数据。
        * **自定义模糊点：** 使用 `FUZZ` 关键字灵活定义模糊的位置。
    * **高度可配置：** 提供极其丰富的命令行选项，可以精细控制请求、过滤响应、设置并发、递归扫描等。
    * **灵活的过滤机制：** 支持根据状态码、响应大小、行数、单词数等进行过滤，这对于快速筛选出有价值的结果至关重要。
    * **速度快：** Go 语言编写，性能优异。
    * **JSON 输出：** 支持 JSON 格式输出结果，便于与其他工具集成或进行自动化分析。
    * **递归扫描：** 支持递归发现目录（`--recursion`）。
* **适用场景：**
    * 需要进行更复杂和更灵活的模糊测试，不仅仅是简单的目录爆破。
    * 寻找各种 Web 漏洞，例如 SQL 注入、XSS、LFI 等。
    * 对 Web 应用程序进行深入的信息收集和漏洞挖掘。

### 总结比较表格：

| 特性       | dirb                  | Gobuster                  | FFUF                          |
| :--------- | :-------------------- | :------------------------ | :---------------------------- |
| **开发语言** | C                     | Go                        | Go                            |
| **主要功能** | 目录/文件爆破         | 目录/文件、子域名、VHost、S3 等多种模式爆破 | 通用模糊测试引擎，包含目录/文件爆破、参数模糊、HTTP 头模糊等 |
| **速度** | 较慢（相对）          | 快速                      | 非常快速                      |
| **灵活性** | 较低                  | 中等                      | 极高，高度可配置              |
| **过滤** | 基础过滤              | 较好                      | 强大且灵活（状态码、大小、内容等） |
| **输出** | 简洁                  | 清晰                      | 支持 JSON 输出，便于集成      |
| **递归** | 支持                  | 支持                      | 支持                          |

**选择建议：**

* 如果你只是想快速进行**基本的目录和文件发现**，并且对速度没有极致要求，`dirb` 仍然可以胜任。
* 如果你需要**快速且高效地进行多种类型的枚举**（如目录、子域名、VHost），`Gobuster` 是一个非常好的选择。
* 如果你需要进行**更高级、更灵活的模糊测试**，寻找各种潜在的 Web 漏洞，并希望能够精细控制测试过程，那么 `FFUF` 无疑是功能最强大和最推荐的工具。

在实际的渗透测试中，经验丰富的测试人员通常会根据具体的目标和测试阶段，灵活选择并结合使用这些工具。例如，可能会先用 `Gobuster` 进行快速的目录和子域名枚举，然后针对发现的特定页面或参数，使用 `FFUF` 进行更深入的模糊测试。

---

## dnsrecon

`dnsrecon` 是一个功能强大的 **DNS 侦察 (reconnaissance) 和枚举 (enumeration) 命令行工具**，通常用于渗透测试和安全审计的信息收集阶段。它的主要目的是通过多种技术收集目标域名的 DNS 相关信息，以发现潜在的漏洞或获取网络拓扑的线索。

简单来说，`dnsrecon` 的作用是：

* **全面获取 DNS 记录：** 它能够枚举各种 DNS 记录类型，包括：
    * **A 记录 (Address Record)：** 将域名解析为 IPv4 地址。
    * **AAAA 记录 (IPv6 Address Record)：** 将域名解析为 IPv6 地址。
    * **MX 记录 (Mail Exchange Record)：** 邮件服务器记录。
    * **NS 记录 (Name Server Record)：** 域名服务器记录。
    * **SOA 记录 (Start of Authority Record)：** 区域起始授权记录，包含域名的基本信息。
    * **SRV 记录 (Service Record)：** 服务记录，指定特定服务的服务器和端口。
    * **TXT 记录 (Text Record)：** 文本记录，常用于 SPF (Sender Policy Framework) 和 DKIM (DomainKeys Identified Mail) 等邮件认证。
    * **SPF 记录 (Sender Policy Framework Record)：** 用于验证发件人身份的记录。
    * **PTR 记录 (Pointer Record)：** 反向解析记录，将 IP 地址解析为域名。
* **尝试区域传输 (Zone Transfer)：** 尝试对目标域名的 DNS 服务器进行区域传输（AXFR）请求。如果成功，这将泄露整个域名的 DNS 区域信息，包括所有主机名和 IP 地址，这通常是一个严重的安全配置错误。
* **子域名暴力破解 (Subdomain Brute-forcing)：** 使用字典文件来猜测和发现目标域名的子域名。
* **反向 DNS 查询 (Reverse DNS Lookup)：** 对给定的 IP 地址范围或 CIDR 块执行 PTR 记录查找，以发现与这些 IP 地址关联的域名。
* **DNSSEC 区域遍历 (DNSSEC Zone Walk)：** 利用 DNSSEC 中的 NSEC 记录进行区域遍历，可以发现区域中的所有记录。
* **缓存嗅探 (Cache Snooping)：** 检查 DNS 服务器的缓存记录，以获取更多信息。
* **Whois 信息深度分析：** 对 Whois 记录进行深度分析，并反向查找其中发现的 IP 范围。
* **集成外部服务：** 可以结合 Google、Bing、crt.sh 等服务来枚举子域名和主机。

**为什么 `dnsrecon` 很重要？**

在渗透测试的初期阶段，信息收集至关重要。`dnsrecon` 能够帮助安全分析师和渗透测试人员：

* **绘制目标网络拓扑：** 了解目标组织有哪些子域名、邮件服务器、Web 服务器等，以及它们对应的 IP 地址。
* **发现隐藏的服务和主机：** 通过子域名爆破和区域传输，可以发现未公开但仍在运行的服务。
* **识别错误配置：** 区域传输漏洞是一个典型的 DNS 配置错误，`dnsrecon` 可以帮助发现它。
* **为后续攻击提供线索：** 收集到的 DNS 信息可以为后续的漏洞扫描、社会工程学攻击或直接攻击提供有价值的数据。

**基本用法示例：**

1.  **标准枚举：**
    ```bash
    dnsrecon -d example.com
    ```
    这将对 `example.com` 执行标准的 DNS 记录枚举（A、AAAA、MX、NS、SOA、SRV、TXT 等）。

2.  **尝试区域传输：**
    ```bash
    dnsrecon -d example.com -a
    ```
    这将尝试对 `example.com` 执行区域传输，并同时进行标准枚举。

3.  **子域名暴力破解：**
    ```bash
    dnsrecon -d example.com -D /path/to/wordlist.txt -t brt
    ```
    这将使用指定的字典文件对 `example.com` 进行子域名暴力破解。

`dnsrecon` 是一个非常实用的 Python 脚本，在 Kali Linux 等渗透测试发行版中通常是预装的。它为进行全面的 DNS 侦察提供了强大的能力。

---

## Sublist3r

`Sublist3r` 是一个用 Python 编写的**快速子域名枚举工具**，专为渗透测试人员和漏洞赏金猎人设计。它的核心功能是通过利用**开源情报 (OSINT)** 来收集目标网站的所有子域名。

**Sublist3r 的主要工作原理和特点：**

1.  **多来源收集：** Sublist3r 不仅仅依赖一种方法，它会从多个公共来源和搜索引擎获取子域名信息，包括：
    * **搜索引擎：** Google, Yahoo, Bing, Baidu, Ask 等。它通过在这些搜索引擎中执行特定的查询来查找与目标域名相关的子域名。
    * **OSINT 平台：** Netcraft, Virustotal, ThreatCrowd, DNSdumpster, ReverseDNS 等。这些平台通常维护着大量的 DNS 和域名相关数据，Sublist3r 可以查询它们来发现子域名。
    * **子域名暴力破解 (可选)：** Sublist3r 也集成了 `subbrute` 工具，允许用户选择启用暴力破解模式，通过字典猜测更多的子域名。

2.  **被动式侦察 (Passive Reconnaissance)：** 大部分情况下，Sublist3r 采用的是被动式侦察。这意味着它不会直接向目标服务器发送大量请求（除了 DNS 查询），而是通过查询公开可用的数据和第三方服务来收集信息。这使得它在信息收集阶段非常隐蔽和安全。

3.  **速度快：** 由于其多线程和对 Go 语言（对于集成的 `subbrute` 部分）的优化，Sublist3r 在执行子域名枚举时通常非常快速。

4.  **易于使用：** 它是一个命令行工具，但用法相对简单。

5.  **Python 模块：** 还可以作为 Python 模块在自己的脚本中调用，方便自动化。

**为什么子域名枚举很重要？**

在渗透测试和漏洞赏金活动中，子域名枚举是信息收集阶段至关重要的一步。因为：

* **扩大攻击面：** 主域名可能非常安全，但其子域名（例如 `dev.example.com`, `test.example.com`, `admin.example.com`）可能存在未打补丁的软件、错误配置或更弱的防护，从而成为攻击入口。
* **发现隐藏的服务：** 很多时候，企业会将不同的服务部署在不同的子域名下，通过枚举子域名可以发现这些不为人知的服务。
* **收集更多信息：** 子域名可能泄露开发环境、旧系统、内部测试环境等，这些都可能包含有价值的信息或漏洞。

**基本用法示例：**

```bash
python sublist3r.py -d example.com
```

这个命令会枚举 `example.com` 的子域名。

你还可以指定其他选项，例如：

* `-p 80,443`：扫描发现的子域名的 80 和 443 端口，以判断其是否开放 Web 服务。
* `-b`：启用暴力破解模块。
* `-e google,yahoo`：只使用 Google 和 Yahoo 搜索引擎来枚举子域名。
* `-o output.txt`：将结果保存到文件中。

总而言之，`Sublist3r` 是渗透测试人员在侦察阶段用于快速、高效地发现目标网站子域名的重要工具之一。