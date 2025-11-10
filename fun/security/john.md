---
title: "John the Ripper"
categories:
  - 技术
  - 教程
tags: [John the Rippe, password-cracking]
draft: true
sidebar: false
outline: 2
---

# John the Ripper

John the Ripper is a free and open-source password-cracking tool. It can crack passwords stored in various formats, including hashes, passwords, and encrypted private keys. It can be used to test passwords' security and recover lost passwords.

John the Ripper is a well-known, well-loved, and versatile hash-cracking tool. It combines a fast cracking speed with an extraordinary range of compatible hash types.

## Setting Up Your System

<span style="font-size: 23px;">**installation**</span>

[official installation guide](https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL) 

[ Openwall Wiki](https://www.openwall.com/john/)

<span style="font-size: 23px;">**Wordlists**</span>

As we mentioned earlier, to use a dictionary attack against hashes, you need a list of words to hash and compare; unsurprisingly, this is called a wordlist. There are many different wordlists out there, and a good collection can be found in the [SecLists](https://github.com/danielmiessler/SecLists) repository. There are a few places you can look for wordlists for attacking the system of choice.

**RockYou**

The infamous `rockyou.txt` wordlis,a very large common password wordlist obtained from a data breach on a website called rockyou.com in 2009. If you are not using any of the above distributions, you can get the `rockyou.txt` wordlist from the [SecLists](https://github.com/danielmiessler/SecLists) repository under the `/Passwords/Leaked-Databases` subsection. You may need to extract it from the .tar.gz format using `tar xvzf rockyou.txt.tar.gz`.

## Cracking Basic Hashes

<span style="font-size: 23px;">**John Basic Syntax**</span>

`john [options] [file path]`

- `john`: Invokes the John the Ripper program
- `[options]`: Specifies the options you want to use
- `[file path]`: The file containing the hash you're trying to crack; if it's in the same directory, you won't need to name a path, just the file.

<span style="font-size: 23px;">**Automatic Cracking**</span>

John has built-in features to detect what type of hash it's being given and to select appropriate rules and formats to crack it for you; this isn't always the best idea as it can be unreliable, but if you can't identify what hash type you're working with and want to try cracking it, it can be a good option! To do this, we use the following syntax:

`john --wordlist=[path to wordlist] [path to file]`

- `--wordlist=`: Specifies using wordlist mode, reading from the file that you supply in the provided path
- `[path to wordlist]`: The path to the wordlist you're using, as described in the previous task

example:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

<span style="font-size: 23px;">**Identifying Hashes**</span>

Sometimes, John won't play nicely with automatically recognising and loading hashes, but that's okay! We can use other tools to identify the hash and then set John to a specific format. There are multiple ways to do this, such as using an online hash identifier like [this site](https://hashes.com/en/tools/hash_identifier). I like to use a tool called [hash-identifier](https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master), a Python tool that is super easy to use and will tell you what different types of hashes the one you enter is likely to be, giving you more options if the first one fails.

To use hash-identifier, you can use `wget` or `curl` to download the Python file hash-id.py from its GitLab page. Then, launch it with `python3 hash-id`.py and enter the hash you're trying to identify. It will give you a list of the most probable formats. These two steps are shown in the terminal below.

```bash
user@TryHackMe$ wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py
$ python3 hash-id.py

--------------------------------------------------
 HASH: 2e728dd31fb5949bc39cac5a9f066498

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
...

```

<span style="font-size: 23px;">**Format-Specific Cracking**</span>

Once you have identified the hash that you're dealing with, you can tell John to use it while cracking the provided hash using the following syntax:

`john --format=[format] --wordlist=[path to wordlist] [path to file]`

- `--format=`: This is the flag to tell John that you're giving it a hash of a specific format and to use the following format to crack it
- `[format]`: The format that the hash is in

Example :
```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

**A Note on Formats:**

When you tell John to use formats, if you're dealing with a standard hash type, e.g. md5 as in the example above, you have to prefix it with `raw-` to tell John you're just dealing with a standard hash type, though this doesn't always apply. To check if you need to add the prefix or not, you can list all of John's formats using `john --list=formats` and either check manually or grep for your hash type using something like `john --list=formats | grep -iF "md5"`.

<span style="font-size: 23px;">Practical  </span>

```bash
# hash4.txt 破解
## step1 查询hash码
user@ip-10-10-131-87:~$ cat hash4.txt
c5a60cc6bbba781c601c5402755ae1044bbf45b78d1183cbf2ca1c865b6c792cf3c6b87791344986c8a832a0f9ca8d0b4afd3d9421a149d57075e1b4e93f90bf
## step2 查询hash类型
┌──(root㉿kali)-[~]
└─# hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: c5a60cc6bbba781c601c5402755ae1044bbf45b78d1183cbf2ca1c865b6c792cf3c6b87791344986c8a832a0f9ca8d0b4afd3d9421a149d57075e1b4e93f90bf

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------
## step3 选择第一个可能类型 未破解成功 
user@ip-10-10-131-87:~$ john --format=raw-sha512 --wordlist=/usr/share/wordlists/rockyou.txt hash4.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 256/256 AVX2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Note: Passwords longer than 37 [worst case UTF-8] to 111 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:05 DONE (2025-05-18 02:07) 0g/s 2427Kp/s 2427Kc/s 2427KC/s !)!#1013..*7¡Vamos!
Session completed. 

## step4 尝试第二个 破解成功
user@ip-10-10-131-87:~$ john --format=whirlpool --wordlist=/usr/share/wordlists/rockyou.txt hash4.txt
Using default input encoding: UTF-8
Loaded 1 password hash (whirlpool [WHIRLPOOL 32/64])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
colossal         (?)     
1g 0:00:00:00 DONE (2025-05-18 02:11) 2.083g/s 1416Kp/s 1416Kc/s 1416KC/s cooldog12..chata1994
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

## tip 查看破解后的密码 
user@ip-10-10-131-87:~$ john --show --format=whirlpool hash4.txt
?:colossal

1 password hash cracked, 0 left
```

## Cracking Windows Authentication Hashes

<span style="font-size: 23px;">**NTHash / NTLM**</span>

**NThash** is the hash format modern Windows operating system machines use to store user and service passwords. It's also commonly referred to as NTLM, which references the previous version of Windows format for hashing passwords known as **LM**, thus **NT/LM**.

**Windows New Technology LAN Manager (NTLM)** is a suite of security protocols offered by Microsoft to authenticate users' identity and protect the integrity and confidentiality of their activity.

A bit of history: the NT designation for Windows products originally meant New Technology. It was used starting with Windows NT to denote products not built from the MS-DOS Operating System. Eventually, the “NT” line became the standard Operating System type to be released by Microsoft, and the name was dropped, but it still lives on in the names of some Microsoft technologies.

In Windows, SAM (Security Account Manager) is used to store user account information, including usernames and hashed passwords. You can acquire NTHash/NTLM hashes by dumping the SAM database on a Windows machine, using a tool like Mimikatz, or using the Active Directory database: `NTDS.dit`. You may not have to crack the hash to continue privilege escalation, as you can often conduct a “pass the hash” attack instead, but sometimes, hash cracking is a viable option if there is a weak password policy.

<span style="font-size: 23px;">**Practical**</span>

```bash
user@ip-10-10-131-87:~$ john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Note: Passwords longer than 27 rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
mushroom         (?)     
1g 0:00:00:00 DONE (2025-05-18 02:47) 50.00g/s 153600p/s 153600c/s 153600C/s skater1..dangerous
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```

## Cracking /etc/shadow Hashes

The `/etc/shadow` file is the file on Linux machines where [password hashes](../cyber/cryptography.md#linux-passwords) are stored. It also stores other information, such as the date of last password change and password expiration information. It contains one entry per line for each user or user account of the system. This file is usually only accessible by the root user, so you must have sufficient privileges to access the hashes. However, if you do, there is a chance that you will be able to crack some of the hashes.

<span style="font-size: 23px;">**Unshadowing**</span>

John can be very particular about the formats it needs data in to be able to work with it; for this reason, to crack `/etc/shadow` passwords, you must combine it with the `/etc/passwd` file for John to understand the data it's being given. To do this, we use a tool built into the John suite of tools called `unshadow`. The basic syntax of `unshadow` is as follows:

`unshadow [path to passwd] [path to shadow]`

- `unshadow`: Invokes the unshadow tool
- `[path to passwd]`: The file that contains the copy of the /etc/passwd file you've taken from the target machine
- `[path to shadow]`: The file that contains the copy of the /etc/shadow file you've taken from the target machine

Example
```bash
unshadow local_passwd local_shadow > unshadowed.txt
```
**Note on the files**

When using `unshadow`, you can either use the entire `/etc/passwd` and `/etc/shadow` files, assuming you have them available, or you can use the relevant line from each, for example:

**FILE 1 - local_passwd**

Contains the `/etc/passwd` line for the root user:

`root:x:0:0::/root:/bin/bash`

**FILE 2 - local_shadow**

Contains the `/etc/shadow` line for the root user: 

`root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX0OJjY1L6l.DS3KEVsZ9rOVLB/ldTeEL/OIhJZ4GMFMGA0:18576::::::`

<span style="font-size: 23px;">**Cracking**</span>

We can then feed the output from `unshadow`, in our example use case called `unshadowed.txt`, directly into John. We should not need to specify a mode here as we have made the input specifically for John; however, in some cases, you will need to specify the format as we have done previously using: `--format=sha512crypt`

`john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt`

<span style="font-size: 23px;">**Practical**</span>

```bash
# step1 Unshadowing 
user@ip-10-10-131-87:~/John-the-Ripper-The-Basics/Task06$ ls
etc_hashes.txt  local_passwd  local_shadow
user@ip-10-10-131-87:~/John-the-Ripper-The-Basics/Task06$ cat local_passwd 
root:x:0:0::/root:/bin/bash
user@ip-10-10-131-87:~/John-the-Ripper-The-Basics/Task06$ cat local_shadow 
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:18576::::::
user@ip-10-10-131-87:~/John-the-Ripper-The-Basics/Task06$ unshadow local_passwd local_shadow > unshadowed.txt
user@ip-10-10-131-87:~/John-the-Ripper-The-Basics/Task06$ ls
etc_hashes.txt  local_passwd  local_shadow  unshadowed.txt
user@ip-10-10-131-87:~/John-the-Ripper-The-Basics/Task06$ cat unshadowed.txt 
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:0:0::/root:/bin/bash

# step2 Cracking  
user@ip-10-10-131-87:~/John-the-Ripper-The-Basics/Task06$ cat etc_hashes.txt 
This is everything I managed to recover from the target machine before my computer crashed... See if you can crack the hash so we ca
n at least salvage a password to try and get back in.

root:x:0:0::/root:/bin/bash
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:18576::::::

user@ip-10-10-131-87:~/John-the-Ripper-The-Basics/Task06$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Note: Passwords longer than 26 [worst case UTF-8] to 79 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
1234             (root)     
1g 0:00:00:02 DONE (2025-05-18 03:06) 0.4274g/s 547.0p/s 547.0c/s 547.0C/s kucing..poohbear1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

## Single Crack Mode

So far, we've been using John's wordlist mode to brute-force simple and not-so-simple hashes. But John also has another mode, called the **Single Crack mode**. In this mode, John uses only the information provided in the username to try and work out possible passwords heuristically by slightly changing the letters and numbers contained within the username.

<span style="font-size: 23px;">**Word Mangling**</span>

The best way to explain Single Crack mode and word mangling is to go through an example:

Consider the username “Markus”.

Some possible passwords could be:

- Markus1, Markus2, Markus3 (etc.)
- MArkus, MARkus, MARKus (etc.)
- Markus!, Markus$, Markus* (etc.)

This technique is called **word mangling**. John is building its dictionary based on the information it has been fed and uses a set of rules called “mangling rules,” which define how it can mutate the word it started with to generate a wordlist based on relevant factors for the target you're trying to crack. This exploits how poor passwords can be based on information about the username or the service they're logging into.

<span style="font-size: 23px;">**GECOS**</span>

John's implementation of word mangling also features compatibility with the GECOS field of the UNIX operating system, as well as other UNIX-like operating systems such as Linux. GECOS stands for General Electric Comprehensive Operating System. In the last task, we looked at the entries for both `/etc/shadow` and /etc/passwd. Looking closely, you will notice that the fields are separated by a colon :. The fifth field in the user account record is the GECOS field. It stores general information about the user, such as the user's full name, office number, and telephone number, among other things. John can take information stored in those records, such as full name and home directory name, to add to the wordlist it generates when cracking `/etc/shadow` hashes with single crack mode.

<span style="font-size: 23px;">**Using Single Crack Mode**</span>

To use single crack mode, we use roughly the same syntax that we've used so far; for example, if we wanted to crack the password of the user named “Mike”, using the single mode, we'd use:

`john --single --format=[format] [path to file]`

- `--single`: This flag lets John know you want to use the single hash-cracking mode
- `--format=[format]`: As always, it is vital to identify the proper format.

**Example Usage:**

`john --single --format=raw-sha256 hashes.txt`

**A Note on File Formats in Single Crack Mode:**

If you're cracking hashes in single crack mode, you need to change the file format that you're feeding John for it to understand what data to create a wordlist from. You do this by prepending the hash with the username that the hash belongs to, so according to the above example, we would change the file `hashes.txt`

**From** `1efee03cdcb96d90ad48ccc7b8666033`

**To** `mike:1efee03cdcb96d90ad48ccc7b8666033`

<span style="font-size: 23px;">**Q&A**</span>

```bash
user@ip-10-10-84-180:~$ ls
hash07.txt
user@ip-10-10-84-180:~$ cat hash07.txt 
7bf6d9bb82bed1302f331fc6b816aada
user@ip-10-10-84-180:~$ echo -n "joker:" | cat - hash07.txt > hash.txt
user@ip-10-10-84-180:~$ ls
hash.txt  hash07.txt
user@ip-10-10-84-180:~$ cat hash.txt 
joker:7bf6d9bb82bed1302f331fc6b816aada
user@ip-10-10-84-180:~$ john --single --format=raw-md5 hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Note: Passwords longer than 18 [worst case UTF-8] to 55 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Warning: Only 18 candidates buffered for the current salt, minimum 24 needed for performance.
Jok3r            (joker)     
1g 0:00:00:00 DONE (2025-05-18 15:01) 100.0g/s 19600p/s 19600c/s 19600C/s JOKER5..J0ker
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

## Custom Rules

<span style="font-size: 23px;">**What are Custom Rules?**</span>

As we explored what John can do in Single Crack Mode, you may have some ideas about some good mangling patterns or what patterns your passwords often use that could be replicated with a particular mangling pattern. The good news is that you can define your rules, which John will use to create passwords dynamically. The ability to define such rules is beneficial when you know more information about the password structure of whatever your target is.

<span style="font-size: 23px;">**Common Custom Rules**</span>

Many organisations will require a certain level of password complexity to try and combat dictionary attacks. In other words, when creating a new account or changing your password, if you attempt a password like `polopassword`, it will most likely not work. The reason would be the enforced password complexity. As a result, you may receive a prompt telling you that passwords have to contain at least one character from each of the following:

- Lowercase letter
- Uppercase letter
- Number
- Symbol

Password complexity is good! However, we can exploit the fact that most users will be predictable in the location of these symbols. For the above criteria, many users will use something like the following:

`Polopassword1!`

Consider the password with a capital letter first and a number followed by a symbol at the end. This familiar pattern of the password, appended and prepended by modifiers (such as capital letters or symbols), is a memorable pattern that people use and reuse when creating passwords. This pattern can let us exploit **password complexity predictability**.

Now, this does meet the password complexity requirements; however, as attackers, we can exploit the fact that we know the likely position of these added elements to create dynamic passwords from our wordlists.

<span style="font-size: 23px;">**How to create Custom Rules**</span>

Custom rules are defined in the `john.conf` file. This file can be found in `/opt/john/john.conf` on the TryHackMe Attackbox. It is usually located in `/etc/john/john.conf` if you have installed John using a package manager or built from source with `make`.

Let's go over the syntax of these custom rules, using the example above as our target pattern. Note that you can define a massive level of granular control in these rules. I suggest looking at the wiki [here](https://www.openwall.com/john/doc/RULES.shtml) to get a full view of the modifiers you can use and more examples of rule implementation.

The first line:

`[List.Rules:THMRules]` is used to define the name of your rule; this is what you will use to call your custom rule a John argument.

We then use a regex style pattern match to define where the word will be modified; again, we will only cover the primary and most common modifiers here:

- `Az`: Takes the word and appends it with the characters you define
- `A0`: Takes the word and prepends it with the characters you define
- `c`: Capitalises the character positionally

These can be used in combination to define where and what in the word you want to modify.

Lastly, we must define what characters should be appended, prepended or otherwise included. We do this by adding character sets in square brackets `[ ]` where they should be used. These follow the modifier patterns inside double quotes `" "`. Here are some common examples:

- `[0-9]`: Will include numbers 0-9
- `[0]`: Will include only the number 0
- `[A-z]`: Will include both upper and lowercase
- `[A-Z]`: Will include only uppercase letters
- `[a-z]`: Will include only lowercase letters

Please note that:

- `[a]`: Will include only `a`
- `[!£$%@]`: Will include the symbols `!`, `£`, `$`, `%`, and `@`

Putting this all together, to generate a wordlist from the rules that would match the example password Polopassword1! (assuming the word polopassword was in our wordlist), we would create a rule entry that looks like this:

`[List.Rules:PoloPassword]`

`cAz"[0-9] [!£$%@]"`

Utilises the following:

- `c`: Capitalises the first letter
- `Az`: Appends to the end of the word
- `[0-9]`: A number in the range 0-9
- `[!£$%@]`: The password is followed by one of these symbols

<span style="font-size: 23px;">**Using Custom Rules**</span>

We could then call this custom rule a John argument using the  `--rule=PoloPassword` flag.

As a full command: `john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]`

As a note, I find it helpful to talk out the patterns if you're writing a rule; as shown above, the same applies to writing RegEx patterns.

Jumbo John already has an extensive list of custom rules containing modifiers for use in almost all cases. If you get stuck, try looking at those rules [around line 678] if your syntax isn't working correctly.

## Cracking Password Protected Zip Files

Yes! You read that right. We can use John to crack the password on password-protected Zip files. Again, we'll use a separate part of the John suite of tools to convert the Zip file into a format that John will understand, but we'll use the syntax you're already familiar with for all intents and purposes.

<span style="font-size: 23px;">**Zip2John**</span>

Similarly to the `unshadow` tool we used previously, we will use the `zip2john` tool to convert the Zip file into a hash format that John can understand and hopefully crack. The primary usage is like this:

`zip2john [options] [zip file] > [output file]`

- `[options]`: Allows you to pass specific checksum options to zip2john; this shouldn't often be necessary
- `[zip file]`: The path to the Zip file you wish to get the hash of
- `>`: This redirects the output from this command to another file
- `[output file]`: This is the file that will store the output 

**Example Usage**

`zip2john zipfile.zip > ziphash.txt`

<span style="font-size: 23px;">**zip2john zipfile.zip > zip_hash.txt**</span>

We're then able to take the file we output from `zip2john` in our example use case, `zip_hash.txt`, and, as we did with `unshadow`, feed it directly into John as we have made the input specifically for it.

`john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt`

<span style="font-size: 23px;">**Q&A**</span>

```bash
# step1 convert the Zip file into a hash format
user@ip-10-10-237-125:~$ zip2john secure.zip > ziphash.txt
user@ip-10-10-237-125:~$ ls
secure.zip  ziphash.txt
user@ip-10-10-237-125:~$ cat ziphash.txt 
secure.zip/zippy/flag.txt:$pkzip$1*2*2*0*26*1a*849ab5a6*0*48*0*26*b689*964fa5a31f8cefe8e6b3456b578d66a08489def78128450ccf07c28dfa6c1
97fd148f696e3a2*$/pkzip$:zippy/flag.txt:secure.zip::secure.zip
# step2 Cracking
user@ip-10-10-237-125:~$ john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Note: Passwords longer than 21 [worst case UTF-8] to 63 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
pass123          (secure.zip/zippy/flag.txt)     
1g 0:00:00:00 DONE (2025-05-19 03:52) 33.33g/s 273066p/s 273066c/s 273066C/s newzealand..total90
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
# step3 uzip the file
user@ip-10-10-237-125:~$ unzip secure.zip 
Archive:  secure.zip
[secure.zip] zippy/flag.txt password: 
 extracting: zippy/flag.txt          
user@ip-10-10-237-125:~$ ls
secure.zip  ziphash.txt  zippy
user@ip-10-10-237-125:~$ cd zippy/
user@ip-10-10-237-125:~/zippy$ ls
flag.txt
user@ip-10-10-237-125:~/zippy$ cat flag.txt 
THM{w3ll_d0n3_h4sh_r0y4l}
```


## Cracking Password-Protected RAR Archives

We can use a similar process to the one we used in the last task to obtain the password for RAR archives. If you aren't familiar, RAR archives are compressed files created by the WinRAR archive manager. Like Zip files, they compress folders and files.

<span style="font-size: 23px;">**Rar2John**</span>

Almost identical to the `zip2john` tool, we will use the `rar2john` tool to convert the RAR file into a hash format that John can understand. The basic syntax is as follows:

`rar2john [rar file] > [output file]`

- `rar2john`: Invokes the rar2john tool
- `[rar file]`: The path to the RAR file you wish to get the hash of
- `>`: This redirects the output of this command to another file
- `[output file]`: This is the file that will store the output from the command

**Example Usage**

`/opt/john/rar2john rarfile.rar > rarhash.txt`

<span style="font-size: 23px;">**Cracking**</span>

Once again, we can take the file we output from rar2john in our example use case, rar_hash.txt, and feed it directly into John as we did with zip2john.

`john --wordlist=/usr/share/wordlists/rockyou.txt rarhash.txt`

<span style="font-size: 23px;">**Q&A**</span>

```bash
# step1
user@ip-10-10-237-125:~$ ls
secure.rar
user@ip-10-10-237-125:~$ rar2john secure.rar > rarhash.txt
user@ip-10-10-237-125:~$ ls
rarhash.txt  secure.rar
user@ip-10-10-237-125:~$ cat rarhash.txt 
secure.rar:$rar5$16$b7b0ffc959b2bc55ffb712fc0293159b$15$4f7de6eb8d17078f4b3c0ce650de32ff$8$ebd10bb79dbfb9f8
# step2
user@ip-10-10-237-125:~$ john --wordlist=/usr/share/wordlists/rockyou.txt rarhash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (RAR5 [PBKDF2-SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 2 OpenMP threads
Note: Passwords longer than 10 [worst case UTF-8] to 32 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
password         (secure.rar)     
1g 0:00:00:00 DONE (2025-05-19 04:05) 1.754g/s 112.3p/s 112.3c/s 112.3C/s 123456..charlie
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
# step3
user@ip-10-10-237-125:~$ unrar x secure.rar 

UNRAR 7.00 freeware      Copyright (c) 1993-2024 Alexander Roshal

Enter password (will not be echoed) for secure.rar: 


Extracting from secure.rar

Extracting  flag.txt                                                  OK 
All OK
user@ip-10-10-237-125:~$ ls
flag.txt  rarhash.txt  secure.rar
user@ip-10-10-237-125:~$ cat flag.txt 
THM{r4r_4rch1ve5_th15_t1m3}
```

## Cracking SSH Key Passwords

Okay, okay, I hear you. There are no more file archives! Fine! Let's explore one more use of John that comes up semi-frequently in CTF challenges—using John to crack the SSH private key password of `id_rsa` files. Unless configured otherwise, you authenticate your SSH login using a password. However, you can configure key-based authentication, which lets you use your private key, `id_rsa`, as an authentication key to log in to a remote machine over SSH. However, doing so will often require a password to access the private key; here, we will be using John to crack this password to allow authentication over SSH using the key.

<span style="font-size: 23px;">**SSH2John**</span>

Who could have guessed it, another conversion tool? Well, that's what working with John is all about. As the name suggests, `ssh2john` converts the `id_rsa` private key, which is used to log in to the SSH session, into a hash format that John can work with. Jokes aside, it's another beautiful example of John's versatility. The syntax is about what you'd expect. Note that if you don't have `ssh2john` installed, you can use `ssh2john.py`, located in the `/opt/john/ssh2john.py`. If you're doing this on the AttackBox, replace the `ssh2john` command with python3 `/opt/john/ssh2john.py` or on Kali, `python /usr/share/john/ssh2john.py`.

`ssh2john [id_rsa private key file] > [output file]`

- `ssh2john`: Invokes the ssh2john tool
- `[id_rsa private key file]`: The path to the id_rsa file you wish to get the hash of
- `>`: This is the output director. We're using it to redirect the output from this command to another file.
- `[output file]`: This is the file that will store the output from

**Example Usage**

`/opt/john/ssh2john.py id_rsa > id_rsa_hash.txt`

<span style="font-size: 23px;">**Cracking**</span>

For the final time, we're feeding the file we output from ssh2john, which in our example use case is called `id_rsa_hash.txt` and, as we did with `rar2john`, we can use this seamlessly with John:

`john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt`

<span style="font-size: 23px;">**Q&A**</span>

```bash
# step1
user@ip-10-10-237-125:~$ ssh2john.py id_rsa > id_rsa_hash.txt
user@ip-10-10-237-125:~$ ls
id_rsa  id_rsa_hash.txt
# step2
user@ip-10-10-237-125:~$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: Passwords longer than 10 [worst case UTF-8] to 32 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
mango            (id_rsa)     
1g 0:00:00:00 DONE (2025-05-19 04:18) 50.00g/s 214400p/s 214400c/s 214400C/s praise..mango
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
user@ip-10-10-237-125:~$ ls
id_rsa  id_rsa_hash.txt 

```