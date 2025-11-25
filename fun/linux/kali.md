---
title: "kali"
date: 2025-05
categories:
  - 技术
  - 教程
tags: [Markdown, linux, kali]
description: kali Fundamentals
draft: false
sidebar: false
outline: 2
---

# kali

## 0.常用命令

```bash
sudo apt update
sudo apt full-upgrade
sudo apt autoremove
sudo apt clean
```

---

## 1.更新源

```zsh
vim /etc/apt/sources.list
```

```bash
# 官方源
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
# 中科大
deb http://mirrors.ustc.edu.cn/kali kali-rolling main non-free contrib
deb-src http://mirrors.ustc.edu.cn/kali kali-rolling main non-free contrib
# 阿里云
deb http://mirrors.aliyun.com/kali kali-rolling main non-free contrib
deb-src http://mirrors.aliyun.com/kali kali-rolling main non-free contrib
# 清华大学
deb http://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free
deb-src https://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free
# 浙大
deb http://mirrors.zju.edu.cn/kali kali-rolling main contrib non-free
deb-src http://mirrors.zju.edu.cn/kali kali-rolling main contrib non-free

```

```bash
# 更新更新源：
apt-get update

# 更新系统：
apt-get dist-upgrade

# 更新软件：
apt-get upgrade
# 清理安装包：
apt-get clean
apt-get autoclean

# 安装KDE界面：
apt-get install kde-full
```

---

## 2.proxychains

```bash
sudo apt-get install proxychains4

sudo vim /etc/proxychains4.conf
```

---

## 3.SSH

```bash
sudo apt-get install ssh
```

```BASH
sudo systemctl enable ssh
```

```BASH
sudo systemctl start ssh
sudo systemctl status ssh
```

---

## 4.OpenVPN

```bash
sudo apt-get install openvpn
```

```bash
sudo openvpn --config yourname.ovpn --socks-proxy proxyip port
```