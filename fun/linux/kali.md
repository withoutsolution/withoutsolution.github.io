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
## 5.VMware share folder

在 Kali Linux 中，VMware 共享文件夹配置后不显示（`/mnt/hgfs` 为空）是一个**非常经典**的问题。这通常是因为 Kali 默认安装的 `open-vm-tools` 虽然支持剪贴板，但往往不会自动挂载文件系统。

请按照以下步骤依次排查和解决，通常只需执行到**第 3 步**即可解决。

-----

### 第一步：确认 VMware 设置（宿主机端）

确保您在 VMware Workstation/Player 的设置中已经正确配置：

1.  虚拟机处于**关机**或**运行**状态均可。
2.  点击菜单：**虚拟机 (VM)** -\> **设置 (Settings)**。
3.  选项卡：**选项 (Options)** -\> **共享文件夹 (Shared Folders)**。
4.  右侧选择：**总是启用 (Always enabled)**。
5.  在下方添加了您的 Windows 文件夹，并确保没有勾选“只读”。

-----

### 第二步：安装/更新必要的 VMware 工具（虚拟机端）

Kali 推荐使用 `open-vm-tools` 而不是旧版的 VMware Tools 安装包。必须安装 `desktop` 版本才支持共享文件夹。

打开终端执行：

```bash
# 1. 更新软件源
sudo apt update

# 2. 安装 open-vm-tools-desktop (如果已安装会尝试更新)
sudo apt install open-vm-tools-desktop fuse -y

# 3. 建议重启一下虚拟机，确保驱动加载
sudo reboot
```

-----

### 第三步：手动挂载（核心解决步骤）

重启回来后，如果文件夹还是没出现，请执行以下“终极命令”。

1.  **检查 VM 是否识别到了文件夹：**
    输入以下命令，如果能看到您在 Windows 设置的文件夹名字，说明连接是通的，只是没挂载上。

    ```bash
    vmware-hgfsclient
    ```

2.  **创建挂载点（如果不存在）：**

    ```bash
    sudo mkdir -p /mnt/hgfs
    ```

3.  **执行挂载命令：**
    这是最关键的一步，使用 `vmhgfs-fuse` 驱动进行挂载。

    ```bash
    sudo mount -t fuse.vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other
    ```

4.  **验证：**
    现在去查看目录，应该就能看到了：

    ```bash
    ls /mnt/hgfs
    ```

    或者在文件管理器中打开 `/mnt/hgfs`。

-----

### 第四步：设置开机自动挂载（一劳永逸）

第三步的命令在重启后会失效。如果您希望每次开机自动挂载，需要修改 `/etc/fstab` 文件。

1.  **编辑 fstab 文件：**

    ```bash
    sudo nano /etc/fstab
    ```

2.  **在文件末尾添加这一行：**
    （注意：请确保是独立的一行）

    ```text
    .host:/ /mnt/hgfs fuse.vmhgfs-fuse allow_other 0 0
    ```

3.  **保存并退出：**
    按 `Ctrl + O` -\> `Enter` 保存，然后 `Ctrl + X` 退出。

4.  **测试配置是否正确：**
    执行 `sudo mount -a`，如果没有报错，说明配置成功。下次重启后文件夹会自动出现。

-----

### 常见报错处理

  * **报错：`Error: cannot mount filesystem: No such device`**
      * 原因：fuse 模块没加载或 open-vm-tools 没装好。
      * 解决：重装工具 `sudo apt install --reinstall open-vm-tools-desktop` 并重启。
  * **权限问题：**
      * 如果您发现能看到文件但无法修改（锁住了），确保挂载命令中加了 `-o allow_other` 参数。

您可以先试一下**第三步**的那个挂载命令，看能不能立刻看到文件？