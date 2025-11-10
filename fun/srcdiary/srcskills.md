---
title: "SRC Skills"
categories:
  - 技术
  - 教程
tags: [SRC, skills]
draft: true
sidebar: false
outline: deep
---

# SRC Skills

**SRC**（**Security Researcher Acknowledgement Program**）是各大互联网厂商开启的漏洞发现奖励计划，也就是我们常说的漏洞赏金计划（bug bounty），旨在鼓励广大的安全研究人员积极发现厂商产品或服务安全漏洞并向厂商提交漏洞报告，帮助厂商修补漏洞，保障整个互联网的安全。

<span style="font-size: 23px;">**SRC漏洞挖掘的流程**</span>
1. **收集信息**

首先，需要了解目标网站或应用的基本信息，包括目标服务器的IP地址、端口号、网站或应用的URL地址、功能等，以及目标网站的后端架构、Web应用程序的技术栈、目标网站的漏洞历史等信息，这些信息可以通过一些工具及技术如端口扫描、Web应用程序漏洞扫描等获取。

2. **发现漏洞**

在已掌握的信息基础上，利用漏洞扫描器或手动尝试探测漏洞，当发现漏洞之后，需要尽快记录漏洞详细信息，如漏洞地址、漏洞类型、漏洞危害程度、漏洞修复难度等等，并尽快向漏洞提交平台提交漏洞报告。

3. **验证漏洞**

漏洞验证是确认漏洞是否真实存在和漏洞危害程度的过程。漏洞提交平台通常也会要求安全研究人员在提交漏洞报告后，进行漏洞验证工作，以尽早地确定漏洞的危害性并帮助厂商更快地修复漏洞。

4. **提交漏洞报告**

将漏洞信息、验证过程、漏洞影响、漏洞截图等详细信息整理成漏洞报告并提交给漏洞提交平台，并等待漏洞提交平台处理并转交给厂商。

5. **等待漏洞修复和奖励**

漏洞提交平台的工作人员通常会将漏洞报告转交给漏洞厂商进行修复，如果该厂商通过了相关的审核，则会发放漏洞赏金或者其他奖励。

**Note:** 在提交漏洞报告之前，安全研究人员要遵守相关的法规、规定和道德规范，不得进行未授权的攻击或试图入侵目标网站或应用。

网络安全法：https://www.cac.gov.cn/2016-11/07/c_1119867116.htm

众测平台：https://www.ichunqiu.com/cqyc

国家信息安全漏洞库: https://www.cnnvd.org.cn/home/childHome

![src 平台](<assets/src 平台.png>)

## what

能突破系统限制，但是对任何人产生不了危害，对自己有危害。 ❌

能突破系统限制，可以对企业或个人造成影响，有受益方或损失方。 ✔️

## 工具

### fiddler

https://www.telerik.com/download/fiddler

https://telerik-fiddler.s3.amazonaws.com/fiddler/addons/fiddlercertmaker.exe

## 信息收集

### 域名搜索 

[Fofa](https://fofa.info/): `domain="baidu.com"`

[Hunter](https://hunter.qianxin.com/): `domain.suffix="baidu.com"`

[Google](https://www.google.com): `site:baidu.com`


[SEO](https://seo.chinaz.com/)


## 操作

### 越权

做自己权限外的事情

<span style="font-size: 23px;">**横向越权和纵向越权**</span>

**横向越权**指的是你可以操作其他权限和你相同的账户

**纵向越权**指的是你可以对你未拥有的权限进行操作

### 并发

<span style="font-size: 23px;">**并发逻辑**</span>

A用户向后端发起购买请求，后端收到请求后去数据库里面查询用户余额，然后后端认为用户余额够就下发商品。

但是A用户如果用并发的方式发起请求，后端同时向数据库发起多次请求，返回都成功但是还没到扣费那一步，导致了用户可以购买超出自身余额的商品。

### 支付

服务器对是否支付成功做校验 ❌

服务器对订单金额做校验 ✔️

---

## tips

---

### 数值

<span style="font-size: 23px;">**int类型**</span>

**有符号(Signed)**

最小值: $-2^{31}$= -2,147,483,648

最大值: $2^{31}$ - 1 = 2,147,483,647

**无符号(unsigned)**

最小值: 0

最大值: $2^{32}$ - 1  = 4,294,967,295

<span style="font-size: 23px;">**科学计数法**</span> 

```python
>>> 1E+5
100000.0
>>> 1E-1
0.1
```
<span style="font-size: 23px;">**四舍五入**</span>

充值 0.016 到账 0.02

充值 0.014, 支付显示0.01 实际到账0.014, 
由于前端给后端发起的请求是0.014, 但是第三方支付工具最小支付单位为分导致

### 返回值

生成签名前提前修改返回值

