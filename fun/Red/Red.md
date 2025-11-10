---
title: "Red"
categories:
  - 技术
  - 教程
tags: [web app, Red Team]
draft: true
sidebar: false
outline: deep
---

# Red

![red](assets/red.png)

## intro

<span style="font-size: 23px;">**cyber kill chains**</span>

[Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)

| Technique          | Purpose                                                     | Examples                                                                |
|--------------------|-------------------------------------------------------------|--------------------------------------------------------------------------|
| Reconnaissance     | Obtain information on the target                           | Harvesting emails, OSINT                                                  |
| Weaponization      | Combine the objective with an exploit. Commonly results in a deliverable payload. | Exploit with backdoor, malicious office document                            |
| Delivery           | How will the weaponized function be delivered to the target | Email, web, USB                                                            |
| Exploitation       | Exploit the target's system to execute code                 | MS17-010, Zero-Logon, etc.                                                |
| Installation       | Install malware or other tooling                              | Mimikatz, Rubeus, etc.                                                    |
| Command & Control  | Control the compromised asset from a remote central controller | Empire, Cobalt Strike, etc.                                               |
| Actions on Objectives | Any end objectives: ransomware, data exfiltration, etc.    | Conti, LockBit2.0, etc.                                                   |

## Red Team Engagements

Rules of Engagement ([RoE](../common.md#roe)) are a legally binding outline of the client objectives and scope with further details of engagement expectations between both parties. This is the first "official" document in the engagement planning process and requires proper authorization between the client and the red team. This document often acts as the general contract between the two parties; an external contract or other NDAs (**Non-Disclosure Agreement**) can also be used.

The format and wording of the RoE are critical since it is a legally binding contract and sets clear expectations.

Each RoE structure will be determined by the client and red team and can vary in content length and overall sections. Below is a brief table of standard sections you may see contained in the RoE.

| Section Name                            | Section Details                                                                                                                                               |
|-----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Executive Summary                       | Overarching summary of all contents and authorization within RoE document                                                                                      |
| Purpose                                 | Defines why the RoE document is used                                                                                                                              |
| References                              | Any references used throughout the RoE document (HIPAA, ISO, etc.)                                                                                                 |
| Scope                                     | Statement of the agreement to restrictions and guidelines                                                                                                       |
| Definitions                             | Definitions of technical terms used throughout the RoE document                                                                                                  |
| Rules of Engagement and Support Agreement | Defines obligations of both parties and general technical expectations of engagement conduct                                                                   |
| Provisions                              | Define exceptions and additional information from the Rules of Engagement                                                                                          |
| Requirements, Restrictions, and Authority | Define specific expectations of the red team cell                                                                                                                 |
| Ground Rules                            | Define limitations of the red team cell's interactions                                                                                                           |
| Resolution of Issues/Points of Contact   | Contains all essential personnel involved in an engagement                                                                                                         |
| Authorization                           | Statement of authorization for the engagement                                                                                                                     |
| Approval                                  | Signatures from both parties approving all subsections of the preceding document                                                                                  |
| Appendix                                  | Any further information from preceding subsections                                                                                                               |

When analyzing the document, it is important to remember that it is only a summary, and its purpose is to be a legal document. Future and more in-depth planning are required to expand upon the RoE and client objectives.

For this task we will use a shortened document adapted from [redteam.guide](https://redteam.guide/docs/templates/roe_template/)

<span style="font-size: 23px;">**Concept of Operations**</span>

The Concept of Operation (CONOPS) is a part of the engagement plan that details a high-level overview of the proceedings of an engagement; we can compare this to an executive summary of a penetration test report. The document will serve as a business/client reference and a reference for the red cell to build off of and extend to further campaign plans.

The CONOPS document should be written from a semi-technical summary perspective, assuming the target audience/reader has zero to minimal technical knowledge. Although the CONOPS should be written at a high level, you should not omit details such as common tooling, target group, etc. As with most red team documents, there is not a set standard of a CONOPS document; below is an outline of critical components that should be included in a CONOPS

- Client Name
- Service Provider
- Timeframe
- General Objectives/Phases
- Other Training Objectives (Exfiltration)
- High-Level Tools/Techniques planned to be used
- Threat group to emulate (if any)

The key to writing and understanding a CONOPS is to provide just enough information to get a general understanding of all on-goings. The CONOPS should be easy to read and show clear definitions and points that readers can easily digest.

<span style="font-size: 23px;">**Resource Plan**</span>

The resource plan is the second document of the engagement plan, detailing a brief overview of dates, knowledge required (optional), resource requirements. The plan extends the CONOPS and includes specific details, such as dates, knowledge required, etc.

Unlike the CONOPS, the resource plan should not be written as a summary; instead, written as bulleted lists of subsections. As with most red team documents, there is no standard set of resource plan templates or documents; below is an outline of example subsections of the resource plan.

- Header
  - Personnel writing
  - Dates
  - Customer
- Engagement Dates
  - Reconnaissance Dates
  - Initial Compromise Dates
  - Post-Exploitation and [Persistence](../common.md#persistence) Dates
  - Misc. Dates
- Knowledge Required (optional)
  - Reconnaissance
  - Initial Compromise
  - Post-Exploitation
- Resource Requirements
  - Personnel
  - Hardware
  - Cloud
  - Misc.

The key to writing and understanding a resource plan is to provide enough information to gather what is required but not become overbearing. The document should be straight to the point and define what is needed.

<span style="font-size: 23px;">**Operations Plan**</span>

The operations plan is a flexible document(s) that provides specific details of the engagement and actions occurring. The plan expands upon the current CONOPS and should include a majority of specific engagement information; the ROE can also be placed here depending on the depth and structure of the ROE.

The operations plan should follow a similar writing scheme to the resource plan, using bulleted lists and small sub-sections. As with the other red team documents, there is no standard set of operation plan templates or documents; below is an outline of example subsections within the operations plan.

- Header
  - Personnel writing
  - Dates
  - Customer
- Halting/stopping conditions (can be placed in ROE depending on depth)
- Required/assigned personnel
- Specific TTPs and attacks planned
- Communications plan
- Rules of Engagement (optional)

The most notable addition to this document is the communications plan. The communications plan should summarize how the red cell will communicate with other cells and the client overall. Each team will have its preferred method to communicate with clients. Below is a list of possible options a team will choose to communicate.

- [vectr.io](https://vectr.io/)
- Email
- Slack

<span style="font-size: 23px;">**Mission Plan**</span>

The mission plan is a cell-specific document that details the exact actions to be completed by operators. The document uses information from previous plans and assigns actions to them.

How the document is written and detailed will depend on the team; as this is an internally used document, the structure and detail have less impact. As with all the documents outlined in this room, presentation can vary; this plan can be as simple as emailing all operators. Below is a list of the minimum detail that cells should include within the plan.

- Objectives
- Operators
- Exploits/Attacks
- Targets (users/machines/objectives)
- Execution plan variations

The two plans can be thought of similarly; the operations plan should be considered from a business and client perspective, and the mission plan should be thought of from an operator and red cell perspective.

## Red Team Threat Intel

**Threat Intelligence (TI)** or **Cyber Threat Intelligence ([CTI](../common.md#cti))** is the information, or TTPs (**Tactics, Techniques, and Procedures**), attributed to an adversary, commonly used by defenders to aid in detection measures. The red cell can leverage CTI from an offensive perspective to assist in adversary emulation.

**TIBER-EU** (Threat Intelligence-based Ethical Red Teaming) is a common framework developed by the European Central Bank that centers around the use of threat intelligence.

From the [ECB TIBER-EU white paper](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf), "The Framework for Threat Intelligence-based Ethical Red Teaming (TIBER-EU) enables European and national authorities to work with financial infrastructures and institutions (hereafter referred to collectively as 'entities') to put in place a programme to test and improve their resilience against sophisticated cyber attacks."

![TIBER-EU](assets/TIBER-EU.svg)

<span style="font-size: 23px;">**TTP Mapping**</span>

**[TTP](../common.md#ttp) Mapping** is employed by the red cell to map adversaries' collected TTPs to a standard cyber kill chain. Mapping TTPs to a kill chain aids the red team in planning an engagement to emulate an adversary.

## Red Team OPSEC

Operations Security ([OPSEC](../common.md#opsec)) is a term coined by the United States military.

Denying any potential adversary the ability to gather information about our capabilities and intentions is critical to maintaining OPSEC. OPSEC is a process to identify, control and protect any information related to the planning and execution of our activities. 

![OPSEC process](<assets/OPSEC process.png>)

The OPSEC process has five steps:

1. Identify critical information
2. Analyse threats
3. Analyse vulnerabilities
4. Assess risks
5. Apply appropriate countermeasures

![OPSEC process steps](<assets/OPSEC process steps.png>)

If the adversary discovers that you are scanning their network with Nmap (the blue team in our case), they should easily be able to discover the IP address used. For instance, if you use this same IP address to host a phishing site, it won't be very difficult for the blue team to connect the two events and attribute them to the same actor.

OPSEC is not a solution or a set of rules; OPSEC is a five-step process to deny adversaries from gaining access to any critical information.

### Critical Information Identification

What a red teamer considers critical information worth protecting depends on the operation and the assets or tooling used. In this setting, critical information includes, but is not limited to, the red team's intentions, capabilities, activities, and limitations. Critical information includes any information that, once obtained by the blue team, would hinder or degrade the red team's mission.

![Critical Information](<assets/Critical Information.png>)

To identify critical information, the red team needs to use an adversarial approach and ask themselves what information an adversary, the blue team, in this case, would want to know about the mission. If obtained, the adversary will be in a solid position to thwart the red team's attacks. Therefore, critical information is not necessarily sensitive information; however, it is any information that might jeopardise your plans if leaked to an adversary. The following are some examples:

- Client information that your team has learned. It's unacceptable to share client specific information such as employee names, roles, and infrastructure that your team has discovered. Sharing this type of information should kept on need-to-know basis as it could compromise the integrity of the operation. The Principle of Least Privilege (PoLP) dictates that any entity (user or process) must be able to access only the information necessary to carry out its task. PoLP should be applied in every step taken by the Red Team.
- Red team information, such as identities, activities, plans, capabilities and limitations. The adversary can use such information to be better prepared to face your attacks.
- Tactics, Techniques, and Procedures ([TTP](../common.md#ttp)) that your team uses in order to emulate an attack.
- [OS](../common.md#os), cloud hosting provider, or [C2](../common.md#c2) framework utilised by your team. Let's say that your team uses Pentoo for penetration testing, and the defender knows this. Consequently, they can keep an eye for logs exposing the OS as Pentoo. Depending on the target, there is a possibility that other attackers are also using Pentoo to launch their attacks; however, there is no reason to expose your OS if you don't have to.
- Public IP addresses that your red team will use. If the blue team gains access to this kind of information, they could quickly mitigate the attack by blocking all inbound and outbound traffic to your IP addresses, leaving you to figure out what has happened.
- Domain names that your team has registered. Domain names play a significant role in attacks such as [phishing](../common.md#phishing). Likewise, if the blue team figures out the domain names you will be using to launch your attacks, they could simply block or sinkhole your malicious domains to neutralize your attack.
- Hosted websites, such as phishing websites, for adversary emulation.

---

### Threat Analysis

After we identify critical information, we need to analyse threats. Threat analysis refers to identifying potential adversaries and their intentions and capabilities. Adapted from the US Department of Defense [(DoD) Operations Security (OPSEC) Program Manual](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodm/520502m.pdf), threat analysis aims to answer the following questions:

1. Who is the adversary?
2. What are the adversary's goals?
3. What tactics, techniques, and procedures does the adversary use?
4. What critical information has the adversary obtained, if any?

![Threat Analysis](<assets/Threat Analysis.png>)

We consider any adversary with the intent and capability to take actions that would prevent us from completing our operation as a threat:

`threat = adversary + intent + capability`

In other words, an adversary without the intent or capability does not pose a threat for our purposes.

---

### Vulnerability Analysis

After identifying critical information and analysing threats, we can start with the third step: analysing vulnerabilities. This is not to be confused with vulnerabilities related to cybersecurity. An OPSEC vulnerability exists when an adversary can obtain critical information, analyse the findings, and act in a way that would affect your plans.

![Vulnerability Analysis](<assets/Vulnerability Analysis.png>)

To better understand an OPSEC vulnerability as related to red teaming, we'll consider the following scenario. You use Nmap to discover live hosts on a target subnet and find open ports on live hosts. Moreover, you send various phishing emails leading the victim to a phishing webpage you're hosting. Furthermore, you're using the Metasploit framework to attempt to exploit certain software vulnerabilities. These are three separate activities; however, if you use the same IP address(es) to carry out these different activities, this would lead to an OPSEC vulnerability. Once any hostile/malicious activity is detected, the blue team is expected to take action, such as blocking the source IP address(es) temporarily or permanently. Consequently, it would take one source IP address to be blocked for all the other activities use this IP address to fail. In other words, this would block access to the destination IP address used for the phising server, and the source IP address using by Nmap and Metasploit Framework.

Another example of an OPSEC vulnerability would be an unsecured database that's used to store data received from phishing victims. If the database is not properly secured, it may lead to a malicious third party compromising the operation and could result in data being exfiltrated and used in an attack against your client's network. As a result, instead of helping your client secure their network, you would end up helping expose login names and passwords.

Lax OPSEC could also result in less sophisticated vulnerabilities. For instance, consider a case where one of your red team members posts on social media revealing your client's name. If the blue team monitors such information, it will trigger them to learn more about your team and your approaches to better prepare against expected penetration attempts.

---

### Risk Assessment 

We finished analysing the vulnerabilities, and now we can proceed to the fourth step: conducting a risk assessment. [NIST](../common.md#nist) defines a risk assessment as "The process of identifying risks to organizational operations (including mission, functions, image, reputation), organizational assets, individuals, other organizations, and the Nation, resulting from the operation of an information system." In OPSEC, risk assessment requires learning the possibility of an event taking place along with the expected cost of that event. Consequently, this involves assessing the adversary's ability to exploit the vulnerabilities.

![Risk Assessment](<assets/Risk Assessment.png>)

Once the level of risk is determined, countermeasures can be considered to mitigate that risk. We need to consider the following three factors:

1. The efficiency of the countermeasure in reducing the risk
2. The cost of the countermeasure compared to the impact of the vulnerability being exploited.
3. The possibility that the countermeasure can reveal information to the adversary

Let's revisit the two examples from the previous task. In the first example, we considered the vulnerability of scanning the network with Nmap, using the Metasploit framework, and hosting the phishing pages using the same public IP address. We analysed that this is a vulnerability as it makes it easier for the adversary to block our three activities by simply detecting one activity. Now let's assess this risk. To evaluate the risk related to this vulnerability, we need to learn the possibility of one or more of these activities being detected. We cannot answer this without obtaining some information about the adversary's capabilities. Let's consider the case where the client has a Security Information and Event Management ([SIEM](../common.md#siem)) in place. A SIEM is a system that allows real-time monitoring and analysis of events related to security from different sources across the network. We can expect that a SIEM would make it reasonably uncomplicated to detect suspicious activity and connect the three events. As a result, we would assess the related risk as high. On the other hand, if we know that the adversary has minimal resources for detecting security events, we can assess the risk related to this vulnerability as low.

Let's consider the second example of an unsecured database used to store data received from a phishing page. Based on data collected from several research groups using honeypots, we can expect various malicious bots to actively target random IP addresses on the Internet. Therefore, it is only a matter of time before a system with weak security is discovered and exploited.

---

### Countermeasures

The final step is applying countermeasures. The US Department of Defense (DoD) [Operations Security (OPSEC) Program Manual](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodm/520502m.pdf) states, “*Countermeasures are designed to prevent an adversary from detecting critical information, provide an alternative interpretation of critical information or indicators (deception), or deny the adversary's collection system.*”

![Countermeasures](assets/Countermeasures.png)

Let's revisit the two examples we presented in the Vulnerability Analysis task. In the first example, we considered the vulnerability of running Nmap, using the Metasploit framework, and hosting the phishing pages using the same public IP address. The countermeasure for this one seems obvious; use a different IP address for each activity. This way, you can ensure that if one activity was detected the public IP address is blocked, the other activities can continue unaffected.

In the second example, we considered the vulnerability of an unsecured database used to store data received from a phishing page. From a risk assessment perspective, we considered it as high risk due to malicious third parties potentially looking for random easy targets. The countermeasure, in this case, would be to ensure that the database is adequately secured so that the data cannot be accessed except by authorized personnel.

## Intro to C2

[details](../security/c2.md)
