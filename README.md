# Custom Linux-Based Firewall with Interface-Level Logging & WireGuard VPN

## Introduction

This project is a custom-built Linux firewall designed for secure and efficient network traffic control. It provides **interface-level logging**, **packet inspection**, and supports **encrypted VPN communication** using WireGuard. The firewall was developed using **Python** and **Bash scripting** to automate traffic management and log collection, offering a balance between performance and flexibility.

Whether managing internal segments or allowing encrypted remote access, this firewall offers transparency and control with real-time logging and rule-based filtering.

---

## ⚙️ Features

- Dual-interface setup (`ens192` as ingress, `ens160` as egress)
- Secure traffic routing using `iptables` with NAT masquerading
- **Custom Python scripts** for:
  - Interface-level packet logging
  - Real-time log analysis
  - Rule automation and configuration parsing
- VPN support with **WireGuard** for secure remote communication
- Firewall rule management based on IPs, ports, and protocols

---

## 🔧 Technologies Used

- Linux (Red Hat-based)
- Python
- Bash scripting
- iptables
- WireGuard
- Networking tools (`ip`, `tcpdump`, `netstat`, `ss`)

---
