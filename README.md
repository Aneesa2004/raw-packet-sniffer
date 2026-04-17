# Raw Packet Sniffer & Protocol Analyzer (C)

## Project Overview
This project is a raw packet sniffer built in C for the CPAN226 Network Programming course. The goal was to capture live network traffic and analyze packet data without using tools like Wireshark.

The program uses raw sockets to intercept packets directly from the network interface and then breaks them down into different layers to display useful information.

---

## How It Works
The program creates a raw socket using `AF_PACKET`, which allows it to capture all incoming and outgoing packets.

Each packet is stored in a buffer and then parsed step by step:

- **Ethernet Layer (Layer 2)**  
  Extracts source and destination MAC addresses  

- **IP Layer (Layer 3)**  
  Extracts source IP, destination IP, and TTL  

- **Transport Layer (Layer 4)**  
  Identifies the protocol (TCP, UDP, ICMP)  
  Extracts port numbers for TCP and UDP  

---

## Features
- Captures live network packets in real time  
- Displays MAC addresses  
- Displays IP addresses and TTL  
- Detects TCP, UDP, and ICMP protocols  
- Extracts source and destination ports  
- Identifies common services based on port numbers:
  - HTTP (port 80)
  - HTTPS (port 443)
  - DNS (port 53)
- Real-time packet counter (TCP, UDP, ICMP)

---

## Technologies Used
- C programming language  
- Linux (WSL environment)  
- Raw sockets (`AF_PACKET`)  

---

## How to Run the Program

Open a Linux/WSL terminal and run:

```bash
gcc sniffer.c -o sniffer
sudo ./sniffer
