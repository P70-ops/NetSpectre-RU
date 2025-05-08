# NetSpectre-RU
NetSpectre RU network analyzer
# 🇷 КИБЕР-СЕТЕВОЙ СНИФФЕР —  Packet Eye

> 🔍 Ultra-Advanced Terminal-Based Network Sniffer for Hackers, Analysts, and Enthusiasts  
> A beautifully crafted real-time packet monitoring tool — with Russian cyber aesthetics, live logging, protocol filtering, and future-ready features.

---

## 🎯 Features

### 🧠 Smart Real-Time Packet Sniffer
- Captures packets in real-time using `scapy` with live terminal display.
- Shows `SRC_IP`, `SRC_PORT`, `DST_IP`, `DST_PORT`, `PROTOCOL`, and `TIMESTAMP`.

### 🧬 Protocol Detection Engine
- Advanced protocol resolution: **TCP**, **UDP**, **ICMP**, others tagged as **OTHER**.
- Easily extensible for DNS, HTTP, TLS detection.

### 📁 Live Packet Logger
- Optional file logging to `packet_log.txt`.
- Use `tail -f packet_log.txt` to monitor log output in real time.

### 🎨 Hacker Eye UI (Colorized Terminal)
- Stylish terminal output using `Colorama`.
- High contrast for dark terminals – perfect for underground ops.

### 🇷  Hacker Banner
- Custom banner for themed CTFs, underground demos, and personal use.
- Looks like a tool out of a high-budget hacking movie.

### 🔍 Filter Options (Planned)
- Set filters like `src ip`, `dst port`, `proto`, or regex matching for packet contents.

### 🌐 Media Viewer (Coming Soon)
- Integration with HTML/Flask front-end to:
  - View videos or packets from Facebook, YouTube, Telegram links.
  - Live stream captured traffic media (in dev).

---

## ⚙️ Installation

```bash
git clone https://github.com/yourname/russian-packet-eye.git
cd packet-eye
pip install -r requirements.txt
