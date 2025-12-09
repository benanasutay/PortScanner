# PortScanner

![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

**Python & Socket based multi-threaded network scanner. Features TCP/UDP/SYN scanning, TTL-based OS detection, static CVE vulnerability analysis, and a hybrid (CLI/GUI) interface.**

This tool is designed for cybersecurity portfolios and authorized security assessments to demonstrate network discovery mechanics using Python's standard libraries.

## 🚀 Key Features

* **Multi-Mode Scanning:** Supports **TCP Connect**, **UDP Probing**, and **SYN** (Stealth/Raw Socket) scanning methods.
* **OS Detection:** Estimates the target Operating System (Windows/Linux) using **ICMP TTL (Time To Live)** analysis.
* **Vulnerability Assessment:** Performs **Banner Grabbing** and cross-references service versions with an internal **CVE Database** to flag potential security risks.
* **High Performance:** Uses `ThreadPoolExecutor` for fast, concurrent scanning.
* **Hybrid Interface:** Operates as both a Command Line Tool (CLI) for automation and a Graphical Interface (GUI) for ease of use.
* **Portable:** No external dependencies (`pip install` is NOT required).

## 🛠️ Installation

This tool is built using **Python's standard libraries**, so there are **no external requirements** (no `pip install` needed).

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/benanasutay/PortScanner.git](https://github.com/benanasutay/PortScanner.git)
    cd PortScanner
    ```

2.  **Run the tool:**
    * **Windows:**
        ```bash
        py PortScanner.py
        ```
    * **Linux / macOS:**
        ```bash
        python3 PortScanner.py
        ```

## 💻 Usage

The tool automatically detects the running mode. If arguments are provided, it runs in **CLI mode**. If no arguments are provided, it launches the **GUI**.
<img width="996" height="779" alt="image" src="https://github.com/user-attachments/assets/ed219ce3-9c33-47ff-8c21-6e8b7a878f4a" />

### CLI (Command Line Interface)

**1. View Help Menu:**
Displays all available flags and options.
```bash
py PortScanner.py -h
