#!/bin/bash
# Beycan Ana Çalıştırıcı

# Platform algılama
if [ -d /data/data/com.termux/files/usr ]; then
    # Termux ortamı
    pkg update -y
    pkg install -y python nmap net-tools openssl
    pip install --upgrade pip
    pip install -r requirements.txt
    clear
    python beycan.py "$@"
elif grep -qi microsoft /proc/version 2>/dev/null; then
    # WSL (Windows Subsystem for Linux)
    echo "[+] WSL ortamı algılandı."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip nmap net-tools openssl
    pip3 install --upgrade pip
    pip3 install -r requirements.txt
    clear
    python3 beycan.py "$@"
elif [[ "$(uname -s)" == *NT* ]] || [[ "$(uname -o 2>/dev/null)" == *Msys* ]] || [[ "$(uname -o 2>/dev/null)" == *Cygwin* ]]; then
    # Windows ortamı (Git Bash, MSYS, Cygwin)
    echo "[+] Windows ortamı algılandı. Lütfen aşağıdaki komutları PowerShell veya CMD'de manuel çalıştırın:"
    echo "python beycan.py"
    exit 0
else
    # Kali veya diğer Linux
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip nmap net-tools openssl
    pip3 install --upgrade pip
    pip3 install -r requirements.txt
    clear
    python3 beycan.py "$@"
fi 