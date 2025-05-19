#!/bin/bash
# Beycan Güncelleme Scripti

echo "[+] Beycan güncelleniyor..."
git pull
pip3 install --upgrade -r ../requirements.txt
echo "[+] Güncelleme tamamlandı." 