# BEYCAN Network Security Analyzer

## 🛡️ Hakkında
BEYCAN, gelişmiş, interaktif ve renkli bir ağ güvenlik analiz aracıdır. Kali Linux ve Termux üzerinde tam uyumlu çalışır ve 20'den fazla güvenlik aracı içerir. Ağ güvenliği testleri, port tarama, ağ keşfi ve daha fazlası için kullanılabilir.

## ✨ Özellikler
- 🔍 Port tarama ve ağ keşfi
- 🔒 HTTP/SSL/DNS analizleri
- 🛡️ Güvenlik duvarı ve MITM tespiti
- 📊 Detaylı raporlama
- 🎨 Renkli ve interaktif menü
- 🔄 Otomatik güncelleme
- 📱 Platforma özel kurulum (Kali Linux & Termux)

## 🚀 Kurulum

### Kali Linux için Kurulum
1. Gerekli paketleri yükleyin:
```bash
sudo apt update
sudo apt install python3 python3-pip git -y
```

2. Projeyi klonlayın:
```bash
git clone https://github.com/beycanyildiz/beycan.git
cd beycan
```

3. Python bağımlılıklarını yükleyin:
```bash
pip3 install -r requirements.txt
```

4. Çalıştırma izni verin:
```bash
chmod +x beycan.sh
```

5. Programı başlatın:
```bash
bash beycan.sh
```

### Termux için Kurulum
1. Gerekli paketleri yükleyin:
```bash
pkg update && pkg upgrade
pkg install python git -y
```

2. Projeyi klonlayın:
```bash
git clone https://github.com/beycanyildiz/beycan.git
cd beycan
```

3. Python bağımlılıklarını yükleyin:
```bash
pip install -r requirements.txt
```

4. Çalıştırma izni verin:
```bash
chmod +x beycan.sh
```

5. Programı başlatın:
```bash
bash beycan.sh
```

## 🪟 Windows için Kurulum
1. Python 3 ve pip kurulu olmalı. [Python İndir](https://www.python.org/downloads/)
2. Komut İstemcisi (CMD) veya PowerShell'i açın.
3. Projeyi klonlayın veya zip olarak indirin:
```powershell
git clone https://github.com/beycanyildiz/beycan.git
cd beycan
```
4. Bağımlılıkları yükleyin:
```powershell
pip install -r requirements.txt
```
5. Programı başlatın:
```powershell
python beycan.py
```
> Not: Windows ortamında beycan.sh çalışmaz, doğrudan python beycan.py ile başlatın.

## 📋 Kullanım
Programı başlatmak için:
```bash
bash beycan.sh
```

### Komut Satırı Parametreleri
- `-a` : Tüm araçları çalıştırır
- `-l` : İnteraktif menü açar (numara ile seçim)
- `-n` : Ağ keşfi için ağ adresi (örn: 192.168.1.0/24)

### Örnek Kullanımlar
```bash
# İnteraktif menü ile kullanım
bash beycan.sh -l

# Belirli bir ağda tarama yapma
bash beycan.sh -n 192.168.1.0/24

# Tüm araçları çalıştırma
bash beycan.sh -a
```

## 🔄 Güncelleme
Programı güncellemek için:
```bash
bash update/update.sh
```

## 📁 Klasör Yapısı
- `banners/` : Farklı banner dosyaları
- `update/` : Güncelleme scripti
- `beycan.py` : Ana Python uygulaması
- `beycan.sh` : Çalıştırıcı ve kurulum scripti
- `requirements.txt` : Python bağımlılıkları

## ⚠️ Önemli Notlar
- Programı root yetkisi ile çalıştırmanız önerilir
- Bazı özellikler için ek paketler gerekebilir
- Ağ taraması yaparken yasal sınırlar içinde kalın
- Termux'ta bazı özellikler sınırlı olabilir

## 📜 Lisans
MIT

## 📞 İletişim
- [Github](https://github.com/beycanyildiz)
- [Instagram](https://www.instagram.com/beaycan/) 