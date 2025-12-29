#!/usr/bin/env python3
"""
EDL Collector - 診斷測試版本
用於檢查環境和依賴是否正確
"""
import sys
print(f"Python 版本: {sys.version}")

# 檢查必要模組
required_modules = ['requests', 'json', 'pathlib', 'ipaddress', 're', 'datetime']
missing_modules = []

for module in required_modules:
    try:
        __import__(module)
        print(f"✓ {module} 已安裝")
    except ImportError:
        print(f"✗ {module} 缺失")
        missing_modules.append(module)

if missing_modules:
    print(f"\n❌ 缺少模組: {', '.join(missing_modules)}")
    print("請執行: pip install " + " ".join(missing_modules))
    sys.exit(1)

# 測試網路連線
print("\n測試網路連線...")
import requests

test_urls = [
    "https://lists.blocklist.de/lists/all.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
]

for url in test_urls:
    try:
        response = requests.get(url, timeout=10)
        print(f"✓ {url[:50]}... (Status: {response.status_code})")
    except Exception as e:
        print(f"✗ {url[:50]}... (錯誤: {e})")

# 測試目錄建立
print("\n測試目錄建立...")
from pathlib import Path

try:
    Path("edl").mkdir(exist_ok=True)
    Path("stats").mkdir(exist_ok=True)
    print("✓ 目錄建立成功")
except Exception as e:
    print(f"✗ 目錄建立失敗: {e}")
    sys.exit(1)

# 測試檔案寫入
print("\n測試檔案寫入...")
try:
    with open("edl/test.txt", "w") as f:
        f.write("test")
    print("✓ 檔案寫入成功")
except Exception as e:
    print(f"✗ 檔案寫入失敗: {e}")
    sys.exit(1)

print("\n✅ 所有測試通過！環境正常。")
print("現在可以執行完整的 update_edl.py 腳本。")
