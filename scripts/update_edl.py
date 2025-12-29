#!/usr/bin/env python3
import requests
import re
import json
from datetime import datetime
from pathlib import Path
import socket
import ipaddress

class PANEDLCollector:
    """Palo Alto Networks EDL Collector for PA-440"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.malicious_cidrs = set()
        self.malicious_domains = set()
        self.stats = {
            'timestamp': datetime.utcnow().isoformat(),
            'sources': {},
            'total_ips': 0,
            'total_cidrs': 0,
            'total_domains': 0,
            'errors': []
        }
        
        # IP 來源定義
        self.ip_sources = {
            "blocklist.de": "https://lists.blocklist.de/lists/all.txt",
            "OpenDBL_TOR_exit_nodes": "https://opendbl.net/lists/tor-exit.list",
            "OpenDBL_BruteforceBlocker": "https://opendbl.net/lists/bruteforce.list",
            "OpenDBL_Block_Dshield": "https://opendbl.net/lists/dshield.list",
            "OpenDBL_SSL_Abuse_IP_list": "https://opendbl.net/lists/sslblock.list",
            "OpenDBL_Talos": "https://opendbl.net/lists/talos.list",
            "OpenDBL_IPSum_Level_3": "https://opendbl.net/lists/ipsum.list",
            "greensnow": "https://blocklist.greensnow.co/greensnow.txt",
            "FireHOL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            "spamhaus": "https://www.spamhaus.org/drop/drop.txt",
            "feodotracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "emergingthreats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
        }
        
        # Domain 來源定義
        self.domain_sources = {
            "URLhaus": "https://urlhaus.abuse.ch/downloads/text/",
            "Phishing_Army": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
            "MalwareDomainList": "https://www.malwaredomainlist.com/hostslist/hosts.txt"
        }
        
    def is_valid_ip(self, ip_str):
        """驗證單個 IP 地址"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except:
            return False
    
    def is_valid_cidr(self, cidr_str):
        """驗證 CIDR 格式"""
        try:
            ipaddress.ip_network(cidr_str, strict=False)
            return True
        except:
            return False
    
    def is_valid_domain(self, domain):
        """驗證域名格式"""
        # 基本域名格式檢查
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        if re.match(pattern, domain) and len(domain) <= 253:
            return True
        return False
    
    def fetch_ip_source(self, name, url):
        """通用 IP 來源抓取函數"""
        try:
            print(f"  抓取 {name}...", end=" ")
            response = requests.get(url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; EDL-Collector/1.0)'
            })
            response.raise_for_status()
            
            ips = set()
            cidrs = set()
            
            for line in response.text.split('\n'):
                line = line.strip()
                
                # 跳過註解和空行
                if not line or line.startswith('#') or line.startswith(';') or line.startswith('//'):
                    continue
                
                # 移除行內註解
                line = line.split('#')[0].split(';')[0].strip()
                
                # 檢查是否為 CIDR
                if '/' in line:
                    if self.is_valid_cidr(line):
                        cidrs.add(line)
                # 檢查是否為單個 IP
                elif self.is_valid_ip(line):
                    ips.add(line)
            
            self.malicious_ips.update(ips)
            self.malicious_cidrs.update(cidrs)
            self.stats['sources'][name] = {
                'ips': len(ips),
                'cidrs': len(cidrs),
                'total': len(ips) + len(cidrs)
            }
            
            print(f"✓ ({len(ips)} IPs, {len(cidrs)} CIDRs)")
            return True
            
        except Exception as e:
            error_msg = f"{name}: {str(e)}"
            self.stats['errors'].append(error_msg)
            print(f"✗ 失敗: {e}")
            return False
    
    def fetch_domain_source(self, name, url):
        """通用 Domain 來源抓取函數"""
        try:
            print(f"  抓取 {name}...", end=" ")
            response = requests.get(url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; EDL-Collector/1.0)'
            })
            response.raise_for_status()
            
            domains = set()
            
            for line in response.text.split('\n'):
                line = line.strip()
                
                # 跳過註解和空行
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                
                # 處理 hosts 檔案格式 (127.0.0.1 domain.com)
                if line.startswith('127.0.0.1') or line.startswith('0.0.0.0'):
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1]
                        if self.is_valid_domain(domain):
                            domains.add(domain)
                    continue
                
                # 從 URL 提取域名
                if line.startswith('http://') or line.startswith('https://'):
                    match = re.search(r'https?://([^/:\s]+)', line)
                    if match:
                        domain = match.group(1)
                        if self.is_valid_domain(domain):
                            domains.add(domain)
                    continue
                
                # 直接的域名
                domain = line.split('#')[0].split(';')[0].strip()
                if self.is_valid_domain(domain):
                    domains.add(domain)
            
            self.malicious_domains.update(domains)
            self.stats['sources'][name] = len(domains)
            
            print(f"✓ ({len(domains)} domains)")
            return True
            
        except Exception as e:
            error_msg = f"{name}: {str(e)}"
            self.stats['errors'].append(error_msg)
            print(f"✗ 失敗: {e}")
            return False
    
    def fetch_all_sources(self):
        """抓取所有威脅情報來源"""
        print("\n📡 正在抓取 IP 威脅情報來源:\n")
        
        for name, url in self.ip_sources.items():
            self.fetch_ip_source(name, url)
        
        print("\n📡 正在抓取 Domain 威脅情報來源:\n")
        
        for name, url in self.domain_sources.items():
            self.fetch_domain_source(name, url)
    
    def save_pan_edl_lists(self):
        """保存為 Palo Alto Networks EDL 格式"""
        Path("edl").mkdir(exist_ok=True)
        Path("stats").mkdir(exist_ok=True)
        
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # 保存 IP 清單（包含單個 IP 和 CIDR）
        with open("edl/malicious_ips.txt", "w") as f:
            f.write(f"# Palo Alto Networks EDL - Malicious IPs\n")
            f.write(f"# Updated: {timestamp}\n")
            f.write(f"# Total IPs: {len(self.malicious_ips)}\n")
            f.write(f"# Total CIDRs: {len(self.malicious_cidrs)}\n")
            f.write(f"# Compatible with: PA-440, PA-Series\n")
            f.write("#\n")
            
            # 先寫入 CIDR（通常優先級較高）
            for cidr in sorted(self.malicious_cidrs):
                f.write(f"{cidr}\n")
            
            # 再寫入單個 IP
            for ip in sorted(self.malicious_ips, key=lambda x: ipaddress.ip_address(x)):
                f.write(f"{ip}\n")
        
        # 保存 Domain 清單
        with open("edl/malicious_domains.txt", "w") as f:
            f.write(f"# Palo Alto Networks EDL - Malicious Domains\n")
            f.write(f"# Updated: {timestamp}\n")
            f.write(f"# Total: {len(self.malicious_domains)}\n")
            f.write(f"# Compatible with: PA-440, PA-Series\n")
            f.write("#\n")
            for domain in sorted(self.malicious_domains):
                f.write(f"{domain}\n")
        
        # 建立分類清單（可選）
        self.save_categorized_lists()
        
        # 更新統計
        self.stats['total_ips'] = len(self.malicious_ips)
        self.stats['total_cidrs'] = len(self.malicious_cidrs)
        self.stats['total_domains'] = len(self.malicious_domains)
        self.stats['combined_total'] = len(self.malicious_ips) + len(self.malicious_cidrs) + len(self.malicious_domains)
        
        with open("stats/latest.json", "w") as f:
            json.dump(self.stats, f, indent=2)
        
        # 建立簡單的 HTML 統計頁面
        self.create_stats_page()
        
        print(f"\n✅ EDL 清單已保存:")
        print(f"   📄 IPs: {len(self.malicious_ips)} 個")
        print(f"   📄 CIDRs: {len(self.malicious_cidrs)} 個")
        print(f"   📄 Domains: {len(self.malicious_domains)} 個")
        print(f"   📊 總計: {self.stats['combined_total']} 筆")
        
        if self.stats['errors']:
            print(f"\n⚠️  發生 {len(self.stats['errors'])} 個錯誤:")
            for error in self.stats['errors']:
                print(f"   - {error}")
    
    def save_categorized_lists(self):
        """建立分類的 EDL 清單"""
        # TOR 節點單獨清單
        tor_ips = set()
        if 'OpenDBL_TOR_exit_nodes' in self.stats['sources']:
            # 這裡簡化處理，實際上需要從原始資料分離
            pass
        
        # 可以根據需求建立其他分類清單
        # 例如：暴力破解、釣魚、惡意軟體等
    
    def create_stats_page(self):
        """建立統計資訊網頁"""
        html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EDL 統計資訊</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #e85d25; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }}
        .card {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .number {{ font-size: 36px; font-weight: bold; color: #e85d25; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #e85d25; color: white; }}
        .updated {{ color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <h1>🛡️ Palo Alto Networks EDL 統計資訊</h1>
    <p class="updated">最後更新: {self.stats['timestamp']}</p>
    
    <div class="stats">
        <div class="card">
            <h3>惡意 IP</h3>
            <div class="number">{len(self.malicious_ips):,}</div>
        </div>
        <div class="card">
            <h3>CIDR 區段</h3>
            <div class="number">{len(self.malicious_cidrs):,}</div>
        </div>
        <div class="card">
            <h3>惡意域名</h3>
            <div class="number">{len(self.malicious_domains):,}</div>
        </div>
        <div class="card">
            <h3>總計</h3>
            <div class="number">{self.stats['combined_total']:,}</div>
        </div>
    </div>
    
    <h2>📊 來源統計</h2>
    <table>
        <tr>
            <th>來源</th>
            <th>數量</th>
        </tr>
"""
        
        for source, count in sorted(self.stats['sources'].items(), key=lambda x: str(x[1]), reverse=True):
            if isinstance(count, dict):
                count_str = f"{count['total']:,} ({count['ips']} IPs + {count['cidrs']} CIDRs)"
            else:
                count_str = f"{count:,}"
            html += f"        <tr><td>{source}</td><td>{count_str}</td></tr>\n"
        
        html += """    </table>
    
    <h2>📥 EDL URL</h2>
    <ul>
        <li><a href="malicious_ips.txt">malicious_ips.txt</a> - IP 和 CIDR 清單</li>
        <li><a href="malicious_domains.txt">malicious_domains.txt</a> - 域名清單</li>
    </ul>
</body>
</html>"""
        
        with open("edl/index.html", "w", encoding="utf-8") as f:
            f.write(html)

def main():
    print("=" * 60)
    print("  Palo Alto Networks EDL Collector for PA-440")
    print("=" * 60)
    
    collector = PANEDLCollector()
    
    # 抓取所有來源
    collector.fetch_all_sources()
    
    # 保存 EDL 清單
    print("\n💾 正在保存 EDL 清單...")
    collector.save_pan_edl_lists()
    
    print("\n✅ 完成！")
    print("\n📝 下一步:")
    print("   1. 提交變更到 GitHub")
    print("   2. 確認 GitHub Pages 已啟用")
    print("   3. 在 PA-440 中設定 EDL URL")
    print("=" * 60)

if __name__ == "__main__":
    main()