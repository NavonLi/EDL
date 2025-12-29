#!/usr/bin/env python3
"""
Palo Alto Networks EDL Collector
Collects threat intelligence from multiple open sources
"""
import requests
import re
import json
from datetime import datetime
from pathlib import Path
import ipaddress
import sys

class PANEDLCollector:
    """Palo Alto Networks EDL Collector for PA-440"""
    
    def __init__(self):
        self.malicious_ips_v4 = set()
        self.malicious_ips_v6 = set()
        self.malicious_cidrs_v4 = set()
        self.malicious_cidrs_v6 = set()
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
            
            ips_v4 = set()
            ips_v6 = set()
            cidrs_v4 = set()
            cidrs_v6 = set()
            
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
                        ip_obj = ipaddress.ip_network(line, strict=False)
                        if ip_obj.version == 4:
                            cidrs_v4.add(line)
                        else:
                            cidrs_v6.add(line)
                # 檢查是否為單個 IP
                elif self.is_valid_ip(line):
                    ip_obj = ipaddress.ip_address(line)
                    if ip_obj.version == 4:
                        ips_v4.add(line)
                    else:
                        ips_v6.add(line)
            
            self.malicious_ips_v4.update(ips_v4)
            self.malicious_ips_v6.update(ips_v6)
            self.malicious_cidrs_v4.update(cidrs_v4)
            self.malicious_cidrs_v6.update(cidrs_v6)
            
            total = len(ips_v4) + len(ips_v6) + len(cidrs_v4) + len(cidrs_v6)
            self.stats['sources'][name] = {
                'ipv4': len(ips_v4),
                'ipv6': len(ips_v6),
                'cidr_v4': len(cidrs_v4),
                'cidr_v6': len(cidrs_v6),
                'total': total
            }
            
            print(f"✓ ({len(ips_v4)} IPv4, {len(ips_v6)} IPv6, {len(cidrs_v4)+len(cidrs_v6)} CIDRs)")
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
        
        # 保存 IPv4 清單
        with open("edl/malicious_ips_v4.txt", "w") as f:
            f.write(f"# Palo Alto Networks EDL - Malicious IPv4\n")
            f.write(f"# Updated: {timestamp}\n")
            f.write(f"# Total IPs: {len(self.malicious_ips_v4)}\n")
            f.write(f"# Total CIDRs: {len(self.malicious_cidrs_v4)}\n")
            f.write(f"# Compatible with: PA-440, PA-Series\n")
            f.write("#\n")
            
            # 先寫入 CIDR
            for cidr in sorted(self.malicious_cidrs_v4):
                f.write(f"{cidr}\n")
            
            # 再寫入單個 IP
            for ip in sorted(self.malicious_ips_v4, key=lambda x: ipaddress.ip_address(x)):
                f.write(f"{ip}\n")
        
        # 保存 IPv6 清單
        with open("edl/malicious_ips_v6.txt", "w") as f:
            f.write(f"# Palo Alto Networks EDL - Malicious IPv6\n")
            f.write(f"# Updated: {timestamp}\n")
            f.write(f"# Total IPs: {len(self.malicious_ips_v6)}\n")
            f.write(f"# Total CIDRs: {len(self.malicious_cidrs_v6)}\n")
            f.write(f"# Compatible with: PA-440, PA-Series\n")
            f.write("#\n")
            
            # 先寫入 CIDR
            for cidr in sorted(self.malicious_cidrs_v6):
                f.write(f"{cidr}\n")
            
            # 再寫入單個 IP
            for ip in sorted(self.malicious_ips_v6, key=lambda x: ipaddress.ip_address(x)):
                f.write(f"{ip}\n")
        
        # 保存合併的 IP 清單（IPv4 + IPv6）
        with open("edl/malicious_ips.txt", "w") as f:
            f.write(f"# Palo Alto Networks EDL - All Malicious IPs (IPv4 + IPv6)\n")
            f.write(f"# Updated: {timestamp}\n")
            f.write(f"# Total IPv4: {len(self.malicious_ips_v4)} IPs + {len(self.malicious_cidrs_v4)} CIDRs\n")
            f.write(f"# Total IPv6: {len(self.malicious_ips_v6)} IPs + {len(self.malicious_cidrs_v6)} CIDRs\n")
            f.write(f"# Compatible with: PA-440, PA-Series\n")
            f.write("#\n")
            f.write("# IPv4 CIDRs\n")
            for cidr in sorted(self.malicious_cidrs_v4):
                f.write(f"{cidr}\n")
            f.write("# IPv4 Addresses\n")
            for ip in sorted(self.malicious_ips_v4, key=lambda x: ipaddress.ip_address(x)):
                f.write(f"{ip}\n")
            f.write("# IPv6 CIDRs\n")
            for cidr in sorted(self.malicious_cidrs_v6):
                f.write(f"{cidr}\n")
            f.write("# IPv6 Addresses\n")
            for ip in sorted(self.malicious_ips_v6, key=lambda x: ipaddress.ip_address(x)):
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
        
        # 更新統計
        self.stats['total_ipv4'] = len(self.malicious_ips_v4)
        self.stats['total_ipv6'] = len(self.malicious_ips_v6)
        self.stats['total_cidr_v4'] = len(self.malicious_cidrs_v4)
        self.stats['total_cidr_v6'] = len(self.malicious_cidrs_v6)
        self.stats['total_domains'] = len(self.malicious_domains)
        self.stats['combined_total'] = (len(self.malicious_ips_v4) + len(self.malicious_ips_v6) + 
                                        len(self.malicious_cidrs_v4) + len(self.malicious_cidrs_v6) + 
                                        len(self.malicious_domains))
        
        with open("stats/latest.json", "w") as f:
            json.dump(self.stats, f, indent=2)
        
        # 建立簡單的 HTML 統計頁面
        self.create_stats_page()
        
        print(f"\n✅ EDL 清單已保存:")
        print(f"   📄 IPv4: {len(self.malicious_ips_v4)} IPs + {len(self.malicious_cidrs_v4)} CIDRs")
        print(f"   📄 IPv6: {len(self.malicious_ips_v6)} IPs + {len(self.malicious_cidrs_v6)} CIDRs")
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
        total_ips = len(self.malicious_ips_v4) + len(self.malicious_ips_v6)
        total_cidrs = len(self.malicious_cidrs_v4) + len(self.malicious_cidrs_v6)
        
        html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EDL 統計資訊</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #e85d25; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .card {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .number {{ font-size: 36px; font-weight: bold; color: #e85d25; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #e85d25; color: white; }}
        .updated {{ color: #666; font-size: 14px; }}
        .download {{ margin-top: 20px; }}
        .download a {{ display: inline-block; padding: 10px 20px; background: #e85d25; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }}
        .download a:hover {{ background: #c74d1f; }}
    </style>
</head>
<body>
    <h1>🛡️ Palo Alto Networks EDL 統計資訊</h1>
    <p class="updated">最後更新: {self.stats['timestamp']}</p>
    
    <div class="stats">
        <div class="card">
            <h3>IPv4</h3>
            <div class="number">{len(self.malicious_ips_v4):,}</div>
            <small>{len(self.malicious_cidrs_v4):,} CIDRs</small>
        </div>
        <div class="card">
            <h3>IPv6</h3>
            <div class="number">{len(self.malicious_ips_v6):,}</div>
            <small>{len(self.malicious_cidrs_v6):,} CIDRs</small>
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
    
    <div class="download">
        <h2>📥 下載 EDL 清單</h2>
        <a href="malicious_ips.txt">完整 IP 清單 (IPv4 + IPv6)</a>
        <a href="malicious_ips_v4.txt">IPv4 專用清單</a>
        <a href="malicious_ips_v6.txt">IPv6 專用清單</a>
        <a href="malicious_domains.txt">域名清單</a>
    </div>
    
    <h2>📊 來源統計</h2>
    <table>
        <tr>
            <th>來源</th>
            <th>數量</th>
        </tr>
"""
        
        for source, count in sorted(self.stats['sources'].items(), key=lambda x: x[1].get('total', x[1]) if isinstance(x[1], dict) else x[1], reverse=True):
            if isinstance(count, dict):
                count_str = f"{count['total']:,} (IPv4: {count['ipv4']}, IPv6: {count['ipv6']}, CIDRs: {count['cidr_v4']+count['cidr_v6']})"
            else:
                count_str = f"{count:,}"
            html += f"        <tr><td>{source}</td><td>{count_str}</td></tr>\n"
        
        html += """    </table>
</body>
</html>"""
        
        with open("edl/index.html", "w", encoding="utf-8") as f:
            f.write(html)

def main():
    print("=" * 60)
    print("  Palo Alto Networks EDL Collector for PA-440")
    print("=" * 60)
    
    try:
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
        
        # 檢查是否有過多錯誤
        if len(collector.stats['errors']) > 5:
            print(f"\n⚠️  警告: 有 {len(collector.stats['errors'])} 個來源失敗")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ 執行失敗: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
