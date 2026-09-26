#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HyperADRules 规则剔除与统计更新脚本
功能：剔除指定上游规则、同步更新规则数量。
使用：配置下方链接后运行 python3 custom_rules_injector.py
"""
import requests
import os
import re

# ==================== 【配置区域】 ====================
# 需要【去除】的上游源链接
EXCLUDE_SOURCES = [
    "https://filters.adtidy.org/android/filters/3_optimized.txt",
    "https://filters.adtidy.org/android/filters/17_optimized.txt",
]

# 是否更新 README.md 和规则文件头部的数量统计
UPDATE_README = True
UPDATE_TOTAL_COUNT = True
README_FILE = "README.md"

# ==================== 核心逻辑 ====================
TARGET_FILES = ["rules.txt", "dns.txt", "allow.txt"]

def fetch_rules(url):
    """下载规则文件，去除注释后返回规则列表"""
    try:
        print(f"  ⏳ 下载: {url}")
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        return [
            line.split('!')[0].split('#')[0].strip()
            for line in resp.text.splitlines()
            if line.split('!')[0].split('#')[0].strip()
        ]
    except Exception as e:
        print(f"  ❌ 下载失败: {e}")
        return []

def extract_domain(rule):
    """从 AdGuard 规则中提取核心域名"""
    rule = rule.strip()
    if rule.startswith('@@||'):
        rule = rule[4:]
    elif rule.startswith('||'):
        rule = rule[2:]
    if '$' in rule:
        rule = rule.split('$')[0]
    if rule.endswith('^'):
        rule = rule[:-1]
    return rule.lower()

def is_rule_line(line):
    """判断是否为有效规则行（用于统计）"""
    s = line.strip()
    if not s or s.startswith('[Adblock') or s.startswith('!'):
        return False
    if s.startswith('#') and not s.startswith('##'):
        return False
    return True

def count_rules(lines):
    """统计有效规则行数"""
    return sum(1 for l in lines if is_rule_line(l))

def count_file(path):
    """统计文件中的有效规则数"""
    if not os.path.exists(path):
        return 0
    with open(path, 'r', encoding='utf-8') as f:
        return count_rules(f)

def update_total_header(lines):
    """更新文件头部的 ! Total count"""
    if not UPDATE_TOTAL_COUNT:
        return lines
    total = count_rules(lines)
    for i, line in enumerate(lines):
        if line.strip().startswith('! Total count:'):
            lines[i] = f'! Total count: {total}\n'
            break
    return lines

def update_readme():
    """更新 README.md 中的规则数量"""
    if not UPDATE_README or not os.path.exists(README_FILE):
        return
    
    counts = {
        "拦截规则数量": count_file("rules.txt"),
        "DNS拦截规则数量": count_file("dns.txt"),
        "白名单规则数量": count_file("allow.txt"),
    }
    
    with open(README_FILE, 'r', encoding='utf-8') as f:
        text = f.read()
    original = text
    
    for label, num in counts.items():
        text = re.sub(rf'({re.escape(label)}[^0-9\n]*?)\d+', rf'\g<1>{num}', text)
        
    if text != original:
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(text)
        print("\n📝 已更新 README.md 规则数量")

def process_file(filename, exclude_domains, exclude_exact):
    """处理单个规则文件：剔除 + 更新统计"""
    if not os.path.exists(filename):
        print(f"⚠️ 跳过 {filename}（不存在）")
        return
        
    print(f"\n⚙️ 处理: {filename}")
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    filtered, removed = [], 0
    in_block = False
    
    for line in lines:
        # 跳过/清理残留的自定义注入块（保证幂等，清理旧版脚本留下的痕迹）
        if '! >>>>> CUSTOM_INJECT_START <<<<<' in line:
            in_block = True
            continue
        if '! >>>>> CUSTOM_INJECT_END <<<<<' in line:
            in_block = False
            continue
        if in_block:
            continue
            
        clean = line.split('!')[0].split('#')[0].strip()
        if not clean:
            filtered.append(line)
            continue
            
        # 匹配剔除：精确 / AdGuard域名 / Hosts / 裸域名
        if clean in exclude_exact:
            removed += 1
            continue
        if clean.startswith(('||', '@@||')):
            if extract_domain(clean) in exclude_domains:
                removed += 1
                continue
        elif clean.startswith(('0.0.0.0', '127.0.0.1')):
            parts = clean.split()
            if len(parts) > 1 and parts[1].lower() in exclude_domains:
                removed += 1
                continue
        elif '/' not in clean and '.' in clean:
            if clean.lower() in exclude_domains:
                removed += 1
                continue
                
        filtered.append(line)

    # 更新统计并写入
    filtered = update_total_header(filtered)
    with open(filename, 'w', encoding='utf-8') as f:
        f.writelines(filtered)
    print(f"  ✅ 完成 | 🗑️ 剔除 {removed} 条规则")

def main():
    print("🚀 开始执行规则剔除与统计更新...")
    
    # 解析排除列表
    exclude_domains, exclude_exact = set(), set()
    if EXCLUDE_SOURCES:
        print("\n🔍 解析排除列表...")
        for url in EXCLUDE_SOURCES:
            for rule in fetch_rules(url):
                if rule.startswith(('||', '@@||')):
                    exclude_domains.add(extract_domain(rule))
                elif rule.startswith(('0.0.0.0', '127.0.0.1')):
                    parts = rule.split()
                    if len(parts) > 1:
                        exclude_domains.add(parts[1].lower())
                    else:
                        if '/' not in rule and '.' in rule:
                            exclude_domains.add(rule.lower())
                exclude_exact.add(rule)
        print(f"  📊 提取 {len(exclude_domains)} 个域名, {len(exclude_exact)} 条精确规则")
    else:
        print("⚠️ 未配置需要剔除的上游源 (EXCLUDE_SOURCES)")

    # 处理目标文件
    for f in TARGET_FILES:
        process_file(f, exclude_domains, exclude_exact)

    # 更新 README
    update_readme()
    
    print("\n🎉 完成！")

if __name__ == "__main__":
    main()
