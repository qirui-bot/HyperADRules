#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HyperADRules 规则定制与注入脚本
功能：剔除指定上游规则、添加自定义规则（自动分类）、同步更新规则数量。
使用：配置下方链接后运行 python3 custom_rules_injector.py
"""
import requests
import os

# ==================== 【配置区域】 ====================

# 需要【去除】的上游源链接
EXCLUDE_SOURCES = [
      "https://filters.adtidy.org/android/filters/3_optimized.txt",
]

# 需要【添加】的新规则源链接（自动分类）
INCLUDE_SOURCES = [
    # "https://example.com/1.txt",
]

# 手动指定分类（可选，覆盖自动分类）
CUSTOM_CATEGORIES = {
    # "https://example.com/tv.txt": "TV 盒子去广告",
}

# 是否更新 README.md 和规则文件头部的数量统计
UPDATE_README = True
UPDATE_TOTAL_COUNT = True
README_FILE = "README.md"

# ==================== 核心逻辑 ====================

TARGET_FILES = ["rules.txt", "dns.txt", "allow.txt"]

CATEGORY_KEYWORDS = {
    "adguard": "AdGuard 基础规则",
    "easyprivacy": "隐私保护 (EasyPrivacy)",
    "easylist": "通用广告过滤 (EasyList)",
    "oisd": "OISD 规则",
    "antiad": "AntiAD 规则",
    "hagezi": "HaGeZi 规则",
    "youtube": "视频广告过滤 (YouTube等)",
    "tracker": "隐私追踪拦截 (Trackers)",
    "malware": "恶意软件防护 (Malware)",
    "phishing": "防钓鱼网站 (Phishing)",
    "dns": "DNS 基础规则",
    "tv": "TV 盒子去广告",
    "yhosts": "YHosts 规则",
    "halflife": "HalfLife 规则",
    "cjxlist": "CJXList 规则",
    "xinggsf": "乘风视频净化",
    "neodevpro": "NeoDevPro",
    "ad-wars": "AdWars",
    "whitelist": "白名单 (Allowlist)",
    "allow": "白名单 (Allowlist)",
    "goodbyeads": "GOODBYEADS",
}


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


def auto_categorize(url):
    """根据 URL 关键词自动分类"""
    url_lower = url.lower()
    for kw, cat in CATEGORY_KEYWORDS.items():
        if kw in url_lower:
            return cat
    return "其他自定义规则"


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
    return lines


def update_readme():
    """更新 README.md 中的规则数量"""
    if not UPDATE_README or not os.path.exists(README_FILE):
        return

    import re
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


def process_file(filename, exclude_domains, exclude_exact, includes):
    """处理单个规则文件：剔除 + 追加 + 更新统计"""
    if not os.path.exists(filename):
        print(f"⚠️ 跳过 {filename}（不存在）")
        return

    print(f"\n⚙️ 处理: {filename}")
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    filtered, removed = [], 0
    in_block = False

    for line in lines:
        # 跳过上次注入的自定义块（保证幂等）
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

    # 追加自定义规则
    added = 0
    if includes:
        filtered.append("\n! >>>>> CUSTOM_INJECT_START <<<<<\n")
        for cat, rules in includes.items():
            if rules:
                filtered.append(f"! =========================================================\n")
                filtered.append(f"! ===                 {cat}                  ===\n")
                filtered.append(f"! =========================================================\n")
                for r in rules:
                    filtered.append(r if r.endswith('\n') else r + '\n')
                    added += 1
        filtered.append("! >>>>> CUSTOM_INJECT_END <<<<<\n")

    # 更新统计并写入
    filtered = update_total_header(filtered)
    with open(filename, 'w', encoding='utf-8') as f:
        f.writelines(filtered)

    print(f"  ✅ 完成 | 🗑️ 剔除 {removed} | ➕ 添加 {added}")


def main():
    print("🚀 开始执行规则注入...")

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

    # 解析添加列表
    includes = {}
    if INCLUDE_SOURCES:
        print("\n➕ 解析添加列表...")
        for url in INCLUDE_SOURCES:
            cat = CUSTOM_CATEGORIES.get(url, auto_categorize(url))
            print(f"  📂 {url} → {cat}")
            rules = fetch_rules(url)
            if rules:
                includes.setdefault(cat, []).extend(rules)

    # 处理目标文件
    for f in TARGET_FILES:
        process_file(f, exclude_domains, exclude_exact, includes)

    # 更新 README
    update_readme()
    print("\n🎉 完成！")


if __name__ == "__main__":
    main()
