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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# 下载并发线程数（可根据网络带宽调整）
MAX_WORKERS = 8

# ==================== 核心逻辑 ====================
TARGET_FILES = ["rules.txt", "dns.txt", "allow.txt"]

# 线程局部 Session，复用连接
_thread_local = threading.local()

def get_session():
    """获取当前线程的 requests.Session（复用 TCP 连接）"""
    if not hasattr(_thread_local, 'session'):
        _thread_local.session = requests.Session()
        _thread_local.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; HyperADRules/1.0)'
        })
    return _thread_local.session

def fetch_rules(url):
    """下载规则文件，去除注释后返回规则列表"""
    try:
        print(f"  ⏳ 下载: {url}")
        session = get_session()
        resp = session.get(url, timeout=(5, 15))  # (连接超时, 读取超时)
        resp.raise_for_status()
        return [
            line.split('!')[0].split('#')[0].strip()
            for line in resp.text.splitlines()
            if line.split('!')[0].split('#')[0].strip()
        ]
    except Exception as e:
        print(f"  ❌ 下载失败: {e}")
        return []

def fetch_all_rules(urls, max_workers=MAX_WORKERS):
    """并行下载所有上游规则源"""
    all_rules = []
    if not urls:
        return all_rules
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_rules, url): url for url in urls}
        for future in as_completed(futures):
            try:
                all_rules.extend(future.result())
            except Exception as e:
                print(f"  ❌ 并发下载异常: {e}")
    return all_rules

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
    """统计文件中的有效规则数（流式读取，避免全量加载）"""
    if not os.path.exists(path):
        return 0
    count = 0
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if is_rule_line(line):
                count += 1
    return count

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

def update_total_header_inplace(filename, total):
    """只扫描文件头部区域，就地更新 ! Total count（避免整文件重写）"""
    if not UPDATE_TOTAL_COUNT:
        return
    with open(filename, 'r', encoding='utf-8') as f:
        head_lines = f.readlines(4096)  # 只读前 4KB，足够覆盖头部
    for i, line in enumerate(head_lines):
        if line.strip().startswith('! Total count:'):
            head_lines[i] = f'! Total count: {total}\n'
            with open(filename, 'r+', encoding='utf-8') as f:
                f.writelines(head_lines)
            return

def update_readme(file_counts=None):
    """更新 README.md 中的规则数量"""
    if not UPDATE_README or not os.path.exists(README_FILE):
        return

    if file_counts is None:
        file_counts = {
            "rules.txt": count_file("rules.txt"),
            "dns.txt": count_file("dns.txt"),
            "allow.txt": count_file("allow.txt"),
        }

    counts = {
        "拦截规则数量": file_counts.get("rules.txt", 0),
        "DNS拦截规则数量": file_counts.get("dns.txt", 0),
        "白名单规则数量": file_counts.get("allow.txt", 0),
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
    """处理单个规则文件：剔除 + 更新统计（流式读写，低内存）"""
    if not os.path.exists(filename):
        print(f"⚠️ 跳过 {filename}（不存在）")
        return 0

    print(f"\n⚙️ 处理: {filename}")
    tmp_path = filename + ".tmp"
    removed = 0
    in_block = False
    total = 0

    with open(filename, 'r', encoding='utf-8') as fin, \
         open(tmp_path, 'w', encoding='utf-8') as fout:
        for line in fin:
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
                fout.write(line)
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

            fout.write(line)
            if is_rule_line(line):
                total += 1

    # 原子替换，避免中途异常导致文件损坏
    os.replace(tmp_path, filename)

    # 就地更新头部 ! Total count
    update_total_header_inplace(filename, total)

    print(f"  ✅ 完成 | 🗑️ 剔除 {removed} 条规则")
    return total

def main():
    print("🚀 开始执行规则剔除与统计更新...")

    # 解析排除列表
    exclude_domains, exclude_exact = set(), set()
    if EXCLUDE_SOURCES:
        print("\n🔍 解析排除列表...")
        all_rules = fetch_all_rules(EXCLUDE_SOURCES)
        for rule in all_rules:
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

    # 处理目标文件，并缓存每个文件的统计结果（避免重复遍历）
    file_counts = {}
    for f in TARGET_FILES:
        if os.path.exists(f):
            file_counts[f] = process_file(f, exclude_domains, exclude_exact)
        else:
            print(f"⚠️ 跳过 {f}（不存在）")
            file_counts[f] = 0

    # 更新 README（复用已统计的数量）
    update_readme(file_counts)

    print("\n🎉 完成！")

if __name__ == "__main__":
    main()
