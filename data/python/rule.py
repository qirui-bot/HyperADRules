import os
import re

# 新增：匹配 *.example.com 形式的通配符
RE_WILDCARD = re.compile(r'^\*\.([a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})$')

def extract_wildcard(line):
    s = line.strip().lower().rstrip('.')
    if not s:
        return None
    parts = s.split()
    if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::'):
        s = parts[1]
    if s.startswith('@@||'): s = s[4:]
    elif s.startswith('||'): s = s[2:]
    elif s.startswith('@@'): s = s[2:]
    s = s.split('$')[0]
    if s.endswith('^'): s = s[:-1]
    s = s.split('/')[0].split(':')[0].strip()
    m = RE_WILDCARD.match(s)
    return m.group(1) if m else None

def extract_domain_simple(line):
    s = line.strip()
    if not s or s[0] in '![#@': return None
    t = s
    if t.startswith('@@||'): t = t[4:]
    elif t.startswith('||'): t = t[2:]
    elif t.startswith('@@'): t = t[2:]
    t = t.split('$')[0]
    if t.endswith('^'): t = t[:-1]
    t = t.split('/')[0].split(':')[0].strip().lower().rstrip('.')
    parts = t.split()
    if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::'):
        t = parts[1]
    if t and '.' in t and not t.startswith('*.'):
        return t
    return None

def is_covered(domain, wildcards):
    parts = domain.split('.')
    for i in range(1, len(parts)):
        if '.'.join(parts[i:]) in wildcards:
            return True
    return False

# 去重开始
print("规则去重中")
os.chdir(".././")  # 将当前目录更改为.././目录下
files = os.listdir()  # 得到文件夹下的所有文件名称
result = []
for file in files:  # 遍历文件夹
    if not os.path.isdir(file):  # 判断是否是文件夹，不是文件夹才打开
        if os.path.splitext(file)[1] == '.txt':
            # print('开始去重'+(file))
            f = open(file, encoding="utf8")  # 打开文件
            lines = f.readlines()
            f.close()

            # 新增：收集本文件内所有通配符域名
            wildcards = set()
            for line in lines:
                wd = extract_wildcard(line)
                if wd:
                    wildcards.add(wd)

            # 新增：过滤被通配符吸收的子域（白名单 @@ 例外保留）
            filtered = []
            for line in lines:
                s = line.strip()
                if s.startswith('@@') or not s or s[0] in '![#':
                    filtered.append(line)
                    continue
                d = extract_domain_simple(line)
                if d and is_covered(d, wildcards):
                    continue
                filtered.append(line)

            result = list(set(filtered))
            result.sort()
            fo = open('test' + (file), "w", encoding="utf8")
            fo.writelines(result)
            os.remove(file)
            os.rename('test' + (file), (file))
            # print((file) + '去重完成')

# 处理完毕
print("规则去重完成")
