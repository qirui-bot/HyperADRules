import os, re, time, gzip, json, threading
import dns.resolver
import dns.exception
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============ 0. 环境自适应 ============
IS_CI = os.getenv("GITHUB_ACTIONS") == "true"
if os.name == 'nt' and not IS_CI: os.system('')

class C:
    R, G, Y, B, CY, E = ("", "", "", "", "", "") if IS_CI else ("\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[0m")
    BOLD = "" if IS_CI else "\033[1m"

log = lambda m, c=C.B: print(f"{c}{m}{C.E}", flush=True)

# ============ 1. 核心配置 ============
FILES = ["rules.txt", "dns.txt", "allow.txt"]
CACHE_FILE = "dns_cache.json.gz"
MAX_WORKERS   = 500    # ⚠️ runner 仅 2 核，800 会打爆 DNS 解析器导致集体超时
DNS_TIMEOUT   = 3.0    # 单次查询上限
HEARTBEAT_SEC = 10     # 独立心跳间隔：无论是否有结果返回都按时打印
CACHE_ALIVE_DAYS, CACHE_DEAD_DAYS = 7, 3
# 已修正正则：必须转义 ||，否则提取全失败
RE_DOMAIN = re.compile(r'^\|\|([^\^/\s*]+)')

# 上游源映射 (对应 update-rules.sh，自动忽略越界产生的空文件)
UPSTREAM = [
    ("yhosts", "rules001.txt", "拦截"), ("大圣净化", "rules002.txt", "拦截"), ("乘风视频", "rules003.txt", "拦截"),
    ("adg基础", "rules0.txt", "拦截"), ("adg移动", "rules1.txt", "拦截"), ("adgURL", "rules2.txt", "拦截"),
    ("HyperADRules", "rules3.txt", "拦截"), ("adg中文", "rules4.txt", "拦截"), ("Tv规则", "rules5.txt", "拦截"),
    ("EasyPrivacy", "rules6.txt", "拦截"), ("去APP下载", "rules7.txt", "拦截"), ("d3ward", "rules8.txt", "拦截"),
    ("oisd", "rules9.txt", "拦截"), ("秋风", "rules10.txt", "拦截"), ("Anti-AD", "rules11.txt", "拦截"),
    ("adblockfilters", "rules12.txt", "拦截"), ("GOODBYEADS", "rules13.txt", "拦截"),
    ("HyperADRules恶意软件", "rules14.txt", "拦截"), ("edentwCustom", "rules15.txt", "拦截"),
    ("AG中文白", "allow0.txt", "白名单"), ("AG德语白", "allow1.txt", "白名单"), ("AG土耳其白", "allow2.txt", "白名单"),
    ("AG防跟踪白", "allow3.txt", "白名单"), ("anti-ad白", "allow4.txt", "白名单"), ("Filterlist白", "allow5.txt", "白名单"),
    ("liwenjie白", "allow6.txt", "白名单"), ("ChengJi-e白", "allow7.txt", "白名单"), ("GOODBYEADS白", "allow8.txt", "白名单"),
    ("HyperADRules白", "allow9.txt", "白名单")
]

# ============ 2. 上游源状态检测 ============
def check_upstream():
    results = []
    for name, file, cat in UPSTREAM:
        path = os.path.join("tmp", file)
        status, reason, lines = "❌", "未生成/崩溃", 0
        if os.path.exists(path):
            size = os.path.getsize(path)
            if size == 0:
                reason = "空文件(超时)"
            else:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    sample = f.read(500)
                    f.seek(0)
                    lines = sum(1 for _ in f)
                if "404" in sample:   reason = "404失效"
                elif lines < 5:        reason = "内容异常"
                else:                  status, reason = "✅", "正常抓取"
        results.append((status, cat, name, reason, lines))
    return results

# ============ 3. 域名提取与 DNS ============
def extract_domain(rule):
    rule = rule.strip()
    if not rule or rule[0] in '![@#': return None
    m = RE_DOMAIN.match(rule)
    if m and m.group(1):
        d = re.sub(r'[^a-zA-Z0-9.-]', '', m.group(1).split(':')[0])
        if '.' in d: return d
    return None

def check_dns(domain):
    try:
        dns.resolver.resolve(domain, 'A', lifetime=DNS_TIMEOUT)
        return domain, True
    except dns.resolver.NXDOMAIN:
        return domain, False   # 唯一死刑
    except Exception:
        return domain, True    # 保守保留防误杀

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with gzip.open(CACHE_FILE, 'rt', encoding='utf-8') as f: return json.load(f)
        except: pass
    return {}

# ============ 4. 主流程 ============
def main():
    t0 = time.time()
    log(f"\n{C.BOLD}{C.CY}🚀 HyperADRules 深度清洗与可视化报告{C.E}\n")

    # [1/3] 上游源状态
    log(f"{C.BOLD}📡 [1/3] 上游源抓取状态检测{C.E}")
    up_res = check_upstream()
    ok_cnt  = sum(1 for r in up_res if r[0] == "✅")
    fail_cnt = sum(1 for r in up_res if r[0] == "❌")
    md_up = ["| 状态 | 类型 | 上游源 | 结果 | 行数 |", "| :--: | :--: | --- | --- | --: |"]
    for st, cat, name, reason, lines in up_res:
        c = C.G if st == "✅" else C.R
        log(f"  {c}{st}{C.E} [{cat}] {name:<12} | {reason:<12} | {lines:>6}")
        md_up.append(f"| {st} | {cat} | {name} | {reason} | `{lines:,}` |")
    log(f"  📊 汇总: {C.G}成功 {ok_cnt}{C.E} / {C.R}失败 {fail_cnt}{C.E} (共 {len(up_res)} 个源)\n")

    # [2/3] 读取 + 提取
    log(f"{C.BOLD}🧹 [2/3] 域名提取与死链清洗{C.E}")
    all_domains, file_data = set(), {}
    for fp in FILES:
        if not os.path.exists(fp): continue
        with open(fp, 'r', encoding='utf-8') as f: lines = f.readlines()
        hdr, rules, r_map, u_doms = [], [], {}, set()
        for line in lines:
            s = line.strip()
            (hdr if not s or s[0] in '![' else rules).append(line)
        for r in rules:
            d = extract_domain(r)
            if d:
                r_map[r.strip()] = d
                u_doms.add(d)
        file_data[fp] = {'hdr': hdr, 'rules': rules, 'map': r_map, 'orig': len(rules)}
        all_domains |= u_doms
    log(f"  📖 提取完成，共 {len(all_domains)} 个唯一域名")

    cache, now, to_check = load_cache(), datetime.now(), set()
    for d in all_domains:
        if d in cache:
            try:
                days = (now - datetime.fromtimestamp(cache[d]['time'])).days
                if (cache[d]['alive'] and days < CACHE_ALIVE_DAYS) or \
                   (not cache[d]['alive'] and days < CACHE_DEAD_DAYS): continue
            except: pass
        to_check.add(d)
    log(f"  💾 缓存命中 {len(all_domains)-len(to_check)}，需查询 {len(to_check)}")
    if len(to_check) > 50000:
        log(f"  ⚠️ 需查询量巨大（多半是首次运行无缓存），耗时较长属正常，心跳会持续播报...", C.Y)

    # DNS 并发 + 独立心跳
    dead_set = set()
    if to_check:
        total, done = len(to_check), 0
        lock = threading.Lock()
        stop_evt = threading.Event()

        def heartbeat():
            # 关键：独立线程按时打印，不依赖任务是否返回，杜绝"假死"
            while not stop_evt.wait(HEARTBEAT_SEC):
                with lock: cur = done
                log(f"  🔄 进度: {cur}/{total} ({cur/total*100:.1f}%) | 死链: {len(dead_set)}", C.CY)

        threading.Thread(target=heartbeat, daemon=True).start()
        t_dns = time.time()
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
                futs = [exe.submit(check_dns, d) for d in to_check]
                for f in as_completed(futs):
                    domain, alive = f.result()
                    if not alive: dead_set.add(domain)
                    cache[domain] = {'alive': alive, 'time': now.timestamp()}
                    with lock: done += 1
        finally:
            stop_evt.set()
        log(f"  ✅ DNS 检查完成，耗时 {time.time()-t_dns:.0f}s，发现 {len(dead_set)} 个死链", C.G)

        try:
            with gzip.open(CACHE_FILE, 'wt', encoding='utf-8') as f:
                json.dump(cache, f, separators=(',', ':'))
        except Exception as e:
            log(f"  ⚠️ 保存缓存失败: {e}", C.Y)

    # 去重 + 重写
    t_orig = t_dead = t_dup = t_final = 0
    for fp, data in file_data.items():
        seen, clean, dead, dup = set(), [], 0, 0
        for r in data['rules']:
            s = r.strip()
            if s in data['map'] and data['map'][s] in dead_set:
                dead += 1; continue
            if s not in seen:
                clean.append(r); seen.add(s)
            else:
                dup += 1
        for i, h in enumerate(data['hdr']):
            if h.startswith("! Total count:"):
                data['hdr'][i] = f"! Total count: {len(clean)}\n"; break
        with open(fp, 'w', encoding='utf-8') as f:
            f.writelines(data['hdr']); f.writelines(clean)
        t_orig += data['orig']; t_dead += dead; t_dup += dup; t_final += len(clean)

    # [3/3] 报告
    size = os.path.getsize("rules.txt") if os.path.exists("rules.txt") else 0
    size_str = f"{size/1024:.1f} KB" if size < 1048576 else f"{size/1048576:.2f} MB"
    log(f"\n{C.BOLD}📊 [3/3] 数据漏斗体检报告{C.E}")
    print(f" ├─ 原始规则总数:   {t_orig:,}", flush=True)
    print(f" ├─ 死链剔除(无效): {C.R}{t_dead:,}{C.E}", flush=True)
    print(f" ├─ 规则去重剔除:   {C.Y}{t_dup:,}{C.E}", flush=True)
    print(f" ├─ {C.G}最终保留规则: {C.BOLD}{t_final:,}{C.E}", flush=True)
    print(f" ├─ 📦 文件大小:    {C.CY}{size_str}{C.E}", flush=True)
    print(f" └─ ⏱️  总耗时:      {C.Y}{time.time()-t0:.1f} 秒{C.E}\n", flush=True)

    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], 'a', encoding='utf-8') as f:
            f.write(f"### 📡 上游源抓取状态\n**汇总**: ✅ `{ok_cnt}` / ❌ `{fail_cnt}` (共 `{len(up_res)}`)\n\n" + "\n".join(md_up) + "\n\n")
            f.write(f"### 📊 规则清洗体检报告\n| 项目 | 数量 |\n| --- | --- |\n")
            f.write(f"| 📥 原始总数 | `{t_orig:,}` |\n| 💀 死链清除 | `{t_dead:,}` |\n| 🔄 去重剔除 | `{t_dup:,}` |\n| ✅ 最终保留 | `{t_final:,}` |\n| 📦 文件大小 | `{size_str}` |\n\n")
        log(f"{C.G}✅ 已生成 GitHub Actions Summary 报告！{C.E}", C.G)

if __name__ == "__main__":
    main()
