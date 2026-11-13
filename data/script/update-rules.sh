#!/bin/bash
# ============================================================
# update-rules.sh (修订版)
# 基于 update-rules(1).sh 修改，主要修复：
#   1. shebang 改为 bash，匹配后续数组语法
#   2. 开头清理 tmp 目录旧文件，避免残留混入
#   3. curl 统一加 -f（HTTP 错误返回非零）并打印失败 URL
#   4. 下载后统计非空文件数，全军覆没时告警
#   5. 无输入的 `cat |` 改为 `cat </dev/null |`，防止 stdin 挂起
#   6. 文件遍历改用 glob + 引号，避免文件名含空格出错
# ============================================================
LC_ALL='C'

rm -f ./*.txt

wait
echo '创建临时文件夹'
mkdir -p ./tmp/
# FIX: 清理 tmp 目录旧文件，避免上次残留被 cat rules*.txt 混入
rm -f ./tmp/*.txt

# 添加补充规则
cp ./data/rules/adblock.txt ./tmp/rules01.txt
cp ./data/rules/whitelist.txt ./tmp/allow01.txt

cd tmp

# ------------------------------------------------------------
# 下载 SMAdHosts 规则
# FIX: 加超时、-f，失败时打印具体 URL，避免无超时导致 wait 无限挂起
# ------------------------------------------------------------
{ curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts \
    || echo "❌ 下载失败/超时: https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts" >&2; } | \
awk '{
    sub(/[[:space:]]*#.*/, "");      # 去掉行尾注释
    sub(/[[:space:]]+$/, "");        # 去掉行尾空格
    if ($0 == "") next;              # 跳过空行
    if (($1 == "0.0.0.0" || $1 == "127.0.0.1") && $2 != "localhost" && $2 != "ip6-localhost") {
        print "||" $2 "^";
    }
}' > rules001.txt &

# ------------------------------------------------------------
# 下载 Host 10007 规则，提取 0.0.0.0 行并转为 ||域名^ 格式
# 输出：rules002.txt（去重后的 AdGuard/clash 域名规则）
# ------------------------------------------------------------
{ curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/lingeringsound/10007_auto/master/all \
    || echo "❌ 下载失败/超时: https://raw.githubusercontent.com/lingeringsound/10007_auto/master/all" >&2; } \
  | awk '
      $1 != "0.0.0.0" { next }
      {
        for (i = 2; i <= NF; i++) {
          if ($i ~ /^#/) break
          d = $i
          sub(/\r$/, "", d)
          if (d == "") continue
          if (d ~ /^(localhost|broadcasthost|local|ip6-.*|0\.0\.0\.0)$/) continue
          if (d !~ /^[A-Za-z0-9._-]+$/) continue
          print "||" d "^"
        }
      }
    ' \
  | sort -u > rules002.txt &

# ------------------------------------------------------------
# 下载 abclq 规则
# ------------------------------------------------------------
{ curl -fsSL --connect-timeout 10 --max-time 60 "https://raw.githubusercontent.com/abclq/home-dns-adblock/main/dist/adguard-dns-full.txt" \
    || echo "❌ 下载失败/超时: https://raw.githubusercontent.com/abclq/home-dns-adblock/main/dist/adguard-dns-full.txt" >&2; } | \
awk '
    /^$/ || /^[!#]/ { next }
    /^\|\|/ || /^@@\|\|/ { print; next }
    /^[a-zA-Z0-9.-]+$/ { print "||" $0 "^"; next }
    { next }
' | sort -u > rules003.txt &

# 等待三个独立规则源并行下载完成
wait

echo '下载规则'
rules=(
  "https://filters.adtidy.org/android/filters/2_optimized.txt" #adg基础过滤器
  "https://filters.adtidy.org/android/filters/11_optimized.txt" #adg移动设备过滤器
  "https://raw.githubusercontent.com/ph00lt0/blocklist/master/blocklist.txt"  #ph00lt0 - Blocklist
  "https://github.com/Lynricsy/HyperADRules/releases/latest/download/hyper_adrules_ads_adguard.txt" #HyperADRules
  "https://github.com/Lynricsy/HyperADRules/releases/latest/download/hyper_adrules_malware_adguard.txt" #HyperADRules恶意软件
  "https://filters.adtidy.org/android/filters/224_optimized.txt" #adg中文过滤器
  "https://raw.githubusercontent.com/Natsuki-Kaede/Natsuki-List/main/hosts.txt" #Natsuki-List
  "https://easylist-downloads.adblockplus.org/easyprivacy.txt" #EasyPrivacy隐私保护规则
  "https://raw.githubusercontent.com/Noyllopa/NoAppDownload/master/NoAppDownload.txt" #去APP下载提示规则
  "https://raw.githubusercontent.com/hl2guide/curated-adblock-lists/main/lists/trackers.txt" #Curated Trackers List
  "https://big.oisd.nl" #oisd规则
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt" #秋风规则
  "https://anti-ad.net/easylist.txt" #Anti-AD规则
  "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt" #adblockfilters规则
  "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt" #GOODBYEADS规则
  "https://raw.githubusercontent.com/sbwml/halflife-list/master/ad-edentw.txt" #edentwCustom
  "https://raw.githubusercontent.com/Menghuibanxian/AdguardHome/main/Black.txt" #梦回半仙
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt" #AD886
  "https://raw.githubusercontent.com/the-advoid/ad-void/main/AdVoid.DNS.txt" #AdVoid.DNS
  "https://raw.githubusercontent.com/Chaniug/AdSuper/main/adnew.txt" #AdSuper
  "https://gp.adrules.top/dns.txt" #Cats-Team
  "https://lingeringsound.github.io/adblock_auto/Rules/adblock_auto.txt" #混合规则
  "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt" #uniartisan's Adblock
  "https://raw.githubusercontent.com/damengzhu/abpmerge/main/abpmerge.txt" #ABP Merge Rules
  "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt" #uniartisan's Privacy
  "https://neodev.team/adblocker" #NEO DEV HOST
  "https://raw.githubusercontent.com/qq5460168/666/master/dns.txt" #666DNS
  "https://raw.githubusercontent.com/rentianyu/Ad-set-hosts/master/adguard" #Ad-set-hosts
  "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/cpbl-abp-list.txt" #CPBL Filters for ABP & uBO
  "https://raw.githubusercontent.com/DickaHandsome/My-Ads-Rule/main/MyRule.txt" #My Ads Rule
  "https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt" #Privacy Essentials
  "https://raw.githubusercontent.com/afwfv/DD-AD/release/easylist.txt" #DD-AD of easylist
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt" #茯苓黑名单
  "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt" #HG黑名单
)

allow=(
  "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt"
  "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/GermanFilter/sections/allowlist.txt"
  "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TurkishFilter/sections/allowlist.txt"
  "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt"
  "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt"
  "https://raw.githubusercontent.com/hl2guide/Filterlist-for-AdGuard/master/filter_whitelist.txt"
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt"
  "https://raw.githubusercontent.com/ChengJi-e/AFDNS/master/QD.txt"
  "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt"
  "https://github.com/Lynricsy/HyperADRules/releases/latest/download/hyper_adrules_allow_adguard.txt"
  "https://raw.githubusercontent.com/Ealenn/AdGuard-Home-List/gh-pages/AdGuard-Home-List.Allow.txt"
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt"
  "https://raw.githubusercontent.com/smdx/AdGHome_Filter_List/main/White-List.txt"
  "https://raw.githubusercontent.com/hl2guide/curated-adblock-lists/main/lists/allowed.txt"
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt"
  "https://raw.githubusercontent.com/2771936993/HG/main/hg2.txt"
)

# ------------------------------------------------------------
# 并发下载函数：全局共享 MAX_PARALLEL 个槽位
# 用法：download_limited <并发数> <out|url> ...
# FIX: 原脚本 rules 与 allow 各自开满后台任务，峰值可达数十，
#      易触发 GitHub/AdGuard 限流；此处合并为统一并发池，
#      全局恒 ≤ MAX_PARALLEL，失败仍打印具体 URL。
# 说明：调用方已经开了 3 个「管道+awk」源（rules001~003），
#      峰值约为 3 + 15 = 18，仍在安全范围内。
# ------------------------------------------------------------
MAX_PARALLEL=15

download_limited() {
  local max=$1; shift
  local running=0 pair out url
  for pair in "$@"; do
    # 已达并发上限：等待任一任务结束再继续下一个
    if (( running >= max )); then
      wait -n
      (( running-- ))
    fi
    # out|url 编码：前半部分为输出文件名，后半部分为 URL
    out="${pair%%|*}"
    url="${pair#*|}"
    # 子 shell 隔离：curl 的退出状态与局部变量不污染主 shell
    (
      curl -fsS -m 60 --connect-timeout 10 --retry-delay 2 --retry 5 -k -L \
           -o "$out" "$url" \
        || echo "❌ 下载失败/超时: $url" >&2
    ) &
    (( running++ ))
  done
  wait
}

# 组装任务列表：rules 与 allow 共用同一个并发池
tasks=()
for i in "${!rules[@]}"; do tasks+=("rules${i}.txt|${rules[$i]}"); done
for i in "${!allow[@]}"; do tasks+=("allow${i}.txt|${allow[$i]}"); done

download_limited "$MAX_PARALLEL" "${tasks[@]}"
echo '规则下载完成'

# FIX: 下载后统计非空文件，便于判断是否有源全军覆没
non_empty=0
total=0
for f in rules*.txt allow*.txt; do
  [ -e "$f" ] || continue
  total=$((total + 1))
  [ -s "$f" ] && non_empty=$((non_empty + 1))
done
echo "📊 下载文件非空统计: ${non_empty} / ${total}"
if [ "$non_empty" -eq 0 ]; then
  echo "❌ 严重错误: 所有下载文件均为空，请检查网络或规则源" >&2
fi

# 添加空格
# FIX: 用 glob + 引号，避免文件名含空格出错
for i in *.txt; do
  [ -f "$i" ] && echo -e '\n' >> "$i"
done
wait

echo '处理规则中'

# FIX: 原脚本此处 cat 无输入，会从 stdin 读取导致挂起或空输出。
#      显式从 /dev/null 读取以保持原“空输出”行为；如需实际处理请替换为具体文件。
cat </dev/null | sort -n | grep -v -E "^((#.*)|(\s*))$" \
 | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
 | grep -Ev "local.*\.local.*$" \
 | sed s/127.0.0.1/0.0.0.0/g | sed s/::/0.0.0.0/g | grep '0.0.0.0' | grep -Ev '.0.0.0.0 ' | sort \
 | uniq > base-src-hosts.txt &
wait

cat base-src-hosts.txt | grep -Ev '#|\$|@|!|/|\\|\*' \
 | grep -v -E "^((#.*)|(\s*))$" \
 | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|loopback)$" \
 | sed 's/127.0.0.1 //' | sed 's/0.0.0.0 //' \
 | sed "s/^/||&/g" | sed "s/$/&^/g" | sed '/^$/d' \
 | grep -v '^#' \
 | sort -n | uniq | awk '!a[$0]++' \
 | grep -E "^((\|\|)\S+\^)" & #Hosts规则转ABP规则

# FIX: 以下多处 cat 原本无输入，改为 </dev/null 防止挂起（原行为在 CI 中即为空输出）
cat </dev/null | sed '/^$/d' | grep -v '#' \
 | sed "s/^/@@||&/g" | sed "s/$/&^/g" \
 | sort -n | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat </dev/null | sed '/^$/d' | grep -v "#" \
 | sed "s/^/@@||&/g" | sed "s/$/&^/g" | sort -n \
 | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat </dev/null | sed '/^$/d' | grep -v "#" \
 | sed "s/^/0.0.0.0 &/g" | sort -n \
 | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat *.txt | sed '/^$/d' \
 | grep -E "^\/[a-z]([a-z]|\.)*\.$" \
 | sort -u > l.txt &

cat </dev/null \
 | sed "s/^/||&/g" | sed "s/$/&^/g" &

cat </dev/null \
 | sed "s/^/0.0.0.0 &/g" &


echo 开始合并

# 合并时统一将残留的 hosts 规则(0.0.0.0/127.0.0.1) 转换为 ||domain^ 并做多级去重
cat rules*.txt \
 | grep -Ev "^((\!)|(\[)).*" \
 | awk '{
     sub(/\r$/, "");
     if ($0 ~ /^[[:space:]]*$/) next;
     if ($0 ~ /^[[:space:]]*#/) next;
     if ($1 == "0.0.0.0" || $1 == "127.0.0.1") {
         domain = $2;
         sub(/#.*/, "", domain);
         gsub(/[[:space:]]/, "", domain);
         if (domain != "" && domain !~ /^(localhost|ip6-localhost|local|loopback)$/) {
             print "||" domain "^";
         }
         next;
     }
     # ↓↓↓ 新增：裸域名 example.com -> ||example.com^ ↓↓↓
     if ($0 ~ /^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$/) {
         print "||" tolower($0) "^";
         next;
     }
     # ↑↑↑ 新增结束 ↑↑↑
     print $0;
 }' \
 | sort -n | uniq | awk '!a[$0]++' > tmp-rules.txt & #处理AdGuard的规则(含hosts转ABP+去重)

cat </dev/null \
 | grep -E "^[(\@\@)|(\|\|)][^\/\^]+\^$" \
 | grep -Ev "([0-9]{1,3}.){3}[0-9]{1,3}" \
 | sort | uniq > ll.txt &
wait


cat *.txt | grep '^@' \
 | sort -n | uniq > tmp-allow.txt & #允许清单处理
wait

cp tmp-allow.txt .././allow.txt
cp tmp-rules.txt .././rules.txt

echo 规则合并完成

# 在 Python 脚本运行之前，先把 rules.txt 中的 hosts 规则统一转成 ||domain^ 并全局去重
awk '{
    sub(/\r$/, "");
    if ($0 ~ /^[[:space:]]*$/) next;
    if ($0 ~ /^[[:space:]]*[#!]/) { print $0; next; }
    if ($1 == "0.0.0.0" || $1 == "127.0.0.1") {
        domain = $2;
        sub(/#.*/, "", domain);
        gsub(/[[:space:]]/, "", domain);
        if (domain != "" && domain !~ /^(localhost|ip6-localhost|local|loopback)$/) {
            print "||" domain "^";
        }
        next;
    }
    # ↓↓↓ 新增：裸域名 example.com -> ||example.com^ ↓↓↓
    if ($0 ~ /^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$/) {
        print "||" tolower($0) "^";
        next;
    }
    # ↑↑↑ 新增结束 ↑↑↑
    print $0;
}' .././rules.txt | awk '!a[$0]++' > .././rules.txt.cleaned
mv .././rules.txt.cleaned .././rules.txt

# Python 处理重复规则
python .././data/python/rule.py
python .././data/python/filter-dns.py

# Start Add title and date
python .././data/python/title.py

# 最终兜底清理 —— 在 Python 脚本处理完成后，对 rules.txt 再做一次 hosts -> ||domain^ 转换与全局去重
awk '{
    sub(/\r$/, "");
    if ($0 ~ /^[[:space:]]*$/) next;
    if ($0 ~ /^[[:space:]]*[#!]/) { print $0; next; }
    if ($1 == "0.0.0.0" || $1 == "127.0.0.1") {
        domain = $2;
        sub(/#.*/, "", domain);
        gsub(/[[:space:]]/, "", domain);
        if (domain != "" && domain !~ /^(localhost|ip6-localhost|local|loopback)$/) {
            print "||" domain "^";
        }
        next;
    }
    # ↓↓↓ 新增：裸域名 example.com -> ||example.com^ ↓↓↓
    if ($0 ~ /^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$/) {
        print "||" tolower($0) "^";
        next;
    }
    # ↑↑↑ 新增结束 ↑↑↑
    print $0;
}' .././rules.txt | awk '!a[$0]++' > .././rules.txt.cleaned

# 用清理后的文件覆盖原文件
mv .././rules.txt.cleaned .././rules.txt

# 校验：如果仍有 hosts 格式规则则打印告警（不中断，便于排查）
if grep -qE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' .././rules.txt; then
    echo '警告: rules.txt 中仍存在 hosts 格式规则, 请检查 Python 脚本输出'
    grep -nE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' .././rules.txt | head -20
fi

if grep -qE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' .././dns.txt; then
    echo '警告: dns.txt 中仍存在 hosts 格式规则'
    grep -nE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' .././dns.txt | head -20
fi

wait
echo '更新成功'

exit
