#!/bin/sh
LC_ALL='C'

rm *.txt

wait
echo '创建临时文件夹'
mkdir -p ./tmp/

#添加补充规则
cp ./data/rules/adblock.txt ./tmp/rules01.txt
cp ./data/rules/whitelist.txt ./tmp/allow01.txt

cd tmp
#下载SMAdHosts规则
curl -sL https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts | \
awk '{
    sub(/[[:space:]]*#.*/, "");      # 去掉行尾注释
    sub(/[[:space:]]+$/, "");        # 去掉行尾空格
    if ($0 == "") next;              # 跳过空行
    if (($1 == "0.0.0.0" || $1 == "127.0.0.1") && $2 != "localhost" && $2 != "ip6-localhost") {
        print "||" $2 "^";
    }
}' > rules001.txt &

#下载domestic-ad-hosts规则
curl -sSL https://raw.githubusercontent.com/insoxin/domestic-ad-hosts/main/hosts | awk '!/视频|奇艺|微信|localhost/ && /^127\.0\.0\.1[ \t]+/ {print "||"$2"^"}' | sort -u > rules002.txt &

#下载abclq规则
curl -sL "https://raw.githubusercontent.com/abclq/home-dns-adblock/main/dist/adguard-dns.txt" | \
awk '
    # 跳过空行和注释行（以 ! 或 # 开头）
    /^$/ || /^[!#]/ { next }
    # 处理 AdGuard 风格规则 (||...^ 或 @@||...^)
    /^\|\|/ || /^@@\|\|/ { print; next }
    # 处理纯域名行：自动补全为 ||domain^ 格式
    /^[a-zA-Z0-9.-]+$/ { print "||" $0 "^"; next }
    # 其他无法识别的行，原样输出或跳过（此处选择跳过）
    { next }
' | sort -u > rules003.txt &

# 等待三个独立规则源并行下载完成，避免与主循环争抢并发连接
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
  "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt" #GOODBYEADS规则
  "https://raw.githubusercontent.com/sbwml/halflife-list/master/ad-edentw.txt" #edentwCustom
  "https://raw.githubusercontent.com/Menghuibanxian/AdguardHome/main/Black.txt" #梦回半仙
  "https://raw.githubusercontent.com/qq5460168/666/master/rules.txt" #666规则
  "https://raw.githubusercontent.com/the-advoid/ad-void/main/AdVoid.Full.txt" #AdVoid.Full
  "https://raw.githubusercontent.com/Chaniug/AdSuper/main/adnew.txt" #AdSuper
  "https://gp.adrules.top/adblock_plus.txt" #Cats-Team
  "https://lingeringsound.github.io/adblock_auto/Rules/adblock_auto.txt" #混合规则
  "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt" #uniartisan's Adblock
  "https://raw.githubusercontent.com/damengzhu/abpmerge/main/abpmerge.txt" #ABP Merge Rules
  "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt" #uniartisan's Privacy
  "https://neodev.team/adblocker" #NEO DEV HOST
  "https://lingeringsound.github.io/10007_auto/adb.txt" #Host 10007
  "https://raw.githubusercontent.com/rentianyu/Ad-set-hosts/master/adguard" #Ad-set-hosts
  "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/cpbl-abp-list.txt" #CPBL Filters for ABP & uBO
  "https://raw.githubusercontent.com/DickaHandsome/My-Ads-Rule/main/MyRule.txt" #My Ads Rule
  "https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt" #Privacy Essentials
  "https://raw.githubusercontent.com/afwfv/DD-AD/release/easylist.txt" #DD-AD of easylist
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt" #茯苓黑名单
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
  "https://raw.githubusercontent.com/qq5460168/666/master/allow.txt"
  "https://raw.githubusercontent.com/smdx/AdGHome_Filter_List/main/White-List.txt"
  "https://raw.githubusercontent.com/hl2guide/curated-adblock-lists/main/lists/allowed.txt"
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt"
)

for i in "${!rules[@]}"
do
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - -o "rules${i}.txt" --connect-timeout 60 -s "${rules[$i]}" &
done

for i in "${!allow[@]}"
do
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - -o "allow${i}.txt" --connect-timeout 60 -s "${allow[$i]}" &
done
wait
echo '规则下载完成'

# 添加空格
file="$(ls|sort -u)"
for i in $file; do
  echo -e '\n' >> $i &
done
wait

echo '处理规则中'

cat | sort -n| grep -v -E "^((#.*)|(\s*))$" \
 | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
 | grep -Ev "local.*\.local.*$" \
 | sed s/127.0.0.1/0.0.0.0/g | sed s/::/0.0.0.0/g |grep '0.0.0.0' |grep -Ev '.0.0.0.0 ' | sort \
 |uniq >base-src-hosts.txt &
wait
cat base-src-hosts.txt | grep -Ev '#|\$|@|!|/|\\|\*'\
 | grep -v -E "^((#.*)|(\s*))$" \
 | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|loopback)$" \
 | sed 's/127.0.0.1 //' | sed 's/0.0.0.0 //' \
 | sed "s/^/||&/g" |sed "s/$/&^/g"| sed '/^$/d' \
 | grep -v '^#' \
 | sort -n | uniq | awk '!a[$0]++' \
 | grep -E "^((\|\|)\S+\^)" & #Hosts规则转ABP规则

cat | sed '/^$/d' | grep -v '#' \
 | sed "s/^/@@||&/g" | sed "s/$/&^/g"  \
 | sort -n | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat | sed '/^$/d' | grep -v "#" \
 |sed "s/^/@@||&/g" | sed "s/$/&^/g" | sort -n \
 | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat | sed '/^$/d' | grep -v "#" \
 |sed "s/^/0.0.0.0 &/g" | sort -n \
 | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat *.txt | sed '/^$/d' \
 |grep -E "^\/[a-z]([a-z]|\.)*\.$" \
 |sort -u > l.txt &

cat \
 | sed "s/^/||&/g" | sed "s/$/&^/g" &

cat \
 | sed "s/^/0.0.0.0 &/g" &


echo 开始合并

# 修改: 合并时统一将残留的 hosts 规则(0.0.0.0/127.0.0.1) 转换为 ||domain^ 并做多级去重
cat rules*.txt \
 |grep -Ev "^((\!)|(\[)).*" \
 | awk '{
     # 修改: 去掉 CRLF 行尾的 \r, 避免 $1 判断失败
     sub(/\r$/, "");
     # 跳过空白行
     if ($0 ~ /^[[:space:]]*$/) next;
     # 跳过纯注释行
     if ($0 ~ /^[[:space:]]*#/) next;
     # 将 0.0.0.0 / 127.0.0.1 开头的 hosts 规则转换为 ||domain^
     if ($1 == "0.0.0.0" || $1 == "127.0.0.1") {
         domain = $2;
         sub(/#.*/, "", domain);              # 去掉可能的行内注释
         gsub(/[[:space:]]/, "", domain);     # 去掉可能的空白
         if (domain != "" && domain !~ /^(localhost|ip6-localhost|local|loopback)$/) {
             print "||" domain "^";
         }
         next;
     }
     # 其他规则原样保留
     print $0;
 }' \
 | sort -n | uniq | awk '!a[$0]++' > tmp-rules.txt & #处理AdGuard的规则(含hosts转ABP+去重)

cat \
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

# 修改: 在 Python 脚本运行之前, 先把 rules.txt 中的 hosts 规则统一转成 ||domain^ 并全局去重
#         这样 rule.py / filter-dns.py / title.py 都会基于干净文件工作, dns.txt 自然干净
awk '{
    # 去掉 CRLF 行尾
    sub(/\r$/, "");
    # 跳过空白行
    if ($0 ~ /^[[:space:]]*$/) next;
    # 保留注释行
    if ($0 ~ /^[[:space:]]*[#!]/) { print $0; next; }
    # hosts 格式转换为 ABP 格式
    if ($1 == "0.0.0.0" || $1 == "127.0.0.1") {
        domain = $2;
        sub(/#.*/, "", domain);
        gsub(/[[:space:]]/, "", domain);
        if (domain != "" && domain !~ /^(localhost|ip6-localhost|local|loopback)$/) {
            print "||" domain "^";
        }
        next;
    }
    print $0;
}' .././rules.txt | awk '!a[$0]++' > .././rules.txt.cleaned
mv .././rules.txt.cleaned .././rules.txt

# Python 处理重复规则
python .././data/python/rule.py
python .././data/python/filter-dns.py

# Start Add title and date
python .././data/python/title.py

# 修改: 最终兜底清理 —— 在 Python 脚本处理完成后, 对 rules.txt 再做一次 hosts -> ||domain^ 转换与全局去重
#         防止 rule.py / filter-dns.py 等步骤重新引入 hosts 格式规则
awk '{
    # 去掉 CRLF 行尾
    sub(/\r$/, "");
    # 跳过空白行
    if ($0 ~ /^[[:space:]]*$/) next;
    # 保留注释行(如 title.py 生成的标题行)
    if ($0 ~ /^[[:space:]]*[#!]/) { print $0; next; }
    # hosts 格式转换为 ABP 格式
    if ($1 == "0.0.0.0" || $1 == "127.0.0.1") {
        domain = $2;
        sub(/#.*/, "", domain);
        gsub(/[[:space:]]/, "", domain);
        if (domain != "" && domain !~ /^(localhost|ip6-localhost|local|loopback)$/) {
            print "||" domain "^";
        }
        next;
    }
    print $0;
}' .././rules.txt | awk '!a[$0]++' > .././rules.txt.cleaned

# 用清理后的文件覆盖原文件
mv .././rules.txt.cleaned .././rules.txt

# 校验: 如果仍有 0.0.0.0 / 127.0.0.1 开头规则则打印告警(不中断, 便于排查)
if grep -qE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' .././rules.txt; then
    echo '警告: rules.txt 中仍存在 hosts 格式规则, 请检查 Python 脚本输出'
    grep -nE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' .././rules.txt | head -20
fi

# 修改: dns.txt 也应校验, 若 filter-dns.py 之后出现 hosts 行, 说明该文件被污染
if grep -qE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' .././dns.txt; then
    echo '警告: dns.txt 中仍存在 hosts 格式规则'
    grep -nE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' .././dns.txt | head -20
fi

wait
echo '更新成功'

exit
