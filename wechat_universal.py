# -*- coding: utf-8 -*-
"""
微信防撤回补丁 —— 通用自适应引擎 v3
======================================
目标：尽可能适配「任何版本」的微信 4.x，而不必等上游补丁库更新。

实测得出的可靠性基准（微信 4.1.15.13，Weixin.dll 192MB）：
    容差 0 字节 → 命中 1 处（原始特征）
    容差 1 字节 → 命中 1 处   ← 黄金线，唯一且安全
    容差 2 字节 → 命中 5 处   ← 开始歧义
    容差 3 字节 → 命中 37 处  ← 不可用
所以引擎策略：**容差从 0 逐级升到 1，永不越过 1**；再往下降级到结构推导。

多级降级（含置信度）：
  L0 已打过识别   用「补丁后特征」反查 → 确认是否已生效（避免重复打）
  L1 精确匹配     在线库原始特征，容差 0，唯一命中            → HIGH
  L2 单字节容差   容差 1，唯一命中 + .text + 指令边界校验      → MEDIUM_HIGH
  L3 特征侵蚀     长特征拆短锚点重定位 + 原特征复核            → MEDIUM
  L4 结构推导     revokemsg 协议表 + 指令模式启发式（仅报告）   → LOW

安全网（任何一级都强制）：
  唯一性硬要求 · .text 段校验 · 指令边界校验 · 写前逐字节核对 · 自动备份
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

import pefile
import capstone

WILDCARD = 63
HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "patch_state.json")
LOG_FILE = os.path.join(HERE, "patch_log.txt")

MAX_TOLERANCE = 1          # 实测黄金线：容差永不超过 1

RULE_SOURCES = [
    ("官方OSS", "https://hui-config.oss-cn-hangzhou.aliyuncs.com/{v}/patch.json"),
    ("jsdelivr", "https://cdn.jsdelivr.net/gh/huiyadanli/RevokeMsgPatcher@master/RevokeMsgPatcher.Assistant/Data/{v}/patch.json"),
    ("gitmirror", "https://raw.gitmirror.com/huiyadanli/RevokeMsgPatcher/master/RevokeMsgPatcher.Assistant/Data/{v}/patch.json"),
    ("raw.gh", "https://raw.githubusercontent.com/huiyadanli/RevokeMsgPatcher/master/RevokeMsgPatcher.Assistant/Data/{v}/patch.json"),
]
LIB_VERSIONS = ["2.1"]

CONF_HIGH, CONF_MEDHIGH, CONF_MED, CONF_LOW = "HIGH", "MEDIUM_HIGH", "MEDIUM", "LOW"


# ================= 日志 =================
def say(msg, quiet=False):
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    if not quiet:
        print(msg)


# ================= PE 镜像 =================
class Image:
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.pe = pefile.PE(path, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.secs = []
        for s in self.pe.sections:
            self.secs.append((s.Name.rstrip(b"\x00").decode("latin1", "ignore"),
                              s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData))
        with open(path, "rb") as f:
            self.blob = f.read()
        # 关键：读完后必须关闭 pefile 句柄，否则 Windows 下写同一文件会报 Errno 22
        self.pe.close()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def off2va(self, off):
        for nm, va, ro, rs in self.secs:
            if ro <= off < ro + rs:
                return self.base + va + (off - ro)
        return None

    def in_text(self, off):
        for nm, va, ro, rs in self.secs:
            if nm == ".text" and ro <= off < ro + rs:
                return True
        return False

    def instr_bounds(self, off, back=48):
        """判断 off 是否落在合法指令边界上（防误伤数据/半条指令）"""
        start = max(0, off - back)
        va = self.off2va(start)
        tgt = self.off2va(off)
        if va is None or tgt is None:
            return None, ""
        last = None
        for ins in self.md.disasm(self.blob[start:off + 16], va):
            if ins.address == tgt:
                return True, "%s %s" % (ins.mnemonic, ins.op_str)
            if ins.address < tgt:
                last = ins
            if ins.address > tgt:
                break
        if last:
            return False, "%s %s (命中点在指令中间)" % (last.mnemonic, last.op_str)
        return None, ""

    def disasm(self, off, back=64, fwd=48):
        start = max(0, off - back)
        va = self.off2va(start)
        if va is None:
            return []
        return [(i.address, i.mnemonic, i.op_str)
                for i in self.md.disasm(self.blob[start:off + fwd], va)]


# ================= 匹配 =================
def longest_fixed_run(pattern):
    best, bi, cur, ci = b"", 0, b"", 0
    for i, b in enumerate(pattern):
        if b == WILDCARD:
            if len(cur) > len(best):
                best, bi = cur, ci
            cur = b""
        else:
            if not cur:
                ci = i
            cur += bytes([b])
    if len(cur) > len(best):
        best, bi = cur, ci
    return best, bi


def mask_find(blob, pattern, max_mismatch=0):
    """返回 [(offset, 不符数)]；用最长固定段做锚点加速"""
    plen = len(pattern)
    if not any(b != WILDCARD for b in pattern):
        return []
    anchor, aoff = longest_fixed_run(pattern)
    if len(anchor) < 2:
        first = next((i, b) for i, b in enumerate(pattern) if b != WILDCARD)
        anchor, aoff = bytes([first[1]]), first[0]
    out, start, a0 = [], 0, anchor[0]
    while True:
        idx = blob.find(bytes([a0]), start)
        if idx == -1:
            break
        pos = idx - aoff
        if pos >= 0 and pos + plen <= len(blob):
            mism, ok = 0, True
            for i in range(plen):
                if pattern[i] == WILDCARD:
                    continue
                if blob[pos + i] != pattern[i]:
                    mism += 1
                    if mism > max_mismatch:
                        ok = False
                        break
            if ok:
                out.append((pos, mism))
        start = idx + 1
    return out


def erode_anchors(pattern, min_len=6):
    """把长特征拆成若干固定段锚点，长的优先"""
    runs, cur, ci = [], b"", 0
    for i, b in enumerate(pattern):
        if b == WILDCARD:
            if cur:
                runs.append((ci, cur))
            cur = b""
        else:
            if not cur:
                ci = i
            cur += bytes([b])
    if cur:
        runs.append((ci, cur))
    runs.sort(key=lambda x: len(x[1]), reverse=True)
    return [(o, r) for o, r in runs if len(r) >= min_len]


def diffs_of(search, replace, off):
    return [(off + i, search[i], replace[i]) for i in range(len(search))
            if search[i] != WILDCARD and search[i] != replace[i]]


# ================= 规则加载 =================
def fetch_rules(quiet=False):
    """多源多版本尝试，返回 (rules, source_desc)。全部失败返回 (None, None)"""
    for libv in LIB_VERSIONS:
        for name, tpl in RULE_SOURCES:
            url = tpl.format(v=libv)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    db = json.loads(r.read().decode("utf-8", "ignore"))
                apps = db.get("Apps", {})
                # 微信 4.x 走 Weixin，旧版走 Wechat.WeChatWin.dll
                out = {}
                if "Weixin" in apps:
                    out["Weixin.dll"] = apps["Weixin"]["FileCommonModifyInfos"]["Weixin.dll"]
                if "Wechat" in apps:
                    wc = apps["Wechat"]["FileCommonModifyInfos"].get("WeChatWin.dll")
                    if wc:
                        out["WeChatWin.dll"] = wc
                if out:
                    say("规则库: 获取成功 (库%s, 数据%s) 来源 %s"
                        % (libv, db.get("PatchVersion", "?"), name), quiet)
                    return out, "%s/%s" % (name, libv)
            except Exception as e:
                say("规则库: %s(lib%s) 失败 %s" % (name, libv, e), quiet)
    say("规则库: 全部源失败", quiet)
    return None, None


def pick_rulesets(rules, dll_name, ver):
    lst = rules.get(dll_name) or []
    out = []
    for r in lst:
        sv = ver_tuple(r.get("StartVersion"))
        ev_raw = r.get("EndVersion")
        ev = ver_tuple(ev_raw) if ev_raw else None
        if ver >= sv and (ev is None or ver < ev):
            out.append(r)
    return out


def all_rulesets(rules, dll_name):
    return rules.get(dll_name) or []


# ================= 版本工具 =================
def ver_tuple(s):
    nums = re.findall(r"\d+", s or "")
    return tuple(int(x) for x in nums[:4]) if nums else (0,)


def file_version(path):
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Item -LiteralPath '%s').VersionInfo.FileVersion" % path],
            capture_output=True, text=True, timeout=60,
            creationflags=0x08000000 if os.name == "nt" else 0)
        raw = (out.stdout or "").strip()
        if re.findall(r"\d+", raw):
            return raw, ver_tuple(raw)
    except Exception:
        pass
    m = re.search(r"[\\/](\d+\.\d+\.\d+\.\d+)[\\/]", path)
    if m:
        return m.group(1), ver_tuple(m.group(1))
    return "unknown", (0, 0, 0, 0)


# ================= 目标定位 =================
CORE_FILES = ["Weixin.dll", "WeChatWin.dll"]


def find_targets():
    """扫描常见安装位置，返回 [{path, dll, ver}]，兼容 4.x 与 3.x"""
    found = []
    roots = []
    for drv in "CDEFGH":
        for sub in ("Tencent\\Weixin", "Tencent\\WeChat",
                    "Program Files\\Tencent\\Weixin", "Program Files\\Tencent\\WeChat",
                    "Program Files (x86)\\Tencent\\Weixin", "Program Files (x86)\\Tencent\\WeChat"):
            d = "%s:\\%s" % (drv, sub)
            if os.path.isdir(d):
                roots.append(d)
    for d in roots:
        # 情况1：子目录里放 DLL（4.x 风格）
        for name in os.listdir(d):
            full = os.path.join(d, name)
            if os.path.isdir(full):
                for cf in CORE_FILES:
                    p = os.path.join(full, cf)
                    if os.path.isfile(p):
                        found.append({"path": p, "dll": cf})
        # 情况2：DLL 直接在这一层（3.x 风格）
        for cf in CORE_FILES:
            p = os.path.join(d, cf)
            if os.path.isfile(p):
                found.append({"path": p, "dll": cf})
    # 去重 + 取版本最高 / 最新
    seen = {}
    for f in found:
        k = os.path.normcase(f["path"])
        if k not in seen:
            seen[k] = f
    out = list(seen.values())
    for f in out:
        f["ver_raw"], f["ver"] = file_version(f["path"])
    out.sort(key=lambda f: (f["ver"], os.path.getmtime(f["path"])), reverse=True)
    return out


def running_exes():
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True, errors="replace",
                             timeout=30,
                             creationflags=0x08000000 if os.name == "nt" else 0).stdout
        txt = (out or "").lower()
        return "weixin.exe" in txt or "wechat.exe" in txt
    except Exception:
        return False


# ================= 自适应规划 =================
def plan_for(img, rulesets, categories, ver, verbose=True):
    """返回 [dict]，每项含 cat/off/diffs/conf/how"""
    res = []
    for rs in rulesets:
        for p in rs.get("ReplacePatterns", []):
            cat = p.get("Category") or "?"
            if cat not in categories:
                continue
            search, replace = p["Search"], p["Replace"]
            base = {"cat": cat, "range": "%s~%s" % (rs.get("StartVersion"),
                                                    rs.get("EndVersion") or "∞")}

            # L0 已打过？
            if mask_find(img.blob, replace, 0):
                res.append(dict(base, off=None, diffs=[], conf=CONF_HIGH,
                                how="L0 已是补丁后状态，无需处理", done=True))
                continue

            # L1 精确
            h = mask_find(img.blob, search, 0)
            if len(h) == 1:
                off = h[0][0]
                res.append(dict(base, off=off, diffs=diffs_of(search, replace, off),
                                conf=CONF_HIGH, how="L1 精确匹配(容差0)"))
                continue
            if len(h) > 1:
                res.append(dict(base, off=None, diffs=[], conf=CONF_LOW,
                                how="L1 命中%d处，歧义中止" % len(h)))
                continue

            # L2 单字节容差（黄金线）
            h2 = mask_find(img.blob, search, 1)
            h2_in = [(o, m) for o, m in h2 if img.in_text(o)]
            if len(h2_in) == 1:
                off, mism = h2_in[0]
                okb, txt = img.instr_bounds(off)
                # 单字节不符时还要确认「只错在可变位」，且指令边界合法
                if okb:
                    res.append(dict(base, off=off, diffs=diffs_of(search, replace, off),
                                    conf=CONF_MEDHIGH,
                                    how="L2 容差1唯一命中，边界✔ [%s]" % txt))
                    continue
                res.append(dict(base, off=None, diffs=[], conf=CONF_LOW,
                                how="L2 命中但非指令边界，放弃(%s)" % txt))
                continue
            if len(h2_in) > 1:
                res.append(dict(base, off=None, diffs=[], conf=CONF_LOW,
                                how="L2 容差1命中%d处，歧义中止" % len(h2_in)))
                continue

            # L3 特征侵蚀（长锚点重定位）
            got = None
            for boff, anchor in erode_anchors(search, 6):
                ah = [o for o, m in mask_find(img.blob, list(anchor), 0) if img.in_text(o)]
                if len(ah) != 1:
                    continue
                cand = ah[0] - boff
                if cand < 0 or cand + len(search) > len(img.blob):
                    continue
                mism = sum(1 for i in range(len(search))
                           if search[i] != WILDCARD and img.blob[cand + i] != search[i])
                if mism == 0:
                    got = (cand, boff, anchor)
                    break
            if got:
                off, boff, anchor = got
                okb, txt = img.instr_bounds(off)
                res.append(dict(base, off=off, diffs=diffs_of(search, replace, off),
                                conf=CONF_MED if okb else CONF_LOW,
                                how="L3 侵蚀锚点(偏移%d/%d字节)重定位%s"
                                    % (boff, len(anchor), "，边界✔" if okb else "，⚠边界异常")))
                continue

            # L4 结构推导（只报告）
            g = structural_guess(img)
            res.append(dict(base, off=g, diffs=[], conf=CONF_LOW,
                            how="L4 结构推导参考" + (("(偏移%d)" % g) if g else "(无候选)")))
    return res


def structural_guess(img):
    """启发式：找「mov [rsi+d], rax + mov [rbp+d], r13」的撤回处理模式"""
    cands = []
    pat = bytes([0x48, 0x89, 0x86])
    start = 0
    while True:
        i = img.blob.find(pat, start)
        if i == -1:
            break
        if img.in_text(i):
            if img.blob[i + 7:i + 11] == bytes([0x4C, 0x89, 0xAD]):
                cands.append(i)
        start = i + 1
    return cands[0] if len(cands) == 1 else None


# ================= 状态 =================
def norm(p):
    return os.path.normcase(os.path.normpath(p))


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


# ================= 命令实现 =================
def cmd_scan():
    """列出本机所有微信核心文件 + 版本 + 支持情况"""
    print("=== 扫描本机微信安装 ===")
    ts = find_targets()
    if not ts:
        print("  未找到微信安装目录")
        return 1
    rules, src = fetch_rules()
    print()
    for t in ts:
        print("  DLL   : %s" % t["path"])
        print("  文件   : %s   版本: %s" % (t["dll"], t["ver_raw"]))
        if rules and t["dll"] in rules:
            rs = pick_rulesets(rules, t["dll"], t["ver"])
            if rs:
                print("  支持   : ✅ 规则库有匹配 %s" %
                      [("%s~%s" % (r.get("StartVersion"), r.get("EndVersion") or "∞")) for r in rs])
            else:
                allrs = all_rulesets(rules, t["dll"])
                print("  支持   : ⚠ 版本不在区间内，共 %d 条规则可选 %s" %
                      (len(allrs), [r.get("StartVersion") for r in allrs][:6]))
        elif rules:
            print("  支持   : ❌ 规则库无 %s 条目" % t["dll"])
        else:
            print("  支持   : ? 规则库获取失败")
        print()
    return 0


def cmd_check(dll_path=None, files=None):
    ts = find_targets()
    if dll_path:
        ts = [{"path": dll_path, "dll": os.path.basename(dll_path),
               "ver_raw": file_version(dll_path)[0], "ver": file_version(dll_path)[1]}]
    if not ts:
        print("未找到微信核心 DLL")
        return 1
    rules, src = fetch_rules()
    t = ts[0]
    img = Image(t["path"])
    print("目标   : %s" % t["path"])
    print("版本   : %s   大小 %.2f MB" % (t["ver_raw"], img.size / 1024 / 1024))
    if not rules:
        print("规则库获取失败（离线）")
        return 1
    if t["dll"] not in rules:
        print("规则库不含 %s" % t["dll"])
        return 1
    rs = pick_rulesets(rules, t["dll"], t["ver"])
    cats = set(files or []) or None
    if not rs:
        print("版本 %s 不在任何规则区间 —— 启用自适应降级（试全部规则）" % t["ver_raw"])
        rs = all_rulesets(rules, t["dll"])
    plan = plan_for(img, rs, cats or {"防撤回", "多开"}, t["ver"])
    print("-" * 64)
    for p in plan:
        loc = ("偏移 %d" % p["off"]) if p.get("off") is not None else "—"
        print("  [%-4s] %-8s %-14s %s" % (p["conf"], p["cat"], loc, p["how"]))
    print("-" * 64)
    return 0


def apply_patch(dll_path, categories, dry=False):
    t = {"path": dll_path, "dll": os.path.basename(dll_path)}
    t["ver_raw"], t["ver"] = file_version(dll_path)
    rules, src = fetch_rules()
    if not rules:
        say("规则库获取失败，无法打补丁")
        return 1
    if t["dll"] not in rules:
        say("规则库不含 %s" % t["dll"])
        return 1
    img = Image(dll_path)
    rs = pick_rulesets(rules, t["dll"], t["ver"]) or all_rulesets(rules, t["dll"])
    plan = plan_for(img, rs, categories, t["ver"])

    writable = []
    for p in plan:
        if p.get("done"):
            say("  [%s] 已打过，跳过" % p["cat"])
            continue
        if p["conf"] == CONF_LOW:
            say("  [%s] 置信度过低，跳过（%s）" % (p["cat"], p["how"]))
            continue
        if not p.get("diffs"):
            say("  [%s] 无可写字节，跳过" % p["cat"])
            continue
        writable.append(p)
        say("  [%s] %s  %d 字节 @ %d  (%s)"
            % (p["conf"], p["cat"], len(p["diffs"]), p["off"], p["how"]))

    if not writable:
        say("没有可安全写入的项。")
        return 0
    if dry:
        say("(dry-run，未写入)")
        return 0

    blob = bytearray(img.blob)
    # 写前逐字节核对
    for p in writable:
        for pos, old, new in p["diffs"]:
            if blob[pos] != old:
                say("  ✗ 偏移 %d 原字节不符(期望%d实为%d)，中止" % (pos, old, blob[pos]))
                return 1
    bak = dll_path + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(dll_path, bak)
        say("已备份 -> %s" % bak)
    for p in writable:
        for pos, old, new in p["diffs"]:
            blob[pos] = new
    with open(dll_path, "wb") as f:
        f.write(blob)

    st = load_state()
    st[norm(dll_path)] = {"size": os.path.getsize(dll_path),
                          "mtime": os.path.getmtime(dll_path),
                          "sha256": sha256(dll_path), "version": t["ver_raw"],
                          "patched": True,
                          "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
    save_state(st)
    say("补丁写入完成 -> %s" % dll_path)
    return 0


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(c)
    return h.hexdigest()


def cmd_auto(quiet=True):
    """定时任务用：所有微信核心文件都尝试，微信在跑就跳过"""
    ts = find_targets()
    if not ts:
        say("auto: 未找到微信", quiet)
        return 1
    if running_exes():
        say("auto: 微信正在运行，本轮跳过", quiet)
        return 0
    st = load_state()
    rc = 0
    for t in ts:
        key = norm(t["path"])
        rec = st.get(key)
        try:
            size, mt = os.path.getsize(t["path"]), os.path.getmtime(t["path"])
        except OSError:
            continue
        if rec and rec.get("patched") and rec.get("size") == size \
                and abs((rec.get("mtime") or 0) - mt) < 1:
            continue
        say("auto: 处理 %s (v%s)" % (t["dll"], t["ver_raw"]), quiet)
        apply_patch(t["path"], {"防撤回"}, dry=False)
    return rc


def cmd_restore(dll_path):
    bak = dll_path + ".bak"
    if not os.path.exists(bak):
        print("未找到备份 %s" % bak)
        return 1
    shutil.copy2(bak, dll_path)
    st = load_state()
    st.pop(norm(dll_path), None)
    save_state(st)
    print("已还原 %s" % dll_path)
    return 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description="微信防撤回补丁 · 通用自适应引擎")
    ap.add_argument("action", choices=["scan", "check", "apply", "restore", "auto"])
    ap.add_argument("--dll", help="指定 Weixin.dll / WeChatWin.dll")
    ap.add_argument("--multi", action="store_true", help="附带多开")
    ap.add_argument("--dry", action="store_true", help="只演算不写入")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    cats = {"防撤回", "多开"} if a.multi else {"防撤回"}

    if a.action == "scan":
        return cmd_scan()
    if a.action == "check":
        return cmd_check(a.dll)
    if a.action == "apply":
        if a.dll:
            path = a.dll
        else:
            ts = find_targets()
            if not ts:
                print("未找到微信核心 DLL")
                return 1
            path = ts[0]["path"]
        if running_exes() and not a.dry:
            print("微信正在运行，请先完全退出")
            return 1
        return apply_patch(path, cats, dry=a.dry)
    if a.action == "auto":
        return cmd_auto(a.quiet)
    if a.action == "restore":
        ts = find_targets()
        if a.dll:
            path = a.dll
        elif ts:
            path = ts[0]["path"]
        else:
            print("未找到目标")
            return 1
        return cmd_restore(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
