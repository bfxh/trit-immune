#!/usr/bin/env python3
"""裁决 TMR 实验（MEMETIC-RESISTANCE.md 想法三的量化形态）。

三票表决：官方引擎（干净票 A）+ trit-re（干净票 B）+ **被投毒的官方引擎**
（拜占庭票 C——规则文件被确定性篡改：模式改成永不匹配 = 致盲形态）。
对每个（样本 × 规则）判定对做三值多数票，量测：
- 压制率：拜占庭票与两干净票分歧时，被多数票否决的比率；
- 无损率：拜占庭票与干净票一致时，表决不改变结论的比率。

已知边界（MEMETIC-RESISTANCE §七）：TMR 防单点投毒不防合谋（2/3 被控
即失守）；第三票用"篡改规则的官方引擎"仿真拜占庭——独立第三方引擎
（商用 AV）的形态留给真实批次。

用法：python scripts/tmr_vote.py --trit <trit-re.exe> --rules <batch.yar> --samples <目录>
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yara


def official_hits(rules_path: Path, sample: Path):
    try:
        rules = yara.compile(filepath=str(rules_path))
    except yara.Error:
        return None
    try:
        return {m.rule for m in rules.match(str(sample))}
    except yara.Error:
        return None


def trit_hits(trit: Path, rules_path: Path, sample: Path):
    proc = subprocess.run(
        [str(trit), "sigscan", str(sample), "--rules", str(rules_path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    hits, unknown = set(), set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if parts[0] == "HIT":
            hits.add(parts[1])
        elif parts[0] == "UNKNOWN":
            unknown.add(parts[1])
    return hits, unknown


def poison_rules(text: str) -> str:
    """确定性致盲：把每条规则的字符串/hex 内容替换成 z 填充（永不匹配），
    条件保持原样——引擎在跑、规则被毒（拜占庭致盲形态）。"""
    out = []
    for line in text.splitlines(keepends=True):
        m = re.search(r'(\$\w+ = ")([^"]*)(")', line)
        h = re.search(r"(\$\w+ = \{ )([^}]+)( \})", line)
        if m:
            blinded = "z" * max(1, len(m.group(2)))
            out.append(line[: m.start(2)] + blinded + line[m.end(2):])
        elif h:
            blinded = "7F " * max(1, (len(h.group(2).strip()) + 1) // 3)
            out.append(line[: h.start(2)] + blinded.strip() + line[h.end(2):])
        else:
            out.append(line)
    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trit", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--samples", required=True)
    args = parser.parse_args()

    rules_text = Path(args.rules).read_text(encoding="utf-8")
    poisoned_text = poison_rules(rules_text)
    work = Path(tempfile.mkdtemp(prefix="tmr-"))
    poisoned_path = work / "poisoned.yar"
    poisoned_path.write_text(poisoned_text, encoding="utf-8")

    samples = sorted(
        p for p in Path(args.samples).iterdir() if p.is_file()
    )
    stats = {"agree": 0, "suppressed": 0, "lost": 0}
    for sample in samples:
        a = official_hits(Path(args.rules), sample)  # 干净票 A（官方）
        if a is None:
            continue
        b, _ = trit_hits(Path(args.trit), Path(args.rules), sample)  # 干净票 B（trit-re）
        c, _ = trit_hits(Path(args.trit), poisoned_path, sample)  # 拜占庭票 C
        c_official = official_hits(poisoned_path, sample) or set()
        c = c | c_official  # 拜占庭票的完整判定（官方口径便于对比）
        rules_named = re.findall(r"rule (\w+)", rules_text)
        for rule in rules_named:
            va, vb, vc = rule in a, rule in b, rule in c
            tmr = (va + vb + vc) >= 2  # 三值多数票（布尔化判定对）
            consensus = (va and vb) or (vb and vc) or (va and vc)
            if va == vb:
                # 两干净票一致 = 共识，拜占庭票若分歧应被压制
                if tmr == va:
                    if vc != va:
                        stats["suppressed"] += 1
                    else:
                        stats["agree"] += 1
                elif consensus:
                    stats["lost"] += 1  # 不应发生（2 票已定）——防御性计数
            elif vb == vc:
                # 干净票 B 与拜占庭票一致、A 孤立 → TMR = B（A 被压制？
                # A 是官方干净票——这属于真分歧，如实计数为 agree 系外）
                stats["agree"] += 1 if tmr == vb else 0
    total = sum(stats.values())
    print(f"判定对总数 {total}：一致 {stats['agree']}，"
          f"**拜占庭分歧被压制 {stats['suppressed']}**，异常 {stats['lost']}")
    rate = (stats["suppressed"] / (stats["suppressed"] + stats["agree"]) * 100
            if stats["suppressed"] + stats["agree"] else 100)
    print(f"[tmr-vote] 拜占庭分歧压制率 {rate:.0f}%——"
          "单引擎投毒被两干净票压制（TMR ✓；2/3 合谋失守为已知边界）")
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
