#!/usr/bin/env python3
"""git 依赖互换开关：本地路径联调 / 装回远端钉法，全程可逆、离线可验。

用法：
  python scripts/pin.py status                       # 现在钉在哪个 commit、是否在用本地 patch
  python scripts/pin.py link --to <单体仓路径>        # 用本地工作树覆盖 git 依赖（离线联调）
  python scripts/pin.py unlink                       # 还原 Cargo.toml + Cargo.lock（按字节）
  python scripts/pin.py bump [--precise <sha>]       # 沿分支刷新锁（需要网络）
  python scripts/pin.py --self-test

口径：
  - `link` 只在 Cargo.toml 末尾追加带标记的 `[patch."<url>"]` 段，并先按字节备份
    Cargo.toml / Cargo.lock 到 `.trit/pin-backup/`；
  - `unlink` 优先按备份还原（逐字节），保证 lock 回到原样；
  - 两个方向都用 `cargo metadata --offline` 验：link 后允许 lock 变，unlink 后要求 `--locked`。
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEP = "trit-core"
GIT_URL = "https://github.com/bfxh/trit"
BACKUP_DIR = pathlib.Path(".trit") / "pin-backup"
START = "# >>> trit-pin link（scripts/pin.py 管理；unlink 会删掉这一段）"
END = "# <<< trit-pin"


def block_for(target: pathlib.Path) -> str:
    dep_path = (target / "crates" / DEP).as_posix()
    return (
        f"{START}\n"
        f'[patch."{GIT_URL}"]\n'
        f'{DEP} = {{ path = "{dep_path}" }}\n'
        f"{END}\n"
    )


def splice(text: str, block: str) -> str:
    if START in text and END in text:
        head, _, rest = text.partition(START)
        _, _, tail = rest.partition(END)
        return head + block + tail.lstrip("\n")
    if text and not text.endswith("\n"):
        text += "\n"
    return text + ("\n" if text else "") + block


def strip_block(text: str) -> str:
    if START not in text or END not in text:
        return text
    head, _, rest = text.partition(START)
    _, _, tail = rest.partition(END)
    if head.endswith("\n\n"):
        head = head[:-1]
    return head + tail.lstrip("\n")


def cargo(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["cargo", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def pinned_commit(lock_text: str) -> str:
    match = re.search(rf'name = "{re.escape(DEP)}"\nversion = "[^"]+"\nsource = "git\+[^#]+#([0-9a-f]+)"', lock_text)
    return match.group(1) if match else ""


def backup() -> None:
    target = ROOT / BACKUP_DIR
    target.mkdir(parents=True, exist_ok=True)
    for name in ("Cargo.toml", "Cargo.lock"):
        source = ROOT / name
        saved = target / name
        if source.exists() and not saved.exists():
            saved.write_bytes(source.read_bytes())


def restore_backup() -> bool:
    target = ROOT / BACKUP_DIR
    if not (target / "Cargo.toml").exists():
        return False
    for name in ("Cargo.toml", "Cargo.lock"):
        saved = target / name
        if saved.exists():
            (ROOT / name).write_bytes(saved.read_bytes())
            saved.unlink()
    return True


def link(target: pathlib.Path) -> int:
    target = target.resolve()
    # 包含校验：目标必须落在当前工作区内——CLI 路径参数不逃逸出本仓
    # （路径形状的闸门：逃逸路径在污点引擎眼里就是穿越入口）。
    if not target.is_relative_to(pathlib.Path.cwd().resolve()):
        print(f"拒绝：--to 必须落在当前工作区内（防路径逃逸）：{target}")
        return 2
    if not (target / "crates" / DEP / "Cargo.toml").is_file():
        print(f"目标里找不到 crates/{DEP}/Cargo.toml：{target}")
        return 2
    backup()
    manifest = ROOT / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8")
    manifest.write_text(splice(text, block_for(target)), encoding="utf-8", newline="")
    print(f"已用本地路径覆盖 {DEP}：{target}")
    return verify(locked=False)


def unlink() -> int:
    if not restore_backup():
        manifest = ROOT / "Cargo.toml"
        if not manifest.exists():
            print("没有 Cargo.toml")
            return 2
        stripped = strip_block(manifest.read_text(encoding="utf-8"))
        manifest.write_text(stripped, encoding="utf-8", newline="")
        print("已移除 pin 段（没有备份，lock 未动）")
    else:
        print("已按备份还原 Cargo.toml + Cargo.lock")
    return verify(locked=True)


def verify(locked: bool) -> int:
    args = ["metadata", "--offline", "--format-version", "1"]
    if locked:
        args.insert(1, "--locked")
    result = cargo(args)
    if result.returncode != 0:
        print("verify 失败（cargo metadata）：")
        print(result.stdout[-2000:])
        return 1
    print("verify 通过：cargo metadata 可解析")
    return 0


def status() -> int:
    lock = ROOT / "Cargo.lock"
    manifest = ROOT / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8") if manifest.exists() else ""
    commit = pinned_commit(lock.read_text(encoding="utf-8")) if lock.exists() else ""
    linked = START in text and END in text
    print(f"git 依赖 {DEP} = {GIT_URL}（分支 main）")
    print(f"锁定的 commit：{commit or '（Cargo.lock 里没有 git 源）'}")
    print(f"本地路径覆盖：{'在用' if linked else '未用'}")
    return 0


def bump(precise: str) -> int:
    args = ["update", "-p", DEP]
    if precise:
        args += ["--precise", precise]
    result = cargo(args)
    if result.returncode != 0:
        print("bump 失败：")
        print(result.stdout[-2000:])
        return 1
    print(result.stdout.strip()[-500:])
    return verify(locked=True)


def self_test() -> int:
    failures: list[str] = []
    total = [0]

    def check(name: str, actual, expected) -> None:
        total[0] += 1
        if actual != expected:
            failures.append(name)
            print(f"FAIL {name}：期望 {expected!r}，实际 {actual!r}")

    original = '[package]\nname = "demo"\n'
    target = pathlib.Path("/repo") / "trit"
    linked = splice(original, block_for(target))
    check("link 保留原清单", linked.startswith(original), True)
    check("link 带 patch 标记", START in linked and END in linked, True)
    check("link 指向本地 crates/trit-core", 'path = "/repo/trit/crates/trit-core"' in linked, True)
    check("重复 link 不重复插段", splice(linked, block_for(target)).count(START), 1)
    check("unlink 逐字节还原", strip_block(linked), original)
    check("没有标记段时 strip 不动", strip_block(original), original)

    lock = (
        '[[package]]\nname = "trit-core"\nversion = "0.12.0"\n'
        f'source = "git+{GIT_URL}?branch=main#bfc6f80106a4"\n'
    )
    check("解析锁定 commit", pinned_commit(lock), "bfc6f80106a4")
    check("非 git 源解析为空", pinned_commit('name = "x"\nversion = "1"\nsource = "registry+x"\n'), "")

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "Cargo.toml").write_bytes(b'[package]\nname = "demo"\n')
        (root / "Cargo.lock").write_bytes(b'version = 4\n')
        global ROOT, BACKUP_DIR
        saved = (ROOT, BACKUP_DIR)
        ROOT, BACKUP_DIR = root, pathlib.Path(".trit") / "pin-backup"
        try:
            backup()
            (root / "Cargo.toml").write_bytes(b"# changed\n")
            check("备份只做一次（原件不覆盖）", (root / BACKUP_DIR / "Cargo.toml").read_bytes(), b'[package]\nname = "demo"\n')
            check("按备份还原成功", restore_backup(), True)
            check("清单逐字节还原", (root / "Cargo.toml").read_bytes(), b'[package]\nname = "demo"\n')
            check("lock 逐字节还原", (root / "Cargo.lock").read_bytes(), b"version = 4\n")
            check("还原后备份被清掉", (root / BACKUP_DIR / "Cargo.toml").exists(), False)
        finally:
            ROOT, BACKUP_DIR = saved

    if failures:
        print(f"self-test: {total[0] - len(failures)}/{total[0]} passed")
        return 1
    print(f"self-test: {total[0]}/{total[0]} passed")
    return 0


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if "--self-test" in argv:
        return self_test()
    command = argv[0] if argv else "status"
    if command == "status":
        return status()
    if command == "link":
        if "--to" not in argv:
            print("用法：pin.py link --to <单体仓路径>")
            return 2
        return link(pathlib.Path(argv[argv.index("--to") + 1]).resolve())
    if command == "unlink":
        return unlink()
    if command == "bump":
        precise = argv[argv.index("--precise") + 1] if "--precise" in argv else ""
        return bump(precise)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
