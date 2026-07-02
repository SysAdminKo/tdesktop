#!/usr/bin/env python3
"""
Bump or set TelegramWSS version across all source files.

Updates:
  - Telegram/SourceFiles/core/version.h
  - Telegram/build/version
  - Telegram/Resources/winrc/Telegram.rc
  - Telegram/Resources/winrc/Updater.rc

Usage:
    python bump_version.py --bump
    python bump_version.py --set 6.9.301
    python bump_version.py --set 6009301
"""
import argparse
import os
import re
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, '..', '..'))

VERSION_H_PATH = os.path.join(
    REPO_ROOT, 'Telegram', 'SourceFiles', 'core', 'version.h')
BUILD_VERSION_PATH = os.path.join(
    REPO_ROOT, 'Telegram', 'build', 'version')
TELEGRAM_RC_PATH = os.path.join(
    REPO_ROOT, 'Telegram', 'Resources', 'winrc', 'Telegram.rc')
UPDATER_RC_PATH = os.path.join(
    REPO_ROOT, 'Telegram', 'Resources', 'winrc', 'Updater.rc')


def parse_version_components(version):
    major = version // 1000000
    minor = (version // 1000) % 1000
    patch = version % 1000
    return major, minor, patch


def pack_version(major, minor, patch):
    return major * 1000000 + minor * 1000 + patch


def format_version_str(major, minor, patch):
    return f"{major}.{minor}.{patch}"


def parse_version_input(value):
    text = str(value).strip()

    if re.fullmatch(r'\d+', text):
        version = int(text)
        if version < 1000:
            print(f"ERROR: numeric version too small: {version}", file=sys.stderr)
            sys.exit(1)
        major, minor, patch = parse_version_components(version)
        return version, format_version_str(major, minor, patch)

    match = re.fullmatch(
        r'(\d+)\.(\d+)\.(\d+)',
        text,
    )
    if not match:
        print(
            "ERROR: version must be MMMmmmppp (e.g. 6009301) "
            "or semver (e.g. 6.9.301)",
            file=sys.stderr,
        )
        sys.exit(1)

    major, minor, patch = (int(match.group(i)) for i in range(1, 4))
    for label, part in [('major', major), ('minor', minor), ('patch', patch)]:
        if part < 0 or part >= 1000:
            print(f"ERROR: bad {label} part: {part}", file=sys.stderr)
            sys.exit(1)

    version = pack_version(major, minor, patch)
    return version, format_version_str(major, minor, patch)


def read_current_version():
    with open(VERSION_H_PATH, 'r', encoding='utf-8') as f:
        text = f.read()

    match = re.search(r'constexpr auto AppVersion\s*=\s*(\d+);', text)
    if not match:
        print("ERROR: cannot parse AppVersion from version.h", file=sys.stderr)
        sys.exit(1)
    version = int(match.group(1))

    match = re.search(r'constexpr auto AppVersionStr\s*=\s*"([^"]+)";', text)
    ver_str = match.group(1) if match else ''
    return version, ver_str


def bump_patch(version):
    major, minor, patch = parse_version_components(version)
    patch += 1
    if patch >= 1000:
        patch = 0
        minor += 1
        if minor >= 1000:
            minor = 0
            major += 1
    new_version = pack_version(major, minor, patch)
    return new_version, format_version_str(major, minor, patch)


def replace_in_file(path, replacements):
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    found = {pattern: False for pattern, _ in replacements}
    updated = False
    new_lines = []

    for line in lines:
        for pattern, repl in replacements:
            if re.search(pattern, line):
                found[pattern] = True
                changed = re.sub(pattern, repl, line)
                if changed != line:
                    line = changed
                    updated = True
        new_lines.append(line)

    for pattern, _ in replacements:
        if not found[pattern]:
            print(f'ERROR: pattern not found in {path}: {pattern}', file=sys.stderr)
            sys.exit(1)

    if updated:
        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.writelines(new_lines)

    return updated


def write_version_h(version, ver_str):
    updated = replace_in_file(VERSION_H_PATH, [
        (r'(constexpr auto AppVersion\s*=\s*)\d+(;)', rf'\g<1>{version}\g<2>'),
        (r'(constexpr auto AppVersionStr\s*=\s*)"[^"]*"(;)',
         rf'\g<1>"{ver_str}"\g<2>'),
    ])
    if updated:
        print(f"  version.h: AppVersion = {version}, AppVersionStr = \"{ver_str}\"")


def write_build_version(version, ver_str):
    major, minor, _ = parse_version_components(version)
    major_minor = f"{major}.{minor}"

    lines = []
    with open(BUILD_VERSION_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('AppVersion '):
                lines.append(f"AppVersion         {version}\n")
            elif line.startswith('AppVersionStrMajor'):
                lines.append(f"AppVersionStrMajor {major_minor}\n")
            elif line.startswith('AppVersionStrSmall'):
                lines.append(f"AppVersionStrSmall {ver_str}\n")
            elif line.startswith('AppVersionStr '):
                lines.append(f"AppVersionStr      {ver_str}\n")
            elif line.startswith('AppVersionOriginal'):
                lines.append(f"AppVersionOriginal {ver_str}\n")
            else:
                lines.append(line)

    with open(BUILD_VERSION_PATH, 'w', encoding='utf-8', newline='') as f:
        f.writelines(lines)

    print(f"  build/version: AppVersion = {version}, str = \"{ver_str}\"")


def write_winrc(path, major, minor, patch):
    withcomma = f"{major},{minor},{patch},0"
    withdot = f"{major}.{minor}.{patch}.0"
    label = os.path.basename(path)

    updated = replace_in_file(path, [
        (r'(FILEVERSION\s+)\d+,\d+,\d+,\d+', rf'\g<1>{withcomma}'),
        (r'(PRODUCTVERSION\s+)\d+,\d+,\d+,\d+', rf'\g<1>{withcomma}'),
        (r'("FileVersion",\s+)"[^"]+"', rf'\g<1>"{withdot}"'),
        (r'("ProductVersion",\s+)"[^"]+"', rf'\g<1>"{withdot}"'),
    ])
    if updated:
        print(f"  {label}: {withdot}")


def apply_version(version, ver_str=None):
    if ver_str is None:
        major, minor, patch = parse_version_components(version)
        ver_str = format_version_str(major, minor, patch)

    major, minor, patch = parse_version_components(version)

    print(f"=== Setting version {version} (\"{ver_str}\") ===")
    write_version_h(version, ver_str)
    write_build_version(version, ver_str)
    write_winrc(TELEGRAM_RC_PATH, major, minor, patch)
    write_winrc(UPDATER_RC_PATH, major, minor, patch)
    return version, ver_str


def bump():
    current_version, current_ver_str = read_current_version()
    new_version, new_ver_str = bump_patch(current_version)
    print(f"=== Bumping version ===")
    print(f"  {current_version} (\"{current_ver_str}\") -> "
          f"{new_version} (\"{new_ver_str}\")")
    apply_version(new_version, new_ver_str)
    return new_version, new_ver_str


def main():
    parser = argparse.ArgumentParser(
        description='Bump or set TelegramWSS version in source files')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--bump', action='store_true',
                       help='Increment patch version')
    group.add_argument('--set', metavar='VERSION',
                       help='Set version: 6.9.301 or 6009301')
    args = parser.parse_args()

    if args.bump:
        version, ver_str = bump()
    else:
        version, ver_str = parse_version_input(args.set)
        current_version, current_ver_str = read_current_version()
        if version != current_version or ver_str != current_ver_str:
            print(f"  {current_version} (\"{current_ver_str}\") -> "
                  f"{version} (\"{ver_str}\")")
        apply_version(version, ver_str)

    print(f"\nDone: {version} (\"{ver_str}\")")


if __name__ == '__main__':
    main()
