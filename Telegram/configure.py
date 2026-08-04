'''
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
'''
import sys, os, re, subprocess

sys.dont_write_bytecode = True
scriptPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(scriptPath + '/../cmake')
import run_cmake
sys.path.append(scriptPath + '/build')
import qt_version

executePath = os.getcwd()
def finish(code):
    global executePath
    os.chdir(executePath)
    sys.exit(code)

def error(message):
    print('[ERROR] ' + message)
    finish(1)

def ensureCmakeWinQt6OpensslTls():
    if sys.platform != 'win32':
        return
    repoRoot = os.path.normpath(os.path.join(scriptPath, '..'))
    cmakeLists = os.path.join(
        repoRoot, 'cmake', 'external', 'qt', 'CMakeLists.txt')
    patchFile = os.path.join(
        repoRoot, 'patches', 'cmake-qt6-win-openssl-tls.patch')
    if not os.path.isfile(cmakeLists) or not os.path.isfile(patchFile):
        return
    with open(cmakeLists, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()
    if 'qschannelbackend' not in text:
        return
    result = subprocess.run(
        ['git', 'apply', '--directory=cmake', patchFile],
        cwd=repoRoot,
        capture_output=True,
        text=True)
    if result.returncode != 0:
        error(
            'Failed to apply patches/cmake-qt6-win-openssl-tls.patch:\n'
            + (result.stderr or result.stdout or ''))
    print('Applied patches/cmake-qt6-win-openssl-tls.patch')

if sys.platform == 'win32' and 'COMSPEC' not in os.environ:
    error('COMSPEC environment variable is not set.')

scriptName = os.path.basename(scriptPath)

arguments = sys.argv[1:]

officialTarget = ''
officialTargetFile = scriptPath + '/build/target'
if os.path.isfile(officialTargetFile):
    with open(officialTargetFile, 'r') as f:
        for line in f:
            officialTarget = line.strip()

arch = ''
if officialTarget in ['win', 'uwp']:
    arch = 'x86'
elif officialTarget in ['win64', 'uwp64']:
    arch = 'x64'
elif officialTarget in ['winarm', 'uwparm']:
    arch = 'arm'
if not qt_version.resolve(arch):
    error('Unsupported platform.')

if 'qt6' in arguments:
    arguments.remove('qt6')

if officialTarget != '':
    officialApiIdFile = scriptPath + '/../../DesktopPrivate/custom_api_id.h'
    if not os.path.isfile(officialApiIdFile):
        error('DesktopPrivate/custom_api_id.h not found.')
    with open(officialApiIdFile, 'r') as f:
        for line in f:
            apiIdMatch = re.search(r'ApiId\s+=\s+(\d+)', line)
            apiHashMatch = re.search(r'ApiHash\s+=\s+"([a-fA-F\d]+)"', line)
            if apiIdMatch:
                arguments.append('-DTDESKTOP_API_ID=' + apiIdMatch.group(1))
            elif apiHashMatch:
                arguments.append('-DTDESKTOP_API_HASH=' + apiHashMatch.group(1))
    if arch != '':
        arguments.append(arch)

ensureCmakeWinQt6OpensslTls()
finish(run_cmake.run(scriptName, arguments))
