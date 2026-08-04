@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === FIDO ===
dumpbin /SYMBOLS "D:\GitHub\tdesktop\out\Telegram\Debug\lib_fido2.lib" | findstr /i "cbor_" | findstr /i "External"
echo === QT ===
dumpbin /SYMBOLS "D:\GitHub\Libraries\win64\Qt-6.11.1\lib\Qt6Cored.lib" | findstr /i "cbor_" | findstr /i "External"
