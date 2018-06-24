@if "%vcinstalldir%"=="" call "c:\program files (x86)\microsoft visual studio 14.0\vc\bin\x86_amd64\vcvarsx86_amd64.bat"

@setlocal
@set wireshark_source_dir=..\wireshark-2.6.0
@set wireshark_build_dir=..\wireshark-2.6.0-build64
@set wireshark_run_dir=%wireshark_build_dir%\run\RelWithDebInfo
@set gtk2_dir=..\wireshark-win64-libs-2.6\gtk2

cl.exe /nologo /O2 /I%wireshark_source_dir% /I%wireshark_build_dir% /I%gtk2_dir%\include\glib-2.0 /I%gtk2_dir%\lib\glib-2.0\include /LD gbcs.c %wireshark_run_dir%\wireshark.lib

copy gbcs.dll %wireshark_run_dir%\plugins\2.6\epan\gbcs.dll
