cd /d "C:\Users\kelvinchan\Downloads\DdiMon-master-nested-2016-10-08\DdiMon-master\DdiMon" &msbuild "DdiMon.vcxproj" /t:sdvViewer /p:configuration="Debug" /p:platform=x64
exit %errorlevel% 