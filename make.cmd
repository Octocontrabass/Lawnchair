gcc -m32 -mwindows -municode -nostartfiles -Wl,-e_WinMainCRTStartup@0 -Wall -std=c99 -s -Os -o lawnchair.exe lawnchair.c
