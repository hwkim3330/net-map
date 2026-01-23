@echo off
REM Net-Map Build Script for Windows
REM Requires: CMake, Ninja, MinGW-w64, Npcap SDK

setlocal

REM Check for running instance
tasklist /FI "IMAGENAME eq net-map.exe" 2>NUL | find /I /N "net-map.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo Stopping running net-map.exe...
    taskkill /F /IM net-map.exe >NUL 2>&1
    timeout /t 1 >NUL
)

REM Create build directory if not exists
if not exist build mkdir build

REM Configure with CMake if needed
if not exist build\build.ninja (
    echo Configuring with CMake...
    cmake -B build -G Ninja
    if errorlevel 1 (
        echo CMake configuration failed!
        exit /b 1
    )
)

REM Build
echo Building...
cmake --build build
if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo.
echo Build successful!
echo Output: build\bin\net-map.exe
echo.
echo Run with: build\bin\net-map.exe -l
