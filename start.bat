@echo off
setlocal EnableExtensions
title 源代码静态审计平台 - 启动器

rem ============================================================
rem  依赖项：只需本机已安装 Python 3.9 或更高版本，无需 pip install 任何包。
rem  迁移：整个 audit-tool 目录可直接拷贝到其他电脑运行（路径全部相对化）。
rem  指定解释器：设置环境变量 AUDIT_PYTHON 为 python.exe 的完整路径。
rem  环境自检：start.bat --check-env  （或双击 checkenv.bat）
rem  问题反馈：wangwangdui214@qq.com
rem ============================================================

set "HERE=%~dp0"
set "MODE="
if /i "%~1"=="--check-env" set "MODE=1"
if /i "%~1"=="check" set "MODE=1"
set "PY="

rem 32 位系统下的 Program Files 路径含右括号，先取出到变量，避免在括号代码块中出错
set "PF86="
if defined ProgramFiles(x86) set "PF86=%ProgramFiles(x86)%"

rem ---------- 一、定位 Python 解释器 ----------
rem 0) 环境变量显式指定（优先级最高）
if defined AUDIT_PYTHON if exist "%AUDIT_PYTHON%" set "PY=%AUDIT_PYTHON%"

rem 1) py 启动器：python.org 安装时默认附带，能自动选中最新 3.x
if not defined PY for /f "delims=" %%P in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do if not defined PY if exist "%%~fP" set "PY=%%~fP"

rem 2) PATH 中的 python（安装时勾选了 Add Python to PATH 的情况）
if not defined PY for %%P in (python.exe) do if not defined PY set "PY=%%~$PATH:P"

rem 3) 常见安装目录，按版本号由高到低依次尝试
for %%V in (314 313 312 311 310 39) do (
  if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe"
  if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python%%V-32\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python%%V-32\python.exe"
  if not defined PY if exist "%ProgramFiles%\Python%%V\python.exe" set "PY=%ProgramFiles%\Python%%V\python.exe"
  if not defined PY if defined PF86 if exist "%PF86%\Python%%V\python.exe" set "PY=%PF86%\Python%%V\python.exe"
  if not defined PY if exist "C:\Python%%V\python.exe" set "PY=C:\Python%%V\python.exe"
)

if not defined PY goto NOPY

rem ---------- 二、校验解释器版本（须 >= 3.9） ----------
"%PY%" -c "import sys;sys.exit(0 if sys.version_info[:2]>=(3,9) else 1)" >nul 2>&1
if errorlevel 1 goto OLD

rem ---------- 三、环境自检模式 ----------
if defined MODE goto CHECKENV

rem ---------- 四、启动审计平台 ----------
echo 解释器：%PY%
echo 正在启动源代码静态审计平台，请稍候…
echo （服务就绪后会自动打开浏览器；关闭本窗口即可停止服务）
echo.

"%PY%" "%HERE%app.py" --root "%HERE%.." --port 8770 --open
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" goto FAILED
echo 服务已退出。
goto END

:CHECKENV
echo 解释器：%PY%
echo.
"%PY%" "%HERE%app.py" --check-env
set "RC=%ERRORLEVEL%"
goto END

:FAILED
echo [提示] 服务未能正常启动（错误码 %RC%）。
echo        若提示端口被占用，请双击 stop.bat 停止旧服务后重试。
echo        也可直接访问 http://127.0.0.1:8770/ 确认服务是否已在运行。
goto END

:OLD
echo [错误] 找到的 Python 版本过低：%PY%
echo        本工具要求 Python 3.9 或更高版本。
echo        下载地址：https://www.python.org/downloads/
set "RC=1"
goto END

:NOPY
echo [错误] 未找到 Python 解释器。
echo        本工具零第三方依赖，但需要本机已安装 Python 3.9 或更高版本。
echo        1) 打开 https://www.python.org/downloads/ 下载安装，
echo           安装时请务必勾选 "Add Python to PATH"。
echo        2) 若已安装仍报此错，可设置环境变量 AUDIT_PYTHON 指向 python.exe，
echo           例如：set AUDIT_PYTHON=D:\Python313\python.exe
echo        3) 完成后重新双击本文件即可；也可运行 start.bat --check-env 查看环境自检。
set "RC=1"

:END
echo.
echo 按任意键关闭本窗口…
pause >nul
exit /b %RC%
