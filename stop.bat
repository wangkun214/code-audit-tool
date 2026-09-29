@echo off
setlocal
title 源代码静态审计平台 - 停止服务

set "PORT=8770"
set "N=0"

echo 正在查找监听端口 %PORT% 的服务进程…
echo.

for /f "tokens=5" %%a in ('netstat -ano ^| findstr /c:"LISTENING" ^| findstr /c:":%PORT%"') do (
  echo   正在停止 PID %%a …
  taskkill /f /pid %%a >nul 2>&1
  if not errorlevel 1 set /a N+=1
)

echo.
if %N% gtr 0 goto DONE
echo 未发现监听端口 %PORT% 的服务，无需停止。
goto END

:DONE
echo 已停止 %N% 个服务进程，端口 %PORT% 已释放。

:END
echo.
echo 按任意键关闭本窗口…
pause >nul
