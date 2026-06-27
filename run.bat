@echo off
REM ================================================================
REM  DevSecAgent - Arm A baseline demo (Windows)
REM  Sets up the environment and runs the Arm A baseline on one
REM  sample: scan a vulnerable project, generate a fix, verify it
REM  on four checks, route on confidence, and deploy with rollback.
REM  Double-click this file, or run it from a terminal.
REM ================================================================
setlocal
cd /d "%~dp0"

echo.
echo ================================================================
echo    DevSecAgent  -  Arm A baseline demo
echo ================================================================
echo.

REM --- 1. Python on PATH? ---
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python was not found. Install Python 3.11+ from python.org,
  echo         tick "Add Python to PATH", then run this file again.
  echo.
  pause
  exit /b 1
)

REM --- 2. virtual environment + install ---
if not exist ".venv\Scripts\python.exe" (
  echo [setup] creating the virtual environment ...
  python -m venv .venv
)
set "PY=.venv\Scripts\python.exe"
echo [setup] installing the package, the first run takes a minute ...
"%PY%" -m pip install -q --upgrade pip
"%PY%" -m pip install -q -e .

REM --- 3. Azure key present? ---
if not exist ".env" (
  echo.
  echo [ERROR] No .env file found. Set up your Azure key first:
  echo            copy .env.example .env
  echo         then open .env and fill in AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY
  echo.
  pause
  exit /b 1
)

echo.
REM --- 4. run the best demo the machine can support ---
where trivy >nul 2>nul && docker info >nul 2>nul && goto FULL

echo [info] Trivy and a running Docker were not both found, so this runs the
echo        Azure-only Arm A demo over the sample CVEs. Install Trivy and start
echo        Docker Desktop to see the full scan-and-deploy run.
echo.
echo ---------------------------------------------------------------
echo    Arm A baseline: generate, verify on four checks, route on confidence
echo ---------------------------------------------------------------
echo.
"%PY%" run_baseline.py
goto DONE

:FULL
echo [info] Running the full Arm A pipeline on one sample package.
echo.
echo ---------------------------------------------------------------
echo    scan with Trivy and Snyk, then Arm A: generate the fix,
echo    verify it on four checks, and install-test it in a container
echo ---------------------------------------------------------------
echo.
"%PY%" remediate.py samples\vuln_python 1

:DONE
echo.
echo ================================================================
echo    Demo finished.
echo ================================================================
echo.
pause
endlocal
