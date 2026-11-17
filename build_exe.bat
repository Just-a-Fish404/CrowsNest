@echo off
REM Builds CrowsNest.exe (GUI) and crowsnest-cli.exe (CLI) into dist\
REM Run from the repo root, inside a clean virtual environment:
REM   python -m venv .venv ^&^& .venv\Scripts\activate ^&^& pip install -r requirements-dev.txt

pyinstaller --onefile --noconsole --name CrowsNest ^
  --add-data "src\crowsnest.png;." ^
  --collect-submodules dns ^
  src\gui.py || exit /b 1

pyinstaller --onefile --name crowsnest-cli ^
  --collect-submodules dns ^
  src\crowsnest_cli.py || exit /b 1

echo.
echo Done. See the dist folder.
