@echo off
echo [*] Cloning CICFlowMeter repository...
git clone https://github.com/ahlashkari/CICFlowMeter.git
cd CICFlowMeter
echo [*] Building CICFlowMeter...
gradle build
echo [*] Setup complete!
pause