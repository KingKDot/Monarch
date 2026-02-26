# Test WinRM Connectivity to Windows 11 VM
# Target IP: 10.0.0.94

$targetIP = "10.0.0.94"

Write-Host "Testing WinRM connectivity to $targetIP..." -ForegroundColor Cyan
Write-Host ""

# Test 1: Basic network connectivity
Write-Host "[1/4] Testing network connectivity (ping)..." -ForegroundColor Yellow
$pingResult = Test-Connection -ComputerName $targetIP -Count 2 -Quiet
if ($pingResult) {
    Write-Host "SUCCESS: Ping successful" -ForegroundColor Green
}
else {
    Write-Host "FAILED: Ping failed" -ForegroundColor Red
}
Write-Host ""

# Test 2: Check if WinRM HTTP port is open
Write-Host "[2/4] Testing WinRM HTTP port (5985)..." -ForegroundColor Yellow
$tcpTest = Test-NetConnection -ComputerName $targetIP -Port 5985 -WarningAction SilentlyContinue
if ($tcpTest.TcpTestSucceeded) {
    Write-Host "SUCCESS: Port 5985 is open" -ForegroundColor Green
}
else {
    Write-Host "FAILED: Port 5985 is closed" -ForegroundColor Red
}
Write-Host ""

# Test 3: Check if WinRM HTTPS port is open
Write-Host "[3/4] Testing WinRM HTTPS port (5986)..." -ForegroundColor Yellow
$tcpTest2 = Test-NetConnection -ComputerName $targetIP -Port 5986 -WarningAction SilentlyContinue
if ($tcpTest2.TcpTestSucceeded) {
    Write-Host "SUCCESS: Port 5986 is open" -ForegroundColor Green
}
else {
    Write-Host "FAILED: Port 5986 is closed" -ForegroundColor Red
}
Write-Host ""

# Test 4: Test WinRM using Test-WSMan
Write-Host "[4/4] Testing WinRM service (Test-WSMan)..." -ForegroundColor Yellow
try {
    $wsmanTest = Test-WSMan -ComputerName $targetIP -ErrorAction Stop
    Write-Host "SUCCESS: WinRM service is responding" -ForegroundColor Green
    Write-Host "Product Version: $($wsmanTest.ProductVersion)" -ForegroundColor Gray
    Write-Host "Protocol Version: $($wsmanTest.ProtocolVersion)" -ForegroundColor Gray
}
catch {
    Write-Host "FAILED: WinRM test failed" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "Testing complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "If you want to test a remote session, run:" -ForegroundColor Yellow
Write-Host "Enter-PSSession -ComputerName $targetIP -Credential (Get-Credential)" -ForegroundColor Gray