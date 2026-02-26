# Configure TrustedHosts and Connect to VM with Hardcoded Credentials
# Target IP: 10.0.0.94
# Run this in Windows PowerShell (not PowerShell Core/7)
# WARNING: Storing passwords in plain text is insecure. Use only for testing.

$targetIP = "10.0.0.94"
$username = "Avast"  # Change this to your username
$password = "Avast"  # Change this to your password

Write-Host "Configuring WinRM TrustedHosts for $targetIP..." -ForegroundColor Cyan
Write-Host ""

# Check current TrustedHosts
Write-Host "Current TrustedHosts configuration:" -ForegroundColor Yellow
$currentTrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts
Write-Host $currentTrustedHosts.Value -ForegroundColor Gray
Write-Host ""

# Add the target IP to TrustedHosts
Write-Host "Adding $targetIP to TrustedHosts..." -ForegroundColor Yellow
try {
    $currentValue = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
    
    if ($currentValue -eq "" -or $currentValue -eq $null) {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $targetIP -Force
        Write-Host "SUCCESS: Added $targetIP to TrustedHosts" -ForegroundColor Green
    }
    elseif ($currentValue -like "*$targetIP*") {
        Write-Host "INFO: $targetIP is already in TrustedHosts" -ForegroundColor Yellow
    }
    else {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$currentValue,$targetIP" -Force
        Write-Host "SUCCESS: Added $targetIP to TrustedHosts" -ForegroundColor Green
    }
}
catch {
    Write-Host "FAILED: Could not update TrustedHosts" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Make sure you're running PowerShell as Administrator!" -ForegroundColor Yellow
    exit
}
Write-Host ""

# Show updated TrustedHosts
Write-Host "Updated TrustedHosts configuration:" -ForegroundColor Yellow
$newTrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts
Write-Host $newTrustedHosts.Value -ForegroundColor Gray
Write-Host ""

# Create credential object using Add-Type approach
Write-Host "Creating credentials..." -ForegroundColor Yellow
try {
    # Use reflection to create SecureString
    $securePassword = New-Object System.Security.SecureString
    $password.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }
    $securePassword.MakeReadOnly()
    
    $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
    Write-Host "SUCCESS: Credentials created for user: $username" -ForegroundColor Green
}
catch {
    Write-Host "FAILED: Could not create credentials" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit
}
Write-Host ""

# Now try to connect
Write-Host "Attempting to connect to $targetIP as $username..." -ForegroundColor Cyan
Write-Host ""

try {
    $session = New-PSSession -ComputerName $targetIP -Credential $credential -ErrorAction Stop
    Write-Host "SUCCESS: Remote session established!" -ForegroundColor Green
    Write-Host ""
    
    # Get some basic info
    Write-Host "Remote System Information:" -ForegroundColor Cyan
    $osInfo = Invoke-Command -Session $session -ScriptBlock {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        
        [PSCustomObject]@{
            ComputerName = $cs.Name
            OS = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        }
    }
    
    Write-Host "Computer Name: $($osInfo.ComputerName)" -ForegroundColor Gray
    Write-Host "OS: $($osInfo.OS)" -ForegroundColor Gray
    Write-Host "Version: $($osInfo.Version) (Build $($osInfo.BuildNumber))" -ForegroundColor Gray
    Write-Host "Total Memory: $($osInfo.TotalMemoryGB) GB" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Session is ready!" -ForegroundColor Yellow
    Write-Host "Session stored in `$global:RemoteSession variable" -ForegroundColor Green
    Write-Host ""
    Write-Host "Example commands:" -ForegroundColor Yellow
    Write-Host "  Invoke-Command -Session `$global:RemoteSession -ScriptBlock { Get-Process }" -ForegroundColor Gray
    Write-Host "  Invoke-Command -Session `$global:RemoteSession -ScriptBlock { hostname }" -ForegroundColor Gray
    Write-Host "  Remove-PSSession -Session `$global:RemoteSession  # To close the session" -ForegroundColor Gray
    
    # Keep session open - store in global variable
    $global:RemoteSession = $session
}
catch {
    Write-Host "FAILED: Could not establish remote session" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Verify the username format - try: .\Avast or COMPUTERNAME\Avast" -ForegroundColor Gray
    Write-Host "2. Make sure the password is correct" -ForegroundColor Gray
    Write-Host "3. Ensure the user has admin rights on the remote machine" -ForegroundColor Gray
    Write-Host "4. Check if WinRM is enabled on the remote machine (run: winrm quickconfig)" -ForegroundColor Gray
}