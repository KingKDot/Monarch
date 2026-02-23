param(
	[Parameter(Mandatory=$true)]
	[string]$InputFile,
	[Parameter(Mandatory=$true)]
	[string]$OutputFile,
	[Parameter(Mandatory=$true)]
	[string]$SHA256,
	[int]$WaitSeconds = 15,
	[switch]$FromStdin
)

$ErrorActionPreference = 'Stop'

function Write-Json($obj, $path) {
	$dir = Split-Path -Parent $path
	if ($dir -and !(Test-Path -LiteralPath $dir)) {
		New-Item -ItemType Directory -Force -Path $dir | Out-Null
	}
	($obj | ConvertTo-Json -Compress) | Set-Content -LiteralPath $path -Encoding UTF8
}

function Append-Log($path, $message) {
	try {
		$ts = (Get-Date).ToString('o')
		Add-Content -LiteralPath $path -Encoding UTF8 -Value "$ts $message"
	} catch { }
}

$outDir = Split-Path -Parent $OutputFile
try {
	if ($outDir -and !(Test-Path -LiteralPath $outDir)) {
		New-Item -ItemType Directory -Force -Path $outDir | Out-Null
	}
	$logPath = Join-Path $outDir 'monarch_scan.log'
	# Marker file you can watch on the VM to confirm the script ran.
	"started $(Get-Date -Format o) input=$InputFile" | Set-Content -LiteralPath (Join-Path $outDir 'monarch_started.txt') -Encoding UTF8
	# Best-effort popup to interactive sessions (often won't display from WinRM/session0).
	cmd.exe /c "msg * Monarch scan started" | Out-Null
} catch { }

$result = [ordered]@{
	schema_version = 1
	av = 'Defender'
	result = 'unknown'
	detection_name = $null
	detection_type = $null
	engine_version = $null
	started_at = (Get-Date).ToUniversalTime().ToString('o')
	finished_at = $null
	error = $null
	details = [ordered]@{
		input_file = $InputFile
		output_file = $OutputFile
		mpcmdrun_path = $null
		mpcmdrun_exit = $null
		startmpscan_used = $false
	}
}

try {
	if (!(Test-Path -LiteralPath $InputFile)) {
		if ($FromStdin) {
			$stdin = [Console]::OpenStandardInput()
			$ms = New-Object System.IO.MemoryStream
			$buf = New-Object byte[] 65536
			while (($n = $stdin.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
			[IO.File]::WriteAllBytes($InputFile, $ms.ToArray())
		} else {
			throw "InputFile does not exist: $InputFile"
		}
	}
	Append-Log $logPath "Skipping command-line scan; relying on Defender real-time protection."
} catch {
	$result.error = $_.ToString()
	Append-Log $logPath "Unhandled error: $($result.error)"
}

$scanStart = (Get-Date)
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
	if (-not (Test-Path -LiteralPath $InputFile)) { break }
	$ev = $null
	try {
		$ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=@(1116,1117); StartTime=$scanStart} -ErrorAction Stop |
			Where-Object { $_.Message -match $SHA256 } | Select-Object -First 1
	} catch { }
	if ($ev) { break }
	Start-Sleep -Milliseconds 200
}

$exists = Test-Path -LiteralPath $InputFile
$evDet = $false
$evMsg = $null
try {
	$evObj = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=@(1116,1117); StartTime=$scanStart} -ErrorAction Stop |
		Where-Object { $_.Message -match $SHA256 } | Select-Object -First 1
	if ($evObj) { $evDet = $true; $evMsg = $evObj.Message }
} catch { }

$threat = $null
if ($evMsg) {
	if ($evMsg -match 'Threat Name\s*:\s*(.+)') { $threat = $Matches[1].Trim() }
	elseif ($evMsg -match '(?m)^\s*Name\s*:\s*(.+)$') { $threat = $Matches[1].Trim() }
}

$result.finished_at = (Get-Date).ToUniversalTime().ToString('o')
if ($result.error) { $result.result = 'error' }
$out = [ordered]@{
	file_exists = $exists
	deleted = (-not $exists -or $evDet)
	event_detected = $evDet
	event_message = $evMsg
	threat_name = $threat
	script_out_path = $OutputFile
	script_json = $result
}
$json = $out | ConvertTo-Json -Compress
$json | Set-Content -LiteralPath $OutputFile -Encoding UTF8
$json
