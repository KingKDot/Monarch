param(
	[Parameter(Mandatory=$true)]
	[string]$InputFile,
	[Parameter(Mandatory=$true)]
	[string]$OutputFile
)

$ErrorActionPreference = 'Stop'

function Write-Json($obj, $path) {
	$dir = Split-Path -Parent $path
	if ($dir -and !(Test-Path -LiteralPath $dir)) {
		New-Item -ItemType Directory -Force -Path $dir | Out-Null
	}
	($obj | ConvertTo-Json -Compress) | Set-Content -LiteralPath $path -Encoding UTF8
}

$outDir = Split-Path -Parent $OutputFile
try {
	if ($outDir -and !(Test-Path -LiteralPath $outDir)) {
		New-Item -ItemType Directory -Force -Path $outDir | Out-Null
	}
	# Marker file you can watch on the VM to confirm the script ran.
	"started $(Get-Date -Format o) input=$InputFile" | Set-Content -LiteralPath (Join-Path $outDir 'monarch_started.txt') -Encoding UTF8
	# Best-effort popup to interactive sessions (often won't display from WinRM/session0).
	cmd.exe /c "msg * Monarch scan started" | Out-Null
} catch { }

$result = [ordered]@{
	av = 'Defender'
	input_file = $InputFile
	output_file = $OutputFile
	started_at = (Get-Date).ToUniversalTime().ToString('o')
	mpcmdrun_path = $null
	mpcmdrun_exit = $null
	startmpscan_used = $false
	error = $null
}

try {
	if (!(Test-Path -LiteralPath $InputFile)) {
		throw "InputFile does not exist: $InputFile"
	}

	$mpCmdRunCandidates = @(
		"$env:ProgramFiles\Windows Defender\MpCmdRun.exe",
		"$env:ProgramFiles\Windows Defender Advanced Threat Protection\MpCmdRun.exe",
		"$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
	)
	$mp = $null
	foreach ($c in $mpCmdRunCandidates) {
		$found = Get-Item -LiteralPath $c -ErrorAction SilentlyContinue
		if ($found) { $mp = $found.FullName; break }
		$glob = Get-Item -Path $c -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($glob) { $mp = $glob.FullName; break }
	}

	if ($mp) {
		$result.mpcmdrun_path = $mp
		& $mp -Scan -ScanType 3 -File $InputFile | Out-Null
		$result.mpcmdrun_exit = $LASTEXITCODE
	} else {
		# Fallback: Start-MpScan (less deterministic per-file, but works for basic testing)
		Start-MpScan -ScanType CustomScan -ScanPath (Split-Path -Parent $InputFile) | Out-Null
		$result.startmpscan_used = $true
	}
} catch {
	$result.error = $_.ToString()
}

$result.finished_at = (Get-Date).ToUniversalTime().ToString('o')
Write-Json $result $OutputFile
