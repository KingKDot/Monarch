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
$reportPath = 'C:\ProgramData\Avast Software\Avast\Report\FileSystemShield.txt'
$debugPath = Join-Path -Path $PSScriptRoot -ChildPath 'avast-debug.log'

function Write-TraceLog([string]$message) {
	try {
		$ts = (Get-Date).ToString('o')
		Add-Content -LiteralPath $debugPath -Value "$ts $message" -Encoding UTF8
	} catch { }
}

function Write-Json($obj, $path) {
	$dir = Split-Path -Parent $path
	if ($dir -and !(Test-Path -LiteralPath $dir)) {
		New-Item -ItemType Directory -Force -Path $dir | Out-Null
	}
	($obj | ConvertTo-Json -Compress) | Set-Content -LiteralPath $path -Encoding UTF8
}

function Normalize-PathForCompare([string]$path) {
	if ([string]::IsNullOrWhiteSpace($path)) { return '' }
	return (($path -replace '/', '\').Trim().Trim('"')).ToLowerInvariant()
}

function Parse-AvastTimestamp([string]$text) {
	$formats = @(
		'M/d/yyyy h:mm:ss tt',
		'M/d/yyyy hh:mm:ss tt',
		'MM/dd/yyyy h:mm:ss tt',
		'MM/dd/yyyy hh:mm:ss tt'
	)
	$cultures = @(
		[System.Globalization.CultureInfo]::InvariantCulture,
		[System.Globalization.CultureInfo]::GetCultureInfo('en-US')
	)
	foreach ($culture in $cultures) {
		foreach ($fmt in $formats) {
			$dt = [datetime]::MinValue
			if ([datetime]::TryParseExact($text, $fmt, $culture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
				return $dt
			}
		}
	}
	return $null
}

function Find-AvastDetection([string]$Path, [string]$InputPath, [datetime]$StartTime) {
	if (!(Test-Path -LiteralPath $Path)) {
		Write-TraceLog "report missing path=$Path"
		return $null
	}

	$inputNorm = Normalize-PathForCompare $InputPath
	$lines = Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction SilentlyContinue
	if (!$lines) {
		Write-TraceLog "report empty path=$Path"
		return $null
	}

	$scanned = 0
	$tsMiss = 0
	$timeMiss = 0
	$formatMiss = 0
	$pathMiss = 0
	$earliestAllowed = $StartTime.AddSeconds(-2)
	Write-TraceLog "scan-begin input=$InputPath input_norm=$inputNorm lines=$($lines.Count) start=$($StartTime.ToString('o')) earliest=$($earliestAllowed.ToString('o'))"

	for ($i = $lines.Count - 1; $i -ge 0; $i--) {
		$line = $lines[$i]
		$scanned++
		if ([string]::IsNullOrWhiteSpace($line)) { continue }

		if ($line -notmatch '^\s*(?<ts>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s(?:AM|PM))\s+(?<rest>.+?)\s*$') {
			$tsMiss++
			continue
		}

		$entryTime = Parse-AvastTimestamp $Matches['ts']
		if ($null -eq $entryTime) { continue }
		if ($entryTime -lt $earliestAllowed) {
			$timeMiss++
			continue
		}

		$rest = $Matches['rest']
		if ($rest -notmatch '^(?<path>[A-Za-z]:\\.+?)\s+\[(?<dtype>[^\]]+)\]\s+(?<threat>.+?)\s*\((?<code>-?\d+)\)\s*$') {
			$formatMiss++
			continue
		}

		$loggedPath = $Matches['path']
		$loggedNorm = Normalize-PathForCompare $loggedPath
		if ($loggedNorm -ne $inputNorm) {
			$pathMiss++
			continue
		}

		$followUp = $null
		if (($i + 1) -lt $lines.Count) {
			$nextLine = $lines[$i + 1]
			if ($nextLine -and ($nextLine -notmatch '^\s*\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s(?:AM|PM)\s+')) {
				$followUp = $nextLine.Trim()
			}
		}
		Write-TraceLog "hit ts=$($Matches['ts']) path=$loggedPath dtype=$($Matches['dtype']) threat=$($Matches['threat']) code=$($Matches['code']) follow_up=$followUp scanned=$scanned"

		return [ordered]@{
			line = $line
			follow_up = $followUp
			timestamp = $entryTime
			logged_path = $loggedPath
			detection_type = $Matches['dtype']
			threat_name = $Matches['threat']
			result_code = $Matches['code']
		}
	}

	Write-TraceLog "scan-miss input=$InputPath scanned=$scanned ts_miss=$tsMiss time_miss=$timeMiss format_miss=$formatMiss path_miss=$pathMiss"

	return $null
}

$result = [ordered]@{
	schema_version = 1
	av = 'Avast'
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
		debug_log_path = $debugPath
		report_path = $reportPath
		report_found = $false
		result_code = $null
	}
}

$scanStart = Get-Date
Write-TraceLog "start input=$InputFile output=$OutputFile sha256=$SHA256 wait_seconds=$WaitSeconds from_stdin=$FromStdin"

try {
	$outDir = Split-Path -Parent $OutputFile
	if ($outDir -and !(Test-Path -LiteralPath $outDir)) {
		New-Item -ItemType Directory -Force -Path $outDir | Out-Null
	}
} catch {
	$result.error = $_.ToString()
	Write-TraceLog "output-dir error=$($result.error)"
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
	$result.details.report_found = (Test-Path -LiteralPath $reportPath)
	Write-TraceLog "input-ready exists=$((Test-Path -LiteralPath $InputFile)) report_found=$($result.details.report_found)"
} catch {
	$result.error = $_.ToString()
	Write-TraceLog "input/setup error=$($result.error)"
}

$hit = $null
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
	$hit = Find-AvastDetection -Path $reportPath -InputPath $InputFile -StartTime $scanStart
	if ($hit) { break }
	Start-Sleep -Milliseconds 200
}

$exists = Test-Path -LiteralPath $InputFile
$detected = $false
$eventMessage = $null
$threatName = $null

if ($hit) {
	$detected = $true
	$eventMessage = $hit.line
	if ($hit.follow_up) {
		$eventMessage = "$($hit.line)`n$($hit.follow_up)"
	}
	$threatName = $hit.threat_name
	$result.detection_name = $hit.threat_name
	$result.detection_type = $hit.detection_type
	$result.details.result_code = $hit.result_code
	$result.result = 'detected'
	Write-TraceLog "result detected exists=$exists threat=$threatName code=$($hit.result_code)"
} elseif ($result.error) {
	$result.result = 'error'
	Write-TraceLog "result error=$($result.error)"
} else {
	$result.result = 'clean'
	Write-TraceLog "result clean exists=$exists"
}

$result.finished_at = (Get-Date).ToUniversalTime().ToString('o')

$out = [ordered]@{
	file_exists = $exists
	deleted = (-not $exists -or $detected)
	event_detected = $detected
	event_message = $eventMessage
	threat_name = $threatName
	script_out_path = $OutputFile
	script_json = $result
}

$json = $out | ConvertTo-Json -Compress
Write-Json $out $OutputFile
Write-TraceLog "write-json output=$OutputFile"
$json
