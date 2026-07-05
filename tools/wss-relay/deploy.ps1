#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { '/opt/wss-relay' }
$RemoteSrc = "$InstallDir/src"
$SshOpts = @()
if ($env:SSH_OPTS) {
	$SshOpts = $env:SSH_OPTS -split '\s+' | Where-Object { $_ }
}

function Show-Usage {
	@'
Usage: .\deploy.ps1 [options] user@host
       deploy.cmd [options] user@host

Deploy wss-relay to a remote Linux host over SSH.
Sources are synced to /opt/wss-relay/src and built on the server.

Options:
  --check-only   Verify local/remote prerequisites, do not deploy
  --listen ADDR  Relay listen address (default: 127.0.0.1:8283)
  -h, --help     Show this help

Environment:
  INSTALL_DIR    Remote install root (default: /opt/wss-relay)
  SSH_OPTS       Extra ssh options (space-separated)
  FORCE_SERVICE_INSTALL  Set to 1 to overwrite an existing systemd unit

Examples:
  .\deploy.ps1 root@31.76.21.175
  .\deploy.ps1 --check-only root@31.76.21.175
  $env:LISTEN_ADDR = '127.0.0.1:8283'; .\deploy.ps1 root@example.com
'@ | Write-Host
}

function Write-Log {
	param([string]$Message)
	Write-Host $Message
}

function Stop-Deploy {
	param([string]$Message)
	Write-Error $Message
	exit 1
}

function Get-DeployArgs {
	param([object[]]$InputArgs)

	$checkOnly = $false
	$listen = if ($env:LISTEN_ADDR) { $env:LISTEN_ADDR } else { '127.0.0.1:8283' }
	$deployHost = $null
	$i = 0
	while ($i -lt $InputArgs.Count) {
		switch ($InputArgs[$i]) {
			'--check-only' { $checkOnly = $true }
			'--listen' {
				$i++
				if ($i -ge $InputArgs.Count) { Stop-Deploy '--listen requires an address' }
				$listen = [string]$InputArgs[$i]
			}
			'-h' { Show-Usage; exit 0 }
			'--help' { Show-Usage; exit 0 }
			{ $_ -like '-*' } { Stop-Deploy "unknown option: $($InputArgs[$i])" }
			default {
				if ($deployHost) { Stop-Deploy "unexpected argument: $($InputArgs[$i])" }
				$deployHost = [string]$InputArgs[$i]
			}
		}
		$i++
	}
	if (-not $deployHost) { Stop-Deploy 'missing user@host (see: .\deploy.ps1 --help)' }
	return @{
		CheckOnly = $checkOnly
		Listen = $listen
		DeployHost = $deployHost
	}
}

function Test-LocalPrerequisites {
	Write-Log 'Checking local prerequisites...'
	if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
		Stop-Deploy 'missing command: ssh (install OpenSSH Client: Settings → Apps → Optional features)'
	}
	if (-not (Get-Command scp -ErrorAction SilentlyContinue)) {
		Stop-Deploy 'missing command: scp (install OpenSSH Client)'
	}
	if (Get-Command rsync -ErrorAction SilentlyContinue) {
		$syncMode = 'rsync'
	}
	elseif (Get-Command tar -ErrorAction SilentlyContinue) {
		$syncMode = 'tar'
	}
	else {
		Stop-Deploy 'need rsync or tar+scp for file sync (tar is included in Windows 10+)'
	}
	Write-Log "Local prerequisites OK (sync via $syncMode)"
	return $syncMode
}

function Invoke-Remote {
	param(
		[string]$DeployHost,
		[string]$Command
	)
	$sshArgs = @()
	if ($SshOpts.Count -gt 0) { $sshArgs += $SshOpts }
	$sshArgs += $DeployHost
	$sshArgs += $Command
	& ssh @sshArgs
	if ($LASTEXITCODE -ne 0) { Stop-Deploy "ssh failed (exit $LASTEXITCODE)" }
}

function Sync-Sources {
	param(
		[string]$DeployHost,
		[string]$SyncMode
	)

	Write-Log "Syncing sources to ${DeployHost}:${RemoteSrc}..."
	Invoke-Remote -DeployHost $DeployHost -Command "mkdir -p '$RemoteSrc'"

	if ($SyncMode -eq 'rsync') {
		$sshCommand = 'ssh'
		if ($SshOpts.Count -gt 0) { $sshCommand += ' ' + ($SshOpts -join ' ') }
		& rsync -az --delete `
			-e $sshCommand `
			--exclude '.git/' `
			--exclude '*.exe' `
			--exclude 'deploy.sh' `
			--exclude 'deploy.ps1' `
			--exclude 'deploy.cmd' `
			"$ScriptDir/" "${DeployHost}:${RemoteSrc}/"
		if ($LASTEXITCODE -ne 0) { Stop-Deploy "rsync failed (exit $LASTEXITCODE)" }
	}
	else {
		$archive = Join-Path $env:TEMP ("wss-relay-src-{0}.tar.gz" -f (Get-Date -Format 'yyyyMMddHHmmss'))
		try {
			Push-Location $ScriptDir
			& tar -czf $archive `
				--exclude='.git' `
				--exclude='*.exe' `
				--exclude='deploy.sh' `
				--exclude='deploy.ps1' `
				--exclude='deploy.cmd' `
				.
			if ($LASTEXITCODE -ne 0) { Stop-Deploy "tar failed (exit $LASTEXITCODE)" }

			$scpArgs = @()
			if ($SshOpts.Count -gt 0) { $scpArgs += $SshOpts }
			$scpArgs += @($archive, "${DeployHost}:/tmp/wss-relay-src.tar.gz")
			& scp @scpArgs
			if ($LASTEXITCODE -ne 0) { Stop-Deploy "scp failed (exit $LASTEXITCODE)" }

			Invoke-Remote -DeployHost $DeployHost -Command @"
tar -xzf /tmp/wss-relay-src.tar.gz -C '$RemoteSrc' && rm -f /tmp/wss-relay-src.tar.gz
"@
		}
		finally {
			Pop-Location
			if (Test-Path $archive) { Remove-Item -Force $archive }
		}
	}
	Write-Log 'Sources synced'
	Invoke-Remote -DeployHost $DeployHost -Command "find '$RemoteSrc' -name '*.sh' -exec sed -i 's/\r$//' {} +"
}

function Invoke-RemoteBuild {
	param(
		[string]$DeployHost,
		[string]$Listen,
		[string]$Mode
	)
	$forceService = if ($env:FORCE_SERVICE_INSTALL) { $env:FORCE_SERVICE_INSTALL } else { '0' }
	$command = "INSTALL_DIR='$InstallDir' LISTEN_ADDR='$Listen' FORCE_SERVICE_INSTALL='$forceService' bash '$RemoteSrc/remote-build.sh' '$Mode'"
	Invoke-Remote -DeployHost $DeployHost -Command $command
}

$parsed = Get-DeployArgs -InputArgs $args
$syncMode = Test-LocalPrerequisites

Write-Log "Target: $($parsed.DeployHost)"
Write-Log "Install dir: $InstallDir"

Sync-Sources -DeployHost $parsed.DeployHost -SyncMode $syncMode

if ($parsed.CheckOnly) {
	Invoke-RemoteBuild -DeployHost $parsed.DeployHost -Listen $parsed.Listen -Mode 'check'
	Write-Log 'Remote prerequisites OK'
	exit 0
}

Invoke-RemoteBuild -DeployHost $parsed.DeployHost -Listen $parsed.Listen -Mode 'deploy'
Write-Log "Done. Stats: ssh -L 8283:$($parsed.Listen) $($parsed.DeployHost)  then open http://127.0.0.1:8283/stats"
