param(
    [ValidateSet('up', 'down', 'status', 'test')]
    [string]$Action = 'up'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $root 'compose.suricata.yaml'
$eveFile = Join-Path $root 'suricata\logs\eve.json'
$fastFile = Join-Path $root 'suricata\logs\fast.log'

function Invoke-Compose {
    param([string[]]$Arguments)

    & docker compose --project-name cisf-suricata --file $composeFile @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Get-JsonLines {
    param(
        [string]$Path,
        [int]$Skip = 0
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $events = @()
    foreach ($line in (Get-Content -LiteralPath $Path | Select-Object -Skip $Skip)) {
        if ($line) {
            $events += $line | ConvertFrom-Json
        }
    }
    return $events
}

function Get-CowrieEvents {
    $temporaryFile = Join-Path ([System.IO.Path]::GetTempPath()) "cisf-cowrie-$PID-$([guid]::NewGuid().ToString('N')).json"
    try {
        & docker cp 'cisf-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json' $temporaryFile
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to copy Cowrie JSON events from the persistent volume.'
        }
        return @(Get-JsonLines $temporaryFile)
    }
    finally {
        Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
    }
}

switch ($Action) {
    'up' {
        Invoke-Compose @('up', '--detach', '--remove-orphans')
        Invoke-Compose @('ps')
    }
    'down' {
        Invoke-Compose @('down', '--remove-orphans')
    }
    'status' {
        Invoke-Compose @('ps')
        & docker network inspect cisf-lab-net --format 'Network={{.Name}} Internal={{.Internal}} Subnet={{(index .IPAM.Config 0).Subnet}}'
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to inspect cisf-lab-net.'
        }
    }
    'test' {
        foreach ($container in @('kali-01', 'kali-02', 'cisf-cowrie', 'cisf-suricata')) {
            $running = & docker inspect --format '{{.State.Running}}' $container
            if ($LASTEXITCODE -ne 0 -or $running -ne 'true') {
                throw "$container must be running. Start the Kali lab and .\scripts\suricata.ps1 up."
            }
        }

        $network = & docker network inspect cisf-lab-net --format '{{.Internal}}|{{(index .IPAM.Config 0).Subnet}}'
        if ($LASTEXITCODE -ne 0 -or $network -ne 'true|10.77.0.0/24') {
            throw "Unexpected cisf-lab-net configuration: $network"
        }

        foreach ($participant in @(
            @{ Name = 'kali-01'; IP = '10.77.0.11' },
            @{ Name = 'kali-02'; IP = '10.77.0.12' },
            @{ Name = 'cisf-cowrie'; IP = '10.77.0.10' }
        )) {
            $ip = & docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $participant.Name
            if ($LASTEXITCODE -ne 0 -or $ip -ne $participant.IP) {
                throw "$($participant.Name) IP mismatch: expected $($participant.IP), found $ip."
            }
        }

        $telnetEnabled = & docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' cisf-cowrie
        if ($LASTEXITCODE -ne 0 -or $telnetEnabled -notcontains 'COWRIE_TELNET_ENABLED=yes') {
            throw 'Cowrie Telnet is not explicitly enabled.'
        }

        $publishedPorts = & docker inspect --format '{{json .HostConfig.PortBindings}}' cisf-cowrie
        if ($LASTEXITCODE -ne 0 -or ($publishedPorts -ne 'null' -and $publishedPorts -ne '{}')) {
            throw "Cowrie must not publish host ports: $publishedPorts"
        }

        $cowrieId = & docker inspect --format '{{.Id}}' cisf-cowrie
        $sensorNetworkMode = & docker inspect --format '{{.HostConfig.NetworkMode}}' cisf-suricata
        if ($LASTEXITCODE -ne 0 -or $sensorNetworkMode -ne "container:$cowrieId") {
            throw "Suricata is not sharing Cowrie's network namespace: $sensorNetworkMode"
        }

        $baselineCowrie = @(Get-CowrieEvents).Count
        $baselineEve = @(Get-JsonLines $eveFile).Count
        $baselineFast = if (Test-Path -LiteralPath $fastFile) { @(Get-Content -LiteralPath $fastFile).Count } else { 0 }

        foreach ($participant in @(
            @{ Name = 'kali-01'; IP = '10.77.0.11' },
            @{ Name = 'kali-02'; IP = '10.77.0.12' }
        )) {
            $sshKeys = & docker exec $participant.Name ssh-keyscan -T 5 -p 2222 10.77.0.10 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $sshKeys) {
                throw "SSH handshake failed from $($participant.Name) ($($participant.IP)) to 10.77.0.10:2222."
            }
            Write-Output "PASS SSH handshake from $($participant.Name) ($($participant.IP)) to 10.77.0.10:2222"

            & docker exec $participant.Name bash -c 'exec 3<>/dev/tcp/10.77.0.10/2223; read -r -t 5 -N 1 -u 3 negotiation; [[ -n "$negotiation" ]]'
            if ($LASTEXITCODE -ne 0) {
                throw "Telnet protocol test failed from $($participant.Name) ($($participant.IP)) to 10.77.0.10:2223."
            }
            Write-Output "PASS Telnet negotiation from $($participant.Name) ($($participant.IP)) to 10.77.0.10:2223"
        }

        $deadline = (Get-Date).AddSeconds(20)
        $newCowrieEvents = @()
        $newEveEvents = @()
        $newFastLines = @()
        do {
            $newCowrieEvents = @(Get-CowrieEvents | Select-Object -Skip $baselineCowrie)
            $newEveEvents = @(Get-JsonLines $eveFile $baselineEve)
            $newFastLines = if (Test-Path -LiteralPath $fastFile) {
                @(Get-Content -LiteralPath $fastFile | Select-Object -Skip $baselineFast)
            }
            else {
                @()
            }

            $ready = $true
            foreach ($ip in @('10.77.0.11', '10.77.0.12')) {
                $sshSessions = @($newCowrieEvents | Where-Object {
                    $_.eventid -eq 'cowrie.session.connect' -and $_.protocol -eq 'ssh' -and $_.src_ip -eq $ip -and $_.dst_port -eq 2222
                })
                $telnetSessions = @($newCowrieEvents | Where-Object {
                    $_.eventid -eq 'cowrie.session.connect' -and $_.protocol -eq 'telnet' -and $_.src_ip -eq $ip -and $_.dst_port -eq 2223
                })
                $sshAlert = @($newEveEvents | Where-Object {
                    $_.event_type -eq 'alert' -and $_.alert.signature_id -eq 1000002 -and $_.src_ip -eq $ip -and $_.dest_port -eq 2222
                })
                $telnetAlert = @($newEveEvents | Where-Object {
                    $_.event_type -eq 'alert' -and $_.alert.signature_id -eq 1000003 -and $_.src_ip -eq $ip -and $_.dest_port -eq 2223
                })
                $sshFast = @($newFastLines | Where-Object { $_ -match [regex]::Escape($ip) -and $_ -match 'CISF Cowrie SSH connection' -and $_ -match '-> 10\.77\.0\.10:2222' })
                $telnetFast = @($newFastLines | Where-Object { $_ -match [regex]::Escape($ip) -and $_ -match 'CISF Cowrie Telnet connection' -and $_ -match '-> 10\.77\.0\.10:2223' })
                if ($sshSessions.Count -eq 0 -or $telnetSessions.Count -eq 0 -or $sshAlert.Count -eq 0 -or $telnetAlert.Count -eq 0 -or $sshFast.Count -eq 0 -or $telnetFast.Count -eq 0) {
                    $ready = $false
                    break
                }
            }
            if ($ready) {
                break
            }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)

        foreach ($ip in @('10.77.0.11', '10.77.0.12')) {
            $sshSessions = @($newCowrieEvents | Where-Object {
                $_.eventid -eq 'cowrie.session.connect' -and $_.protocol -eq 'ssh' -and $_.src_ip -eq $ip -and $_.dst_port -eq 2222
            })
            $telnetSessions = @($newCowrieEvents | Where-Object {
                $_.eventid -eq 'cowrie.session.connect' -and $_.protocol -eq 'telnet' -and $_.src_ip -eq $ip -and $_.dst_port -eq 2223
            })
            $sshAlert = @($newEveEvents | Where-Object {
                $_.event_type -eq 'alert' -and $_.alert.signature_id -eq 1000002 -and $_.src_ip -eq $ip -and $_.dest_port -eq 2222
            })
            $telnetAlert = @($newEveEvents | Where-Object {
                $_.event_type -eq 'alert' -and $_.alert.signature_id -eq 1000003 -and $_.src_ip -eq $ip -and $_.dest_port -eq 2223
            })
            $sshFast = @($newFastLines | Where-Object { $_ -match [regex]::Escape($ip) -and $_ -match 'CISF Cowrie SSH connection' -and $_ -match '-> 10\.77\.0\.10:2222' })
            $telnetFast = @($newFastLines | Where-Object { $_ -match [regex]::Escape($ip) -and $_ -match 'CISF Cowrie Telnet connection' -and $_ -match '-> 10\.77\.0\.10:2223' })
            if ($sshSessions.Count -eq 0 -or $telnetSessions.Count -eq 0) {
                throw "Cowrie did not log both SSH and Telnet test sessions from $ip."
            }
            if ($sshAlert.Count -eq 0 -or $telnetAlert.Count -eq 0) {
                throw "Suricata EVE did not record SSH and Telnet traffic from $ip."
            }
            if ($sshFast.Count -eq 0 -or $telnetFast.Count -eq 0) {
                throw "Suricata fast.log did not record SSH and Telnet traffic from $ip."
            }
            Write-Output "PASS Cowrie logged SSH and Telnet sessions from $ip"
            Write-Output "PASS Suricata EVE and fast.log recorded SSH and Telnet from $ip"
        }
    }
}
