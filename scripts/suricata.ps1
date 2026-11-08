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

function Get-JsonEvents {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $events = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line) {
            $events += $line | ConvertFrom-Json
        }
    }
    return $events
}

switch ($Action) {
        'up' {
            Invoke-Compose @('up', '--detach')
            Invoke-Compose @('ps')
        }
        'down' {
            Invoke-Compose @('down')
        }
        'status' {
            Invoke-Compose @('ps')
            docker network inspect cisf-lab-net --format 'Network={{.Name}} Internal={{.Internal}} Subnet={{(index .IPAM.Config 0).Subnet}}'
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to inspect cisf-lab-net.'
            }
        }
        'test' {
            foreach ($container in @('kali-01', 'kali-02', 'cisf-lab-target', 'cisf-suricata')) {
                $running = & docker inspect --format '{{.State.Running}}' $container
                if ($LASTEXITCODE -ne 0 -or $running -ne 'true') {
                    throw "$container must be running. Start the lab with .\scripts\lab.ps1 up and .\scripts\suricata.ps1 up."
                }
            }

            $network = & docker network inspect cisf-lab-net --format '{{.Internal}}|{{(index .IPAM.Config 0).Subnet}}'
            if ($LASTEXITCODE -ne 0 -or $network -ne 'true|10.77.0.0/24') {
                throw "Unexpected cisf-lab-net configuration: $network"
            }

            $targetInspection = & docker inspect cisf-lab-target
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to inspect cisf-lab-target.'
            }
            $target = (($targetInspection -join [Environment]::NewLine) | ConvertFrom-Json).NetworkSettings.Networks.PSObject.Properties['cisf-lab-net'].Value.IPAddress
            if ($target -ne '10.77.0.10') {
                throw "Expected target at 10.77.0.10; found $target."
            }

            $suricata = & docker inspect cisf-suricata --format '{{.HostConfig.NetworkMode}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}'
            if ($LASTEXITCODE -ne 0 -or
                $suricata -notmatch '^container:' -or
                $suricata -notmatch '"ALL"' -or
                $suricata -notmatch '"CAP_NET_RAW"' -or
                $suricata -notmatch '\|402653184\|500000000$') {
                throw "Suricata is not using the expected shared target namespace and restricted privileges: $suricata"
            }

            $baselineEve = @(Get-JsonEvents $eveFile).Count
            $baselineFast = if (Test-Path -LiteralPath $fastFile) { @(Get-Content -LiteralPath $fastFile).Count } else { 0 }
            $markers = @{}

            foreach ($participant in @(
                @{ Name = 'kali-01'; IP = '10.77.0.11' },
                @{ Name = 'kali-02'; IP = '10.77.0.12' }
            )) {
                $marker = '?cisf-suricata-test-{0}-{1}' -f $participant.Name, [guid]::NewGuid().ToString('N')
                $markers[$participant.Name] = $marker
                $url = "http://10.77.0.10:8080/$marker"
                $statusCode = & docker exec $participant.Name curl --silent --show-error --output /dev/null --write-out '%{http_code}' $url
                if ($LASTEXITCODE -ne 0 -or $statusCode -ne '200') {
                    throw "$($participant.Name) HTTP request to the temporary target failed: $statusCode"
                }
                Write-Output "PASS $($participant.Name) ($($participant.IP)) HTTP GET $url returned $statusCode"
            }

            $deadline = (Get-Date).AddSeconds(20)
            $newEvents = @()
            $newFastLines = @()
            $expectedIPs = @('10.77.0.11', '10.77.0.12')
            do {
                $allEvents = @(Get-JsonEvents $eveFile)
                $newEvents = @($allEvents | Select-Object -Skip $baselineEve)
                $allFastLines = if (Test-Path -LiteralPath $fastFile) { @(Get-Content -LiteralPath $fastFile) } else { @() }
                $newFastLines = @($allFastLines | Select-Object -Skip $baselineFast)

                $httpEvents = @($newEvents | Where-Object { $_.event_type -eq 'http' })
                $alertEvents = @($newEvents | Where-Object {
                    $_.event_type -eq 'alert' -and $_.alert.signature_id -eq 1000001
                })
                $capturedIPs = @($httpEvents | ForEach-Object { $_.src_ip } | Sort-Object -Unique)
                $alertIPs = @($alertEvents | ForEach-Object { $_.src_ip } | Sort-Object -Unique)
                if (@($expectedIPs | Where-Object { $_ -notin $capturedIPs }).Count -eq 0 -and
                    @($expectedIPs | Where-Object { $_ -notin $alertIPs }).Count -eq 0) {
                    break
                }
                Start-Sleep -Milliseconds 500
            } while ((Get-Date) -lt $deadline)

            foreach ($participant in @(
                @{ Name = 'kali-01'; IP = '10.77.0.11' },
                @{ Name = 'kali-02'; IP = '10.77.0.12' }
            )) {
                $httpMatch = @($httpEvents | Where-Object {
                    $_.src_ip -eq $participant.IP -and $_.http.url -like "*$($markers[$participant.Name])*"
                })
                if ($httpMatch.Count -eq 0) {
                    throw "eve.json did not record the test HTTP request from $($participant.IP)."
                }
                $alertMatch = @($alertEvents | Where-Object { $_.src_ip -eq $participant.IP })
                if ($alertMatch.Count -eq 0) {
                    throw "No SID 1000001 alert was recorded for $($participant.IP)."
                }
                if (@($newFastLines | Where-Object { $_ -match [regex]::Escape($participant.IP) -and $_ -match 'CISF lab HTTP test request' }).Count -eq 0) {
                    throw "fast.log did not record the test alert for $($participant.IP)."
                }
                Write-Output "PASS eve.json HTTP event and SID 1000001 alert preserve source IP $($participant.IP)"
                Write-Output "PASS fast.log contains the test alert for $($participant.IP)"
            }

            Write-Output "PASS persistent logs: $eveFile and $fastFile"
        }
}
