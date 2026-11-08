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
        & docker cp 'cisf-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json' $temporaryFile | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to copy Cowrie JSON events from the persistent volume.'
        }
        return @(Get-JsonLines $temporaryFile)
    }
    finally {
        Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-OpenCanaryEvents {
    $lines = & docker exec cisf-opencanary cat /var/tmp/opencanary.log
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to read OpenCanary JSON events from its persistent volume.'
    }
    $events = @()
    foreach ($line in $lines) {
        if ($line) {
            $events += $line | ConvertFrom-Json
        }
    }
    return $events
}

function Invoke-KaliBashScript {
    param(
        [string]$Container,
        [string]$Script
    )

    $Script = $Script.Replace("`r", '')
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script))
    & docker exec $Container bash -c "printf '%s' '$encoded' | base64 -d | bash"
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
        foreach ($container in @('kali-01', 'kali-02', 'cisf-cowrie', 'cisf-suricata', 'cisf-opencanary')) {
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

        $cowrieId = & docker inspect --format '{{.Id}}' cisf-cowrie
        foreach ($container in @('cisf-cowrie', 'cisf-opencanary')) {
            $publishedPorts = & docker inspect --format '{{json .HostConfig.PortBindings}}' $container
            if ($LASTEXITCODE -ne 0 -or ($publishedPorts -ne 'null' -and $publishedPorts -ne '{}')) {
                throw "$container must not publish host ports: $publishedPorts"
            }
            $networkMode = & docker inspect --format '{{.HostConfig.NetworkMode}}' $container
            if ($container -eq 'cisf-cowrie' -and $networkMode -ne 'cisf-lab-net') {
                throw "Cowrie is not attached directly to cisf-lab-net: $networkMode"
            }
            if ($container -eq 'cisf-opencanary' -and $networkMode -ne "container:$cowrieId") {
                throw "OpenCanary is not sharing Cowrie's network namespace: $networkMode"
            }
        }

        $sensorNetworkMode = & docker inspect --format '{{.HostConfig.NetworkMode}}' cisf-suricata
        if ($LASTEXITCODE -ne 0 -or $sensorNetworkMode -ne "container:$cowrieId") {
            throw "Suricata is not sharing Cowrie's network namespace: $sensorNetworkMode"
        }

        $baselineCowrie = @(Get-CowrieEvents).Count
        $baselineOpenCanary = @(Get-OpenCanaryEvents).Count
        $baselineEve = @(Get-JsonLines $eveFile).Count
        $baselineFast = if (Test-Path -LiteralPath $fastFile) { @(Get-Content -LiteralPath $fastFile).Count } else { 0 }

        $participants = @(
            @{ Name = 'kali-01'; IP = '10.77.0.11' },
            @{ Name = 'kali-02'; IP = '10.77.0.12' }
        )
        foreach ($participant in $participants) {
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

            $ftpScript = @'
exec 3<>/dev/tcp/10.77.0.10/21
IFS= read -r -t 5 -u 3 banner
[[ "$banner" == 220* ]] || exit 1
printf "USER cisf-user\r\n" >&3
IFS= read -r -t 5 -u 3 user_reply
[[ "$user_reply" == 331* ]] || exit 1
printf "PASS incorrect-test-password\r\n" >&3
IFS= read -r -t 5 -u 3 pass_reply
[[ "$pass_reply" == 530* ]]
'@
            Invoke-KaliBashScript $participant.Name $ftpScript
            if ($LASTEXITCODE -ne 0) {
                throw "FTP banner/login test failed from $($participant.Name) ($($participant.IP)) to 10.77.0.10:21."
            }
            Write-Output "PASS FTP banner and rejected login from $($participant.Name) ($($participant.IP)) to 10.77.0.10:21"

            $httpResult = & docker exec $participant.Name curl --fail --location --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}' http://10.77.0.10/
            if ($LASTEXITCODE -ne 0 -or $httpResult -ne '200') {
                throw "HTTP GET failed or returned $httpResult from $($participant.Name) ($($participant.IP)) to 10.77.0.10:80."
            }
            Write-Output "PASS HTTP GET returned HTTP 200 from $($participant.Name) ($($participant.IP)) to 10.77.0.10:80"

            $mysqlScript = @'
exec 3<>/dev/tcp/10.77.0.10/3306
IFS= read -r -t 5 -N 1 -u 3 greeting
[[ -n "$greeting" ]] || exit 1
printf "\x30\x00\x00\x01\x85\xa2\x00\x00\x00\x00\x00\x00\x21" >&3
printf "\0%.0s" {1..23} >&3
printf "cisf-user\0\x05wrong" >&3
read -r -t 5 -N 1 -u 3 response
[[ -n "$response" ]]
'@
            Invoke-KaliBashScript $participant.Name $mysqlScript
            if ($LASTEXITCODE -ne 0) {
                throw "MySQL handshake/authentication test failed from $($participant.Name) ($($participant.IP)) to 10.77.0.10:3306."
            }
            Write-Output "PASS MySQL handshake and authentication attempt from $($participant.Name) ($($participant.IP)) to 10.77.0.10:3306"
        }

        $serviceSpecs = @(
            @{ Port = 2222; SID = 1000002; Signature = 'CISF Cowrie SSH connection'; LogType = $null },
            @{ Port = 2223; SID = 1000003; Signature = 'CISF Cowrie Telnet connection'; LogType = $null },
            @{ Port = 21; SID = 1000004; Signature = 'CISF OpenCanary FTP login'; LogType = 2000 },
            @{ Port = 80; SID = 1000005; Signature = 'CISF OpenCanary HTTP GET'; LogType = 3000 },
            @{ Port = 3306; SID = 1000006; Signature = 'CISF OpenCanary MySQL login'; LogType = 8001 }
        )
        $deadline = (Get-Date).AddSeconds(30)
        do {
            $missingEvents = @()
            $newCowrieEvents = @(Get-CowrieEvents | Select-Object -Skip $baselineCowrie)
            $newCanaryEvents = @(Get-OpenCanaryEvents | Select-Object -Skip $baselineOpenCanary)
            $newEveEvents = @(Get-JsonLines $eveFile $baselineEve)
            $newFastLines = if (Test-Path -LiteralPath $fastFile) {
                @(Get-Content -LiteralPath $fastFile | Select-Object -Skip $baselineFast)
            }
            else {
                @()
            }

            foreach ($participant in $participants) {
                foreach ($spec in $serviceSpecs) {
                    $sourceIP = $participant.IP
                    if ($spec.Port -in @(2222, 2223)) {
                        $protocol = if ($spec.Port -eq 2222) { 'ssh' } else { 'telnet' }
                        $cowrieSession = @($newCowrieEvents | Where-Object {
                            $_.eventid -eq 'cowrie.session.connect' -and $_.protocol -eq $protocol -and $_.src_ip -eq $sourceIP -and $_.dst_port -eq $spec.Port
                        })
                        if ($cowrieSession.Count -eq 0) {
                            $missingEvents += "Cowrie $protocol session from $sourceIP to port $($spec.Port)"
                        }
                    }
                    else {
                        $canaryEvent = @($newCanaryEvents | Where-Object {
                            $_.logtype -eq $spec.LogType -and $_.src_host -eq $sourceIP -and $_.dst_port -eq $spec.Port
                        })
                        if ($canaryEvent.Count -eq 0) {
                            $missingEvents += "OpenCanary logtype $($spec.LogType) from $sourceIP to port $($spec.Port)"
                        }
                    }

                    $alert = @($newEveEvents | Where-Object {
                        $_.event_type -eq 'alert' -and $_.alert.signature_id -eq $spec.SID -and $_.src_ip -eq $sourceIP -and $_.dest_port -eq $spec.Port
                    })
                    $fastAlert = @($newFastLines | Where-Object {
                        $_ -match [regex]::Escape($sourceIP) -and $_ -match [regex]::Escape($spec.Signature) -and $_ -match "-> 10\.77\.0\.10:$($spec.Port)(?:\s|$)"
                    })
                    if ($alert.Count -eq 0) {
                        $missingEvents += "Suricata EVE SID $($spec.SID) from $sourceIP to port $($spec.Port)"
                    }
                    if ($fastAlert.Count -eq 0) {
                        $missingEvents += "Suricata fast.log SID $($spec.SID) from $sourceIP to port $($spec.Port)"
                    }
                }
            }
            $ready = $missingEvents.Count -eq 0
            if ($ready) {
                break
            }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)

        if (-not $ready) {
            throw "Missing verification events: $($missingEvents -join '; ')"
        }

        foreach ($participant in $participants) {
            $mysqlConnect = @($newCanaryEvents | Where-Object {
                $_.logtype -eq 9003 -and $_.src_host -eq $participant.IP -and $_.dst_port -eq 3306
            })
            if ($mysqlConnect.Count -eq 0) {
                throw "OpenCanary did not log MySQL connection event 9003 from $($participant.IP)."
            }
            Write-Output "PASS Cowrie logged SSH/Telnet and OpenCanary logged FTP/HTTP/MySQL from $($participant.IP)"
            Write-Output "PASS Suricata EVE and fast.log recorded all five services from $($participant.IP)"
        }
    }
}
