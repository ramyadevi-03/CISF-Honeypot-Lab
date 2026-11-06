param(
    [ValidateSet('up', 'down', 'build', 'status', 'test')]
    [string]$Action = 'up',

    [ValidateRange(2, 244)]
    [int]$Count = 2
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $root 'compose.yaml'
$runtimeFile = Join-Path ([System.IO.Path]::GetTempPath()) "cisf-kali-$PID.json"
$participants = [ordered]@{}

for ($index = 1; $index -le $Count; $index++) {
    $name = 'kali-{0:D2}' -f $index
    $participants[$name] = @{
        extends = @{
            file = $composeFile
            service = 'kali-template'
        }
        container_name = $name
        profiles = @('participants')
        networks = @{
            'cisf-lab-net' = @{
                ipv4_address = "10.77.0.$(10 + $index)"
            }
        }
    }
}

$override = @{ services = $participants }
$override | ConvertTo-Json -Depth 20 | Set-Content -Path $runtimeFile -Encoding utf8

function Invoke-Compose {
    param([string[]]$Arguments)

    & docker compose --file $composeFile --file $runtimeFile @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Invoke-Docker {
    param([string[]]$Arguments)

    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Get-ContainerDetails {
    param([string]$Name)

    $inspection = & docker inspect $Name
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect $Name."
    }
    $container = ($inspection -join [Environment]::NewLine) | ConvertFrom-Json
    $network = $container.NetworkSettings.Networks.PSObject.Properties['cisf-lab-net'].Value
    return [pscustomobject]@{
        Running = $container.State.Running
        IPAddress = $network.IPAddress
        Memory = $container.HostConfig.Memory
        NanoCpus = $container.HostConfig.NanoCpus
        PidsLimit = $container.HostConfig.PidsLimit
        CapDrop = $container.HostConfig.CapDrop -join ','
        CapAdd = $container.HostConfig.CapAdd -join ','
        SecurityOpt = $container.HostConfig.SecurityOpt -join ','
        User = $container.Config.User
    }
}

try {
    switch ($Action) {
        'build' {
            Invoke-Compose @('--profile', 'template', 'build', 'kali-template')
        }
        'up' {
            Invoke-Compose @('--profile', 'template', 'build', 'kali-template')
            Invoke-Compose @('--profile', 'participants', 'up', '--detach', '--remove-orphans')
            Invoke-Compose @('ps')
        }
        'down' {
            Invoke-Compose @('down', '--remove-orphans')
        }
        'status' {
            Invoke-Compose @('ps')
            foreach ($name in $participants.Keys) {
                $details = Get-ContainerDetails $name
                Write-Output "$name running=$($details.Running) ip=$($details.IPAddress)"
            }
        }
        'test' {
            $network = & docker network inspect --format '{{.Internal}}|{{(index .IPAM.Config 0).Subnet}}' cisf-lab-net
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to inspect cisf-lab-net. Start the lab first.'
            }
            $networkDetails = $network -split '\|'
            if ($networkDetails[0] -ne 'true' -or $networkDetails[1] -ne '10.77.0.0/24') {
                throw "Unexpected network configuration: $network"
            }
            Write-Output "PASS network internal=$($networkDetails[0]) subnet=$($networkDetails[1])"

            foreach ($name in $participants.Keys) {
                $details = Get-ContainerDetails $name
                $expectedIp = "10.77.0.$(10 + [int]$name.Substring(5))"
                if (-not $details.Running -or $details.IPAddress -ne $expectedIp) {
                    throw "$name is not running with expected IP $expectedIp."
                }
                if ($details.Memory -ne 536870912 -or
                    $details.NanoCpus -ne 1000000000 -or
                    $details.PidsLimit -ne 128) {
                    throw "$name does not have the expected 512 MiB / 1 CPU / 128 process limits."
                }
                if ($details.CapDrop -ne 'ALL' -or
                    $details.CapAdd -or
                    $details.SecurityOpt -notmatch 'no-new-privileges:true' -or
                    $details.User -ne 'kali') {
                    throw "$name does not have the expected container security restrictions."
                }

                $tools = 'set -e; for tool in nmap ssh curl ping ip ifconfig dig traceroute; do command -v "$tool" >/dev/null; done; nmap --version >/dev/null; ssh -V >/dev/null 2>&1; curl --version >/dev/null; id'
                Invoke-Docker @('exec', $name, 'sh', '-lc', $tools)
                Write-Output "PASS $name running at $expectedIp with tools and resource/security limits"
            }

            $egressContainer = $participants.Keys | Select-Object -First 1
            $egressStatus = & docker exec $egressContainer sh -lc 'curl --connect-timeout 2 --max-time 3 --noproxy "*" --silent --output /dev/null --write-out "%{http_code}" http://1.1.1.1 || true'
            if ($LASTEXITCODE -ne 0) {
                throw 'Unable to run the external egress check.'
            }
            if ($egressStatus -ne '000') {
                throw "External network access is available (HTTP status $egressStatus)."
            }
            Write-Output 'PASS outbound internet access is blocked'

            for ($index = 1; $index -le $Count; $index++) {
                $nextIndex = ($index % $Count) + 1
                $source = 'kali-{0:D2}' -f $index
                $target = 'kali-{0:D2}' -f $nextIndex
                Invoke-Docker @('exec', $source, 'ping', '-c', '2', '-W', '2', $target)
                Write-Output "PASS $source can reach $target"
            }
        }
    }
}
finally {
    Remove-Item -LiteralPath $runtimeFile -Force -ErrorAction SilentlyContinue
}
