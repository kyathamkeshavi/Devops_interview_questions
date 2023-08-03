#-------------------------------------------------------------------------------------
# <copyright file="AzureServiceDeployClient.ps1" company="Microsoft">
#     Copyright (c) Microsoft Corporation.  All rights reserved.
# </copyright>
#
# <Summary>
#     AzureServiceDeploy Powershell command console startup script.
# </Summary>
#-------------------------------------------------------------------------------------
param(
    [bool]$fromShortcut,
    [bool]$skipScriptUpdate
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ev2NugetSource = "https://msazure.pkgs.visualstudio.com/_packaging/ExpressV2/nuget/v3/index.json"

$startupScriptPkgName = "Microsoft.Azure.AzureServiceDeployClientStartup"
$sdkPackageName = "Microsoft.Azure.AzureServiceDeployClient"

function CheckScriptUpdate
{
    try
    {
        $scriptPackagePath = Join-Path $azureServiceDeployClientPath "AzureServiceDeployClientStartup"
        $startupPkgVersionFile = Join-Path $azureServiceDeployClientPath "AzureServiceDeployClientStartup_version.txt"
        $found = $false

        EnsureDependencyPresence

        # Query latest version and check with the current version of the startup script.
        $latestPkgVer = GetLatestPackageVersion $startupScriptPkgName $ev2NugetSource

        if (Test-Path $startupPkgVersionFile)
        {
            $installedVersion = Get-Content $startupPkgVersionFile
            $found = $installedVersion -eq $latestPkgVer
        }

        if (!$found)
        {
            Write-Host "Latest startup script not found. Downloading latest startup package $startupScriptPkgName."
            DownloadStartupScriptPackage $scriptPackagePath $latestPkgVer

            $scriptPackageLibPath = "$scriptPackagePath\$startupScriptPkgName.$latestPkgVer\lib\"

            # Update nuget.exe and credential provider exe from startup package path to the Startup-Script path
            $newNugetExePath = Join-Path $scriptPackageLibPath "Nuget.exe"
            if (Test-Path $newNugetExePath) {
                xcopy $newNugetExePath, $scriptPath /Y /C | Out-Null
            }

            $newCredManagerPath = Join-Path $scriptPackageLibPath "CredentialProvider.VSS.exe"
            if (Test-Path $newCredManagerPath) {
                xcopy $newCredManagerPath, $scriptPath /Y /C | Out-Null
            }

            $clientStartupPath = Join-Path $scriptPackageLibPath "AzureServiceDeployClient.ps1"
            if (Test-Path $clientStartupPath) {
                xcopy $clientStartupPath $scriptPath /Y /C | Out-Null

                Set-Content -Path $startupPkgVersionFile $latestPkgVer

                # Remove AzureServiceDeployClientStartup directory in %localappdata%
                Remove-Item $scriptPackagePath -Force -Recurse -Confirm:$false

                . "$scriptPath\AzureServiceDeployClient.ps1"

                return
            }
        }
    }
    catch
    {
        Write-Warning "Failed to update current script, continue to run the existing one"
    }

    if (Test-Path $scriptPackagePath)
    {
        Remove-Item $scriptPackagePath -Force -Recurse -Confirm:$false
    }

    LaunchCmdlet
}

function EnsureDependencyPresence
{
    if (!(Test-Path $nugetPath))
    {
        $appLocalNugetPath = Join-Path $azureServiceDeployClientPath "nuget.exe" 
        if (Test-Path $appLocalNugetPath)
        {
            xcopy $appLocalNugetPath, $scriptPath /Y /C | Out-Null
        }
        else {
            Write-Host "Required dependencies not found. Copy the latest Ev2 cmdlets and try again."
        }
    }

    $credManagerPath = Join-Path $scriptPath "CredentialProvider.VSS.exe"
    if (!(Test-Path $credManagerPath))
    {
        $appLocalCredMgrPath = Join-Path $azureServiceDeployClientPath "CredentialProvider.VSS.exe"
        if (Test-Path $appLocalCredMgrPath)
        {
            xcopy $appLocalCredMgrPath, $scriptPath /Y /C | Out-Null
        }
        else {
            Write-Host "Required dependencies not found. Copy the latest Ev2 cmdlets and try again."
        }
    }
}

function DownloadStartupScriptPackage($scriptPackagePath, $latestPkgVer)
{
    # Recreate AzureServiceDeployClientStartup directory before downloading the latest client startup package to that dir.
    if (Test-Path $scriptPackagePath)
    {
        Remove-Item -Path $scriptPackagePath -Force -Recurse -Confirm:$false
    }

    New-Item -ItemType Directory $scriptPackagePath | Out-Null
    & $nugetPath install $startupScriptPkgName -Prerelease -version $latestPkgVer -o $scriptPackagePath -ConfigFile "$azureServiceDeployClientPath\Nuget.config"
}

function write-header 
{
    param ([string]$s)
    $greeting = "`n*** $s ***`n"
    return $greeting
}

function SetupUI 
{
    write-host "Windows PowerShell"
    write-host "Copyright (C) 2022 Microsoft Corporation. All rights reserved."
    write-host 
    # available: "Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White
    $title = "Azure Service Deploy PowerShell"
    try
    {
        $Host.UI.RawUI.WindowTitle = $title
    }
    catch
    {
        # ignore error when Core language is not allowed in SAW machine
    }
    $msg = write-header "Welcome to $title"
    write-host $msg -foregroundcolor Cyan
}

function InstallLatestVersion($targetPath, $lastestPkg)
{
    if (!(Test-Path $targetPath))
    {
        New-Item -ItemType Directory $targetPath | Out-Null
    }

    $asdc = Join-Path $targetPath $lastestPkg 

    Write-Host "Fetching latest version $latestVStr of $sdkPackageName package"
    
    & $nugetPath install $sdkPackageName -Prerelease -version $latestVStr -o $targetPath -ConfigFile "$azureServiceDeployClientPath\Nuget.config"
    if (!(Test-Path "$targetPath\Microsoft.IdentityModel.Clients.ActiveDirectory.5.2.7"))
    {
        Remove-Item -Path "$targetPath\Microsoft.IdentityModel.Clients.ActiveDirectory*" -Force -Recurse -Confirm:$false
        & $nugetPath install "Microsoft.IdentityModel.Clients.ActiveDirectory" -version "5.2.7" -o $targetPath -ConfigFile "$azureServiceDeployClientPath\Nuget.config"
    }
    if (!(Test-Path "$targetPath\Microsoft.Identity.Client.4.39.0"))
    {
        Remove-Item -Path "$targetPath\Microsoft.Identity.Client*" -Force -Recurse -Confirm:$false
        & $nugetPath install "Microsoft.Identity.Client" -version "4.39.0" -o $targetPath -ConfigFile "$azureServiceDeployClientPath\Nuget.config"
    }

    xcopy "$asdc\lib\*.*" $targetPath /Y /C | Out-Null
    $manifest = "$targetPath\AzureServiceDeployClient.manifest"
    if (Test-Path $manifest)
    {
        Get-Content $manifest | % {
            $parts = $_.Split(',');
            $path = (Get-ChildItem -Directory "$targetPath\$($parts[0]).*")[0].Name;
            xcopy "$targetPath\$path\$($parts[1])\*.*" $targetPath /Y /C | Out-Null
        }
    }
    else
    {
        # fallback when there is no manifest file in the package
        $path = (Get-ChildItem -Directory "$targetPath\Microsoft.IdentityModel.Clients.ActiveDirectory.*")[0].Name
        xcopy "$targetPath\$path\lib\net45\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\WindowsAzure.Storage.*")[0].Name
        xcopy "$targetPath\$path\lib\net40\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\Newtonsoft.Json.*")[0].Name
        xcopy "$targetPath\$path\lib\net45\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\System.IdentityModel.Tokens.Jwt.*")[0].Name
        xcopy "$targetPath\$path\lib\net45\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\System.ValueTuple.*")[0].Name
        xcopy "$targetPath\$path\lib\netstandard1.0\*.*" $targetPath /Y /C
    }

    Get-ChildItem -Directory -Exclude CmdLets,Samples,Schema $targetPath | %{ Remove-Item $_ -Force -Recurse -Confirm:$false }
}

function SetupNugetConfigFile
{
    $config = '<?xml version="1.0" encoding="utf-8"?>' +
        '<configuration>' +
            '<packageSources>' +
                '<add key="ExpressV2" value="{0}" />' +
            '</packageSources>' + 
            '<activePackageSource>' +
                '<add key="ExpressV2" value="{0}" />' +
            '</activePackageSource>' +
        '</configuration>'
    $config -f $ev2NugetSource | Out-File "$azureServiceDeployClientPath\Nuget.config" -Encoding ascii
}

function GetLatestPackageVersion($packageName, $source)
{
    $configFilePath = "$azureServiceDeployClientPath\Nuget.config"

    $packages = & $nugetPath list $packageName -Prerelease -Source $source -ConfigFile $configFilePath
    if (!($packages) -or ($packages -contains "No packages found.")) {
        # if no package found in the mirror source then throw
        throw
    }
  
    $versions = @()
    $vStrs = @()
    # Parsing all version string to version oject and get the latest
    foreach ($p in $packages) {
        if ($p.Contains($packageName)) {
            $vStr = $p.Split(' ')[1]
            $vStrs = $vStrs + $vStr
            $v = new-object Version($vstr.Split('-')[0])
            $versions = $versions + $v
        }
    }
    $latestVersion = ($versions | Sort -Descending)[0].ToString()
    $latestVStr = $vStrs | ? { $_.Contains($latestVersion) }

    return $latestVStr
}

function LaunchCmdlet
{
    try
    {
        # Check if any previous version already installed
        $versionFile = Join-Path $azureServiceDeployClientPath "versions.txt"
        $InstalledVersions = $null
        $prevVersion = $null
        $found = $false
        $latestVstr = $null
        if (Test-Path $versionFile)
        {
            $InstalledVersions = Get-Content $versionFile
            if ($InstalledVersions)
            {
                if ($InstalledVersions.GetType().Name -ieq "String")
                {
                    $prevVersion = $InstalledVersions
                }
                else
                {
                    $prevVersion = $InstalledVersions[$InstalledVersions.Length - 1]
                }
            }
        }

        # Ensuring dependency presence of nuget.exe and Cred Provider for back-compat
        EnsureDependencyPresence

        Write-Host "Checking for latest version of Azure Service Deploy cmdlets"
        # Query latest version

        $latestVstr = GetLatestPackageVersion $sdkPackageName $ev2NugetSource
        $lastestPkg = "$sdkPackageName.$latestVStr"
        if ($InstalledVersions)
        {
            $found = $InstalledVersions | ? { $_ -eq $latestVStr }    
        }

        if (!$found)
        {
            if ($prevVersion)
            {
                # try to delete all older version except n-1
                Get-ChildItem -Directory -Exclude $prevVersion $azureServiceDeployClientPath | %{ Remove-Item $_ -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
            }

            InstallLatestVersion -targetPath "$azureServiceDeployClientPath\$latestVStr" -lastestPkg $lastestPkg
            Set-Content -Path $versionFile $prevVersion
            Add-Content -Path $versionFile $latestVstr
            $scriptPath = Join-Path $azureServiceDeployClientPath $latestVstr
        }
        else
        {
            $scriptPath = Join-Path $azureServiceDeployClientPath $prevVersion
            $latestVStr = $prevVersion
        }

        cls
    }
    catch
    {
        if ($latestVstr)
        {
            Remove-Item (Join-Path $azureServiceDeployClientPath $latestVstr) -Force -Recurse -Confirm:$false
        }

        if ($prevVersion)
        {
            $scriptPath = Join-Path $azureServiceDeployClientPath $prevVersion
            $latestVStr = $prevVersion
        }
        else
        {
            Write-Error "Cannot access Nuget source to install the cmdlets at this time. Cannot fall back to a previously installed version either since none was found."
            Write-Warning "Please check network and try again."
            return
        }

        cls
        Write-Warning "Not able to fetch latest version of Azure Service Deploy cmdlets package"
        Write-Warning "Will continue to start with currently installed version of cmdlets if present."
    }

    SetupUI

    Write-Host "Using version $latestVStr"
    Write-Host "Load module from $scriptPath"

    $modulesToImport = @("Microsoft.Azure.Deployment.Express.Client" )

    foreach ($e in $modulesToImport) {
      Import-Module -global (Join-Path $scriptPath "$e.dll")
    }

    $cmdlets = $modulesToImport | %{ Get-Command -Module $_ } | %{$_.Name}
    $commands = ($cmdlets | Select -Unique | Sort)

    # Display the available cmdlets
    write-host "`n Commands:" -foregroundcolor Cyan
    $commands | %{write-host (' * {0}' -f $_) -foregroundcolor Cyan}

    write-Host
    write-host "For help on commands type Get-Help <command name>" -foregroundcolor Cyan
    write-Host

    try
    {
        $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$scriptPath\Microsoft.Azure.Deployment.Express.Client.dll").FileVersion
        $Host.UI.RawUI.WindowTitle += " $fileVersion ($latestVStr)"
    }
    catch
    {
        # ignore error when Core language is not allowed in SAW machine
    }
}

$scriptPath = Split-Path -Parent $PSCommandPath
$nugetPath = Join-Path $scriptPath "nuget.exe"
$azureServiceDeployClientPath = Join-Path $env:LOCALAPPDATA "Microsoft\AzureServiceDeployClient"

if (!(Test-Path $azureServiceDeployClientPath))
{
    New-Item -ItemType Directory $azureServiceDeployClientPath | Out-Null
}

SetupNugetConfigFile

if ($skipScriptUpdate)
{
    LaunchCmdlet
}
else
{
    CheckScriptUpdate
}

# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCytdAQp4sjK8LY
# vVN1g8nyePa12eC/N3hlGpktBc7G0KCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
# v/jUTF1RAAAAAALNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAyWhcNMjMwNTExMjA0NjAyWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDrIzsY62MmKrzergm7Ucnu+DuSHdgzRZVCIGi9CalFrhwtiK+3FIDzlOYbs/zz
# HwuLC3hir55wVgHoaC4liQwQ60wVyR17EZPa4BQ28C5ARlxqftdp3H8RrXWbVyvQ
# aUnBQVZM73XDyGV1oUPZGHGWtgdqtBUd60VjnFPICSf8pnFiit6hvSxH5IVWI0iO
# nfqdXYoPWUtVUMmVqW1yBX0NtbQlSHIU6hlPvo9/uqKvkjFUFA2LbC9AWQbJmH+1
# uM0l4nDSKfCqccvdI5l3zjEk9yUSUmh1IQhDFn+5SL2JmnCF0jZEZ4f5HE7ykDP+
# oiA3Q+fhKCseg+0aEHi+DRPZAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU0WymH4CP7s1+yQktEwbcLQuR9Zww
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ3MDUzMDAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AE7LSuuNObCBWYuttxJAgilXJ92GpyV/fTiyXHZ/9LbzXs/MfKnPwRydlmA2ak0r
# GWLDFh89zAWHFI8t9JLwpd/VRoVE3+WyzTIskdbBnHbf1yjo/+0tpHlnroFJdcDS
# MIsH+T7z3ClY+6WnjSTetpg1Y/pLOLXZpZjYeXQiFwo9G5lzUcSd8YVQNPQAGICl
# 2JRSaCNlzAdIFCF5PNKoXbJtEqDcPZ8oDrM9KdO7TqUE5VqeBe6DggY1sZYnQD+/
# LWlz5D0wCriNgGQ/TWWexMwwnEqlIwfkIcNFxo0QND/6Ya9DTAUykk2SKGSPt0kL
# tHxNEn2GJvcNtfohVY/b0tuyF05eXE3cdtYZbeGoU1xQixPZAlTdtLmeFNly82uB
# VbybAZ4Ut18F//UrugVQ9UUdK1uYmc+2SdRQQCccKwXGOuYgZ1ULW2u5PyfWxzo4
# BR++53OB/tZXQpz4OkgBZeqs9YaYLFfKRlQHVtmQghFHzB5v/WFonxDVlvPxy2go
# a0u9Z+ZlIpvooZRvm6OtXxdAjMBcWBAsnBRr/Oj5s356EDdf2l/sLwLFYE61t+ME
# iNYdy0pXL6gN3DxTVf2qjJxXFkFfjjTisndudHsguEMk8mEtnvwo9fOSKT6oRHhM
# 9sZ4HTg/TTMjUljmN3mBYWAWI5ExdC1inuog0xrKmOWVMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGZ4wghmaAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFH9
# 3dZj6Lran+poDlb3RlcSxl6FgPpQweMkdZOifpIsMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEATQjVo4bpzsZccSELLr0uOJbnrIBXgxF4Mcuo
# owAWpMbEJYjyDPe8b+ZFolh5YzxvEMe9bmkFj8j/qD7VSHniA54fYcDH+NBA80RS
# Vszr3RilIZONgPhAPtw3lC+pJxU+D0Qd1jmZnH1I8lJDf0lPb9rG1uWpkHw0IFBU
# J5deh9quttvwl4P70LelcLqaNsThZ1Gf18YaUPEwmhozdbdA8F2g9nSalLV+CIQs
# Go9yN81TqEW/67T3jee7YsfqoJGsd2rciFp2valdbro29fq7pfMrn0YZSJzhPYpi
# Dlz8a4yxc32OusHo2mFY99V1v9UIhALffj9x2vUGyHjNiQ3+H6GCFygwghckBgor
# BgEEAYI3AwMBMYIXFDCCFxAGCSqGSIb3DQEHAqCCFwEwghb9AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFYBgsqhkiG9w0BCRABBKCCAUcEggFDMIIBPwIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCCk9TuHdn9ZWhMthQ8lxqBd9TR8t0OC5+JZ
# YGczpzyO7gIGY/dYhQrTGBIyMDIzMDIyODA5NDY0MS4yN1owBIACAfSggdikgdUw
# gdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsT
# JE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMd
# VGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbT7gAhE
# BdIt+gABAAABtDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDAeFw0yMjA5MjAyMDIyMDlaFw0yMzEyMTQyMDIyMDlaMIHSMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3Nv
# ZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBU
# U1MgRVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1T
# dGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtEem
# nmUHMkIfvOiu27K86ZbwWhksGwV72Dl1uGdqr2pKm+mfzoT+Yngkq9aLEf+XDtAD
# yA+2KIZU0iO8WG79eJjzz29flZpBKbKg8xl2P3O9drleuQw3TnNfNN4+QIgjMXpE
# 3txPF7M7IRLKZMiOt3FfkFWVmiXJAA7E3OIwJgphg09th3Tvzp8MT8+HOtG3bdrR
# d/y2u8VrQsQTLZiVwTZ6qDYKNT8PQZl7xFrSSO3QzXa91LipZnYOl3siGJDCee1B
# a7X1i13dQFHxKl5Ff4JzDduOBZ85e2VrpyFy1a3ayGUzBrIw59jhMbjIw9YVcQt9
# kUWntyCmNk15WybCS+hXpEDDLVj1X5W9snmoW1qu03+unprQjWQaVuO7BfcvQdNV
# dyKSqAeKy1eT2Hcc5n1aAVeXFm6sbVJmZzPQEQR3Jr7W8YcTjkqC5hT2qrYuIcYG
# Of3Pj4OqdXm1Qqhuwtskxviv7yy3Z+PxJpxKx+2e6zGRaoQmIlLfg/a42XNVHTf6
# Wzr5k7Q1w7v0uA/sFsgyKmI7HzKHX08xDDSmJooXA5btD6B0lx/Lqs6Qb4KthnA7
# N2IEdJ5sjMIhyHZwBr7fzDskU/+Sgp2UnfqrN1Vda/gb+pmlbJwi8MphvElYzjT7
# PZK2Dm4eorcjx7T2QVe3EIelLuGbxzybblZoRTkCAwEAAaOCAUkwggFFMB0GA1Ud
# DgQWBBTLRIXl8ZS4Opy7Eii3Tt44zDLZfjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP0
# 5dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUt
# U3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOC
# AgEAEtEPBYwpt4JioSq0joGzwqYX6SoNH7YbqpgArdlnrdt6u3ukKREluKEVqS2X
# ajXxx0UkXGc4Xi9dp2bSxpuyQnTkq+IQwkg7p1dKrwAa2vdmaNzz3mrSaeUEu40y
# CThHwquQkweoG4eqRRZe19OtVSmDDNC3ZQ6Ig0qz79vivXgy5dFWk4npxA5LxSGR
# 4wBaXaIuVhoEa06vd/9/2YsQ99bCiR7SxJRt1XrQ5kJGHUi0Fhgz158qvXgfmq7q
# NqfqfTSmsQRrtbe4Zv/X+qPo/l6ae+SrLkcjRfr0ONV0vFVuNKx6Cb90D5LgNpc9
# x8V/qIHEr+JXbWXW6mARVVqNQCmXlVHjTBjhcXwSmadR1OotcN/sKp2EOM9JPYr8
# 6O9Y/JAZC9zug9qljKTroZTfYA7LIdcmPr69u1FSD/6ivL6HRHZd/k2EL7FtZwzN
# cRRdFF/VgpkOxHIfqvjXambwoMoT+vtGTtqgoruhhSk0bM1F/pBpi/nPZtVNLGTN
# aK8Wt6kscbC9G6f09gz/wBBJOBmvTLPOOT/3taCGSoJoDABWnK+De5pie4KX8Bxx
# KQbJvxz7vRsVJ5R6mGx+Bvav5AjsxvZZw6eQmkI0vPRckxL9TCVCfWS0uyIKmyo6
# TdosnbBO/osre7r0jS9AH8spEqVlhFcpQNfOg/CvdS2xNVMwggdxMIIFWaADAgEC
# AhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVa
# Fw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7V
# gtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeF
# RiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3X
# D9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoP
# z130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+
# tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5Jas
# AUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/b
# fV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuv
# XsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg
# 8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzF
# a/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqP
# nhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEw
# IwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSf
# pxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBB
# MD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0Rv
# Y3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmg
# R4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
# BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEs
# H2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHk
# wo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinL
# btg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCg
# vxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsId
# w2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2
# zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23K
# jgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beu
# yOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/
# tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjm
# jJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBj
# U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHS
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRN
# aWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRo
# YWxlcyBUU1MgRVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQg
# VGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBlnNiQ85uX9nN4KRJt
# /gHkJx4JCKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0G
# CSqGSIb3DQEBBQUAAgUA56fFpjAiGA8yMDIzMDIyODA4MTMyNloYDzIwMjMwMzAx
# MDgxMzI2WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDnp8WmAgEAMAcCAQACAgKx
# MAcCAQACAhEuMAoCBQDnqRcmAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
# mic+EOvoemnlF4XjHhetvfUmXwKg85DDgq/6aVcNMvCfPfOgLpE8VP9ditF8s2x2
# herwGZYxoLbIpybsqm8Q0gzXgXHrpsrzuo+5BpgN8cE2gQasSHHR94qUNrmKcU7j
# cdd/rg+FHdcxQE7QAhEfqqygWGnZIIHnBWjs9ZcOfoAxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbT7gAhEBdIt+gABAAAB
# tDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCBmg13kRpHjmBO7DxXWwhEGHMDdWv5ShqGehaGErZ14
# /TCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EINPI93vmozBwBlFxvfr/rElr
# eFPR4ux7vXKx2ni3AfcGMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAG0+4AIRAXSLfoAAQAAAbQwIgQgXrbP9oD/wRQOm0yt2NfIzVqt
# yTM8QYvyMiob+WY1/1EwDQYJKoZIhvcNAQELBQAEggIAX/JI05q85Q7V+m0tJSKX
# 6EvYZvjhdu+nv0oKV/8v8JnfEK1110SQw3nzA1r9j1gNyqhFvoXQNv25ckM2ogS2
# ja1PzzJTyPa+13lcGJfpZfCuEw8CkZ50qcZYl2HbyPGnj3uIf+xpCS1GiJYA219V
# 2pG9vHOcc52w4LZnSDq6LQodfSDcsSJZXMVypS7+p2QblcLDBGWuXTtPwN5OajWH
# P872AMnWxPdstUhLbpwXotG/wWkPIefXms3dQevVCXWn4OBAhy13ZY8/eQviPBQH
# DJHM70mqMHIXGpUry8Zp5ZLAZPFsGXRpMKZOVq3P2TCq9xDFSlCM4BC0gi9TuWoC
# LP/CbQa+2eH67pyvG42OmmGy4Z9IEKclCSkqfx0oEAMpcT38ZRTBLbB+ux/I34hj
# UYfqqU1GDc3wbXS1iuhbQZTI8Sq9CovV/5x4H6Se1tv3DsaDZdgUYYkYF+QkmzSS
# a4Wimoom137dfRH9tC2FTMZPnQ3Xh/WUMxchLSuBQV2BwuOZQAE7YWOjtlyqST00
# JnCgRWV7D2Ri+mZ3DXP4TYDn7uSLmHcUdCmrBB1TBawdCF5/Azr7g8cPkdu6+r1t
# s+v+/4J6+ldUdpPNuJ12KNUKcJOWASb+GQ+YfvzfR2bWeHMbPztyYAIPGOs+zww0
# W35vilPBAvU+ermuG/1NhAQ=
# SIG # End signature block
