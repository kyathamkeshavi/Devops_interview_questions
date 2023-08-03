# This script is run during official build to apend geoscope and capacity unit to the appsetting and service model MEOv2 files. 
$root = "$PSScriptRoot"
# Read configuration json which has the env to region mappings 
$config = (Get-Content "$root\configNew.json" | Out-String | ConvertFrom-Json)


$emailconfig = (Get-Content "$root\EmailConfig.json" | Out-String | ConvertFrom-Json)



# append capacityunit and geo specific parameters appsetting files and saves a new geo and CU file.
$originalJSONdata = Get-Content $root\prod.public.config.json -Raw | ConvertFrom-Json
#Write-Output $originalJSONdata
function Replace-Env {  
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        $path
    
    )
         $geos = $config.geos;
         $apiURLendPointSuffix = $config.apiURLendPointSuffix;
         $V2BatchEmailCutargetFile = "$root\$path\syntheticV2BatchEmailCuTemplate.json";  
         foreach ($geography in $geos) {
           $geoName = $geography.geoName.ToLower();
           foreach($capacityunit in $geography.capacityUnits){
              $unit = $capacityunit.unit;

              if($config.cloudType -eq "public"){
                foreach($syntheticemail in $emailconfig.public | Get-Random){
                  $syntheticEmailAddress = $syntheticemail.syntheticEmailAddress;
                  $syntheticEmailKeyVaultSecretId = $syntheticemail.syntheticEmailKeyVaultSecretId;
                  
                }

              }elseif($config.cloudType -eq "fairfax"){
                 foreach($syntheticemail in $emailconfig.ff | Get-Random){
                  $syntheticEmailAddress = $syntheticemail.syntheticEmailAddress;
                  $syntheticEmailKeyVaultSecretId = $syntheticemail.syntheticEmailKeyVaultSecretId;
                }
              
              }else{
                foreach($syntheticemail in $emailconfig.mooncake | Get-Random){
                  $syntheticEmailAddress = $syntheticemail.syntheticEmailAddress;
                  $syntheticEmailKeyVaultSecretId = $syntheticemail.syntheticEmailKeyVaultSecretId;
                }

              }
              
                $V2BatchEmailCuAddJson =   (Get-Content $V2BatchEmailCutargetFile) | Foreach-Object {
                $_ -replace $geoNameStr, $geoName `
                   -replace $apiURLendPointSuffixStr, $apiURLendPointSuffix `
                   -replace $endPointEnvStr, $endPointEnv `
                   -replace $syntheticEmailAddressStr, $syntheticEmailAddress `
                   -replace $syntheticEmailKeyVaultSecretIdStr, $syntheticEmailKeyVaultSecretId `
                   -replace $unitstr, $unit
            } | Out-String | ConvertFrom-Json


           $i =0
           $originalJSONdata.SyntheticJobGroup.SyntheticJobs | Foreach-object {
             if ( $_.JobName -eq "v2BatchEmail" ) {
                Write-Output "Found v2BatchEmail!!!"
                $_[$i].SyntheticJobInstances += $V2BatchEmailCuAddJson
                $i++
                
            }
          }
         
          }
        }
        $V2HealthPingCutargetFile = "$root\$path\syntheticV2HealthPingCuTemplate.json";    
         foreach ($geography in $geos) {
            $geoName = $geography.geoName.ToLower();
            foreach ($capacityunit in $geography.capacityUnits) {       
             $unit = $capacityunit.unit;
            # Replace parameters and save the content in cudestFile file
             $V2HealthPingCuAddJson =    (Get-Content $V2HealthPingCutargetFile) | Foreach-Object {
                $_ -replace $geoNameStr, $geoName `
                    -replace $apiURLendPointSuffixStr, $apiURLendPointSuffix `
                    -replace $unitstr, $unit
                    
              } | Out-String | ConvertFrom-Json
              $i =0
               $originalJSONdata.SyntheticJobGroup.SyntheticJobs | Foreach-object {
                 if ( $_.JobName -eq "V2HealthPing" ) {
                  Write-Output "Found V2HealthPing!!!"
                    $_[$i].SyntheticJobInstances += $V2HealthPingCuAddJson
                  $i++
                 }
                 
               }
           }
         }

$originalJSONdata | ConvertTo-Json -Depth 50 | %{
        [Regex]::Replace($_, 
            "\\u(?<Value>[a-zA-Z0-9]{4})", {
                param($m) ([char]([int]::Parse($m.Groups['Value'].Value,
                [System.Globalization.NumberStyles]::HexNumber))).ToString() } )} | Format-Json | Out-File C:\Users\v-kkyatham\synthetic\prod.public.config.json
}
function Format-Json([Parameter(Mandatory, ValueFromPipeline)][String] $json) {
    $indent = 0;
    ($json -Split "`n" | % {
        if ($_ -match '[\}\]]\s*,?\s*$') {
            # This line ends with ] or }, decrement the indentation level
            $indent--
        }
        $line = ('  ' * $indent) + $($_.TrimStart() -replace '":  (["{[])', '": $1' -replace ':  ', ': ')
        if ($_ -match '[\{\[]\s*$') {
            # This line ends with [ or {, increment the indentation level
            $indent++
        }
        $line
    }) -Join "`n"
}

# Parameters in the Ev2 files
$geoNameStr = "{geoName}";
$endPointEnvStr = "{endPointEnv}";
$envStr = "{env}";
$apiURLendPointSuffixStr = "{apiURLendPointSuffix}";
$unitstr = "{unit}";
$syntheticEmailAddressStr = "{syntheticEmailAddress}";
$syntheticEmailKeyVaultSecretIdStr = "{syntheticEmailKeyVaultSecretId}";
Replace-Env "Common"
