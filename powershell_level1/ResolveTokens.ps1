. ./Utils.ps1

# Link: https://github.com/DTW-DanWard/PowerShell-Beautifier/blob/master/src/DTW.PS.Beautifier.PopulateValidNames.psm1
Function Get-CoreSafeAliases {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $Aliases = @{'?'='Where-Object'; '%'='ForEach-Object'; 'cd'='Set-Location'; 'chdir'='Set-Location'; 'clc'='Clear-Content'; 'clear'='Clear-Host'; 'clhy'='Clear-History'; 'cli'='Clear-Item'; 'clp'='Clear-ItemProperty'; 'cls'='Clear-Host'; 'clv'='Clear-Variable'; 'cnsn'='Connect-PSSession'; 'copy'='Copy-Item'; 'cpi'='Copy-Item'; 'cvpa'='Convert-Path'; 'dbp'='Disable-PSBreakpoint'; 'del'='Remove-Item'; 'dir'='Get-ChildItem'; 'dnsn'='Disconnect-PSSession'; 'ebp'='Enable-PSBreakpoint'; 'echo'='Write-Output'; `
                 'epal'='Export-Alias'; 'epcsv'='Export-Csv'; 'erase'='Remove-Item'; 'etsn'='Enter-PSSession'; 'exsn'='Exit-PSSession'; 'fc'='Format-Custom'; 'fhx'='Format-Hex'; 'fl'='Format-List'; 'foreach'='ForEach-Object'; 'ft'='Format-Table'; 'fw'='Format-Wide'; 'gal'='Get-Alias'; 'gbp'='Get-PSBreakpoint'; 'gc'='Get-Content'; 'gci'='Get-ChildItem'; 'gcm'='Get-Command'; 'gcs'='Get-PSCallStack'; 'gdr'='Get-PSDrive'; 'ghy'='Get-History'; 'gi'='Get-Item'; 'gjb'='Get-Job'; 'gl'='Get-Location'; 'gm'='Get-Member'; `
                 'gmo'='Get-Module'; 'gp'='Get-ItemProperty'; 'gps'='Get-Process'; 'gpv'='Get-ItemPropertyValue'; 'group'='Group-Object'; 'gsn'='Get-PSSession'; 'gtz'='Get-TimeZone'; 'gu'='Get-Unique'; 'gv'='Get-Variable'; 'h'='Get-History'; 'history'='Get-History'; 'icm'='Invoke-Command'; 'iex'='Invoke-Expression'; 'ihy'='Invoke-History'; 'ii'='Invoke-Item'; 'ipal'='Import-Alias'; 'ipcsv'='Import-Csv'; 'ipmo'='Import-Module'; 'irm'='Invoke-RestMethod'; 'iwr'='Invoke-WebRequest'; 'kill'='Stop-Process'; 'md'='mkdir'; `
                 'measure'='Measure-Object'; 'mi'='Move-Item'; 'move'='Move-Item'; 'mp'='Move-ItemProperty'; 'nal'='New-Alias'; 'ndr'='New-PSDrive'; 'ni'='New-Item'; 'nmo'='New-Module'; 'nsn'='New-PSSession'; 'nv'='New-Variable'; 'oh'='Out-Host'; 'popd'='Pop-Location'; 'pushd'='Push-Location'; 'pwd'='Get-Location'; 'r'='Invoke-History'; 'rbp'='Remove-PSBreakpoint'; 'rcjb'='Receive-Job'; 'rcsn'='Receive-PSSession'; 'rd'='Remove-Item'; 'rdr'='Remove-PSDrive'; 'ren'='Rename-Item'; 'ri'='Remove-Item'; 'rjb'='Remove-Job'; `
                 'rmo'='Remove-Module'; 'rni'='Rename-Item'; 'rnp'='Rename-ItemProperty'; 'rp'='Remove-ItemProperty'; 'rsn'='Remove-PSSession'; 'rv'='Remove-Variable'; 'rvpa'='Resolve-Path'; 'sajb'='Start-Job'; 'sal'='Set-Alias'; 'saps'='Start-Process'; 'sbp'='Set-PSBreakpoint'; 'sc'='Set-Content'; 'select'='Select-Object'; 'set'='Set-Variable'; 'si'='Set-Item'; 'sl'='Set-Location'; 'sls'='Select-String'; 'sp'='Set-ItemProperty'; 'spjb'='Stop-Job'; 'spps'='Stop-Process'; 'sv'='Set-Variable'; 'type'='Get-Content'; `
                 'where'='Where-Object'; 'wjb'='Wait-Job'; 'powershell'= 'PowerShell'}
    
    return $Aliases
}

# Remvoe Ticks and RandomCase from tokens(except String token) 
Function Remove-TicksAndRandomCase {
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )

    $Tokens = Tokenize -ScriptString $ScriptString
    $ValidValuesCacheFilePath = Join-Path -Path $PSScriptRoot -ChildPath "validValuesCache.txt"
    if ($true -eq (Test-Path $ValidValuesCacheFilePath)) {
        $ValidNamesData = Set-LookupTableValuesFromFile
    } 
    else {
        $ValidNamesData = Set-LookupTableValuesFromMemory
    }

    # $Members = Get-Content -Path $memberFile  # get members' camel format
    # $SpecialCharacters = @{"`0"='`0'; "`a"='`a'; "`b"='`b'; "`e"='`e'; "`f"='`f'; "`v"='`v'} #"`n"='`n'; "`r"='`r'; "`t"='`t'; }
    $TypeSet0 = @('Command', 'Member',  'Attribute', 'Operator', 'Keyword', 'CommandParameter', 'Type') # 'CommandArgument',

    $indent = 0  # parenthese Level; Need to start a new line after the StatementSeparator ';' not in parenthese.

    $tokensCount = $Tokens.Count - 1
    for ($i = $tokensCount; $i -ge 0; $i--) {
        $Token = $Tokens[$i]

        # Different process for different Type. Todo: remain many types
        if ($Token.Type -eq 'Variable') {
            if ($Token.Content.Contains('`') -eq $false) {
                $OriginTokenString = $ScriptString.SubString($Token.Start, $Token.Length)
                if ($OriginTokenString.StartsWith('${') -and $OriginTokenString.EndsWith('}')) {
                    $obfuscatedVar = $OriginTokenString.Substring(2, $OriginTokenString.Length-3)
                }
                else {
                    $obfuscatedVar = $OriginTokenString.Substring(1)
                }

                $subStr   = $Token.Content
                $VariableNames = $ValidNamesData['Variable']
                if ($null -ne $VariableNames[$subStr]) {
                    $subStr = $VariableNames[$subStr] 
                }

                $ScriptString = $ScriptString.SubString(0, $Token.Start) + $OriginTokenString.replace($obfuscatedVar, $subStr) + $ScriptString.SubString($Token.Start+$Token.Length)
            }
        }

        # elseif ($Token.Type -eq 'CommandArgument') {  # eg: function ||func1|| {}  /  powershell -en ||base64code||
        #     $ScriptString = $ScriptString.SubString(0, $Token.Start) + $Token.Content.ToLower() + $ScriptString.SubString($Token.Start+$Token.Length)
        # }

        elseif ($TypeSet0 -contains $Token.Type) {
            # $Token.Type -eq 'Command' -or $Token.Type -eq 'Member' -or $Token.Type -eq 'CommandParameter' -or $Token.Type -eq 'Attribute' -or 
            #     $Token.Type -eq 'Operator' -or $Token.Type -eq 'Keyword' -or $Token.Type -eq 'Type') {
            $curType = $Token.Type
            $ValidNames = $ValidNamesData["$curType"]
            $curName = $Token.Content 

            if ($null -ne $ValidNames[$curName]) {
                $curName = $ValidNames[$curName]
            }
            else {
                $curName = $curName.ToLower()
            }

            $ScriptString = $ScriptString.Substring(0, $Token.Start) + $curName + $ScriptString.Substring($Token.Start + $Token.Length)
            
        }

        elseif ($Token.Type -eq 'String') {  # eg: $t."len`gth"
            $TokenStr = $ScriptString.SubString($Token.Start, $Token.Length)
            if ($TokenStr[0] -eq '"') {
                $tmpstr = $Token.Content.replace('"', '""')
                $deobstr = '"' + $tmpstr + '"'
            }
            else {
                $tmpstr = $Token.Content.replace("'", "''")
                $deobstr = "'" + $tmpstr + "'"
            }
            $ScriptString = $ScriptString.Substring(0, $Token.Start) + $deobstr + $ScriptString.Substring($Token.Start + $Token.Length) 
        }

        elseif (($Token.Type -eq 'GroupStart' -and $Token.Content -eq '{') -or ($Token.Type -eq 'GroupEnd' -and $Token.Content -eq '}' -and 
                ($i -eq $Tokens.Count-1 -or $Tokens[$i+1].Content -ne '|') ) -or 
                ($Token.Type -eq 'StatementSeparator' -and $Token.Content -eq ';' -and $indent -eq 0)) {
            if ($i+1 -lt $Tokens.Count -and $Tokens[$i+1].Type -ne 'NewLine' -and $Tokens[$i+1].Type -ne 'CommandParameter' -and $Tokens[$i+1].Type -ne 'Operator') {
                $ScriptString = $ScriptString.SubString(0, $Token.Start+1) + "`n" + $ScriptString.SubString($Token.Start+1)
            }
        }

        elseif ($Token.Type -eq 'GroupStart' -and $Token.Content -eq '(') {
            $indent++
        }

        elseif ($Token.Type -eq 'GroupEnd' -and $Token.Content -eq ')') {
            $indent--
        }
        
    }

    if (Test-Script -ScriptString $ScriptString) {
        return $ScriptString
    } 
    else {
        throw "ResolveTokens Error"
    }
}


# https://github.com/DTW-DanWard/PowerShell-Beautifier
# validNames
function Set-LookupTableValuesFromMemory {
    param()

    $ValidData = @{}
    
    # Command 
    $CommandNames = @{}
    $Commands = (Get-Command -CommandType Cmdlet,Function).Name 
    $CommandsCount = $commands.Count 
    for ($i = 0; $i -lt $commandsCount; $i++) {
        for ($i = 0; $i -lt $commandsCount; $i++) {
            if ($CommandNames.ContainsKey($commands[$i])) {
            }
            else {
                $CommandNames[$commands[$i]] = $commands[$i]
            }
        }
    }

    # manually add Aliases that are known to be safe for Core - across all OSes
    $Aliases = Get-CoreSafeAliases
    $Aliases.Keys | ForEach-Object {
        $Key = $_
        if (!$CommandNames.ContainsKey($Key)) {
            $CommandNames.Add($Key,$Aliases.$Key)
        }
    }

    # CommandParameter
    $CommandParameterNames = @{}

    $Params = Get-Command -CommandType Cmdlet | Where-Object { $_.ModuleName.StartsWith('Microsoft.PowerShell.') } | Where-Object { $null -ne $_.Parameters } | ForEach-Object { $_.Parameters.Keys } | Select-Object -Unique
    $Name = $null

    for($i = 0; $i -lt $Params.Count; $i++) {
        $Name = '-' + $Params[$i]
        $CommandParameterNames.Item($Name) = $Name
    }
    # $Params | ForEach-Object {
    #   # param name appears with - in front
    #   $Name = '-' + $_
    #   # for each param, add to hash table with name as both key and value
    #   $CommandParameterNames.Item($Name) = $Name
    # }

    # now get all params for cmdlets and functions; the Microsoft.PowerShell ones will already be in
    # the hashtable; add other ones not found yet
    $Params = Get-Command -CommandType Cmdlet,Function | Where-Object { $null -ne $_.Parameters } | ForEach-Object { $_.Parameters.Keys } | Select-Object -Unique 
    $Name = $null
    for($i = 0; $i -lt $Params.Count; $i++) {
        $Name = '-' + $Params[$i]
        # if doesn't exist, add to hash table with name as both key and value
        if (!$CommandParameterNames.Contains($Name)) {
            $CommandParameterNames.Item($Name) = $Name
        }
    }
    # $Params | ForEach-Object {
    #   # param name appears with - in front
    #   $Name = '-' + $_
    #   # if doesn't exist, add to hash table with name as both key and value
    #   if (!$CommandParameterNames.Contains($Name)) {
    #     $CommandParameterNames.Item($Name) = $Name
    #   }
    # }

    # AttributeNames 
    $AttributeNames = @{Alias = 'Alias'; AllowEmptyCollection = 'AllowEmptyCollection'; AllowEmptyString = 'AllowEmptyString'; AllowNull = 'AllowNull'; CmdletBinding = 'CmdletBinding'; ConfirmImpact = 'ConfirmImpact';
    CredentialAttribute = 'CredentialAttribute'; DefaultParameterSetName = 'DefaultParameterSetName'; OutputType = 'OutputType'; Parameter = 'Parameter'; PositionalBinding = 'PositionalBinding'; PSDefaultValue = 'PSDefaultValue';
    PSTypeName = 'PSTypeName'; SupportsShouldProcess = 'SupportsShouldProcess'; SupportsWildcards = 'SupportsWildcards'; ValidateCount = 'ValidateCount'; alidateLength = 'ValidateLength'; ValidateNotNull = 'ValidateNotNull';
    ValidateNotNullOrEmpty = 'ValidateNotNullOrEmpty'; ValidatePattern = 'ValidatePattern'; ValidateRange = 'ValidateRange'; ValidateScript = 'ValidateScript'; ValidateSet = 'ValidateSet'; }

    # MemberNames
    $MemberNames = @{}
    $TypesToCheck = [System.Management.Automation.ParameterAttribute],`
       [string],[char],[byte],`
       [int],[long],[decimal],[single],[double],`
       [bool],[datetime],[guid],[hashtable],[xml],[array],`
       [System.IO.File],[System.IO.FileInfo],[System.IO.FileAttributes],[System.IO.FileOptions],`
       (Get-Item -Path $PSHOME),`
       [System.IO.Directory],[System.IO.DirectoryInfo],[System.Exception]

    $TypesToCheck | ForEach-Object {
        ($_ | Get-Member).Name;
        ($_ | Get-Member -Static).Name;
    } | ForEach-Object {
        $MemberNames[$_] = $_
        # $MemberNames.Add($_,$_)
    }

    # VariableNames
    $VariableNames = @{true='True'; false='False'; HOME='HOME'; null='Null'}

    $CommandArgumentNames = @{}

    $ValidData['Command']          = $CommandNames
    $ValidData['CommandParameter'] = $CommandParameterNames 
    $ValidData['Attribute']        = $AttributeNames
    $ValidData['Member']           = $MemberNames
    $ValidData['Variable']         = $VariableNames
    $ValidData['CommandArgument']  = $CommandArgumentNames

    # Type、 Operator、 Keyword
    $content = Get-Content 'OtherValidNames.txt'
    for($i = 0; $i -lt $content.count; $i++) {
        $l = $content[$i]
        if ($l.endswith(':')) {
            $name = $l.Split(':')[0]
            $ValidData[$name] = @{}
        }
        elseif ($l -ne '') {
            $ValidData[$name][$l] = $l
        }
    }
    # foreach($l in $content) {
    #     if ($l.endswith(':')) {
    #         $name = $l.Split(':')[0]
    #         $ValidData[$name] = @{}
    #     }
    #     elseif ($l -ne '') {
    #         $ValidData[$name][$l] = $l
    #     }
    # }

    $ValidValuesCacheFilePath = Join-Path -Path $PSScriptRoot -ChildPath "validValuesCache.txt"
    $null = Export-Clixml -InputObject $ValidData -Path $ValidValuesCacheFilePath -Depth 10
    return $ValidData
}

Function Set-LookupTableValuesFromFile {
    param()
    $ValidValuesCacheFilePath = Join-Path -Path $PSScriptRoot -ChildPath "validValuesCache.txt"
    $CacheData = Import-Clixml -Path $ValidValuesCacheFilePath
    return $CacheData
}

# Remove-TicksAndRandomCase -ScriptString (Get-content -raw /Users/chaihj15/Desktop/tmmp/invoke-deobfuscation/Data/demo.ps1)