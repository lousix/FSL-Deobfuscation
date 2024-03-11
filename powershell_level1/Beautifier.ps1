. ./Utils.ps1

Function Beautfier{
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )

    $Tokens = Tokenize -ScriptString $ScriptString
    # deal whitespace
    for ($i = $Tokens.count -1; $i -ge 0; $i--) {
        $curToken = $Tokens[$i]
        if (($i + 1) -lt $Tokens.count) {  # analysis with the next token
            if (($Tokens[$i+1].Type -eq 'StatementSeparator' -and $Tokens[$i+1].Content -eq ';') -or 
                ($curToken.Type -eq 'NewLine')) { 
                $ScriptString = $ScriptString.Substring(0, $curToken.Start + $curToken.Length) + $ScriptString.Substring($Tokens[$i+1].Start)
            }
            elseif (Test-AddSpaceFollowingToken -Token $curToken -NextToken $Tokens[$i+1]) {  # judge to add whitespace or not
                $ScriptString = $ScriptString.Substring(0, $curToken.Start + $curToken.Length) + ' ' + $ScriptString.Substring($Tokens[$i+1].Start)
            }
        }
        else {
            if (Test-AddSpaceFollowingToken -Token $curToken) {
                $ScriptString = $ScriptString.Substring(0, $curToken.Start + $curToken.Length) + ' ' 
            }
        }
    }

    # process code indent
    $ResScriptString = ''
    $indent = 0
    $indentText = '    '  # set the format of indent, maybe it can be a param of function
    $Tokens = Tokenize -ScriptString $ScriptString
    for ($i = 0; $i -lt $Tokens.Count; $i++) {
        $curToken = $Tokens[$i]
        $addIndentFlag = $false
        if ($curToken.Type -eq 'GroupEnd') {
            $indent -= 1
        }

        if ($i -gt 0 -and ($Tokens[$i-1].Type -eq 'NewLine' -or $Tokens[$i-1].Type -eq 'LineContinuation') -and 
            $curToken.Type -ne 'NewLine') {
            
            [int]$indentToUse = $indent
            if ($Tokens[$i-1].Type -eq 'LineContinuation') {
                $indentToUse += 1
            }
            if ($indentToUse -gt 0 -and (!($curToken.Type -eq 'Comment' -and $curToken.Content.ToUpper().Contains('.SYNOPSIS')))) {

                $ResScriptString = $ResScriptString + ($indentText * $indentToUse) + $ScriptString.SubString($Tokens[$i-1].Start+$Tokens[$i-1].Length, ($curToken.Start - $Tokens[$i-1].Start - $Tokens[$i-1].Length)) + $ScriptString.Substring($curToken.Start, $curToken.Length)
                $addIndentFlag = $true
            }
        }

        if ($addIndentFlag -eq $false -and $i -gt 0) {
            $ResScriptString = $ResScriptString + $ScriptString.SubString($Tokens[$i-1].Start+$Tokens[$i-1].Length, ($curToken.Start - $Tokens[$i-1].Start - $Tokens[$i-1].Length)) + $ScriptString.Substring($curToken.Start, $curToken.Length)
        }
        elseif ($addIndentFlag -eq $false) {
            $ResScriptString = $ResScriptString + $ScriptString.Substring($curToken.Start, $curToken.Length)
        }

        if ($curToken.Type -eq 'GroupStart') { 
            $indent += 1 
        }
    }

    if (Test-Script -ScriptString $ScriptString) {
        return $ResScriptString
    }
    else {
        throw "Beautifier Error!"
    }
}

# token kind https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.language.tokenkind?view=powershellsdk-7.0.0
Function Test-AddSpaceFollowingToken {  
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,

        [Parameter(Position = 1)]
        [System.Management.Automation.PSToken]
        $NextToken = $null
    )

    # Operator list: https://docs.microsoft.com/zh-cn/powershell/module/microsoft.powershell.core/about/about_operator_precedence?view=powershell-7.1
    # $AddSpaceOperator = @('-split', '-join', ',', '++', '--', '-f', '-', '+', '*', '/', '%', '-is', '-isnot', '-as', '-eq', '-ne', '-gt', '-lt', '-le',
    #                       '-like', '-notlike', '-match', '-notmatch', '-in', '-notin', '-contains', '-notcontains', '-replace', '-band', '-bnot')
    $NotAddSpaceOperator = @('.', '::', '[', ']', '..', '??')

    if ($Token.Type -eq 'Operator') {
        if ($NotAddSpaceOperator -contains $Token.Content -and $null -ne $NextToken -and $NextToken.Start -eq ($Token.Start + $Token.Length)) {
            return $false
        }
        return $true
    }

    if ($Token.Type -eq 'Variable') {
        if ($null -ne $NextToken -and $NextToken.Type -eq 'Operator' -and $NotAddSpaceOperator -contains $NextToken.Content) {
            return $false
        }
        return $true
    }

    if (($Token.Type -eq 'KeyWord' -and $Token.Content -ne 'param') -or $Token.Type -eq 'Command') {
        return $true
    }

    # if there are other constant types ?
    if (($Token.Type -eq 'Number' -or $Token.Type -eq 'String') -and $null -ne $NextToken -and ($Token.Start + $Token.Length) -ne $NextToken.Start) {
        return $true
    }

    if ($null -ne $NextToken -and ($Token.Start + $Token.Length) -ne $NextToken.Start) {
        return $true
    }

    if ($null -ne $NextToken -and ($Token.Start + $Token.Length) -eq $NextToken.Start) {
        if ($NextToken.Type -eq 'Operator' -and $NotAddSpaceOperator -notcontains $NextToken.Content) {
            return $true
        }
        if ($Token.Type -eq 'StatementSeparator' -and $Token.Content -eq ';') {
            return $true
        }
    }

    return $false
}

# $scriptstring = Get-content -raw $args[0]
# $m = Beautfier -ScriptString $scriptstring
# write-host $m -foregroundcolor green