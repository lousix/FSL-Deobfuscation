. ./Utils.ps1

# collect all variables and function names, then judge them if obfuscated
function IsRandomName {
    [CmdletBinding()] Param (
        [Parameter(Mandatory)]
        [String]
        $ScriptString
    )

    if ((Test-Script -ScriptString $ScriptString) -eq $false) {
        return $false
    }

    $tokens    = Tokenize -ScriptString $ScriptString
    $varnames  = @{}
    $funcnames = @{}
    
    $count = $tokens.Count
    for($i = $count-1; $i -ge 0; $i--){
        $token = $tokens[$i]
        # record variables' name
        if ($token.Type -eq 'Variable') {   
            # $varname = Get-VariableName -VariableString $token.Content 
            $varname = $token.Content
            if ($varnames.keys -notcontains $varname) {
                $varnames[$varname] = $varnames.Keys.Count
            }
        }
        # record function's name
        elseif ($token.Type -eq 'CommandArgument' -and $tokens[$i-1].Type -eq 'Keyword' -and $tokens[$i-1].Content -eq 'Function') {
            $funcname = $token.Content 
            if ($funcnames.Keys -notcontains $funcname) {
                $funcnames[$funcname] = $funcnames.Keys.Count
            }
        }
    }

    $wholeStr, $enStr = '', ''
    foreach ($var in $varnames.Keys) {
        $wholeStr += $var
    }
    foreach ($func in $funcnames.Keys) {
        $wholeStr += $func
    }

    $regex = [regex]'[a-zA-Z]+'
    $resMatch = $regex.Matches($wholeStr)
    foreach($res in $resMatch) {
        $enStr += $res.Value
    }
    # non enlish character percent is more than 50%  ==>  random name
    if ($wholeStr.Length -gt 0 -and $enStr.Length / $wholeStr.Length -lt 0.1) {
        return $true
    }

    $vowelRegex = [regex]'[aeiouAEIOU]'
    $vowels = $vowelRegex.Matches($enStr)
    $vcnt = $vowels.Count 
    if ($enStr.Length -gt 0) {
        $vRatio = $vcnt / $enStr.Length

        # THE RELATIVE FREQUENCY OF PHONEMES IN GENERAL-AMERICAN ENGLISH 
        # https://www.tandfonline.com/doi/pdf/10.1080/00437956.1950.11659381
        # vowel ratio about 0.374  =>  [0.375-0.05, 0.375+0.05]
        if ($vRatio -lt 0.324 -or $vRatio -gt 0.424) {
            return $true
        }
    }

    return $false
}

# post-order traversal
Function Rename-Variables {
    [CmdletBinding()] Param (
        [Parameter(Mandatory)]
        [String]
        $ScriptString
    )

    if ((Test-Script -ScriptString $ScriptString) -eq $false) {  
        Write-Host "Invalid Script"
        return $ScriptString
    } 

    $ScriptBlock = [ScriptBlock]::Create($ScriptString)

    # find variable in string scripts
    # eg: $a = 'iex $m'
    $var_in_str = [System.Collections.ArrayList]@()  
    # $tokens = Tokenize -ScriptString $ScriptString | Where-Object {$_.type -eq 'String'}
    # 11.05
    # $tokens = Get-PSOneToken -Code $scriptstring -TokenKind String
    $tokens = Get-SpecialToken -ScriptString $ScriptString -TokenType String
    foreach($token in $tokens) {
        if ($token.content -eq '' -or (Test-Script -ScriptString $token.content) -eq $false) {
            continue
        }
        # $hiddentokens = Tokenize -ScriptString $token.content | Where-Object {$_.type -eq 'Variable'}
        # 11.05 
        # $hiddentokens = Get-PSOneToken -Code $scriptstring -TokenKind Variable 
        $hiddentokens = Get-SpecialToken -ScriptString $token.content -TokenType Variable
        foreach($tmpvar in $hiddentokens) {
            if ($var_in_str -notcontains $tmpvar.Content) {
                $null = $var_in_str.Add($tmpvar.Content)
            }
        }
    }



    #########
    # variable substitution

    $sysVariables = [System.Collections.ArrayList](Get-Variable).Name
    $null = $sysVariables.add('_')
    $SetVariable0 = @('Set-Variable','SV','Set')                                            # Set m 3
    $SetVariable1 = @('Set-Item', 'SI')                                                     # Set-Item variable:m 3
    $GetVariable0 = @('Get-Variable','Variable', 'GV')                                      # (GV m).value
    $GetVariable1 = @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')  # (DIR variable:m).value

    $subNodeString   = @{}
    $variables = @{}
    #########

    # build a hashtable for parents
    $hierarchy, $hierarchyP = GetHierarchy -ScriptBlock $ScriptBlock

    $queue = New-Object -TypeName System.Collections.ArrayList
    $null = $queue.Add($ScriptBlock.Ast)  # insert root
    $lastVisitedNode = $null
    $currentIndent  = -1

    while ($queue.Count -ne 0) {  # Start traversal
        $curNode, $queue, $currentIndent = PostTraversal -Hierarchy $hierarchy -HierarchyP $hierarchyP -Queue $queue -LastVisitedNode $lastVisitedNode -CurrentIndent $currentIndent
        $curId = $curNode.GetHashCode()

        # remove current node
        $lastVisitedNode = $queue[0]
        $null = $queue.RemoveAt(0)
        if ($layerASTNodes -contains $curNode.GetType().Name) {
            $currentIndent--
        }

        # update current node, strict substitute
        # eg: set a 2    may convert a to varxxx  when visit 'set' node
        # if ($null -ne $subNodeString[$curId] -and '' -ne $subNodeString[$curId]) {
        #     continue
        # }
        $subNodeString[$curId] = ''
        $curType = $curNode.GetType().Name
        $subNodeString[$curId] = Update-NodeExtent $curNode $hierarchy $hierarchyP $subNodeString $ScriptString 
        $childNodes = Get-ChildNodes -curNode $curNode -hierarchy $hierarchy -hierarchyP $hierarchyP
        
        $curstring = $subNodeString[$curId]
        

        # visit child node
        
        if ($curNode.GetType().Name -eq 'VariableExpressionAst'){ 

            $varName = Get-VariableName -VariableString $subNodeString[$curId]

            if ($var_in_str -contains $varName) {
                continue
            }

            if ($sysVariables -notcontains $varName -and $varName.toLower().StartsWith('env:') -eq $false) {
                if ($variables.Keys -notcontains $varName) {
                    $variables[$varName] = 'var' + [string]($variables.Count)  # replace old varname with varxxx
                    $subNodeString[$curId] = $subNodeString[$curId].replace($varName, $variables[$varName])
                }
                else {
                    $subNodeString[$curId] = $subNodeString[$curId].replace($varName, $variables[$varName])
                }
            }
        }
        elseif ($curNode.GetType().Name -eq 'CommandAst') {
            # if ($hierarchy[$curId].Count -ge 2 ) {
            if ($childNodes.Count -ge 2) {
                # $childrent = $hierarchy[$curId]
                $childrent = $childNodes
                $firstcommand = $subNodeString[$childrent[0].GetHashCode()]

                if ($SetVariable0 -Contains $firstcommand -or $SetVariable1 -Contains $firstcommand -or 
                    $GetVariable0 -Contains $firstcommand -or $GetVariable1 -Contains $firstcommand) {

                    $varNode = $childrent[1]  # leaf node
                    $varId = $varNode.GetHashCode()

                    if ($varNode.GetType().Name -ne 'StringConstantExpressionAst') { # error here for replacing
                        $varName = GetInvokeResult -CommandLine $varNode.Extent.Text 
                        # $oldVarName = GetInvokeVariableAssign @{} $oldVarNode.Extent.Text
                    }
                    else {
                        $varName = $varNode.Extent.Text
                    }
    
                    if ($varName -eq '') {
                        continue
                    }

                    $varName = $varName.trim("'`"")
                    if (($SetVariable1 -contains $firstcommand -or $GetVariable1 -contains $firstcommand) -and 
                        $varName.tolower().StartsWith('variable:')) {
                        $varName = $varName.SubString(9)
                    }

                    if ($var_in_str -contains $varName) {
                        continue
                    }

                    if ($sysVariables -notcontains $varName) {
                        if ($variables.Keys -notcontains $varName) {
                            $variables[$varName] = 'var' + [string]$variables.Count
                            $subNodeString[$varId] = $subNodeString[$varId].replace($varName, $variables[$varName])
                        }
                        else {
                            $subNodeString[$varId] = $subNodeString[$varId].replace($varName, $variables[$varName])
                        }
                        $subNodeString[$curId] = Update-NodeExtent $curNode $hierarchy $hierarchyP $subNodeString $ScriptString
                    }
                }
            }
        }

        if ($curNode.Parent -eq $ScriptBlock.Ast) {  # the whole script is done, return
            $startIdx = $ScriptBlock.Ast.Extent.StartOffset
            $curstartIdx = $curNode.Extent.StartOffset
            # foreach($childNode in $hierarchy[$curId]) {
            foreach($childNode in $childNodes) {
                $curstartIdx = [math]::min($curstartIdx, $childNode.Extent.StartOffset)
            }
            return ($ScriptString.Substring($startIdx, $curstartIdx - $startIdx) + $subNodeString[$curId])
        }
    }
}

Function Rename-FunctionNames {
    [CmdletBinding()] Param (
        [Parameter(Mandatory)]
        [String]
        $ScriptString
    )

    $Tokens = Tokenize -ScriptString $ScriptString
    $funcnames = @{}

    for ($i = 0; $i -lt $Tokens.Count; $i++) {
        $funcname = ''
        $Token = $Tokens[$i]
        if ($Token.Type -eq 'CommandArgument' -and $Tokens[$i-1].Content -eq 'function') {
            $funcname = $Token.Content
            if ($funcnames.keys -notcontains $funcname) {
                $funcnames[$funcname] = 'func' + [string]$funcnames.Count
            }
        }
    }

    # if ($funcnames.Keys.Count -eq 0) {
    #     return $ScriptString
    # }

    for ($i = $Tokens.Count-1; $i -ge 0; $i--) {
        $Token = $Tokens[$i]
        if ($Token.Type -eq 'CommandArgument') {
            $funcname = $Token.Content
            if ($funcnames.keys -contains $funcname) {
                $ScriptString = $ScriptString.SubString(0, $Token.Start) + $funcnames[$funcname] + $ScriptString.SubString($Token.Start+$Token.Length)
            }
        }
        elseif ($Token.Type -eq 'Command') {  # function usage
            $funcname = $Token.Content
            if ($funcnames.keys -contains $funcname) {
                $ScriptString = $ScriptString.SubString(0, $Token.Start) + $funcnames[$funcname] + $ScriptString.SubString($Token.Start+$Token.Length)
            }
        }
    }

    return $ScriptString
}

Function Rename-RandomName {
    [CmdletBinding()] Param (
        [Parameter(Mandatory)]
        [String]
        $ScriptString
    )

    $randomFlag = IsRandomName -ScriptString $ScriptString
    if ($randomFlag) {
        try {
            $ScriptString = Rename-Variables -ScriptString $ScriptString
        }
        catch {
            throw "Rename variables error!"
        }
        try{
            $ScriptString = Rename-FunctionNames -ScriptString $ScriptString
        }
        catch {
            throw "Rename functions error!"
        }
    }
    else {
        return $ScriptString
    }

    if (Test-Script -ScriptString $ScriptString) {
        return $ScriptString
    }
    else {
        throw "Rename-RandomName occurs error!"
    }

    return $ScriptString
}


# Rename-RandomName -ScriptString (Get-Content -raw ~/Desktop/demo )
# Rename-Variables -ScriptString (Get-Content -raw ~/desktop/demo)