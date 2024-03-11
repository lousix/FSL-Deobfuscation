Function IncludeVariable {
    [CmdletBinding()] param (
        [Parameter(Position = 0, Mandatory)]
        [String]
        $ScriptString
    )

    # $varTokens = Tokenize -ScriptString $ScriptString | Where-Object {$_.Type -eq 'Varaible'}
    # 11.05
    # $varTokens = Get-PSOneToken -Code $ScriptString -TokenKind Variable -IncludeNestedToken
    $varTokens = Get-SpecialToken -ScriptString $ScriptString -TokenType Variable
    if ($null -ne $varTokens) {
        return $true
    }
    return $false
}

Function IsNonMeaningString {
    [CmdletBinding()] param (
        [Parameter(Position = 0, Mandatory)]
        $Node
    )
    if (($Node.Extent.Text -eq $Node.Parent.Extent.Text) -and ($Node.Extent.Text -eq $Node.Parent.Parent.Extent.Text) -and 
        $Node.Parent.Parent.Parent.GetType().Name -eq 'NamedBlockAst') {
        return $true
    }
    return $false
}

$randomIex = @('IEX', 'Invoke-Expression', `
               "(`$ShellId[1]+`$ShellId[13]+'x')", 
               "(`$PSHome[4]+`$PSHome[30]+'x')", "(`$PSHome[21]+`$PSHome[30]+'x')", "(`$PSHome[4]+`$PSHome[34]+'x')", "(`$PSHome[21]+`$PSHome[34]+'x')",
               "(`$env:ComSpec[4,15,25]-Join'')", "(`$env:ComSpec[4,24,25]-Join'')", "(`$env:ComSpec[4,26,25]-Join'')",
               "((Get-Variable'*mdr*').Name[3,11,2]-Join'')", "((GV'*mdr*').Name[3,11,2]-Join'')", "((Variable'*mdr*').Name[3,11,2]-Join'')",
               "(`$VerbosePreference.ToString()[1,3]+'x'-Join'')",  "(([String]`$VerbosePreference)[1,3]+'x'-Join'')")

Function IsInvokeExpression {
    [CmdletBinding()] param(
        [Parameter(Position = 0, Mandatory)]
        $Node,

        [Parameter(Position = 1, Mandatory)]
        $hierarchy,

        [Parameter(Position = 2, Mandatory)]
        $hierarchyP,

        [Parameter(Position = 3, Mandatory)]
        $subNodeString
    )

    $iexExpression = @('IEX', 'Invoke-Expression')
    $content = $subNodeString[$Node.GetHashCode()]
    $childnodes = Get-ChildNodes $Node $hierarchy $hierarchyP
    if ($content[0] -eq '(' -or $content[0] -eq "'" -or $content[0] -eq '"') {  # eg: . 'iex' xxx
        $nowhitespace = $content -replace ' ', ''
        if ($randomIex -contains $nowhitespace) {
            return $true
        }

        try {
            $content = Invoke-Expression $content
        }
        catch {
            return $false
        }
    }

    if ($iexExpression -contains $content) {  
        return $true
    }

    if ($null -eq $childnodes) {
        return $false
    }

    $childContent = $subNodeString[$childnodes[0].GetHashCode()]

    if ($content[0] -eq '.' -or $content[0] -eq '&') {  # eg:  xxx | . 'iex'
        $nowhitespace = $childContent -replace ' ', ''  # judge by the known obfuscation
        if ($randomIex -contains $nowhitespace) {
            return $true
        }
        
        if ($childContent[0] -eq '(' -or $childContent[0] -eq "'" -or $childContent[0] -eq '"') {  # invoke it to string
            try {
                $childContent = Invoke-Expression $childContent
            }
            catch {
                return $false
            }
        }
        $childContent = $childContent -replace ' ', ''
        if ($randomIex -contains $childContent) {
            return $true
        }
    }

    return $false
}

Function IsPowerShell {
    [CmdletBinding()] param(
        [Parameter(Position = 0, Mandatory)]
        $Node,

        [Parameter(Position = 1, Mandatory)]
        $hierarchy,

        [Parameter(Position = 2, Mandatory)]
        $hierarchyP,

        [Parameter(Position = 2, Mandatory)]
        $subNodeString
    )

    $curId = $Node.GetHashCode()
    $curString = $subNodeString[$curId]
    if ($Node.GetType().Name -ne 'CommandAst' -or $curString.toLower().contains('powershell') -eq $false) {
        return $false
    }

    $childnodes = Get-ChildNodes $Node $hierarchy $hierarchyP
    $firstChildId = $childnodes[0].GethashCode()
    $firstChildStr = $subNodeString[$firstChildId]
    if ($curString[0] -eq '&' -or $curString[0] -eq '.') {
        if ($firstChildStr.trim('"''').tolower() -eq 'powershell') {
            return $true
        }
    }

    if ($firstChildStr.tolower() -eq 'powershell' -or $firstChildstr.tolower().contains('powershell.exe')) {
        return $true
    }

    if ($firstChildStr.contains('cmd')) {
        for ($i = 1; $i -lt $childnodes.count; $i++){
            $tmpId = $childnodes[$i]
            if ($subNodeString[$tmpId].toLower().contains('powershell')) {
                return $true
            }
        }
    }

    return $false
}

# https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.1
# invoke pipeline AST node code
Function Invoke-PipeLineCommand {
    [CmdletBinding()] param (
        [Parameter(Position = 0, Mandatory)]
        [String]
        $ScriptString
    )
    
    # check validation
    if ((Test-Script -ScriptString $ScriptString) -eq $false) { 
        Write-Host "Invalid Script"
        return $ScriptString
    }

    $ScriptBlock = [ScriptBlock]::Create($ScriptString)
    $functionNames = Get-FunctionNames -ScriptString $ScriptString

    # postorder traversal AST Nodes
    $hierarchy, $hierarchyP = GetHierarchy -ScriptBlock $ScriptBlock
    $queue = New-Object -TypeName System.Collections.ArrayList
    $null = $queue.Add($ScriptBlock.Ast)  

    $lastVisitedNode = $null
    $subNodeString   = @{}           # record the deobfuscated result for every AST node 

    $aliasCommand  = @('Set-Alias')  

    $sysVariables = [System.Collections.ArrayList](Get-Variable).Name
    # design a symbol table for tracing variables
    ######
    $SetVariable0     = @('Set-Variable','SV','Set')  # eg: Set m 3
    $SetVariable1     = @('Set-Item', 'SI')           # eg: Set-Item variable:m 3
    $GetVariable0     = @('Get-Variable','Variable')  # eg: (Get-Variable m).value
    $GetVariable1     = @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')  # eg: (Get-ChildItem variable:m).value

    $symbols          = @{}  # symbols tables, save variables and their value
    $sysSymbols       = @{}  # system variables
    $ofs              = ''

    $layerASTNodes  = @('NamedblockAst', 'IfStatementAst', 'WhileStatementAst', 'ForStatementAst', 'ForEachStatementAst', 'StatementBlockAst')
    $expressionType = @('String', 'Int32')
    $subNodeString  = @{}  # record the deobfuscated result for every AST node 
    $BannedNode     = @{}  # record whether the node includes malicious node
    $variableScope  = @{}  # eg: @{'foo' = 0, 'tmp' = 1} 
    $currentIndent  = -1

    $VarByGet       = $null

    # initialize symbols through sys variables
    $sysVars = Get-Variable 
    for($i = 0; $i -lt $sysVars.Name.count; $i++) {
        $varname = $sysVars.Name[$i]
        $sysSymbols[$varname] = $sysVars[$varname]
    }
    ######

    # preference variables https://docs.microsoft.com/zh-cn/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.1
    $preferenceVariable = @('ConfirmPreference', 'DebugPreference', 'ErrorActionPreference', 'ErrorView', 'FormatEnumerationLimit', 'InformationPreference', 'LogCommandHealthEvent', 'LogCommandLifecycleEvent', 'LogEngineHealthEvent', 'LogEngineLifecycleEvent', 'LogProviderLifecycleEvent', 'LogProviderHealthEvent', 'MaximumHistoryCount', 'OFS', 'OutputEncoding', 'ProgressPreference', 'PSDefaultParameterValues', 'PSEmailServer', 'PSModuleAutoLoadingPreference', 'PSSessionApplicationName', 'PSSessionConfigurationName', 'PSSessionOption', 'Transcript', 'VerbosePreference', 'WarningPreference', 'WhatIfPreference')
    $setCommand = ''  # Commands which change environment variable and set-alias

    $foreachAstNode = $null  # eg: foreach-object { xxx $_}
    $invokeStringTemp = ''
    
    while ($queue.Count -ne 0) {  # post traversal AST
        $curNode, $queue, $currentIndent = PostTraversal -Hierarchy $hierarchy -HierarchyP $hierarchyP -Queue $queue -LastVisitedNode $lastVisitedNode -CurrentIndent $currentIndent
        $curId = $curNode.GetHashCode()

        # remove current node
        $lastVisitedNode = $queue[0]
        $null = $queue.RemoveAt(0)

        # update indent
        if ($layerASTNodes -contains $curNode.GetType().Name) {
            $currentIndent--
        }
        
        $resInvoke = ''
        $commandline = ''
        $NoBanned = $false  # skip banned command or not

        # AST Node Content substitute
        $subNodeString[$curId] = ''
        $subNodeString[$curId] = Update-NodeExtent $curNode $hierarchy $hierarchyP $subNodeString $ScriptString
        # update Banned Nodes
        # $BannedNode[$curId] = Update-BannedNode $curNode $hierarchy $BannedNode $subNodeString

        $curString = $subNodeString[$curId]
        $curType   = $curNode.GetType().Name
        $childNodes = Get-ChildNodes $curNode $hierarchy $hierarchyP

        if ($curNode.Parent -eq $ScriptBlock.Ast) {  # the whole script is done, return
            $startIdx = $ScriptBlock.Ast.Extent.StartOffset

            $curstartIdx = $curNode.Extent.StartOffset
            for($i = 0; $i -lt $childNodes.Count; $i++) {
                $curstartIdx = [math]::min($curstartIdx, $childNodes[$i].Extent.StartOffset)
            }
            
            $res = ($ScriptString.Substring($startIdx, $curstartIdx -$startIdx) + $subNodeString[$curId])

            if (Test-Script -ScriptString $res) {
                return $res
            }
            else {
                # $res > ~/Desktop/error.txt
                throw "deobfuscate script occurs error! "
            }
        }
        else {  # deobfuscation as more as possible
            try {
                # avoid executing all variable nodes in loop
                try {
                    $vartokens = (Get-SpecialToken -ScriptString $curString -TokenType Variable).Count
                }
                catch {
                    
                }

                if ($vartokens -ne 0 -and (IsLoopVariable -Node $curNode)) {
                    Continue
                }   

                # powershell param https://blog.walterlv.com/post/powershell-startup-arguments.html
                # deobfuscate special stringconstant again  eg: powershell "xxx"  /  Invoke-Expression "xxx"
                if ($curNode.GetType().Name -eq 'PipelineAst') { 
                    $lastchild = $childNodes[-1]
                    $grandchildnodes = Get-ChildNodes $lastchild $hierarchy $hierarchyP
                    $mayiex = IsInvokeExpression -Node $grandchildnodes[0] -hierarchy $hierarchy -hierarchyP $hierarchyP -subNodeString $subNodeString
                    $maypowershell = IsPowerShell -Node $lastchild -hierarchy $hierarchy -hierarchyP $hierarchyP -subNodeString $subNodeString

                    $grandchildren = Get-ChildNodes $childNodes[0] $hierarchy $hierarchyP
                    $firstChildId0 = $grandchildren[0].GetHashCode() 
                    $firstChildstr = $subNodeString[$firstChildId0]

                    if ($maypowershell) {
                        $invokeString = $null
                        if ($childNodes.count -eq 1 -and $childNodes[0].GetType().Name -eq 'CommandAst') {
                            $childNode = $childNodes[0]
                            $childId   = $childNode.GetHashCode()
                            $grandChilds = Get-ChildNodes $childNode $hierarchy $hierarchyP

                            # check if contains base64 encoding
                            $encodebase64 = $false 
                            $encodeId = ''
                            for ($i = 0; $i -lt $grandChilds.Count-1; $i++) {  # traversal param of powershell
                                $curParam = $subNodeString[$grandChilds[$i].GetHashCode()].ToLower()
                                if ('-encodedcommand'.StartsWith($curParam) -or $curParam -eq '-ec') {
                                    $encodeId = $grandChilds[$i].GethashCode()
                                    $encodebase64 = $true
                                    break
                                }
                            }
                            

                            $lastGrandChild = $grandChilds[-1]
                            $lasttwoGrandChild = $grandChilds[-2]
                            # only deal with      -command 'string'
                            # if ('-command'.StartsWith($subNodeString[$lasttwoGrandChild.GetHashCode()].tolower()) -eq $false -and $encodebase64 -eq $false) {
                            #     continue
                            # }
                            
                            if ($encodebase64 -eq $false -and $lastGrandChild.GetType().Name -ne 'StringConstantExpressionAst' -and
                                $lastGrandChild.GetType().Name -ne 'ExpandableStringExpressionAst') {
                                continue
                            }

                            $stringparam = $subNodeString[$lastGrandChild.GetHashCode()]
                            if (($stringparam[0] -eq '"' -and $stringparam[-1] -eq '"') -or 
                                ($stringparam[0] -eq "'" -and $stringparam[-1] -eq "'")) {
                                # $stringparam = Invoke-Expression $stringparam
                                $stringparam = $stringparam.Substring(1, $stringparam.Length-2)
                            }
                            # write-host $lastGrandChild.GetType().Name $stringparam
                            if ($encodebase64 -and ($lastGrandChild.GetType().Name -eq 'StringConstantExpressionAst' -or $lastGrandChild.GetType().Name -eq 'CommandArgument' -or $subNodeString[$lastGrandChild.GetHashCode()][0] -eq "'")) {
                                # $stringparam = $subNodeString[$lastGrandChild.GetHashCode()]
                                # $stringparam = $stringparam.trim("'`"")
                                
                                $decodestr   = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($stringparam))
                            }
                            else {
                                $decodestr = $stringparam
                            }

                            $resInvoke = DeObfuscatedScript -ScriptString0 $decodestr
                            

                            if ($null -ne $resInvoke -and $resInvoke -ne '') {
                                $resInvoke = Convert-ObjectToString -SrcObject $resInvoke
                                $subNodeString[$lastGrandChild.GethashCode()] = $resInvoke
                            }
                            else {
                                $decodestr = Convert-ObjectToString -SrcObject $decodestr
                                $subNodeString[$lastGrandChild.GethashCode()] = $decodestr
                            }

                            if($encodeId -ne '') {
                                $subNodeString[$encodeId] = ''
                            }

                            $subNodeString[$childId] = Update-NodeExtent $childNode $hierarchy $hierarchyP $subNodeString $ScriptString
                            $subNodeString[$curId]   = Update-NodeExtent $curNode $hierarchy $hierarchyP $subNodeString $ScriptString
                            continue
                            
                        }
                        continue
                    }

                    # iex "xxx"
                    elseif ($mayiex -and $childNodes.count -eq 1) {
                        # write-host hhhh

                    }
                    # 'echo hello' | iex
                    elseif ($lastchild.GetType().name -eq 'CommandAst' -and $grandchildnodes.Count -eq 1 -and  
                            $childNodes.Count -ge 2){

                        $iexFlag = IsInvokeExpression -Node $lastchild -hierarchy $hierarchy -hierarchyP $hierarchyP -subNodeString $subNodeString

                        if ($iexFlag) {
                            $lastTwoChild = $childNodes[-2]
                            $len = $lastTwoChild.Extent.EndOffset - $curNode.Extent.StartOffset

                            #### here use original string ?  OR    modified string?
                            $invokeParam = $curNode.Extent.Text.SubString(0, $len)
                            $resInvoke = GetInvokeResult -CommandLine $invokeParam -Symbols $symbols 

                            if ($null -ne $resInvoke -and $resInvoke.ToString() -ne '' -and 
                                (($resInvoke[0] -eq "'" -and $resInvoke[-1] -eq "'") -or 
                                ($resInvoke[0] -eq '"' -and $resInvoke[-1] -eq '"'))) {
                                try {
                                    $noQuotationString = Invoke-Expression $resInvoke
                                    $subNodeString[$curId] = $noQuotationString
                                }
                                catch {
                                    $subNodeString[$curId] = "Invoke-Expression $resInvoke"
                                    continue
                                }

                                try {
                                    if (Test-Script -ScriptString $noQuotationString) {
                                        $resInvoke = DeObfuscatedScript -ScriptString0 $noQuotationString
                                    }
                                    else {
                                        $subNodeString[$curId] = "Invoke-Expression $resInvoke"
                                    }
                                }
                                catch {
                                    continue
                                }
                                if ($null -ne $resInvoke -and $resInvoke.ToString() -ne '') {
                                    $subNodeString[$curId] = $resInvoke
                                }
                            }
                        }
                    }


                    else {
                        $commandline = $subNodeString[$curId]
                        
                        foreach ($var in $aliasCommand) {  # sepecialCommand [set-alias] 
                            if ($subNodeString[$curId].Contains($var) -and $childNodes[0]) {
                                $childNodeId = $childNodes[0].GetHashCode()
                                $grandchildren = Get-ChildNodes $childNodes[0] $hierarchy $hierarchyP
                                if ($grandchildren.Count -eq 3 -and $aliasCommand -contains $grandchildren[0]) {
                                    $setCommand += $subNodeString[$curId] + '; '
                                }
                            }
                        }
 
                        $firstChild = $childNodes[0]
                        $firstChildId = $firstChild.GethashCode()
                        $firstChildNodes = Get-ChildNodes $firstChild $hierarchy $hierarchyP

                        # Meaningless String
                        if ($curNode.Parent.GetType().Name -eq 'NamedBlockAst' -and $childNodes.Count -eq 1 -and 
                            ($firstChildNodes[0].GetType().Name -eq 'StringConstantExpressionAst' -or $firstChildNodes[0].GetType().Name -eq 'ConstantExpressionAst') -and 
                            $curNode.Extent.Text -eq $firstChildNodes[0].Extent.Text) {
                            
                            $isFuncFlag = $false
                            foreach ($funcName in $functionNames) {
                                if ($curNode.Extent.Text -eq $funcName) {
                                    $subNodeString[$curId] = $curNode.Extent.Text
                                    $isFuncFlag = $true
                                    break
                                }
                            }
                            if ($isFuncFlag -eq $false) {
                                $subNodeString[$curId] = $null
                            }
                            
                            continue
                        }

                        # Situation： commandline  include  $_ only run the pipeline which includes foreach-object 
                        # A trouble here, every $_ should be included 
                        if ((IsCurVariableInScript -ScriptString $subNodeString[$curId]) -and (CurInForeachPipeLine -ScriptString $subNodeString[$curId])) {

                        }
                        elseif (IsCurVariableInScript -ScriptString $subNodeString[$curId]) {
                            continue
                        }

                        
                        $resInvoke = GetInvokeResult -CommandLine $commandline -Symbols $symbols # $setcommand -- sys variable  $commandline --  

                        if ($null -ne $resInvoke -and $resInvoke.ToString() -ne '') {  
                            if ($resInvoke.GetType().Name -eq 'String') {
                                $subNodeString[$curId] = $resInvoke
                            }
                            else {
                                $tmpResult = DeObfuscatedScript -ScriptString0 $resInvoke.ToString()
                                if ($null -ne $tmpResult -and $tmpResult.ToString() -ne '') {
                                    $subNodeString[$curId] = $tmpResult
                                }
                            }
                            continue 
                        }
                        continue

                    }
                }

                elseif ($curNode.GetType().Name -eq 'InvokeMemberExpressionAst') {  # compress;  [array]::reverse($pnac)

                    ## key issue: how to make the change of variables in emulator to the symbol table
                    if ($childnodes.count -eq 3 -and (IsLoopVariable -Node $curNode) -eq $false -and 
                        $childNodes[0].GetType().Name -eq 'TypeExpressionAst') {
                        
                        $varname = ''
                        if ($childNodes[2].GetType().Name -eq 'VariableExpressionAst') {
                            $varNode = $childNodes[2]
                            $varName = Get-VariableName -VariableString $subNodeString[$varNode.GethashCode()]
                        }
                        elseif ($childNodes[2].GetType().Name -eq 'ParenExpressionAst') {  # 这写的有问题？？？ 暂时没改
                            $pipeNode = Get-ChildNodes $childNodes[2] $hierarchy $hierarchyP
                            $commandastNodes = Get-ChildNodes $pipeNode[0] $hierarchy $hierarchyP
                            $commandAstNode = $commandAstNodes[0]
                            # $pipeNode = $hierarchy[$hierarchy[$curId][2].GetHashCode()]
                            # $commandastNode = $hierarchy[$pipeNode.GetHashCode()][0]
                            $varName = Get-VariableNameCall -Node $commandastNode -hierarchy $hierarchy -subNodeString $subNodeString
                        }
                        
                        if ($varName -eq '') {
                            continue
                        }

                        # eg: Invoke-Expression ([system.runtime.interopservices.marshal]::ptrtostringauto([system.runtime.interopservices.marshal]::securestringtobstr($C2 )))
                        if ($variableScope.Keys -contains $varName -and $variableScope[$varName] -le $currentIndent -and   
                            $symbols.Keys -contains $varName -and $curnode.Parent.GetType().Name -eq 'CommandExpressionAst') {
                            $commandline = $subNodeString[$curId] + ';' + '${' + $varName + '}'
                            
                            $resInvoke = GetInvokeResult -CommandLine $commandline -Symbols $symbols -Assign
                            if ($null -ne $resInvoke) {
                                $symbols[$varName] = $resInvoke
                            }
                        }
                        continue
                    }
                    $commandline = $subNodeString[$curId]
                }

                elseif (($curNode.GetType().Name -eq 'ConvertExpressionAst' -and $childNodes[0].Extent.Text -eq '[string]') -or 
                    $curNode.GetType().Name -eq 'BinaryExpressionAst') {
                        #($curNode.GetType().Name -eq 'BinaryExpressionAst' -and $curNode.Parent.GetType().Name -eq 'CommandExpressionAst')) { 
                    
                    if (IsCurVariableInScript -ScriptString $subNodeString[$curId]) {
                        if ((CurInForeachPipeLine -ScriptString $subNodeString[$curId]) -eq $false) {
                            Continue
                        }
                    }
                    
                    $commandline = $subNodeString[$curId]
                    $NoBanned = $true  # in this situation, the result is string generally.
                }

                # ++$a
                elseif ($curNode.GetType().Name -eq 'UnaryExpressionAst' -and $curnode.Parent.GetType().Name -eq 'CommandExpressionAst') {
                    $childNodes = Get-ChildNodes $curNode $hierarchy $hierarchyP

                    if ($childNodes.Count -eq 1 -and $childNodes[0].GetType().Name -eq 'VariableExpressionAst') {  # eg: $a++
                        if (IsLoopVariable -Node $curNode) {
                            continue 
                        }
                        $varNode = $childNodes[0]
                        $varId   = $varNode.GethashCode()

                        $varName = Get-VariableName -VariableString $subNodeString[$varId]
                        if ($varName -eq '' -or $null -eq $varName ) {
                            continue
                        }

                        if ($variableScope.Keys -contains $varName -and $variableScope[$varname] -le $currentIndent -and 
                            $symbols.Keys -contains $varName) {
                            
                            $commandline = $subNodeString[$curId] + ';' + '${' + $varName + '}'
                            $resInvoke = GetInvokeResult -CommandLine $commandline -Symbols $symbols -Assign 

                            if ($null -ne $resInvoke -and $resInvoke.ToString() -ne '') {
                                $valueToString = Convert-ObjectToString -SrcObject $resInvoke
                                if ($valueToString -ne '') {
                                    $subNodeString[$curId] = $valueToString
                                    $symbols[$varName] = $resInvoke
                                }
                            }
                        }
                        continue
                    }
                    else {  # eg: base encode

                        if (IsCurVariableInScript -ScriptString $subNodeString[$curId]) {
                            if ((CurInForeachPipeLine -ScriptString $subNodeString[$curId]) -eq $false) {
                                Continue
                            }
                        }
                        
                        $commandline = $subNodeString[$curId]
                        $NoBanned = $true  # in this situation, the result is string generally.
                    }
                }

                elseif ($curNode.GetType().Name -eq 'CommandExpressionAst' -and $curNode.Parent.GetType().Name -eq 'PipelineAst') {
                    if (IsCurVariableInScript -ScriptString $subNodeString[$curId]) {
                        if ((CurInForeachPipeLine -ScriptString $subNodeString[$curId]) -eq $false) {
                            Continue
                        }
                    }
                    
                    $commandline = $subNodeString[$curId]
                }
                
                elseif ($curNode.GetType().Name -eq 'VariableExpressionAst' -and $curNode.Extent.Text -eq '$_') {
                    $foreachAstNode = Resolve-CurVar -Node $curNode -hierarchy $hierarchy
                    Continue
                }

                elseif ($curNode.GetType().Name -eq 'VariableExpressionAst' -and $curNode.Parent.GetType().Name -eq 'AssignmentStatementAst') {  # the variable which be defined
                    if ((IsLoopVariable -Node $curNode) -eq $true) {
                        $varName = Get-VariableName -VariableString $subNodeString[$curId] #$curNode.Extent.Text
                        
                        $null = $variableScope.Remove($varName)
                        $null = $symbols.remove($varName)
                    }
                    continue
                }

                elseif ($curNode.GetType().Name -eq 'VariableExpressionAst' -and $curNode.Parent.GetType().name -ne 'AssignmentStatementAst') {
                    if ($curNode.Parent.GetType().name -eq 'UnaryExpressionAst') {
                        continue
                    }
                    if ((IsLoopVariable -Node $curNode) -eq $false) {
                        $curVar = Get-VariableName -VariableString $subNodeString[$curId]

                        if ($variableScope[$curVar] -le $currentIndent -and $symbols.Keys -contains $curVar) {
                            if ($curNode.Parent.GetType().Name -eq 'ExpandableStringExpressionAst') {  # eg: write-host "$m"
                                $subNodeString[$curId] = $symbols[$curVar].ToString().Replace('"', '""')
                            }
                            elseif ($expressionType -contains $symbols[$curVar].GetType().Name){
                                $varStr = Convert-ObjectToString -SrcObject $symbols[$curVar]
                                $subNodeString[$curId] = $varStr
                            }
                        }
                        elseif ($sysSymbols -contains $curVar -and $curVar -ne '_') {
                            continue
                            # 9.30 resolve or not system variables
                            # if ($curNode.Parent.GetType().Name -eq 'ExpandableStringExpressionAst') {
                            #     $subNodeString[$curId] = $sysSymbols[$curVar].ToString().Replace('"', '""')
                            # }
                            # elseif ($expressionType -contains $sysSymbols[$curVar].GetType().Name){
                            #     # -and 
                            #     #($curNode.Parent.GetType().Name -eq 'CommandAst' -or $curNode.Parent.GetType().Name -eq 'InvokeMemberExpressionAst')) {  # eg: echo $a
                            #     $varStr = Convert-ObjectToString -SrcObject $sysSymbols[$curVar]
                            #     $subNodeString[$curId] = $varStr
                            # }
                        }
                    }
                    continue
                }

                elseif ($curNode.GetType().Name -eq 'AssignmentStatementAst') {  # eg: $ofs = ''
                    # $curVar = $subNodeString[$hierarchy[$curId][0].GetHashCode()]
                    # $varName = Get-VariableName -VariableString $curVar

                    # if ($preferenceVariable.Contains($varName) -and $hierarchy[$hierarchy[$curId][1].GetHashCode()][0].GetType().Name -eq 'StringConstantExpressionAst') {  # expr is simple string
                    #     $setCommand += $subNodeString[$curId] + ";"
                    # }
                    # continue
                    
                    $assignLeftId  = $hierarchy[$curId][0].GetHashCode()  # eg: $a
                    $assignRightId = $hierarchy[$curId][1].GetHashCode()  # eg: 3 + 4
                    if ($childNodes[0].GetType().Name -eq 'VariableExpressionAst') {
                        $varLeft = Get-VariableName -VariableString $subNodeString[$assignLeftId]
                    }
                    else {  # eg: [byte[]]$shellcode1
                        $varLeft = Get-VariableNode -ScriptString $cur

                        if ($varLeft -eq '') {
                            continue
                        }
                    }

                    ### yes or no ??
                    # if expr have variable, don't process.
                    $nullVariables = GetNullVariablesInChildNodes -ScriptString $subNodeString[$assignRightId] -Symbols $symbols  

                    # if there are unresolved variable in expr, then giving up tracing
                    if ($null -ne $nullVariables) {  
                        for ($i = 0; $i -lt $nullVariables.count; $i++) {
                            $null = $variableScope.Remove($nullVariables[$i])
                            $null = $symbols.Remove($nullVariables[$i])
                        }
                        $null = $variableScope.Remove($varLeft)
                        $null = $symbols.remove($varLeft)

                        continue
                    }

                    # **** Can we get the value in another method? ****
                    $commandline = $subNodeString[$curId] + ";" + '${' + $varLeft + '}'

                    $noSubFlag = $false   
                    if ($childNodes[1].GetType().Name -eq 'CommandExpressionAst') {
                        $resInvoke = GetInvokeResult -CommandLine $commandline -Symbols $symbols -Assign  
                        
                        # $CommandExpressAstNode = $hierarchy[$curId][1]
                        $CommandExpressAstNode = $childNodes[1]
                        $CommandChilds = Get-ChildNodes $CommandExpressAstNode $hierarchy $hierarchyP

                        # ** how to simply continuous assignment？ **

                        if ($CommandChilds[0].GetType().Name -eq 'StringConstantExpressionAst') {
                            $noSubFlag = $true
                        }
                    }
                    else {
                        $resInvoke = GetInvokeResult -CommandLine $commandline -Symbols $symbols -Assign  # modify invoke
                        
                    }
                    
                    if ($null -ne $resInvoke -and $resInvoke.ToString() -ne '') {

                        $assignRes = Convert-ObjectToString -SrcObject $resInvoke  # the type of result which getinvokeresult return is object, need to convert to string

                        if (IsLoopVariable -Node $childNodes[0]) {  # if $variable is loop variable (like $i), skip, not record
                            continue
                        } 

                        if ($noSubFlag -eq $false -and $assignRes -ne '') {
                            $subAssignment = $subNodeString[$assignLeftId] + ' = ' +$assignRes  # $a += 2  =>  $a = x
                            $subNodeString[$curId] = $subAssignment  
                        }

                        if ($variableScope.Keys -contains $varLeft -and $variableScope[$varLeft] -le $currentIndent) {
                            $symbols[$varLeft] = $resInvoke
                        } 
                        else {
                            $variableScope[$varLeft] = $currentIndent
                            $symbols[$varLeft] = $resInvoke
                        }
                    }
                    else {  # assignment update failed, delete record to avoid error
                        $null = $variableScope.Remove($varLeft)
                        $null = $symbols.remove($varLeft)
                    }

                    continue

                }

                # eg: $([string](echo 'hello'))
                elseif ($curNode.GetType().Name -eq 'SubExpressionAst') {
                    if (IsCurVariableInScript -ScriptString $subNodeString[$curId]) {
                        continue
                    }
                    $commandline = $subNodeString[$curId]
                    # $CurObfuscatedTech = 'SubExpression'
                }

                # eg:  (Get-Variable m).value  (Get-ChildItem variable:m).value
                elseif ($curNode.GetType().Name -eq 'MemberExpressionAst') {
                    $firstChild = $childNodes[0]
  
                    if ($childNodes.count -eq 2 -and $subNodeString[$childNodes[1].GetHashCode()] -eq 'value') { 

                        $commandAstNodes = Get-ChildNodes $firstChild $hierarchy $hierarchyP
                        $commandAstNodes = Get-ChildNodes $commandAstNodes[0] $hierarchy $hierarchyP
                        $commandAstNode = $commandAstNodes[0]
                        $commandAstNodeId = $commandAstNode.GetHashCode()
                        $childcommandAstNode = Get-ChildNodes $commandastNode $hierarchy $hierarchyP

                        if ($commandAstNode.GetType().Name -eq 'CommandAst' -and $childcommandAstNode.count -ge 2 -and
                            $childcommandAstNode[0].GetType().Name -eq 'StringConstantExpressionAst') {

                            $curtype = $childcommandAstNode[1].GetType().name 
                            $curtypeId = $childcommandAstNode[1].GetType().GethashCode()

                            $getVarCommand = $subNodeString[$childcommandAstNode[0].GetHashCode()]
                            $getVarString = $subNodeString[$childcommandAstNode[1].GetHashCode()]
                            $getVarName = ''

                            if ($GetVariable0 -contains $getVarCommand -or $GetVariable1 -contains $getVarCommand) {
                                if ($childcommandAstNode[1].GetType().Name -eq 'StringConstantExpressionAst') {
                                    $getVarName = $getVarString
                                }
                                else {
                                    $getVarName = GetInvokeResult -CommandLine $getVarString 
                                }
                                $getVarName = $getVarName.trim("'`"")
                            }
                            else {
                                Continue
                            }

                            if ($GetVariable1 -contains $getVarCommand -and $getVarName.tolower().StartsWith('variable:')) {  # eg: Get-ChildItem variable:m
                                $getVarName = $getVarname.SubString(9)
                            }
                            elseif ($GetVariable1 -contains $getVarCommand) {
                                Continue
                            }

                            if ($getVarName -eq '' -or $null -eq $getVarName) {
                                Continue
                            }

                            if ($symbols.Keys -contains $getVarName -and $variableScope[$getVarName] -le $currentIndent) { 
                                $resString = Convert-ObjectToString -SrcObject $symbols[$getVarName]
                                
                                if ($resString -ne '') {
                                    $subNodeString[$curId] = $resString
                                }
                            }
                        }
                    }
                    Continue
                }

                # eg: iex 'write-host hello'
                elseif ($curnode.GetType().Name -eq 'CommandAst') {
                    if ($childNodes.count -eq 2) {
                        $firstChild = $childNodes[0]
                        $iexFlag = IsInvokeExpression -Node $firstChild -hierarchy $hierarchy -hierarchyP $hierarchyP -subNodeString $subNodeString
                        
                        ### use original string or changed string 
                        $secondContent = $subNodeString[$childNodes[1].GetHashCode()]

                        # here maybe need to use first content
                        if ($iexFlag) {
                            $resInvoke = GetInvokeResult -CommandLine $secondContent -Symbols $symbols # -NoBanned
                            if ($null -ne $resInvoke -and $resInvoke.Tostring() -ne '' -and 
                                $resInvoke[0] -eq "'" -and $resInvoke[-1] -eq "'") {
                                try {
                                    $noQuotationString = Invoke-Expression $resInvoke
                                    $subNodeString[$curId] = $noQuotationString
                                }
                                catch {
                                    $subNodeString[$curId] = "Invoke-Expression $resInvoke"
                                    continue
                                }

                                try {
                                    if (Test-Script -ScriptString $noQuotationString) {
                                        $resInvoke = DeObfuscatedScript -ScriptString0 $noQuotationString 
                                    }
                                    else {
                                        $subNodeString[$curId] = "Invoke-Expression $resInvoke"
                                        continue
                                    }
                                }
                                catch {
                                    $subNodeString[$curId] = "Invoke-Expression $resInvoke"
                                    continue
                                }

                                if ($null -ne $resInvoke -and $resInvoke.ToString() -ne '') {
                                    $subNodeString[$curId] = $resInvoke
                                    continue
                                }
                            }
                            continue
                        }
                    }

                    if ($childNodes.Count -ge 2) {
                        $childrent = $childNodes
                        if ($childrent[0].GetType().Name -eq 'StringConstantExpressionAst') {
                            $setVarName = ''
                            $setCommand = $subNodeString[$childrent[0].GetHashCode()]
                            if ($SetVariable0 -contains $setCommand -or $SetVariable1 -contains $setCommand) {
                                if ($childrent[1].GetType().Name -eq 'StringConstantExpressionAst') {
                                    $setVarname = $subNodeString[$childrent[1].GetHashCode()]
                                }
                                else {
                                    $setVarName = GetInvokeResult -CommandLine $subNodeString[$childrent[1].GethashCode()]
                                }
                                $setVarName = $setVarName.trim("'`"")
                            }
                            else{
                                Continue
                            }

                            if ($SetVariable1 -contains $setCommand -and $setVarName.toLower().StartsWith('variable:')) {  # eg: Set-Item variable:m 3
                                $setVarName = $setVarName.SubString(9)
                            }
                            elseif ($SetVariable1 -contains $setCommand) {
                                Continue
                            }

                            if ($setVarName -eq '') {
                                Continue
                            }

                            $commandline = $subNodeString[$curId] + '; ${' + $setVarName + '}'
                            $setValue = GetInvokeResult -CommandLine $commandline -Symbols $symbols -Assign 

                            
                            ### change '' to null
                            if ($setVarName -eq 'ofs') {
                                continue
                            }
                            if ($null -ne $setValue -and $setValue -ne '') {
                                $variableScope[$setVarName] = $currentIndent
                                $symbols[$setVarName] = $setValue
                            }
                            continue
                        } 
                        else {
                            continue
                        }
                    }

                }

                if ($commandline -eq '') {  
                    continue
                }

                # Write-Verbose "invoke code: $commandLine" 
                $resInvoke = GetInvokeResult -CommandLine $commandline -Symbols $symbols

                if ($null -ne $resInvoke -and $resInvoke.ToString() -ne '') {
                    # eg: $ofs = "`r'n"
                    if ($curNode.GetType().Name -eq 'CommandExpressionAst' -and $childNodes[0].GetType().Name -eq 'StringConstantExpressionAst') {    
                    
                    } 
                    else {
                        $subNodeString[$curId] = $resInvoke
                    }
                }
            }
            catch {
                Continue
            }
        }
    }
}

Function DeObfuscatedScript {
    [CmdletBinding()] Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString0
    )

    # PS console color: Black DarkBlue DarkGreen DarkCyan DarkRed DarkMagenta DarkYellow Gray DarkGray 
    #                   Blue Green Cyan Red Magenta Yellow White
    try {
        $originScript = $ScriptString0
        $ScriptString0 = Remove-TicksAndRandomCase -ScriptString $ScriptString0 
    } catch {
        $ScriptString0 = $originScript
        Write-Verbose $_
    }

    # Write-Host "After Token Parsing:`n$ScriptString0`n" -foregroundcolor blue

    try {
        $null = [Scriptblock]::create($ScriptString0)
    } catch {
        $errormessage = $_.Exception.ErrorRecord.toString(); 
        write-host $errormessage
        # $errormessage  -match "(line:\d+)"
    }
    
    try {
        $originScript = $ScriptString0
        $ScriptString0 = Invoke-PipeLineCommand -ScriptString $ScriptString0 
    } catch {
        $ScriptString0 = $originScript
        Write-Verbose $_
    }
    # Write-Host "After Recovering Based on AST:`n$ScriptString0`n" -foregroundcolor yellow
    
    Return $ScriptString0
}

Function PostProcess {  # Rename Variable + Beautifier Code
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        $ScriptString0
    )

    try {  # Rename 
        $ScriptString0 = Rename-RandomName -ScriptString $ScriptString0 
    }
    catch {
        Write-Verbose $_
    }

    try {  # Beautifier
        $ScriptString0 = Beautfier -ScriptString $ScriptString0 
    }
    catch {
        Write-Verbose $_
    }

    # Write-Host "After Rename&Reformat:`n$ScriptString0`n" -foregroundcolor green

    return $ScriptString0
}


# main function
Function DeObfuscatedMain {
    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString0,

        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptPath0  # To Avoid the influence of variable name
    )
    
    # Either convert ScriptBlock to a String or convert script at $ScriptPath0 to a String.
    if($PSBoundParameters['ScriptPath0']) {
        Get-ChildItem $ScriptPath0 -ErrorAction Stop | Out-Null
        $ScriptString0 = [IO.File]::ReadAllText((Resolve-Path $ScriptPath0))
    }

    try {
        $ScriptString0 = DeObfuscatedScript -ScriptString0 $ScriptString0
    }
    catch {
        Write-Verbose $_
        write-host $PSItem
    }


    try {
        $ScriptString0 = PostProcess -ScriptString0 $ScriptString0
    }
    catch {

        Write-Verbose $_
    }

    Return $ScriptString0 
}

# this function only accepts the param of path
Function Invoke-Deobfuscate {
    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param(
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptPath0,  # To Avoid the influence of variable name

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        $WorkDir,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        $Timeout = 5
    )
    
    if (-not (Test-Path $ScriptPath0)) {
        throw "No such file"
    }
    $ScriptDir = (Get-Item $ScriptPath0).Directory.FullName 
    $FileName = (Get-Item $ScriptPath0).Name
    $ResFile = Join-Path $ScriptDir "de-$FileName"

    $argumentString = "-Command cd $WorkDir;
    Import-Module ./Invoke-DeObfuscation.psd1;
    try {
        `$res = DeObfuscatedMain -ScriptPath0 $ScriptPath0;
        if (`$null -ne `$res -and `$res -ne '') {
            # `$res > $ResFile
            return `$res
        }
    }
    catch {
        `$_ > $ResFile
        `$pwd >> $ResFile
        return `$res
    }
    "

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "pwsh"
    $pinfo.CreateNoWindow = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $argumentString

    $p = New-Object System.Diagnostics.Process 
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null 

    if (-not $p.WaitForExit($Timeout*100)){
        Stop-Process $p
        Write-Host -ForegroundColor Red "$($timeout) second timeout hit when executing decoder. Killing process and breaking out"
        break    
    }

    $resScript = $p.StandardOutput.ReadToEnd()
    $stderr    = $p.StandardError.ReadToEnd()

    if ($p.ExitCode -eq 0) {
        # write-host $resScript
        return $resScript
    }
    else {
        # write-host 'non-zero exit'
        return ''
    }
}

# $a = DeObfuscatedMain -ScriptPath0 ~/Desktop/pwsh-demo/1.ps1
# write-host $a -ForegroundColor blue

# Invoke-Deobfuscate -ScriptPath0 ~/desktop/demo.ps1
# $null = DeObfuscatedMain -ScriptPath0 ~/Desktop/demo.ps1

# Test-Script -ScriptString $res 

# Measure-Command {$res = DeObfuscatedMain -ScriptPath0 ~/desktop/long}

# $scriptstring = Remove-TicksAndRandomCase -scriptstring (Get-content -raw ~/desktop/demo)
# write-host $scriptString -foregroundcolor Yellow

# $ScriptString = Invoke-PipeLineCommand -scriptstring $scriptString
# write-host $ScriptString -foregroundcolor Blue

# Rename-Variables -scriptString $scriptString