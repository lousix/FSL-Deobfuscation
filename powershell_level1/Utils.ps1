Function GetScriptString {
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )
    
    if ($PSBoundParameters.Keys -icontains "Path") {
        if (-not (Test-Path $path)) {
            throw "No such file"
        }
        $ScriptString = Get-Content $path -Raw
    }
    else {
        $ScriptString = [String]$ScriptBlock
    }
    return $ScriptString
}

# Test whether the script is valid
Function Test-Script {
    [CmdletBinding()] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,

        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    # Either convert ScriptBlock to a String or convert script at $Path to a String.
    if($PSBoundParameters['Path']) {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }

    # $isValiadScript = $false
    try {
        $null = [scriptblock]::Create($ScriptString)
        return $true
        # $isValiadScript = $true
    } catch {
        return $false
        # write-Verbose $PSItem
    }

    return $false
    # return $isValiadScript
}

# Parses a PowerShell Script and returns the token
function Get-SpecialToken
{
    [CmdletBinding()]
    param
    (
        # PowerShell Code 
        [String]
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='ScriptString')]
        $ScriptString,
    
        # the type of token requested.
        [String[]]
        $TokenType = $null
    )
    
    $tokens = Tokenize -ScriptString $ScriptString
    for($i = 0; $i -lt $tokens.Count; $i++) {
        if ($null -eq $TokenType -or $TokenType -contains $tokens[$i].Type){
            $tokens[$i]
        }
    }
    # $tokens | & { process {
    #     if ($null -eq $TokenType -or $TokenType -contains $_.Type) {
    #         $_
    #     }
    # }}
}

# Get the script's tokens
Function Tokenize {
    [CmdletBinding()] Param (
        [Parameter(Mandatory)]
        [String]
        $ScriptString
    )

    if (Test-Script -ScriptString $ScriptString) {
        return [System.Management.Automation.PSParser]::Tokenize($ScriptString, [ref]$null) 
    }
    return $null
}

# Construct the Hierarchy of the Script's AST
Function GetHierarchy {
    [CmdletBinding()] Param (
        [Parameter(Mandatory)]
        [ScriptBlock]
        $ScriptBlock
    )

    # $ScriptBlock = [ScriptBlock]::Create($ScriptString)
    $hierarchy = @{}
    $hierarchyP = @{}

    $predicate = {$True}
    $recurse = $True

    try {
        $nodes = $ScriptBlock.Ast.FindAll($predicate, $recurse)
        for($i = 0; $i -lt $nodes.count; $i++) {
            $curnode = $nodes[$i]
            if ($null -ne $curnode.Parent) {
                $id = $curnode.Parent.GetHashCode()
                if ($null -ne $curnode.Parent.Parent) {
                    $parentid = $curnode.Parent.Parent.GetHashCode()
                }
                else {
                    $parentid = 0
                }


                if ($hierarchy.ContainsKey($id) -eq $false) {
                    $hierarchy[$id] = [System.Collections.ArrayList]@()
                    $hierarchyP[$id] = [System.Collections.ArrayList]@()
                }
                $null = $hierarchy[$id].Add($curnode)
                $null = $hierarchyP[$id].Add($parentid)
            }
        }
        # $ScriptBlock.Ast.FindAll($predicate, $recurse) |
        # ForEach-Object {
        #     # take unique object hash as key
        #     # use grandparent's hash to avoid hash collision
        #     if ($null -ne $_.Parent) {
        #         $id = $_.Parent.GetHashCode()
        #         if ($null -ne $_.Parent.Parent) {
        #             $parentid = $_.Parent.Parent.GetHashCode()
        #         }
        #         else {
        #             $parentid = 0
        #         }


        #         if ($hierarchy.ContainsKey($id) -eq $false) {
        #             $hierarchy[$id] = [System.Collections.ArrayList]@()
        #             $hierarchyP[$id] = [System.Collections.ArrayList]@()
        #         }
        #         $null = $hierarchy[$id].Add($_)
        #         $null = $hierarchyP[$id].Add($parentid)
        #     }
        # }
    }
    catch {
        return @{}, @{}
    }

    return $hierarchy, $hierarchyP
}

# visualize tree recursively
# reflink: https://powershell.one/powershell-internals/parsing-and-tokenization/abstract-syntax-tree
Function Convert-CodeToAst {
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [String]
        $ScriptString,

        [Parameter(Position = 0)]
        [String]
        $Path
    )

    if ($PSBoundParameters["Path"]) {
        if(-not (Test-Path $path)) {       
            throw "No such file"
        }
        $ScriptString = Get-Content $path -Raw 
        
    } 
    elseif ($PSBoundParameters["ScriptString"]) {

    } 
    else {
        throw "No Arguments"
    }

    try{
        $ScriptBlock = [ScriptBlock]::Create($ScriptString)
    }
    catch {
        throw "ScriptString can not parser"
    }

    # build a hashtable for parents
    $hierarchy, $hierarchyP = GetHierarchy -ScriptBlock $ScriptBlock
    if ($hierarchy.Count -eq 0) {
       Write-Host "Convert Code to AST Error" 
       return 
    }
    
    # visualize tree recursively
    Function Visualize-Tree($Id, $Indent = 0) {
        # use this as indent per level:
        $space = '--' * $indent
        $hierarchy[$id] | ForEach-Object {
            # output current ast object with appropriate
            $nodeAst = '{0}[{1}]: {2} {3} {4}' -f $space, $_.GetType().Name, $_.Extent.StartOffset, $_.Extent.Endoffset, $_.Extent.Text 
            write-host $nodeAst
            # take id of current ast object 
            $newid = $_.GetHashCode()
            # recursively look at its children (if any):
            if ($hierarchy.ContainsKey($newid)) {
                Visualize-Tree -id $newid -indent ($indent + 1)
            }

        }
    }

    # start visualization with ast root object:
    Visualize-Tree -Id $ScriptBlock.Ast.GetHashCode()
}

# Invoke powershell segment and return the result of execution
Function GetInvokeResult {
    [CmdletBinding()] param (
        [Parameter(Position = 0, Mandatory)]
        [String]
        $CommandLine,

        [Parameter(Position = 1)]  # import symbols for tracing variables
        [Hashtable]
        $Symbols, 

        [Switch]  # variable assignment 
        $Assign
    )
    
    # avoid invoking commands which can affect system status
    $BannedCommands = @('cmd', 'cmd.exe', 'get-wmiobject', 'taskkill', 'shutdown.exe',
        'iex', 'invoke-expression', 'invoke-webrequest', 'invoke-shellcode', 'invoke-command', 'invoke-item',
        'start-bitstransfer', 'createthread', 'memset', 'virtualalloc',  'stop-process', 
        'net.sockets.tcpclient', 'restart', 'shutdown', 'download', 'set-content', 'new-item', 
        'remove-item', 'start-process', 'start-sleep', 'sleep', 'create', 'shouldcontinue', 'readkey', 'write', 'exit', 
        'save', 'logoff', 'get-credential', 'main', 'invoke', 'downloadstring', 'test-connection', 'wget', 'mkdir', 
        'start-job', 'create', 'restart-computer', 'terminate', 'add-type', 'read-host')  

    
    # $tokens = Tokenize -ScriptString $CommandLine | Where-Object {$_.type -eq 'Command' -or $_.type -eq 'CommandArgument' -or $_.type -eq 'Member'}
    # for ($i = 0; $i -lt $tokens.Count; $i++) {
    #     if ($BannedCommands -contains $tokens[$i].Content.tolower() -or $tokens[$i].content.tolower().StartsWith('system.net')) {
    #         return ''
    #     }
    # }

    $tokens = Get-SpecialToken -ScriptString $CommandLine -TokenType Command, CommandArgument, Member
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if ($BannedCommands -contains $tokens[$i].Content.tolower() -or $tokens[$i].content.tolower().StartsWith('system.net')) {
            return ''
        }
    }

    # nobanned execute it directly
    $tokens = Tokenize -ScriptString $CommandLine 
    for($i = 0; $i -lt $tokens.Count; $i++) {
        $token = $Tokens[$i]
        if ($token.Type -eq 'String') {
            if (($i -gt 0 -and ($Tokens[$i-1].Content -eq '.' -or $Tokens[$i-1].Content -eq '&')) -or  # . 'iex'
                ($i -gt 1 -and ($Tokens[$i-2].Content -eq '.' -or $Tokens[$i-2].Content -eq '&'))) {   # .('iex')
                if ($BannedCommands -contains $token.Content.ToLower()) {
                    return ''
                }
            }
            
        }
        elseif($token.type -eq 'Keyword' -and $token.Content.tolower() -eq 'function') {
            return ''
        }
    }
    
    # if commanline contains undefined variable, don't invoke it. except for assignment
    if ($null -ne (GetNullVariablesInChildNodes -ScriptString $CommandLine -Symbols $Symbols) -and $Assign -eq $false) {
        return ''
    }
    
    if ($null -ne $Symbols) {
        $SymbolsString = ''
        foreach ($var in $Symbols.Keys) {  # use the simulator to assign values to variables
            $tmpvar = $var.replace("'", "''")
            $SymbolsString = $SymbolsString + '${' + "$var" + '} = $Symbols[' + "'$tmpvar'];"
        }
        $CommandLine = $SymbolsString + $CommandLine
    }

    try {
        $codeSegment = [ScriptBlock]::Create($CommandLine);
        $output = $codeSegment.Invoke()
    } catch {
        return ''
    }

    if ($null -ne $output -and $Assign) {
        if ( $output.GetType().Name -eq 'Collection`1' -and $output.Count -eq 1) {
            return $output[0]
        }
        return $output
    }

    if ($null -eq $output -or $output -eq '') {
        return ''
    }
    
    if ($Assign) {
        return $output
    }
    else {
        if ($CommandLine.Contains('..') -and 
            $output.GetType().Name -eq 'Collection`1' -and $output.Count -gt 1) {
            return ''
        }
        elseif ($output.Count -gt 0) {
            return (Convert-ObjectToString -SrcObject $output)
        }
        else {
            return ''
        }
    }
    
}

Function Convert-ObjectToString {
    [CmdletBinding()] param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        $SrcObject
    )

    $srcVar = ''
    if ($SrcObject.Count -eq 1) {
        if ($SrcObject.GetType().Name -eq 'Collection`1') {
            $srcVar = $SrcObject[0]
        }
        else {
            $srcVar = $SrcObject
        }

        if ($null -eq $srcVar -or $srcVar.ToString() -eq '') {
            return ''
        }
        elseif ($srcVar.GetType().Name -eq 'String') {
            if ($srcVar.Contains("'")) {
                $srcVar = $srcVar.replace("'", "''")
            }
            $srcVar = "'" + $srcVar + "'"
        }
        elseif ($srcVar.GetType().Name -eq 'Int32') {
            $srcVar = $srcVar.ToString()
        }
        elseif ($srcVar.GetType().Name -eq 'ScriptBlock') {  # remain the special type to deobfuscate iteratively
            
        }
        else {
            return ''
        }
        return $srcVar
    }
    elseif ($SrcObject.GetType().Name -eq 'Collection`1' -and $SrcObject.Count -gt 1) {
        
        $resultStr = '@('
        
        # foreach ($var in $SrcObject) {
        for ($i = 0; $i -lt $SrcObject.Count; $i++) {
            $var = $SrcObject[$i]
            if ($var.GetType().Name -eq 'String'){
                if ($var.contains("'") -eq $true) {
                    $var = $var.replace("'", "''")
                }
                $resultStr += "'" + $var + "'," 
            }
            elseif ($var.GetType().Name -eq 'Int32') {
                $resultStr += $var.ToString() + ','
            }
            else {
                $resultStr = $null
                break
            }
        }

        if ($null -ne $resultStr) {  # remove the last comma
            $resultStr = $resultStr.Substring(0, $resultStr.Length-1) + ')'
            return $resultStr
        }
        else {
            return ''
        }
    }
    
    return ''
}

# if assignment right expr include null variable, give up simplying the expr
Function GetNullVariablesInChildNodes {
    [CmdletBinding()] param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,

        [Parameter(Position = 1)]
        [Hashtable]
        $Symbols
    )

    $variables   = New-Object -TypeName System.Collections.ArrayList
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($ScriptString, [ref]$null, [ref]$null)

    # include command ast objects only
    $predicate = { param($astObject) $astObject -is [System.Management.Automation.Language.VariableExpressionAst]}
    # search for all ast objects, including nested scriptblocks
    $recurse = $true

    $varNodes = $ast.FindAll($predicate, $recurse) 
    for($i = 0; $i -lt $varNodes.count; $i++) {
        $curNode = $varNodes[$i]
        $varname = Get-VariableName -VariableString $curNode.Extent.Text

        if ($varname -eq '_' -or ($null -ne $symbols -and $symbols.keys -contains $varname)) {
            continue
        }

        if ((Get-Variable).Name -contains $varname -eq $false -and $variables -contains $varname -eq $false) {
            $null = $variables.Add($varname)
        }
    }

    # foreach($curNode in $varNodes) {
    #     $varname = Get-VariableName -VariableString $curNode.Extent.Text

    #     if ($varname -eq '_' -or ($null -ne $symbols -and $symbols.keys -contains $varname)) {
    #         continue
    #     }

    #     if ((Get-Variable).Name -contains $varname -eq $false -and $variables -contains $varname -eq $false) {
    #         $null = $variables.Add($varname)
    #     }
    # }

    if ($variables.Count -eq 0){  # -or ($variables.Count -eq 1 -and $variables[0] -eq '_')) {
        return $null
    }
    else {
        return $variables
    }

}

Function IsLoopVariable {
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Node
    )
    $LoopNodes = @('IfStatementAst', 'WhileStatementAst', 'ForStatementAst', 'ForEachStatementAst', 'DoWhileStatementAst')
    $LoopKeys  = @('foreach-object')  # after token parsing, % => foreach

    if ($Node.Extent.Text -eq '$_') {
        return $true
    }

    while ($null -ne $Node.Parent) { 
        if ($LoopNodes -contains $Node.Parent.GetType().Name) {  
            return $true
        }
        else {
            for ($i = 0; $i -lt $LoopKeys.Count; $i++) {
                if ($Node.Parent.Extent.Text.tolower().StartsWith($LoopKeys[$i]) -and $Node.Parent.GetType().Name -eq 'CommandAst') {
                    return $true
                }
            }
            $Node = $Node.Parent
        }
    }

    return $false
}

Function IsInPipe {
    [CmdletBinding()] param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Node
    )

    while ($null -ne $Node.Parent -and $null -ne $Node.Parent.Parent) {
        if ($Node.Parent.GetType().Name -eq 'CommandAst' -and $Node.Parent.Parent.GetType().Name -eq 'PipelineAst') {
            $pipeNode = Get-SpecialToken -ScriptString $Node.Parent.Parent.Extent.Text -TokenType 'Operator' | Where-Object {$_.Content -eq '|'}
            if ($null -ne $pipeNode) {
                return $true
            }
        }
        else {
            $Node = $Node.Parent
        }
    }

    return $false
}

# never called ?
Function IsInAssginment {
    [CmdletBinding()] param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Node,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        $hierarchy
    )

    $OriginText = $Node.Extent.Text

    while ($null -ne $Node.Parent) {
        if ($Node.Parent.GetType().Name -eq 'AssignmentStatementAst') {
            $parentId = $Node.Parent.GetHashCode()
            if ($hierarchy[$parentId][0].Extent.Text.Contains($OriginText)) {
                return $true
            }
            else{
                return $false
            }
        }
        else {
            $Node = $Node.Parent
        }
    }

    return $false
}

# if "$_" in foreach-object {}, it can be resolved
Function Resolve-CurVar {
    [CmdletBinding()] param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Node,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        $hierarchy
    )

    while ($null -ne $Node) {
        if ($Node.GetType().Name -eq 'ScriptBlockExpressionAst') {
            $parentId = $Node.Parent.GetHashCode()
            $broNode = $hierarchy[$parentId][0]
            if ($broNode.GetType().Name -eq 'StringConstantExpressionAst' -and ($broNode.Extent.Text -eq 'foreach-object' -or 
            $broNode.Extent.Text -eq '%')) {
                return $Node.Parent  # CommandAst Node
            }            
        }
        if ($null -ne $Node.Parent) {
            $Node = $Node.Parent
        }
        else {
            return $null
        }        
    }

    return $null
}

# Is $_ in %{} ?
Function CurInForeachPipeLine {
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $ScriptString
    )

    if ($ScriptString.ToLower().Contains('$_') -and $ScriptString.ToLower().Contains('foreach-object')) {

    }
    else {
        return $false
    }

    $tokens = Tokenize -ScriptString $ScriptString

    $inloop, $resFlag = $false, $false
    $indent = 0
    $forCommands = @('%', 'foreach', 'foreach-object')
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if ($inloop -eq $false -and $tokens[$i].Type -eq 'Command'){  
            if ($forCommands -contains $tokens[$i].Content.ToLower()) {
                $inloop = $true
            }
        }
        if ($tokens[$i].Type -eq 'GroupStart' -and $Tokens[$i].Content -eq '{' -and $inloop) {
            $indent += 1
        }
        elseif ($tokens[$i].Type -eq 'GroupEnd' -and $Tokens[$i].Content -eq '}' -and $inloop) {
            $indent -= 1
            if ($indent -eq 0) {
                $inloop = $false
            }
        }
        elseif ($tokens[$i].Type -eq 'Variable' -and $tokens[$i].Content -eq '_') {
            if ($inloop) {
                $resFlag = $true
            }
            else {
                return $false
            }
        }
    }

    return $resFlag
}

# get variable name, without '$' '{' '}'  eg: ${m}  => m
# Token parse can get the varaible name directly, thus don't need this function. If used, errors!!!
Function Get-VariableName {
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $VariableString
    )

    if ($VariableString[0] -eq '$') {
        $VariableString = $VariableString.Substring(1).trim("{}")
    }

    return $VariableString
}

# get variable name, Get Variable:m -value
Function Get-VariableNameCall {
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Node, 

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        $hierarchy,
        
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        $subNodeString
    )

    $SetVariable0     = @('Set-Variable','SV','Set')  # eg: Set m 3
    $SetVariable1     = @('Set-Item', 'SI')           # eg: Set-Item variable:m 3
    $GetVariable0     = @('Get-Variable','Variable')  # eg: (Get-Variable m).value
    $GetVariable1     = @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')  # eg: (Get-ChildItem variable:m).value

    $nodeId = $Node.GethashCode()
    if ($Node.GetType().Name -eq 'CommandAst') {
        $childNodes = $hierarchy[$nodeId]
        $firstChildText = $subNodeString[$childNodes[0].GetHashCode()]
        if ($childNodes.Count -ge 2 -and ($SetVariable0 -contains $firstChildText -or $SetVariable1 -contains $firstChildText -or
            $GetVariable0 -contains $firstChildText -or $GetVariable1 -contains $firstChildText)) {
            
            if ($childNodes[1].GetType().Name -eq 'StringConstantExpressionAst') {  # eg: set m 3
                $varName = $subNodeString[$childNodes[1].GetHashCode()]
            }
            else {  # eg: set ('m'+'1') 3
                $varName = GetInvokeResult -CommandLine $subNodeString[$childNodes[1].GetHashCode()]
            }
            $varName = $varName.trim("'`"")

            if ($varName.StartsWith('variable:') -and ($SetVariable1 -contains $firstChildText -or $GetVariable1 -contains $firstChildText)) {
                $varName = $varName.Substring(9)
            }

            return $varName
        }
        else {
            return ''
        }
    }
}

Function Get-VariableNode {
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Node,

        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $hierarchy
    )

    $queue = New-Object -TypeName System.Collections.ArrayList
    $null = $queue.Add($Node)
    while(0 -ne $queue.Count) {
        $curNode = $queue[0]
        $curId   = $curNode.GetHashCode()
        $null    = $queue.RemoveAt(0)

        if ($curNode.GetType().Name -eq 'VariableExpressionAst') {
            return (Get-VariableName -VariableString $curNode.Extent.Text)
        }
        if ($null -ne $hierarchy[$curId]) {
            for ($i = 0; $i -lt $hierarchy[$curId].Count; $i++) {
                $null = $queue.Add($hierarchy[$curId][$i])
            }
        }
    } 

    return ''
}

# check Script AST if include $_ AST Node
Function IsCurVariableInScript {
    [CmdletBinding()] Param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $ScriptString
    )

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($ScriptString, [ref]$null, [ref]$null)

    # include command ast objects only
    $predicate = { param($astObject) $astObject -is [System.Management.Automation.Language.VariableExpressionAst]}
    # search for all ast objects, including nested scriptblocks
    $recurse = $true

    $tmpNode = $ast.FindAll($predicate, $recurse) | & {process {if ($_.Extent.Text -eq '$_') {$_}}}

    if ($null -ne $tmpNode) {
        return $true
    }
    return $false
}

function Get-FunctionNames {
    [CmdletBinding()] param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )

    $Tokens = Tokenize -ScriptString $ScriptString 
    $functionNames = New-Object -TypeName System.Collections.ArrayList

    for($i = 0; $i -lt $Tokens.Count; $i++) {
        $Token = $Tokens[$i]

        if ($Token.Type -eq 'Keyword' -and $Token.Content -eq 'function') {
            $null = $functionNames.Add($Tokens[$i+1].Content)
        }
    }

    return $functionNames
}

# According to the hash of current node and the parent to determine its child nodes
Function Get-ChildNodes {
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory)]
        $curNode,

        [Parameter(Position = 1, Mandatory)]
        $hierarchy,

        [Parameter(Position = 2, Mandatory)]
        $hierarchyP
    )

    $curId = $curNode.GetHashCode()
    if ($null -ne $curNode.Parent) {
        $parenId = $curNode.Parent.GetHashCode()
    }
    else {
        $parenId = 0
    }
    
    $nodes = $hierarchy[$curId]
    $childNodes = [System.Collections.ArrayList]@()
    if ($null -eq $nodes) {
        return $null
    }
    for($i = 0; $i -lt $nodes.count; $i++) {
        if ($hierarchyP[$curId][$i] -eq $parenId) {
            $null = $childNodes.Add($nodes[$i])
        }
    }
    # $null = $childNodes.Add($null)  # avoid type convert in force

    return $childNodes
}

Function Update-NodeExtent {
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory)]
        $curNode,

        [Parameter(Position = 1, Mandatory)]
        $hierarchy,

        [Parameter(Position = 2, Mandatory)]
        $hierarchyP,

        [Parameter(Position = 3, Mandatory)]
        [hashtable]
        $subNodeString,

        [Parameter(Position = 4, Mandatory)]
        [String]
        $ScriptString
    )

    $curId = $curNode.GetHashCode()

    # $curType = $curNode.GetType().Name
    $childNodes = [array](Get-ChildNodes -curNode $curNode -hierarchy $hierarchy -hierarchyP $hierarchyP)
    # $childNodes = $hierarchy[$curId]
    $curNodeString = ''

    # remove not used subnodestring to avoid hash collision in subnodestring
    # this is an easy and brutal implement
    # if ($null -ne $childNodes) {
    #     foreach($childNode in $childNodes) {
    #         if($null -ne $hierarchy[$childNodes.GetHashCode()]) {
    #             $grandNodes = $hierarchy[$childNodes.GetHashCode()] 
    #             foreach($grandNode in $grandNodes) {
    #                 if ($null -ne $hierarchy[$grandNode.GetHashCode()]) {
    #                     $ggrandNodes = $hierarchy[$grandNode.GetHashCode()]
    #                     foreach($ggrandNode in $ggrandNodes) {
    #                         $null = $subNodeString.Remove($ggrandNode.GetHashCode())
    #                     }
    #                 }
    #             }
    #         }
    #     }
    # }

    if ($curNode.GetType().name -eq 'NamedBlockAst') {  # eg: [diagnostics('test')] param()
        $curNodeString = ''
        # 11.8 
        # case 1: without child nodes
        if ($null -eq $childNodes) { 
            return $curNode.Extent.Text
        }

        # case 2: with child nodes
        for ($i = 0; $i -lt $childNodes.Count; $i++) {
            $curNodeString += $subNodeString[$childNodes[$i].GetHashCode()]

            if ($i -lt $childNodes.Count - 1) {
                $nextChildNode = $childNodes[$i+1]
                if ($nextChildNode.Extent.StartOffset-$childNodes[$i].Extent.EndOffset -gt 0) {
                    $curNodeString += $ScriptString.Substring($childNodes[$i].Extent.EndOffset, $nextChildNode.Extent.StartOffset-$childNodes[$i].Extent.EndOffset)
                }
            }
        }
        $endIdx = $childNodes.Count - 1
        if ($curNode.Extent.EndOffset - $childNodes[$endIdx].Extent.EndOffset -gt 0) {
            $curNodeString += $ScriptString.Substring($childNodes[$endIdx].Extent.EndOffset, $curNode.Extent.EndOffset - $childNodes[$endIdx].Extent.EndOffset)
        }
        return $curNodeString
    }
    
    # 没有改完善
    # if ($null -ne $hierarchy[$curId] -and $curNode.GetType().name -ne 'DoWhileStatementAst' -and $curNode.GetType().name -ne 'DoUntilStatementAst') {  # the child nodes are processed first, so update parent node before processing parent
    if ($null -ne $childNodes -and $curNode.GetType().name -ne 'DoWhileStatementAst' -and $curNode.GetType().name -ne 'DoUntilStatementAst') {  # the child nodes are processed first, so update parent node before processing parent
        # if ($null -eq $childNodes) {
        #     return $curNode.Extent.Text
        # }

        for($idx = 0; $idx -lt $childNodes.Count; $idx++) {
            $curChildNode = $childNodes[$idx]
            $curChildId   = $curChildNode.GetHashCode()
    
            # special case : StatementBlockAst : 0 0     @()
            if ($childNodes.Count -eq 1 -and $subNodeString[$curChildId].Length -eq 0) {
                $curNodeString = $curNode.Extent.Text
                continue 
            }

            if ($curChildNode.GetType().Name -eq 'ParamBlockAst') {
                $grandChildNodes = [array](Get-ChildNodes -curNode $curChildNode -hierarchy $hierarchy -hierarchyP $hierarchyP)
                # $grandChildNodes = $hierarchy[$curChildNode.GetHashCode()]
                if ($idx -eq 0 -and $grandChildNodes[0].Extent.StartOffset - $curNode.Extent.StartOffset -gt 0) {
                    $curNodeString += $ScriptString.Substring($curNode.Extent.StartOffset, $grandChildNodes[0].Extent.StartOffset - $curNode.Extent.StartOffset) 
                }

                for ($j = 0; $j -lt $grandChildNodes.Count; $j++) {
                    $curNodeString += $subNodeString[$grandChildNodes[$j].GetHashCode()]

                    if ($j -lt $grandChildNodes.Count - 1) {
                        $nextgrandNode = $grandChildNodes[$j+1]
                        if ($nextgrandNode.Extent.StartOffset-$grandChildNodes[$j].Extent.EndOffset -gt 0) {
                            $curNodeString += $ScriptString.Substring($grandchildNodes[$j].Extent.EndOffset, $nextgrandNode.Extent.StartOffset-$grandchildNodes[$j].Extent.EndOffset)
                        }
                    }
                }

                $endIdx = $grandchildNodes.Count - 1
                if ($idx -lt $childNodes.Count -1) {
                    # 1. next node is NameBlockAst, included ParameterAst
                    if ($childNodes[$idx+1].Extent.StartOffset-$grandChildNodes[$endIdx].Extent.EndOffset -lt 0) {
                        $namechildnodes = [array](Get-ChildNodes $childnodes[$idx+1] $hierarchy $hierarchyP) 
                        # if ($null -ne $hierarchy[$childNodes[$idx+1].GetHashCode()]) {  # NameBlockAst has child nodes
                        if ($null -ne $namechildnodes) {
                            # $firstNameChildNode = $hierarchy[$childNodes[$idx+1].GetHashCode()][0]
                            $firstNameChildNode = $namechildnodes[0]
                            $curNodeString += $ScriptString.Substring($grandChildNodes[$endIdx].Extent.EndOffset, $firstNameChildNode.Extent.StartOffset-$grandChildNodes[$endIdx].Extent.EndOffset)
                        }
                    }
                    else {
                        $curNodeString += $ScriptString.Substring($grandChildNodes[$endIdx].Extent.EndOffset, $childNodes[$idx+1].Extent.StartOffset-$grandChildNodes[$endIdx].Extent.EndOffset)
                    }
                }
                else {
                    $curNodeString += $ScriptString.Substring($grandChildNodes[$endIdx].Extent.EndOffset, $curChildNode.Extent.StartOffset-$grandChildNodes[$endIdx].Extent.EndOffset)
                }
                continue
            }

            if ($idx -eq 0 -and $curChildNode.Extent.StartOffset - $curNode.Extent.StartOffset -gt 0) {  # curNode-> ParentExpressionAst: ('iex') child-> PipelineAst: 'iex'
                $curNodeString = $ScriptString.Substring($curNode.Extent.StartOffset, $curChildNode.Extent.StartOffset - $curNode.Extent.StartOffset)
            }
    
            if ($idx -lt $childNodes.Count-1) {
                $nextChildNode = $childNodes[$idx+1]
                
                if ($null -ne $subNodeString[$curChildId]) {  # process will delete non meaning string, assign that node with $null
                    $curNodeString += $subNodeString[$curChildId] 
                    if ($nextChildNode.Extent.StartOffset-$curChildNode.Extent.EndOffset -gt 0) {
                        $curNodeString += $ScriptString.Substring($curChildNode.Extent.EndOffset, $nextChildNode.Extent.StartOffset-$curChildNode.Extent.EndOffset)
                    }
                }
            }
            else {
                $curNodeString += $subNodeString[$curChildId]
            }
            if ($idx -eq ($childNodes.Count-1) -and $curNode.Extent.Endoffset - $curChildNode.Extent.EndOffset -gt 0){
                $curNodeString += $ScriptString.Substring($curChildNode.Extent.EndOffset, $curNode.Extent.EndOffset - $curChildNode.Extent.EndOffset)
            }
            # if ($idx -eq $hierarchy[$curId].Count-1 -and $curNode.Extent.EndOffset - $curChildNode.Extent.EndOffset -gt 0) {
            #     $curNodeString += $ScriptString.Substring($curChildNode.Extent.EndOffset, $curNode.Extent.EndOffset - $curChildNode.Extent.EndOffset)
            # }
        }
    }
    # elseif ($null -ne $hierarchy[$curId]) {  # simple deal, may occurs error?
    elseif ($null -ne $childnodes) {
        # $pipelineNode = $hierarchy[$curId][0]
        # $statementBlockNode = $hierarchy[$curId][1]
        $pipelineNode = $childNodes[0]
        $statementBlockNode = $childNodes[1]
    
        $curNodeString = $ScriptString.Substring($curNode.Extent.StartOffset, $statementBlockNode.Extent.StartOffset - $curNode.Extent.StartOffset) + $subNodeString[$statementBlockNode.GethashCode()] + 
                                 $ScriptString.Substring($statementBlockNode.Extent.EndOffset, $pipelineNode.Extent.StartOffset - $statementBlockNode.Extent.EndOffset) + $subNodeString[$pipelineNode.GethashCode()] +
                                 $ScriptString.Substring($pipelineNode.Extent.EndOffset, $curNode.Extent.EndOffset - $pipelineNode.Extent.EndOffset)
    }
    else {  # Leaf Node
        $curNodeString = $curNode.Extent.Text
    }

    return $curNodeString
} 

# update current node's banned flag according to the flags of child nodes.
Function Update-BannedNode {
    [CmdletBinding()] param(
        [Parameter(Position = 0, Mandatory)]
        $curNode,

        [Parameter(Position = 1, Mandatory)]
        $hierarchy,

        [Parameter(Position = 2, Mandatory)]
        [hashtable]
        $BannedNode,

        [Parameter(Position = 3, Mandatory)]
        [hashtable]
        $subNodeString
    )

    $curId      = $curNode.GetHashCode()
    $curString  = $subNodeString[$curId]
    $childnodes = $hierarchy[$curId]
    $checkFlag  = $false

    if ($curString -eq '') {
        return $false
    }

    if ($null -ne $childnodes) {
        # if any child node is forbidden, the ancestor node is forbidden
        foreach($node in $childnodes) {
            $nodeId = $node.GetHashCode()
            if ($BannedNode[$nodeId] -eq $true) {  
                return $true
            }
        }

        foreach($node in $childnodes) {
            $nodeId = $node.GethashCode()
            if ($curString.contains($subNodeString[$nodeId]) -eq $false) {
                $checkFlag = $true
                break
            }
        }
    }

    

    # if curstring consists of substrings, not changed 
    if ($checkFlag -eq $false -and $null -ne $childnodes) {
        return $false
    }
    else {
        $BannedCommands = @('cmd', 'cmd.exe', 'get-wmiobject', 'taskkill', 'invoke-webrequest', 'invoke-shellcode', 'start-bitstransfer', 'createthread', 'memset', 'virtualalloc', 'invoke-command', 'invoke-item', 'stop-process', 'iex', 'invoke-expression', 'net.sockets.tcpclient', 'restart', 'shutdown', 'shutdown.exe', 'download', 'set-content', 'new-item', 'remove-item', 'start-process', 'start-sleep', 'sleep', 'create', 'shouldcontinue', 'readkey', 'write', 'exit', 'save', 'logoff', 'get-credential', 'main', 'invoke', 'downloadstring', 'test-connection', 'wget', 'mkdir', 'start-job', 'create', 'restart-computer', 'terminate')

        if (Test-Script -ScriptString $curString) {
            $tokens = Get-SpecialToken -ScriptString $curString -TokenType Command, CommandArgument, Member
        }
        else {
            return $false
        }
        
        for ($i = 0; $i -lt $tokens.Count; $i++) {
            if ($BannedCommands -contains $tokens[$i].Content.tolower() -or $tokens[$i].content.tolower().StartsWith('system.net')) {
                return $true
            }
        }

        # nobanned execute it directly
        $tokens = Tokenize -ScriptString $curString
        for($i = 0; $i -lt $tokens.Count; $i++) {
            $token = $Tokens[$i]
            if ($token.Type -eq 'String' -and $i -gt 0 -and 
                $Tokens[$i-1].Type -eq 'Operator' -and $Tokens[$i-1].Content -eq '.') {
                if ($BannedCommands -contains $token.Content.ToLower()) {
                    return $true
                }
            }
        }
    }
    return $false
}

Function PostTraversal {
    [CmdletBinding()] param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Hierarchy,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        $HierarchyP,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        $Queue,
        
        [Parameter(Position = 3)]
        $LastVisitedNode,

        [Parameter(Position = 4)]
        $CurrentIndent
    )

    $layerASTNodes  = @('NamedblockAst', 'IfStatementAst', 'WhileStatementAst', 'ForStatementAst', 'ForEachStatementAst', 'StatementBlockAst')

    $curNode = $Queue[0]
    $curId   = $curNode.GetHashCode()
    $childNodes = [array](Get-ChildNodes -curNode $curNode -hierarchy $Hierarchy -hierarchyP $HierarchyP)

    $addChildFlag = $true 
    # if ($Hierarchy[$curId] -contains $LastVisitedNode -eq $true) {
    if ($childNodes -contains $LastVisitedNode -eq $true) {
        # $chidlNum = $Hierarchy[$curId].Count 
        $childNum = $childNodes.Count

        # if ($Hierarchy[$curId].Indexof($LastVisitedNode) -eq ($chidlNum-1)) {
        if ($childNodes.Indexof($LastVisitedNode) -eq ($childNum-1)) {
            $addChildFlag = $false
        }
        else {
            # $LastVisitedIdx = $Hierarchy[$curId].IndexOf($LastVisitedNode)
            # $Queue.Insert(0, $Hierarchy[$curId][$LastVisitedIdx+1])
            $LastVisitedIdx = $childNodes.IndexOf($LastVisitedNode)
            $Queue.Insert(0, $childNodes[$LastVisitedIdx+1])

            $curNode = $Queue[0]
            $curId   = $curNode.GetHashCode()
            if ($null -ne $CurrentIndent -and $layerASTNodes -contains $curNode.GetType().Name) {
                $CurrentIndent++
            }
        }
    }

    if ($addChildFlag) {
        # while ($null -ne $Hierarchy[$curId]) {
        #     $Queue.Insert(0, $Hierarchy[$curId][0])
        while ($null -ne $Hierarchy[$curId]) {  # can't change var in loop, therefore use $hierarchy substitute $childnodes
            $childNodes = [array](Get-ChildNodes -curNode $curNode -hierarchy $Hierarchy -hierarchyP $HierarchyP)
            if ($null -eq $childNodes) {
                break
            }
            $null = $Queue.Insert(0, $childNodes[0])
            $curNode = $Queue[0]
            $curId   = $curNode.GetHashCode()
            if ($null -ne $CurrentIndent -and $layerASTNodes -contains $curNode.GetType().Name) {
                $CurrentIndent++
            }
        }
    }

    if ($null -ne $CurrentIndent) {
        return $curNode, $Queue, $CurrentIndent
    }
    else {
        return $curNode, $Queue
    }
}