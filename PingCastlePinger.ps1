# Argument handling
# -Server: AD Domain to be scanned
# -SendChanges: Notify about changed findings if no new or resolved ones are detected
# -SendEmptyReports: Allow for sending empty notifications
# -Brag: Remove greetings from footer
param (
    [String]$Server = "*",
        [String]$Channel,
    [Switch]$SendAllChanges,
    [Switch]$SendEmptyReports,
    [Switch]$Mail,
    [Switch]$Unbrag,
    [Switch]$Interactive 
)


# Logging
function Log {
    param(
        [String]$LogMessage,
        # Default severity is Info
        [int]$Severity = 0
    )
    
    # Writing message to the log-file with the respective date and time and severity
    Add-Content $LogFile ("[{0} - [{1}]: {2}" -f ((Get-Date -Format "dd/MM/yyyy HH:mm:ss"), $Severities[$Severity], $LogMessage))
    # If the tool is in interactive mode, the messages get written to the standard output as well
    if ($Interactive -and ($Severity -lt 2)) {
        Write-Host $LogMessage
    }
    # Messages of severity Error stop processing
    if ($Severity -eq 2) {
        throw $LogMessage
    }
}

# Clearing log-file if necessary
function RotateLog() {
    param(
        [String]$LogFile
    )

    # Checking if file size is bigger than 5 MB
    if (((Get-Item $LogFile).length/1MB) -gt 5) {
        # Getting the last 100 lines as excerpt
        $Excerpt = (Get-content -tail 100 $LogFile)
        # Clearing the file
        Clear-Content $LogFile
        # Adding the excerpt to the file again
        Add-Content $LogFile $Excerpt
    }
}


# Class: Finding, resembles a vulnerability detected by PingCastle
Class Finding {
    [String]$Category = "N/A"
    [String]$RiskId = "N/A"
    [String]$Rationale = ""
    # OldRationale is used for changed findings only
    [String]$OldRationale = ""
    [String]$Details = ""
    [int]$Points = 0
    # Oldpoints is used for changed findings only
    [int]$OldPoints = 0
}


# Parsing findings from XML to the custom Finding object
function ToFinding() {
    param (
        [System.Xml.XmlElement]$XMLFinding
    )

    # By default, the OldRationale field is not populated
    return New-Object -TypeName Finding -Property @{     
        "RiskId" = $XMLFinding.RiskId
        "Category" = $XMLFinding.Category
        "Rationale" = $XMLFinding.Rationale
        "Details" = $XMLFinding.Details
        "Points" = [int]$XMLFinding.Points
    }
}

# Loading the findings from an XML-file
function LoadResults() {
    param (
        [String]$Location
    )

    # Checking if the XML report is available
    if (-not (Test-Path -Path $Location -PathType Leaf)) {
        return
    }

    # Loading the content of the XML report
    $Doc = New-Object xml
    $Doc.Load( (Convert-Path $Location) )

    # Parsing the individual findings as custom Findings objects
    return @($Doc.HealthcheckData.RiskRules.HealthcheckRiskRule | ForEach { ToFinding $_ } | Sort-Object -Property @{Expression="Points";Descending=$true},@{Expression="Category";Descending=$true})
}


# Parsing the new findings by comparing the current against the last ones
function GetNewFindings() {
    param (
        [Array]$CurrentFindings, 
        [Array]$LastFindings
    )
    
    $NewFindings = [System.Collections.ArrayList]@()
    # RiskIds of the last findings
    $LastIDs = @($LastFindings | ForEach-Object RiskId)

    # Getting the current findings which RiskIds are not present in the list of last RiskIds
    return $CurrentFindings | Where { -not $LastIDs.Contains($_.RiskId) }
}
    
# Parsing the resolved findings by comparing the last against the current ones
function GetResolvedFindings() {
    param (
        [Array]$CurrentFindings, 
        [Array]$LastFindings
    )

    $ResolvedFindings = [System.Collections.ArrayList]@()
    # RiskIds of the current findings
    $CurrentIDs = @($CurrentFindings | ForEach-Object RiskId)

    # Getting the last findings which RiskIds are not present in the list of current RiskIds
    return $LastFindings | Where { -not $CurrentIds.Contains($_.RiskId) }
}

# Parsing the changed findings
# For changed findings, the Rationale from the current scan differs from the one of the last scan
function GetChangedFindings() {
    param (
        [Array]$PersistentFindings, 
        [Array]$LastFindings
    )

    $ChangedFindings = @{"Points" = [System.Collections.ArrayList]@(); "Rationale" = [System.Collections.ArrayList]@()}
    # Iterating through the persistent findings
    foreach ($Finding in $PersistentFindings) {
        # Getting the respective finding from the last scan
        $LastFinding = ($LastFindings | Where-Object { $_.RiskId -eq $Finding.RiskId })
        # Checking if the Points changed
        if ($Finding.Points -ne $LastFinding.Points) {
            $Finding.OldPoints = $LastFinding.Points
            $Finding.OldRationale = $LastFinding.Rationale
            $null = ($ChangedFindings["Points"]).Add($Finding)
        }
        # Checking if the Rationale changed
        elseif ($Finding.Rationale -ne $LastFinding.Rationale) {
            # If a change is detected, the object's field OldRationale is updated
            $Finding.OldRationale = $LastFinding.Rationale
            $null = ($ChangedFindings["Rationale"]).Add($Finding)
        }
    }
    return $ChangedFindings
}

# Formating an integer to a signed string
function Absolut() {
    param (
        [int]$In
    )

    if ($In -ge 0) { return "+{0}" -f [String]$In }
    else { return [String]$In }
}

# Calculating the vulnerability scores for each Category
function CalculateScores() {
    param (
        [Array]$Findings
    )

    $Scores = @{}
    # Iterating through the Categories
    foreach ($Category in $Categories) {
        # Summing up the scores of the individual findings
        $Scores[$Category] = ($Findings | Where-Object -FilterScript { $_.Category -eq $Category } | ForEach-Object Points | measure-object -sum).sum
    }
    return $Scores
}

# Preparing the colored circles indicating the state of security overall and of the individual categories
function ParseCircle() {
    param (
        [int]$Value,
        # Possible range of the scores
        [int]$Range = 100
    )

    # The range is quartered and the ratio of value and range is calculated
    $Ratio = [Math]::Floor([decimal]4*$Value / $Range)
    # Anything outside the range is moved to the fourth quarter
    if ($Ratio -gt 3) { $Ratio = 3 }
    # The ratio is used as index for the Circles list
    return $Circles[$Ratio]
}

# Preparing the coloring of the vulnerability scores of the findings
function ParsePoints() {
    param (
        [int]$Points,
        [bool]$Resolved = $false
    )

    # Scores of resolved findings
    if ($Resolved) { $Points = $Points * -1 }

    if ($Points -lt 0) { return "<span style=`"color: green`">{0}</span>" -f ($Points) }
    elseif ($Points -eq 0) { return "<span style=`"color: gray`">&plusmn;0</span>"  }
    elseif ($Points -lt 5) { return "<span style=`"color: yellow`">{0}</span>" -f (Absolut $Points) }
    elseif ($Points -lt 9) { return "<span style=`"color: orange`">{0}</span>" -f (Absolut $Points) }
    else { return "<span style=`"color: red`">{0}</span>" -f (Absolut $Points) }
}

# Parsing the difference view for changed fiindings
function ParseDiff() {
    param (
        [Finding]$ChangedFinding
    )

    # Comparing the Rationales
    $New = $ChangedFinding.Rationale.Split(" ")
    $Old = $ChangedFinding.OldRationale.Split(" ")
    $Diff = compare $Old $New -PassThru
    
    $News = @($Diff | Where { $_.SideIndicator -eq "=>" })
    $Olds = @($Diff | Where { $_.SideIndicator -eq "<=" })

    $Summary = $ChangedFinding.Rationale
    for($i=0;$i-lt $News.Count;$i++) {
        $Summary = $Summary.Replace($News[$i], "<b>{0} (used to be {1})</b>" -f ($News[$i], $Olds[$i]))
    }

    return $Summary
   
}

# Very polite indeed
function RobotTime() {
    $Hour = [int](Get-Date -Format "HH")
    if ($Hour -lt 4 -or $Hour -gt 17) { $Greeting = "Good evening, Sir/Madam" }
    elseif ($Hour -lt 11) { $Greeting = "Good morning, Sir/Madam" }
    elseif ($Hour -lt 14) { $Greeting = "Bon appetit, Sir/Madam" }
    else { $Greeting = "Good afternoon, Sir/Madam" }

    return $Greeting
}

# Parsing the Teams-Message
function ParseMessage() {
    param (
        [String]$HeaderFile,
        [String]$Domain,
        [String]$Date,
        [Hashtable]$CurrentScores,
        [int]$OverallScore,
        [Hashtable]$LastScores,
        [int]$LastOverallScore,
        [Array]$NewFindings,
        [Array]$ResolvedFindings,
        [Hashtable]$ChangedFindings,
        [bool]$First = $false
    )

    # Preparing the header
    # Loading the 'stencil' file which is then filled with the actual values
    $Header = Get-Content -Raw "$HeaderFile"

    # Parsing the placeholders and their replacements 
    $HeaderReplacements = @{
        "%Domain%" = $Domain;"%Date%" = $Date
        "%Alert%" = "";
        "%Overall%" = $OverallScore;"%ColorOverall%" = (ParseCircle $OverallScore 200);"%DiffOverall%" = Absolut ($OverallScore - $LastOverallScore)
        "%StaleObjects%" = $CurrentScores["StaleObjects"];"%ColorStaleObjects%" = (ParseCircle $CurrentScores["StaleObjects"]);"%DiffStaleObjects%" = Absolut ($CurrentScores["StaleObjects"] - $LastScores["StaleObjects"]);
        "%PrivilegedAccounts%" = $CurrentScores["PrivilegedAccounts"];"%ColorPrivilegedAccounts%" = (ParseCircle $CurrentScores["PrivilegedAccounts"]);"%DiffPrivilegedAccounts%" = Absolut ($CurrentScores["PrivilegedAccounts"] - $LastScores["PrivilegedAccounts"]);
        "%Trusts%" = $CurrentScores["Trusts"];"%ColorTrusts%" = (ParseCircle $CurrentScores["Trusts"]);"%DiffTrusts%" = Absolut ($CurrentScores["Trusts"] - $LastScores["Trusts"])
        "%Anomalies%" = $CurrentScores["Anomalies"];"%ColorAnomalies%" = (ParseCircle $CurrentScores["Anomalies"]);"%DiffAnomalies%" = Absolut ($CurrentScores["Anomalies"] - $LastScores["Anomalies"])
    }

    # Indicating an initial scan
    if ($First) {
        $HeaderReplacements["%Alert%"] = "<h3>Note: This is the first scan for this domain!</h3>"
    }

    # Replacing the placeholders in the header
    foreach ($Replacement in $HeaderReplacements.Keys) {
        $Header = $Header.Replace($Replacement, $HeaderReplacements[$Replacement])
    }

    # Preparing the findings
    # For new and resolved findings, the Points (scores), the Category and the Rationale is posted
    $VulnerabilitiesText = [System.Collections.ArrayList]@()
    if ($NewFindings.Count) {
        $null = $VulnerabilitiesText.Add("<h3>&#x2757; New Vulnerabilities</h3>")
        $null = $VulnerabilitiesText.Add("<ul>")

        foreach ($NewFinding in $NewFindings) {
            $null = $VulnerabilitiesText.Add("<li><b>{0} {1}:</b> {2}</li>" -f ((ParsePoints $NewFinding.Points), $NewFinding.Category, $NewFinding.Rationale))
        }
        $null = $VulnerabilitiesText.Add("</ul>")
        $null = $VulnerabilitiesText.Add("<br/>")
    }

    if ($ResolvedFindings.Count) {
        $null = $VulnerabilitiesText.Add("<h3>&#x2705; Resolved Vulnerabilities</h3>")
        $null = $VulnerabilitiesText.Add("<ul>")

        foreach ($ResolvedFinding in $ResolvedFindings) {
            $null = $VulnerabilitiesText.Add("<li><b>{0} {1}:</b> {2}</li>" -f ((ParsePoints $ResolvedFinding.Points $true), $ResolvedFinding.Category, $ResolvedFinding.Rationale))
        }
        $null = $VulnerabilitiesText.Add("</ul>")
        $null = $VulnerabilitiesText.Add("<br/>")
    }

    # For findings whose Points/score changed, the difference of the Points as well as the changes in the Rationale are added
    if (($ChangedFindings["Points"]).Count) {
        $null = $VulnerabilitiesText.Add("<h3>&#x2139; Vulnerabilities with changed scores</h3>")
        $null = $VulnerabilitiesText.Add("<ul>")

        foreach ($ChangedFinding in ($ChangedFindings["Points"])) {
            $null = $VulnerabilitiesText.Add("<li><b>{0} (used to be {1}) {2}:</b> {3} <br/></li>" -f ((ParsePoints $ChangedFinding.Points), (ParsePoints $ChangedFinding.OldPoints), $ChangedFinding.Category, (ParseDiff $ChangedFinding)))
        }
        $null = $VulnerabilitiesText.Add("</ul>")
        $null = $VulnerabilitiesText.Add("<br/>")
    }

    # For findings whose Rationale changed, only the changes in the Rationale are added
    if (($ChangedFindings["Rationale"]).Count) {
        $null = $VulnerabilitiesText.Add("<h3>&#x2139; Vulnerabilities with changed details</h3>")
        $null = $VulnerabilitiesText.Add("<ul>")

        foreach ($ChangedFinding in ($ChangedFindings["Rationale"])) {
            $null = $VulnerabilitiesText.Add("<li><b>{0} {1}:</b> {2} <br/></li>" -f ((Absolut $ChangedFinding.Points), $ChangedFinding.Category, (ParseDiff $ChangedFinding)))
        }
        $null = $VulnerabilitiesText.Add("</ul>")
        $null = $VulnerabilitiesText.Add("<br/>")
    }
    
    # Concatenating the header and the findings
    return $Header + $VulnerabilitiesText
}


# Sending a message to Teams via a Webhook
function SendMessage() {
    param (
        [String]$Message,
        [String]$Title = ""
    )

    $JSONBody = [PSCustomObject][Ordered]@{
        "@type" = "MessageCard"
        "summary" = "PingCastle Alert!"
        "themeColor" = "#fa9c1a"
        "title" = $Title
        "text" = $Message
        "markdown" = $true
    }

    $TeamsMessageBody = ConvertTo-Json -Compress -InputObject $JSONBody
    try {
        $Response = Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body $TeamsMessageBody -Uri $URI
        if ($Response -ne 1) {
            throw
        }
    }
    catch [Exception] {
        Log ("Sending Teams message failed: {0}" -f $Response) 2
    }
}

# Sending a mail with the report(s) attached
function Mail() {
    param ( 
        [String]$MailFile,
        [String]$Date,
        [Array]$Reports
    )

    # Loading the configuration
    $MailConfiguration = @{}
    foreach ($Item in (Get-Content "$MailFile")) {
        $Pair = $Item.ToLower().Split(":")
        $MailConfiguration[$Pair[0].Trim()] = $Pair[1].Trim()
    }
    # Setting subject and attachments
    $Subject = "PingCastle Report $Date"
    $Attachments = $Reports

    try {
        $Response = Send-MailMessage -From $MailConfiguration["sender"] -To $MailConfiguration["recipient"] -Subject "$Subject" -SmtpServer $MailConfiguration["server"] -Attachments $Attachments
    }
    catch [Exception] {
        Log ("Sending mail failed: {0}" -f $Response) 2
    }
}


# Global variables
# Teams Channel URI
$Script:URI = ""
if ($Channel) {
    $URI = $Channel
}
elseif (-not $Channel -and -not $URI) {
    throw "No Teams channel set."
}

# Is set if no older reports are found to compare the current results to
$Script:First = $false
# Log-Severities
$Script:Severities = @("INFO", "WARNING", "ERROR")
# Vulnerability categories
$Script:Categories = @("StaleObjects", "PrivilegedAccounts", "Trusts", "Anomalies")
# Colored circles
$Script:Circles = @("&#x1F7E2;", "&#x1F7E1;", "&#x1F7E0;", "&#x1F534;")

# Parsing Paths
$PingerHome = $PSScriptRoot
$PingerResources = Join-Path -Path "$PingerHome" -ChildPath "PingCastlePinger_Resources"
$PingCastleScript = Join-Path -Path "$PingerHome" -ChildPath "PingCastle.exe"
$PingCastleUpdateScript = Join-Path -Path "$PingerHome" -ChildPath "PingCastleAutoUpdater.exe"
$LastFolder = Join-Path -Path "$PingerResources" -ChildPath "Last_Reports"
$HeaderFile = Join-Path -Path "$PingerResources" -ChildPath "Header.html" 
$FooterFile = Join-Path -Path "$PingerResources" -ChildPath "Footer.html"
$MailFile = Join-Path -Path "$PingerResources" -ChildPath "mail.conf"
$Script:Logfile = Join-Path -Path "$PingerResources" -ChildPath "log.txt"

$Args = $PsBoundParameters.GetEnumerator() | ForEach-Object {"{0}: {1}" -f ($_.Key, $_.Value)}
$ArgSummary = If ($Args) {" with following non-default parameters: {0}" -f ($Args -join "; ")} Else {"."}
Log ("PingCastlePinger started{0}" -f $ArgSummary)

# Checking if necessary files and folders are available
foreach ($File in @("$PingCastleScript", "$PingCastleUpdateScript", "$HeaderFile", "$FooterFile")) {
    if (-not (Test-Path -Path $File -PathType Leaf)) {
        Log ("Missing file {0}" -f $File) 2
    }
}
foreach ($Folder in @("$LastFolder")) {
    if (-not (Test-Path -Path "$Folder" -PathType Container)) {
        New-Item -Path "$Folder" -Type Directory
        Log ("Created folder {0}" -f $Folder) 1
    }
}

# Roting Log if necessary
RotateLog $LogFile

# Running PingCastle update
Log "Trying to update PingCastle:"
try {
    & "$PingCastleUpdateScript" | Out-File -FilePath $LogFile -Append -Encoding Default 
}
catch [Exception] {
    Log "Could not run PingCastle update." 2
}

# Current date and time
$Date = Get-Date -Format "dd/MM/yyyy HH:mm"

# Executing a PingCastle scan for all Domains
Log "Starting PingCastle scan:"
try {
    & "$PingCastleScript" --healthcheck --server * --level Full | Out-File -FilePath $LogFile -Append -Encoding Default
}
catch [Exception] {
    Log "Could not run PingCastle scan." 2
}

# Detecting all reports/domains
$Reports = dir "$PingerHome" | Where { $_.Name -match ".*\.xml"}
Log ("Following report(s) detected: {0}" -f ($Reports -join ", "))

$Messages = [System.Collections.ArrayList]@()
# Iterating through the reports/Domains
foreach ($Report in $Reports) {
    Log ("Examining report {0}..." -f $Report)
    # Reset for each domain
    $First = $false

    $Domain = $Report.Name | % {$_ -match "ad_hc_([A-Za-z0-9_.-]+)\.xml" > $null; $matches[1]}
    Log ("Domain: {0}" -f $Domain)
    
    # Loading the current results for this Domain
    $CurrentFindings = @(LoadResults $Report.PSPath)
    if (-not $CurrentFindings) {
        Log ("Could not load current report {0}" -f $Report) 2
    }

    # Loading the previous results for this Domain
    $LastFindings = @(LoadResults (Join-Path -Path "$LastFolder" -ChildPath "$Report.Name"))
    if (-not $LastFindings) {
        Log ("Could not load previous report {0} for this domain." -f $Report) 1
        # Indicating it's the first scan for this Domain
        $First = $true
        $LastFindings = @()
    }
    else {
        Log "Successfully loaded previous report for this domain."
    }

    # Parsing the new and the now resolved findings
    $NewFindings = @(GetNewFindings $CurrentFindings $LastFindings)
    $ResolvedFindings = @(GetResolvedFindings $CurrentFindings $LastFindings)
    Log ("Found {0} new and {1} resolved vulnerabilities." -f ($NewFindings.Count, $ResolvedFindings.Count))

    # Parsing changed findings
    # Getting the persistent findings
    $PersistentFindings = $CurrentFindings | ? {$_ -notin $NewFindings}
    # The Points and Rationales of these are compared to the ones of the persistent findings to catch minor changes
    $ChangedFindings = GetChangedFindings $PersistentFindings $LastFindings
    Log ("Found {0} vulnerabilities for which the Points changed and {1} vulnerabilites for which the Rationale changed." -f (($ChangedFindings["Points"]).Count, ($ChangedFindings["Rationale"]).Count))

    # Checking if a notification needs to prepared
    # Changes to the Points/scores are always posted, changes to the findings' Rationales only if activated
    if (($NewFindings.Count + $ResolvedFindings.Count + ($ChangedFindings["Points"]).Count) -eq 0 -and -not $SendAllChanges) {
        Log ("No (relevant) changes detected for domain {0}" -f $Domain)
        # Archiving the report
        Log ("Archiving report...")
        Move-Item -Path $Report.PSPath -Destination "$LastFolder" -Force
        Log ("Continuing.")
        continue
    }

    # Calculating the current and previous score for each category
    Log ("Calculating scores...")
    $CurrentScores = CalculateScores $CurrentFindings
    $LastScores = CalculateScores $LastFindings
    # Calculating the overall scores
    $OverallScore = ($CurrentScores.Values | measure-object -sum).sum
    $LastOverallScore = ($LastScores.Values | measure-object -sum).sum

    # Parsing the Teams message for the current Domain
    Log ("Parsing message...")
    $null = $Messages.Add((ParseMessage "$HeaderFile" $Domain $Date $CurrentScores $OverallScore $LastScores $LastOverallScore $NewFindings $ResolvedFindings $ChangedFindings $First))
    
    # Archiving the report (in both the folder containing the last reports and the folder containing the last sent reports)
    Log ("Archiving report...")
    Move-Item -Path $Report.PSPath -Destination "$LastFolder" -Force

    Log ("Successfully examined report {0} for Domain {1}" -f ($Report, $Domain))
}
Log ("Successfully examined all reports.")

# If no notification is to be send, the tool is terminated
if ($Messages.Count -eq 0 -and -not $SendEmpty) {
    Log "No (relvant) changes detected at all, skipping notification."
    Log "PingCastlePinger finished."
    Exit 0
}
# Notification if no (relevant) changes were detected
elseif ($Messages.Count -eq 0) {
    $Title = "&#x1F2755 PingCastle didn't detect any changes in the Active Directory Security! &#x1F2755"
    $Messages[0] = "<b> This doesn't mean your Active Directory is secure, there were only no changes to its security detected! Stay alert! </b>"
}

# Chunking the message if it's bigger than 13.5 KB, as Teams can't handle arbitrary large posts
# See https://learn.microsoft.com/en-us/microsoftteams/limits-specifications-teams
$MessageChunks = [System.Collections.ArrayList]@("")
$MaxChunkSize = 13500
foreach ($Message in $Messages) {
    if (($MessageChunks[-1].Length + $Message.Length) -gt $MaxChunkSize) {
        $null = $MessageChunks.Add("")
    }
    $MessageChunks[-1] = ($MessageChunks[-1] + $Message)
}

# Preparing the footer if not deactivated
if (-not $Unbrag) {
    # Loading the 'stencil' file which is then filled with the actual values
    $Footer = Get-Content -Raw "$FooterFile"
    # Greetings
    $Footer = $Footer.Replace("%Greeting%", (RobotTime))
    # Adding the footer to the last message chunk
    $MessageChunks[-1] = ($MessageChunks[-1] + $Footer)
}


# Sending the chunks one-by-one
Log ("Sending {0} message(s)..." -f $MessageChunks.Count)
# The first chunk is sent with a title for the post
If (-not $Title) {$Title = "&#x1F6A8 PingCastle detected changes in the Active Directory Security! &#x1F6A8"}
SendMessage ("<h4>1/{0}</h4>{1}" -f ($MessageChunks.Count, $MessageChunks[0])) $Title
for($i=1;$i -lt $MessageChunks.Count;$i++) {
    # No title for the consecutive messages
    SendMessage ("<h4>{0}/{1}</h4>{2}" -f (($i + 1), $MessageChunks.Count, $MessageChunks[$i]))
}

# Sending the report(s) to the Teams Channel as a mail
# This uploads the documents to Sharepoint as well as both applications are integrated
if ($Mail) {
    Log "Sending report(s) as mail..."
    Mail "$MailFile" $Date $Reports
}


Log "PingCastlePinger finished."
