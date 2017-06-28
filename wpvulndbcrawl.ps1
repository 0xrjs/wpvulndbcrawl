Param (
    [Parameter(Mandatory=$True,Position=1)]
    [ValidateSet(“wordpresses”,”plugins”,”themes”)] 
    [string]$searchType,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$searchQuery
)

# stuff to handle wordpress version url crap
if ($searchType -eq "wordpresses")
{
    $searchQuery = $searchQuery -replace '[.]'
}

# create a request URL with the args from cmdline params and execute the web request
$uri = "https://wpvulndb.com/api/v2"
$webCall = Invoke-WebRequest -URI $uri/$searchType/$searchQuery
$vulns = ($webCall.content | ConvertFrom-JSON).$searchQuery.vulnerabilities

# set index to iterate through list of vulns returned from the web request
$vulnCount = $vulns.count - 1

# interate through list of vulns
For ($vulnIndex=0; $vulnIndex -le $vulnCount; $vulnIndex++)
{
    # count the number of URLs for each vuln
    $urlCount = $vulns[$vulnIndex].references.url.count
    
    # set index to iterate through list of URLs
    $urlIndex = $urlCount - 1

    # extract URLs from nested objects and insert them back into the original master object as separate properties
    For ($i=0; $i -le $urlIndex; $i++)
    {
            $vulns[$vulnIndex] | Add-Member -Type NoteProperty -Name url_$i -Value $vulns[$vulnIndex].references.url[$i]
    }
}

# display the final parsed data
$vulns | Select-Object -Property * -ExcludeProperty references