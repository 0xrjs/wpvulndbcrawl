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

# build serach index to aid users in their queries
Function Build_Index
{
	param
	(
		[Parameter(Mandatory=$True,Position=1)]
		[ValidateSet(“wordpresses”,"plugins","themes")]
		[string]$Index
	)
	
	#instatiate arraylist to contain all plugins/themes in loop
	[System.Collections.ArrayList]$extractionsArray = @()
	#count to iterate through pages via URI
	$count = 1
	#flag for loop exit
	$nullPage = $False
	Do
	{
		#retrieve html
		$html = Invoke-WebRequest -Uri https://wpvulndb.com/$($Index)?page=$($count)
		
		#extract from the links all plugins or themes
		$extractions = ($html.links.href | Select-String -Pattern "/$($Index)/") | % {$_.tostring().split('/')[2]}
		
		#if there are no plugins or themes (last page), set exit flag true to exit loop
		If ($extractions -eq $Null)
		{
			$nullPage = $True
		}
		#add the extracted plugins/themes to the arraylist. Out-null because adding items to array has terminal output. increment page count by one.
		Else
		{
			Foreach ($link in $extractions)
			{
				$extractionsArray.Add($link) | Out-Null
			}
			$count++
		}
	}
	Until ($nullpage -eq $True)

	# take arraylist and sort alphabetically removing duplicates. output to text file.
	$extractionsArray | Sort-Object -Unique | Out-File -Path #***WHERE?***

}