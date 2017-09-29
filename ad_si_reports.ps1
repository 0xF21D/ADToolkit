<#
    Author: Robert Hollingshead
    Version: 1
    Version History: First version. 

    Purpose: Get a report of intersite transports and sites.
    * $transports = Intersite Transports
    * $objReport= = Site report. 

    To-Do List: Clean varable names.    
#>

$objSites = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().sites | Select-Object -Property Name, Domain, Subnets, Servers, AdjacentSites, SiteLinks, Location

$transports = $objSites.sitelinks | Select-Object -Property Name, TransportType, Sites, Cost, ReplicationInterval, ReciprocalReplicationEnabled, NotificationEnabled, DataCompressionEnabled, InterSiteReplicationSchedule

foreach ($transport in $transports) 
{
  $transport | Add-Member -MemberType NoteProperty -Name SiteA -Value $($transport.sites[0].name)
  $transport | Add-Member -MemberType NoteProperty -Name SiteB -Value $($transport.sites[1].name)
}

[array]$objReport = $null

foreach ($objSite in $objSites) 
{
  $reportitem = New-Object -TypeName psobject

  if ($objSite.subnets.count -gt 0) 
  { 
    foreach ($subnet in $objSite.subnets) 
    {
      $reportitem = New-Object -TypeName psobject
      $reportitem | Add-Member -MemberType NoteProperty -Name SiteName -Value $($objSite.Name)  
      $reportitem | Add-Member -MemberType NoteProperty -Name SiteLocation -Value $($objSite.Location)
      $reportitem | Add-Member -MemberType NoteProperty -Name Subnet -Value $($subnet.Name)
      $reportitem | Add-Member -MemberType NoteProperty -Name SubnetSite -Value ($subnet.Site)
      $reportitem | Add-Member -MemberType NoteProperty -Name SubnetLocation -Value ($subnet.Value)
      if ($objSite.Servers.count -gt 0 ) 
      {
        $serverlist = $null
        for ($count = 0; $count -lt $objSite.Servers.count; $count++) 
        {
          $serverlist = $serverlist + $objSite.Servers[$count].name + ','
        }
        $reportitem | Add-Member -MemberType NoteProperty -Name ServerList -Value $($serverlist)    
      }
      else 
      {
        $reportitem | Add-Member -MemberType NoteProperty -Name ServerList -Value $null
      }
      $objReport = $objReport + $reportitem
    }
  }

  else
  {
    $reportitem = New-Object -TypeName psobject
    $reportitem | Add-Member -MemberType NoteProperty -Name SiteName -Value $($objSite.Name)  
    $reportitem | Add-Member -MemberType NoteProperty -Name SiteLocation -Value $($objSite.Location)
    $reportitem | Add-Member -MemberType NoteProperty -Name Subnet -Value $null
    $reportitem | Add-Member -MemberType NoteProperty -Name SubnetSite -Value $null
    $reportitem | Add-Member -MemberType NoteProperty -Name SubnetLocation -Value $null
    if ($objSite.Servers.count -gt 0 ) 
    {
      $serverlist = $null
      for ($count = 0; $count -lt $objSite.Servers.count; $count++) 
      {
        $serverlist = $serverlist + $objSite.Servers[$count].name + ','
      }
      $reportitem | Add-Member -MemberType NoteProperty -Name ServerList -Value $($serverlist)    
    }
    else 
    {
      $reportitem | Add-Member -MemberType NoteProperty -Name ServerList -Value $null
    }
    $objReport = $objReport + $reportitem
  }
}
