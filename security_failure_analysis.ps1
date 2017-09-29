<#

    Author: Robert Hollingshead
    Version: 0.3a
    Version History: Made to run a little faster. 

    Purpose: Queries domain controllers for events leading to user lockouts.
    Report is written to HTML but the $scoreboard can be used alone. 

#>

#requires -Modules ActiveDirectory
#requires -Version 2.0

# Set these variables!

# The OU that your domain controllers reside in.
$DomainControllerOU = 'ou=Domain Controllers,dc=your,dc=domain'

# The path of the resulting HTML file. 
$filepath = '.\report.html'

# Leave the stuff below alone

$timestamp = (Get-Date).addminutes(-30)
$domaincontrollers = (Get-ADComputer -SearchBase $DomainControllerOU -Filter *).name

$scriptblock = {
  param($timestamp)

  $eventlist = (Get-WinEvent @{
      logname   = 'security'
      starttime = $($timestamp)
      keywords  = 4503599627370496
  })

  [array]$report = $null

  foreach ($event in $eventlist) 
  {
    [xml]$eventxml = $null
    $reportitem = New-Object -TypeName psobject

    $eventxml = [xml]$event.toxml()

    $reportitem | Add-Member -MemberType NoteProperty -Name EventID -Value $($event.Id)
    $reportitem | Add-Member -MemberType NoteProperty -Name TimeCreated -Value $($event.TimeCreated)

    switch ($event.Id) {


      4625 # An account failed to log on.
      {
        $reportitem | Add-Member -MemberType NoteProperty -Name FailureDescription -Value 'Login Failure'
        $reportitem | Add-Member -MemberType NoteProperty -Name FailureReason -Value ''
        $reportitem | Add-Member -MemberType NoteProperty -Name TargetUserName -Value $($eventxml.Event.EventData.Data[5].'#text')
        $reportitem | Add-Member -MemberType NoteProperty -Name TargetDomainName -Value $($eventxml.Event.EventData.Data[6].'#text')
        $reportitem | Add-Member -MemberType NoteProperty -Name WorkstationName -Value $($eventxml.Event.EventData.Data[13].'#text').replace('\\','')
        $reportitem | Add-Member -MemberType NoteProperty -Name IPAddress -Value $($eventxml.Event.EventData.Data[19].'#text')

        if ($reportitem.LogonType -eq '3') 
        {
          $reportitem.LogonType = 'Network'
        }

        # Get code from status in XML.
        switch ($eventxml.Event.EventData.Data[8].'#text') {
        
          '%%2313' 
          {
            $reportitem.FailureReason = 'Username/Password Bad'
          }

          '%%2310' 
          {
            $reportitem.FailureReason = 'Account Disabled'
          }

          '%%2304' 
          {
            $reportitem.FailureReason = 'Error Occured'
          }

          '%%2309' 
          {
            $reportitem.FailureReason = 'Password Expired'
          }

          '%%2307' 
          {
            $reportitem.FailureReason = 'Account Locked Out'
          }
          
        
        }

        $report = $report + $reportitem
      }

      4768 # A Kerberos authentication ticket (TGT) was requested.
      {
        $reportitem | Add-Member -MemberType NoteProperty -Name FailureDescription -Value 'Kerberos TGT Request Failure'
        $reportitem | Add-Member -MemberType NoteProperty -Name FailureReason -Value ''
        $reportitem | Add-Member -MemberType NoteProperty -Name TargetUserName -Value $($eventxml.Event.EventData.Data[0].'#text')
        $reportitem | Add-Member -MemberType NoteProperty -Name TargetDomainName -Value $($eventxml.Event.EventData.Data[1].'#text')
        $reportitem | Add-Member -MemberType NoteProperty -Name WorkstationName -Value ''
        $reportitem | Add-Member -MemberType NoteProperty -Name IPAddress -Value $($eventxml.Event.EventData.Data[9].'#text').replace('::ffff:','')   
        
         
        # Get code from status in XML.
        switch ($eventxml.Event.EventData.Data[6].'#text') {
          '0x12' 
          {
            $reportitem.FailureReason = 'Account Locked/Expired/Disabled'
          }

          '0x17' 
          {
            $reportitem.FailureReason = 'Password Expired'
          }

          '0x6' 
          {
            $reportitem.FailureReason = 'Bad Username'
          }

          '0x18' 
          {
            $reportitem.FailureReason = 'Bad Password'
          }

          '0x25' 
          {
            $reportitem.FailureReason = 'Time Skew'
          }

        }
      
      

      
        $report = $report + $reportitem
      }


      
      4771 # Kerberos pre-authentication failed.
      {
        $reportitem | Add-Member -MemberType NoteProperty -Name FailureDescription -Value 'Kerberos Pre-Authentication Failure'
        $reportitem | Add-Member -MemberType NoteProperty -Name FailureReason -Value ''
        $reportitem | Add-Member -MemberType NoteProperty -Name TargetUserName -Value $($eventxml.Event.EventData.Data[0].'#text')
        $reportitem | Add-Member -MemberType NoteProperty -Name TargetDomainName -Value ''
        $reportitem | Add-Member -MemberType NoteProperty -Name WorkstationName -Value ''
        $reportitem | Add-Member -MemberType NoteProperty -Name IPAddress -Value $($eventxml.Event.EventData.Data[6].'#text').replace('::ffff:','')   
        
        # Get code from status in XML.
        switch ($eventxml.Event.EventData.Data[4].'#text') {
          '0x12' 
          {
            $reportitem.FailureReason = 'Account Locked/Expired/Disabled'
          }

          '0x17' 
          {
            $reportitem.FailureReason = 'Password Expired'
          }

          '0x6' 
          {
            $reportitem.FailureReason = 'Bad Username'
          }

          '0x18' 
          {
            $reportitem.FailureReason = 'Bad Password'
          }

          '0x25' 
          {
            $reportitem.FailureReason = 'Time Skew'
          }


        
      
        }


        $report = $report + $reportitem
      }

    }
  }

  return $report
}

$jobid = (Invoke-Command -AsJob -ComputerName $domaincontrollers -ScriptBlock $scriptblock -ArgumentList $timestamp).id

while ((Get-Job -Id $jobid).State -eq 'Running') 
{
  Start-Sleep -Seconds 5
  Get-Job -Id $jobid
}

$endtime = Get-Date

$eventlist = Receive-Job -Id $jobid
Remove-Job -Id $jobid

[array]$scoreboard = $null

$firstrun = $true

foreach ($event in $eventlist) 
{
  if ($event.eventid) 
  {
    $score = New-Object -TypeName PSObject
    $found = $false

    if (!$firstrun) 
    {
      foreach ($entry in $scoreboard) 
      {
        if ($entry.IPAddress -eq $event.ipaddress -and $entry.SamAccountName -eq $event.TargetUserName -and $entry.FailureDescription -eq $event.FailureDescription -and $entry.FailureReason -eq $event.FailureReason) 
        {
          $entry.EntryCount++  
          $found = $true
          break
        }
      }
    }
  

    if (!$found -and !$firstrun) 
    {
      try 
      {
        $score | Add-Member -MemberType NoteProperty -Name Hostname -Value $([system.net.dns]::GetHostbyAddress($($event.IPAddress)).HostName)
      }
      catch 
      {
        $score | Add-Member -MemberType NoteProperty -Name Hostname -Value 'Unresolved'
      }
     

      $score | Add-Member -MemberType NoteProperty -Name IPAddress -Value $($event.ipaddress)
      $score | Add-Member -MemberType NoteProperty -Name SamAccountName -Value $($event.TargetUserName)
      $score | Add-Member -MemberType NoteProperty -Name FailureDescription -Value $($event.FailureDescription)
      $score | Add-Member -MemberType NoteProperty -Name FailureReason -Value $($event.FailureReason)
      $score | Add-Member -MemberType NoteProperty -Name EntryCount -Value 1 
      $scoreboard = $scoreboard + $score
    }


    if ($firstrun) 
    {
      try 
      {
        $score | Add-Member -MemberType NoteProperty -Name Hostname -Value $([system.net.dns]::GetHostbyAddress($($event.IPAddress)).HostName)
      }
      catch 
      {
        $score | Add-Member -MemberType NoteProperty -Name Hostname -Value 'Unresolved'
      }
      

      $score | Add-Member -MemberType NoteProperty -Name IPAddress -Value $($event.ipaddress)
      $score | Add-Member -MemberType NoteProperty -Name SamAccountName -Value $((($event.TargetUserName).replace(':',' ')).replace('=',' '))
      $score | Add-Member -MemberType NoteProperty -Name FailureDescription -Value $($event.FailureDescription)
      $score | Add-Member -MemberType NoteProperty -Name FailureReason -Value $($event.FailureReason)
      $score | Add-Member -MemberType NoteProperty -Name EntryCount -Value 1
      $firstrun = $false
      $scoreboard = $scoreboard + $score
    }
  }
}

$Header = '<html><head><title>Active Directory Security Failure Scoreboard</title></head><body><h1>All failures from ' + $timestamp + ' to ' +$endtime + ' (~30 minutes).</h1><p><pre>'
$Footer = '</pre></p></body></html>'

$Header |
Format-Table |
Out-File -Width 256 -FilePath $filepath
$scoreboard |
Sort-Object -Property SamAccountName |
Format-Table |
Out-File -Width 256 -FilePath $filepath -Append
$Footer |
Sort-Object -Property TimeCreated |
Format-Table |
Out-File -Width 256 -FilePath $filepath -Append
