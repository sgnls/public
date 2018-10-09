(get-mailbox).alias | % { "# $_ "; get-inboxrule -mailbox $_ | ? {$_.forwardto -ne $null} | fl forwardto* }
(get-mailbox).alias | % { "# $_ "; get-inboxrule -mailbox $_ | ? {$_.description -match "If the"} | fl description}
$a = "prettylotus@vip.163.com" ;"get-accepteddomain | ? {$_.name -notmatch "microsoft"} | % { get-messagetrace -pagesize 5000 | ? {$_.senderaddress -match "$a"} | ft received,sender*,recipient*,subject*,status* }
