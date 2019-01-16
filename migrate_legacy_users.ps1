## Migrate Users Based on Legacy Domain Aliases

# globals
$logging = "1"
$live = "0"
$ldt = get-date -format "MM-dd-yyyy_hh-mm-ss"
$domains = @("domA","domB","domC")
$log = "legacy_domains-$ldt.log"
$tou = "OU=Ex-Users,DC=domain,DC=local"
$mbx = "exchange"
$id = 0

# prep
if($logging -eq "1"){
	start-transcript -path $log -append | out-null
}
if($suppress -eq "1"){
	$erroractionpreference = "silentlycontinue"
	$warningpreference = "silentlycontinue"
}
if(!(get-module activedirectory)){
	import-module activedirectory >$null 2>&1
}

# mbx : refine
$emc = new-pssession -configurationname Microsoft.Exchange -connectionuri http://$mbx/PowerShell/ -authentication Kerberos
import-pssession $emc >$null 2>&1
$amb = get-mailbox -resultsize unlimited

function main_init{
	$domains | % {
		$dom = $_
		$mbs = $amb | ? {$_.primarysmtpaddress -match $dom}
		$mbc = ($mbs).count
		# "There are $mbc matches against $dom."
		$mbs | % {
			$id++
			$usr = $(($_).samaccountname)
			write-host -foregroundcolor cyan "[$id/$mbc] $usr"

			# disable
			write-host -nonewline "`t- Disabling account for $usr... "
			try{
				if($live -eq "1"){
					 set-aduser -identity $usr -enabled:$false
				}
				write-host -foregroundcolor green "OK!"
			}
			catch{
				$em = $_.exception.message
				$ei = $_.exception.itemname
				if($ei -ne $null){
					$err = "$em / $ei"
				}
				else{
					$err = "$em"
				}
				write-host -foregroundcolor red "Failed! ($err)"
			}

			# migrate
			$pc = $(get-aduser -identity $usr -properties distinguishedname).distinguishedname
			$sou = ("$pc").split(",")
			$ou = ($sou[1..($sou.length -1)] -join ",")
			write-host -nonewline "`t- Migrating $usr from $sou to $tou... "
			try{
				if($live -eq "1"){
					move-adobject -identity $usr -targetpath "$tou"
				}
				write-host -foregroundcolor green "OK!"
			}
			catch{
				$em = $_.exception.message
				$ei = $_.exception.itemname
				if($ei -ne $null){
					$err = "$em / $ei"
				}
				else{
					$err = "$em"
				}
				write-host -foregroundcolor red "Failed! ($err)"
			}

			# disable protocols
			$prot = @("OWA","IMAP","MAPI","POP","ActiveSync","EWS")
			$prot | % {
				write-host -nonewline "`t- Disabling $_... "
				$pr = ($_).tolower()
				$pro = $pr + "enabled"
				$caspara = @{
					$pro = $false
				}
				try{
					if($live -eq "1"){
						set-casmailbox -identity $usr @caspara
					}
					write-host -foregroundcolor green "OK!"
					$n++
				}
				catch{
					write-host -foregroundcolor red "Failed!"
				}
			}

			# hide from GAL
			write-host -nonewline "`t- Hiding from Global Address List... "
			try{
				if($live -eq "1"){
					set-mailbox -identity $usr -hiddenfromaddresslistsenabled:$true
				}
				write-host -foregroundcolor green "OK!"
				$n++
			}
			catch{
				$em = $_.exception.message
				$ei = $_.exception.itemname
				if($ei -ne $null){
					$err = "$em / $ei"
				}
				else{
					$err = "$em"
				}
				write-host -foregroundcolor red "Failed! ($err)"
			}
		}
	}
}

# init
main_init

if($logging -eq "1"){
	stop-transcript
}
