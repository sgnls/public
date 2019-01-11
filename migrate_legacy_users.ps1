## Migrate Users Based on Legacy Domain Aliases

# globals
$logging = "1"
$ldt = get-date -format "MM-dd-yyyy_hh-mm-ss"
$log = "legacy_domains-$ldt.log"
$domains = @("domain1.com","domain2.com")
$tou = "OU=Ex-Users,DC=domain,DC=local"
$mbs = get-mailbox -resultsize unlimited
$mbc = ($mbs).count
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

function main_init{
	$mbs | ? {$_.primarysmtpaddress -match "$domains"} | % {
		$id++
		$usr = $(($_).samaccountname)
		write-host -foregroundcolor cyan "[$id/$mbc] $usr"

		# migrate
		$pc = $(get-aduser -identity $usr -properties distinguishedname).distinguishedname
		$sou = ("$pc").split(",")
		$ou = ($sou[1..($sou.length -1)] -join ",")
		write-host -nonewline "`t- Migrating $usr from $sou to $tou... "
		try{
			# move-adobject -identity $usr -targetpath "$tou"
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
				# set-casmailbox -identity $usr @caspara
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
			# set-mailbox -identity $usr -hiddenfromaddresslistsenabled:$true
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

# init
main_init

if($logging -eq "1"){
	stop-transcript
}
