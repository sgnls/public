## Software Install - Tableau
# Script to initiate remote installation of Tableau (v10.3.0) to workstations

## Preparation / Execution
# 1) Create accessible (read-only) share
# 2) Download binary into share
# 3) If necessary, allow execution of script with;
#	 [PS] set-executionpolicy remotesigned
# 4) If necessary, manually import AD module;
#	 [PS] import-module activedirectory
# 5) Run script within Powershell / ISE;
#	 [PS] .\tableau.ps1

# globals
$erroractionpreference = "silentlycontinue"
$ldt = get-date -format "MM-dd-yyyy_hh-mm-ss"
$log = "tableau-$ldt.txt"
$set_logging = read-host -prompt "Log? [Y/N]"
# case-sensitivity is off by default, but just in case...
if($set_logging -eq "Y" -or $set_logging -eq "y"){
	$logging = "1"
}
else{
	$logging = "0"
}

if($logging -eq "1"){
	start-transcript -path $log -append | out-null
}
if(!(get-module activedirectory)){
	import-module activedirectory >$null 2>&1
}

##!!!##
$src_file = "TableauReader-64bit-10-3-0.exe"
$proc_id = "tableau"
##!!!##
# dirty; change to ENV
$usr_dir = "c$\temp"
$usr_dir_local = "c:\temp"

function selection{
	$selection = read-host -prompt "All Machines [A], All Servers [S], Workstations [W], Hostname(s) [H] or	Subnet Range [N]?"
	if($selection -ne "H" -or $selection -eq "h"){
		if(!(get-module activedirectory)){
			import-module activedirectory >$null 2>&1
		}
		$domain = get-addomain | select -expand distinguishedname
		# $ou = "ou=Computers,ou=Parent,$domain"
	}
	if($selection -eq "A" -or $selection -eq "a"){
		if($domain -ne $null){
			$hostnames = get-adcomputer -searchbase "$domain" -filter {(enabled -eq $True)} | select -expand name | sort
			init
		}
		else{
			write-host "Cannot query AD information. Trying via broadcast..." -foregroundcolor yellow
			ipb
		}
	}
	if($selection -eq "S" -or $selection -eq "s"){
		if($domain -ne $null){
			$hostnames = get-adcomputer -searchbase "$domain" -filter {(OperatingSystem -like "*Server*") -and (enabled -eq $True)} | select -expand name | sort
			init
		}
		else{
			write-host "Cannot query AD information. Trying via broadcast..." -foregroundcolor yellow
			ipb
		}
	}
	if($selection -eq "W" -or $selection -eq "w"){
		if($domain -ne $null){
			$hostnames = get-adcomputer -searchbase "$domain" -filter {(OperatingSystem -notlike "*Server*") -and (enabled -eq $True)} | select -expand name | sort
			init
		}
		else{
			write-host "Cannot query AD information. Trying via broadcast..." -foregroundcolor yellow
			ipb
		}
	}
	if($selection -eq "H" -or $selection -eq "h"){
		$hostnames_ar = @()
		$hostnames = {$hostnames_ar}.invoke()
		while($hostname -ne "."){
			$hostname = read-host -prompt "Hostname(s) (end with . )"
			if($hostname -ne "."){
				$hostnames.add("$hostname")
			}
		}
		$total_hostnames = ($hostnames).count
		if($total_hostnames -eq "0"){
			$hostname = ""
		}
		# $nodes = $hostname
		# $nodes = $env:computername
		init
	}
	if($selection -eq "N" -or $selection -eq "n"){
		ipb
	}
	else{
		selection
	}
}

function init{
	$ins = 0
	$skp = 0
	$kod = 0
	$off = 0 
	foreach($node in $hostnames){
		# check machine if online, else ignore
		if(test-connection $node -count 2 -quiet){
			write-host "$node is online. Checking for existing installation..." -foregroundcolor cyan
			$ins_check = gwmi -class win32_product -computername $node | ? {$_.name -match "tableau"}
			if($ins_check -eq $null){
				$os = (gwmi win32_operatingsystem -computername $node).Name
				$arch = (gwmi win32_processor -computer $node | ? {$_.deviceID -eq "CPU0"}).AddressWidth
				write-host "Software is not installed; attempting to install..." -foregroundcolor yellow
				if(!(test-path -path "\\$node\$usr_dir\$path")){
					try{
						write-host -nonewline "Copying installation files to $node... `n"
						new-item "\\$node\$usr_dir" -type directory -force | out-null
						copy-item "$install_src\$src_file" "\\$node\$usr_dir\" | out-null
						write-host "OK!" -foregroundcolor green
					}
					catch{
						write-host "Failed to copy files to $node!`n" -foregroundcolor red
					}
				}
				write-host -nonewline "Initiating installation on $node..."
				try{
					if($rpt_src -ne $null){
						$rpt_svr = "REPORTINGSERVER=$rpt_src"
					}
					if($upd_src -ne $null){
						$upd_svr = "AUTOUPDATESERVER=$upd_src"
					}
					$bin_install = "cmd.exe /c $usr_dir_local\$src_file /quiet /norestart ACCEPTEULA=1"
					([WMICLASS]"\\$node\ROOT\CIMV2:win32_process").create($bin_install) | out-null
					do{
						(write-host -nonewline "."),(start-sleep -s 3)
					}
					until(
						(gwmi -class win32_process -filter "name='$proc_id'" -computername $node | ? {$_.name -match "$proc_id"}).processid -eq $null
					)
					write-host " OK!" -foregroundcolor green
					$ins++
				}
				catch{
					write-host "ERR!`n" -foregroundcolor red
					$kod++
				}
			}
			else{
				write-host "Software is already installed; skipping...`n" -foregroundcolor green
				$skp++
			}
		}
		else{
			write-host "$node is offline.`n" -foregroundcolor red
			$off++
		}
	}
	if($logging -eq "1"){
		stop-transcript
	}
	break
}

function ipb{
	$ips_ar = @()
	$hostnames = {$ips_ar}.invoke()
	$ipn = read-host -prompt "Subnet (e.g. 10.67.0)"
	$ipss = read-host -prompt "Range Start (e.g. 180)"
	$ipse = read-host -prompt "Range End (e.g. 250)"
	$ips = @($ipss..$ipse)
	foreach($ip in $ips){
		$ipf = "$ipn.$ip"
		$hostnames.add("$ipf")
	}
	init
}

function install_src{
	$install_src = read-host -prompt "Installation Binary Path (e.g. \\serverA\software$)"
	if(!($install_src)){
		install_src
	}
	else{
		selection
	}
}
install_src
