## Crypto Report & Removal
$vers = "v8.0" # v8.0

## todo
# - INCL diag_enum
# - readme check > init chk file
# - verbose mode
# - remove duplicate counts for dual-shares
# - files by owner count
# - show incremental
# - specify share
# - null empty entry
# - take ownership
# - blank owner
# - change / revert share perms
# - remove additional gci
# - servers w/ fp role
# - >$null 2>&1 if err / denied
# - sandbox
# -- per share lockdown (i.e. node > list share(s) > % lock)

## shell
# $Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'black')
# $Host.UI.RawUI.ForegroundColor = 'white'

# globals
$ldt = get-date -format "MM-dd-yyyy_hh-mm-ss"
# $log_path = read-host -prompt "Log Path (e.g. \\server\logs$)? : "
# $log = "$log_path\crypto_log-$ldt.txt"
$log = "crypto_log-$ldt.txt"
$hidden = "\$"
$str = $null
$logging = "1"

# banner
function banner{

write-host "
*****************************************************************************
*                                                                           *"
write-host -nonewline "*   "
write-host -nonewline "# Crypto Scripto" -foregroundcolor yellow
write-host -nonewline "                                                       *"
write-host "
*   - $vers                                                                 *
*                                                                           *
*   This script offers no guarantees and should only be used as per the     *
*   guidelines highlighted in the README.                                   *
*                                                                           *
*   Please make sure you familiarise yourself with the contents of said     *
*   README before proceeding.                                               *
*                                                                           *
*****************************************************************************";
write-host ""

# write-host "
# *****************************************************************************
# *                                                                           *"
# write-host -nonewline "*   "
# write-host -nonewline "# Crypto Scripto" -foregroundcolor yellow
# write-host -nonewline "                                                        *"
# write-host "
# *   - $vers                                                                  *
# *                                                                           *
# *   This program is free software: you can redistribute it and/or modify    *
# *   it under the terms of the GNU General Public License as published by    *
# *    the Free Software Foundation, either version 3 of the License, or      *
# *   (at your option) any later version.                                     *
# *                                                                           *
# *   This program is distributed in the hope that it will be useful,         *
# *   but WITHOUT ANY WARRANTY; without even the implied warranty of          *
# *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
# *   GNU General Public License for more details.                            *
# *                                                                           *
# *   You should have received a copy of the GNU General Public License       *
# *   along with this program.  If not, see <http://www.gnu.org/licenses/>.   *
# *                                                                           *
# *****************************************************************************";
# write-host ""

}

# blurb
function blurb{

	$show_blurb = read-host -prompt "Do you wish to view README? [Y/N]?"

	if($show_blurb -eq "N" -or $show_blurb -eq "n"){
		write-host "`nGood hunting.`n" -foregroundcolor yellow
		init
	}
	if($show_blurb -eq "Y" -or $show_blurb -eq "y"){
write-host "
*****************************************************************************
*                                                                           *"
write-host -nonewline "*   "
write-host -nonewline "# Overview" -foregroundcolor yellow
write-host -nonewline "	                                                       *"
write-host "
*                                                                           *
*   The intention of this script is to enumerate shares against N number    *
*   of hosts for the existance of files matching Y and Z (i.e. encrypted    *
*   files and their associated 'help' HTML / TXT / HTA files).              *
*                                                                           *
*   There are two main functions of the script; a REPORT run and an ACTION  *
*   run. Both will populate a log file and both will provide a summary of;  *
*                                                                           *
*   - Total number of infected files                                        *
*   - Total number of infected shares                                       *
*   - Total number of infected servers                                      *
*   - Total number of owners and a recommendation of the infection source   *
*                                                                           *
*                                                                           *";
write-host -nonewline "*   "
write-host -nonewline "# Report Run" -foregroundcolor yellow
write-host -nonewline "		                                            *"
write-host "
*                                                                           *
*   The report run will prompt for hostnames, building an array, or will    *
*   run against an automatically populating array (i.e. all enabled, domain *
*   joined servers or workstations).                                        *
*                                                                           *
*   The script will then ask for identifcation of the files that are to be  *
*   evaluated. There is a pre-populated set of 'known matches' (e.g. Thor)  *
*   which will negate the requirement to enter them manually.               *
*                                                                           *
*   Where the file(s) do not match a known instance, you should specify     *
*   both the extension and the format of the HTML instruction file.         *
*                                                                           *
*   e.g.                                                                    *
*                                                                           *
*      [3] Other / Unknown                                                  *
*   Selection: 3                                                            *
*   Extension: jefferson                                                    *
*   HTML Name Format: HELP_DECRYPT                                          *
*                                                                           *
*   The script will then ask whether you wish to search in hidden shares.   *
*                                                                           *
*   It will confirm your selections, giving you an option to change any     *
*   previous input(s).                                                      *
*                                                                           *
*   The script will then run against the array of hosts and for each share  *
*   will list all matching files and their owner.                           *
*                                                                           *
*   A summary of files and differing owners (and how many files they own)   *
*   will be generated at the end of each share inspection and an overall    *
*   summary of file count, infected shares, servers and owners will be      *
*   generated and displayed visually in addition to being logged.           *
*                                                                           *
*                                                                           *";
write-host -nonewline "*   "
write-host -nonewline "# Action Run" -foregroundcolor yellow
write-host -nonewline "		                                            *"
write-host "
*                                                                           *
*   The action run will run exactly as the report run, except it will       *
*   pause at the end of each scanned share and ask if you wish to delete    *
*   the files.                                                              *
*                                                                           *
*   A summary of files and differing owners (and how many files they own)   *
*   will be generated at the end of each share inspection and an overall    *
*   summary of file count (deleted / retained), infected shares, servers    *
*   and owners will be generated and displayed visually in addition to      *
*   being logged.                                                           *
*                                                                           *
*****************************************************************************";
write-host ""
init
	}
	else{
		blurb
	}
}

# main
function sysnote{
	[cmdletbinding()]
	param(
		[parameter(mandatory=$true)]
		[string]$title,
		[validateset("info","warning","error")]
		[string]$type = "info",
		[parameter(mandatory=$true)]
		[string]$msg,
		[string]$dur=10000
	)
	[system.reflection.assembly]::loadwithpartialname('system.windows.forms') | out-null
	$note = new-object system.windows.forms.notifyicon
	$path = get-process -id $pid | select -expand path
	$icon = [system.drawing.icon]::extractassociatedicon($path)
	$note.icon = $icon
	$note.balloontipicon = $type
	$note.balloontiptext = $msg
	$note.balloontiptitle = $title
	$note.visible = $true
	$note.showballoontip($dur)
}

# function main ($type,$hidden,$delete)
function main{

	function main_run{
		if($logging -eq "1"){
			start-transcript -path $log -append | out-null
		}
		foreach($node in $hostnames){
			if(test-connection $node -count 1 -quiet){
				write-host -nonewline "[START] Searching $node for..."
				write-host "...`n"
				# $hidden_str = read-host -prompt "Search hidden shares [Y]/[N]?"
				if($hidden_str -eq "Y" -or $hidden_str -eq "y"){
					# dirty > array || wmi
					$shares = gwmi win32_share -computer $node | ? {$_.Name -ne "ADMIN`$" -and $_.Name -notmatch "^[H-Z]\$" -and $_.Name -ne "IPC`$" -and $_.Name -ne "NETLOGON" -and $_.Name -ne "SYSVOL" -and $_.Name -ne "WindowsUpdateRepository" -and $_.Path -notmatch "LocalsplOnly"} | select -expand Name
				}
				else{
					$shares = gwmi win32_share -computer $node | ? {$_.Name -notmatch "$hidden"} | select -expand Name
				}

				$total = 0
				$owner_count = 0
				$owners_array = @()
				$owners = {$owners_array}.invoke()

				foreach($share in $shares){
					$share_path = "\\$node\$share"
					$count = 0
					$removed = 0
					write-host "`t[CHECK] Checking $share..."
					foreach($str in $strs){
						gci -path $share_path -filter "*$str*" -recurse -force -erroraction silentlycontinue | ? { ! $_.psiscontainer } | foreach ($_){
							$count++
							$total++
							$file_path = $_.fullname
							# $owner = (get-acl "$share_path\$_").owner
							$acl = get-acl "$file_path"
							$owner = $acl.owner
							if($owner -eq $null){
								# write-host "`t`t$file_path is owned by $owner" -foregroundcolor green
							}
							if($owner -eq "BUILTIN\Administrators"){
								write-host "`t`t$file_path is owned by $owner" -foregroundcolor green
							}
							else{
								$owner_count++
								$owners.add($owner)
								write-host "`t`t$file_path is owned by $owner" -foregroundcolor yellow
							}
						}
					}
					# =1
					if($count -eq "1"){
						write-host "`t[WARNING] $share has $count infected file." -foregroundcolor "yellow"
						$delete = read-host -prompt "`t[CHECK] Delete infected file [Y]/[N]?"
						if($delete -eq "Y" -or $delete -eq "y"){
							foreach($str in $strs){
								gci -path $share_path -filter "*$str*" -recurse -force -erroraction silentlycontinue | ? { ! $_.psiscontainer } | foreach ($_){
										take_owner
										remove-item -force $_.fullname
										# $_.fullname | remove-item -force
										$removed++
								}
								write-host "`t[OK] Removed $count file from $share.`n" -foregroundcolor green
							}
						}
						else{
								write-host "`t[WARNING] $share STILL has $count infected file.`n" -foregroundcolor yellow
						}
					}
					# >1
					if($count -gt "1"){
						write-host "`t[WARNING] $share has $count infected files." -foregroundcolor yellow
						$delete = read-host -prompt "`t[CHECK] Delete infected files [Y]/[N]?"
						if($delete -eq "Y" -or $delete -eq "y"){
							foreach($str in $strs){
								gci -path $share_path -filter "*$str*" -recurse -force -erroraction silentlycontinue | ? { ! $_.psiscontainer } | foreach ($_){
										take_owner
										remove-item -force $_.fullname
										# $_.fullname | remove-item -force
										$removed++
								}
								write-host "`t[OK] Removed $count files from $share.`n" -foregroundcolor green
							}
						}
						else{
							write-host "`t[WARNING] $share STILL has $count infected files.`n" -foregroundcolor yellow
						}
					}
					# clean
					if($count -eq "0"){
						write-host "`t[OK] $share has $count infected files.`n" -foregroundcolor green
					}
				}
				if($total -eq "0"){
					write-host "`t[OK] There are $total infected files on $node.`n" -foregroundcolor green
				}
				if($total -gt "0"){
					write-host "`t[SUMMARY] There are $total infected files on $node, with $owner_count file(s) owned by non-Administrators." -foregroundcolor cyan
					if($owner_count -ne "0"){
						write-host "`t[SUMMARY] The following are owners. Their machines should be isolated and rebuilt immediately;`n" -foregroundcolor cyan
						$owners_unique = $owners | sort -unique
						foreach($owner in $owners_unique){
							write-host "`t`t- $owner" -foregroundcolor cyan
						}
					}
				}
				if($removed -ne "0"){
					write-host "[TOTAL] $removed files have been removed.`n" -foregroundcolor green
				}
				# else{
					# write-host "`t[OK] There were $total infected files on $node.`n" -foregroundcolor green
				# }
				write-host "`n[END] Finished searching $node.`n"
			}
			else{
				write-host "[FAILED] $node is offline." -foregroundcolor "yellow"
			}
		}
		if($logging -eq "1"){
			stop-transcript
		}
		break
	}

	function selection{
		$selection = read-host -prompt "All Servers [S], Workstations [W], Hostname(s) [H] or Subnet [N]?"

		if($selection -ne "H" -or $selection -eq "h"){
			if(!(get-module activedirectory)){
				import-module activedirectory >$null 2>&1
			}
			$domain = get-addomain | select -expand distinguishedname
			# $ou = "ou=Computers,ou=Parent,$domain"
		}
		if($selection -eq "S" -or $selection -eq "s"){
			$hostnames = get-adcomputer -searchbase "$ou" -filter {(OperatingSystem -like "*Server*") -and (enabled -eq $True)} | select Name -expandproperty Name
			main_run
		}
		if($selection -eq "W" -or $selection -eq "w"){
			$hostnames = get-adcomputer -searchbase "$ou" -filter {(OperatingSystem -notlike "*Server*") -and (enabled -eq $True)} | select Name -expandproperty Name
			main_run
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
			# $comps = $hostname
			# $comps = $env:computername
			sysnote -title "Information" -type info -msg "Beginning a scan of the selected hosts..." -dur 20000
			main_run
		}
		if($selection -eq "N" -or $selection -eq "n"){
			ipb
		}
		else{
			selection
		}
	}
	selection
}

## range
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
	init_process
}

# report
function report{

	function report_run{
		if($logging -eq "1"){
			start-transcript -path $log -append | out-null
		}
		foreach($node in $hostnames){
			if(test-connection $node -count 1 -quiet){
				write-host -nonewline "[START] Searching $node"
				write-host "...`n"
				# $hidden_str = read-host -prompt "Search hidden shares [Y]/[N]?"
				if($hidden_str -eq "Y" -or $hidden_str -eq "y"){
					# dirty > array || wmi
                   			$shares = gwmi win32_share -computer $node | ? {$_.Name -ne "ADMIN`$" -and $_.Name -notmatch "^[H-Z]\$" -and $_.Name -ne "IPC`$" -and $_.Name -ne "NETLOGON" -and $_.Name -ne "SYSVOL" -and $_.Name -ne "WindowsUpdateRepository" -and $_.Path -notmatch "LocalsplOnly"} | select -expand Name
				}
				else{
					$shares = gwmi win32_share -computer $node | ? {$_.Name -notmatch "$hidden" -and $_.Name -notmatch "DFS"} | select -expand Name
				}

				$total = 0
				$owner_count = 0
				$owners_array = @()
				$owners = {$owners_array}.invoke()
				$inf_shares_ar = @()
				$inf_shares = {$inf_shares_ar}.invoke()

				foreach($share in $shares){
					$share_path = "\\$node\$share"
					$count = 0
					$removed = 0
					write-host "`t[CHECK] Checking $share..."
					foreach($str in $strs){
						gci -path $share_path -filter "*$str*" -recurse -force -erroraction silentlycontinue | ? { ! $_.psiscontainer } | % ($_){
							$count++
							$total++
							$file_path = $_.fullname
							$inf_shares.add("$share_path")
							# $owner = (get-acl "$share_path\$_").owner
							$owner = (get-acl "$file_path").owner
							if($owner -eq "BUILTIN\Administrators"){
								write-host "`t`t$file_path is owned by $owner" -foregroundcolor yellow
							}
							else{
								$owner_count++
								$owners.add($owner)
								write-host "`t`t$file_path is owned by $owner" -foregroundcolor yellow
							}
						}
					}
					# =1
					if($count -eq "1"){
						write-host "`t[WARNING] $share has $count infected file.`n" -foregroundcolor red
					}
					# >1
					if($count -gt "1"){
						write-host "`t[WARNING] $share has $count infected files.`n" -foregroundcolor red
					}
					# clean
					if($count -eq "0"){
						write-host "`t[OK] $share has $count infected files.`n" -foregroundcolor green
					}
				}
				if($total -eq "0"){
					write-host "`t[OK] There are $total infected files on $node.`n" -foregroundcolor red
				}
				if($total -gt "0"){

					$inf_shares_uniq = $inf_shares | sort -unique
					$inf_shares_total = ($inf_shares_uniq).count
					write-host "[SUMMARY] The following $inf_shares_total shares are infected. Look to restore these from the latest backup;`n" -foregroundcolor red

					foreach($inf_share in $inf_shares_uniq){
						write-host "`t- $inf_share" -foregroundcolor red
					}

					write-host -nonewline "`n[SUMMARY] There are $total infected files on $node, with $owner_count file(s) owned by non-Administrators. " -foregroundcolor cyan
					if($owner_count -ne "0"){
						write-host "The following are owners. Their machines should be isolated and rebuilt immediately;`n" -foregroundcolor cyan
						$owners_unique = $owners | sort -unique
						$owners_total = $owners | measure
						$owner_esc = [regex]::Escape('$owners_total')
						foreach($owner in $owners_unique){
							$owner_str = $owner.split('\')[1]
							$owner_total = ($owners | ? {$_ -match "$owner_str"}).count
							write-host "`t- $owner ($owner_total files)" -foregroundcolor cyan
						}
					}
					if($owner_count -eq "0"){
						write-host "`n"
					}
				}
				if($removed -ne "0"){
					write-host "[TOTAL] $removed files have been removed.`n" -foregroundcolor green
				}
				# else{
					# write-host "`t[OK] There were $total infected files on $node.`n" -foregroundcolor green
				# }
				write-host "`n[END] Finished searching $node.`n"
			}
			else{
				write-host "[FAILED] $node is offline." -foregroundcolor yellow
			}
		}
		if($logging -eq "1"){
			stop-transcript
		}
		break
	}

	function selection{
		$selection = read-host -prompt "All Servers [S], Workstations [W] or Hostname(s) [H]?"
		if($selection -ne "H" -or $selection -eq "h"){
			if(!(get-module activedirectory)){
				import-module activedirectory >$null 2>&1
			}
			$domain = get-addomain | select -expand distinguishedname
			# $ou = "ou=Computers,ou=Parent,$domain"
		}
		if($selection -eq "S" -or $selection -eq "s"){
			$hostnames = get-adcomputer -searchbase "$domain" -filter {(OperatingSystem -like "*Server*") -and (enabled -eq $True)} | select Name -expandproperty Name | sort
			report_run
		}
		if($selection -eq "W" -or $selection -eq "w"){
			$hostnames = get-adcomputer -searchbase "$domain" -filter {(OperatingSystem -notlike "*Server*") -and (enabled -eq $True)} | select Name -expandproperty Name | sort
			report_run
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
			# $comps = $hostname
			# $comps = $env:computername
			sysnote -title "Information" -type info -msg "Beginning a scan of the selected hosts..." -dur 20000
			report_run
		}
		else{
			selection
		}
	}
	selection

}

# match
function match{
	if($sel_ver -ne $null){
		if($sel_ver -eq $sel_ar_count){
			$str = read-host -prompt "Query String"
			# set-variable -name $str_g -value $str -scope global
			$hidden_str = read-host -prompt "Search hidden shares [Y]/[N]?"
			write-host "Finding files that match" $str
		}
		else{
			# write-host -nonewline "Finding files that match" $sel_ext[$sel_ver]
			write-host "Finding files that match" $sel_ext[$sel_ver]
		}
		write-host " and" $sel_hlp[$sel_ver]
		$str = $sel_ext[$sel_ver]

		$sel_check = read-host -prompt "Is this correct [Y/N]?"
		$sel_check

		if($sel_check -eq "Y" -or $sel_check -eq "y"){
			selecta
		}
		else{
			ver
		}
	}
}

# ownership
function get_owner{
	$owner = (get-acl $file_path).owner
	if($owner -eq $null){
		# write-host "`t`t$_ is owned by $owner" -foregroundcolor green
	}
	if($owner -eq "BUILTIN\Administrators"){
		write-host "`t`t$_ is owned by $owner" -foregroundcolor green
	}
	else{
		$owners++
		write-host "`t`t$_ is owned by $owner" -foregroundcolor yellow
	}
}
function take_owner{
	# $group = new-object System.Security.Principal.NTAccount("Builtin", "Administrators")
	# $acl.SetOwner($group)
	# write-host "Adjusting owner from $owner to $new_owner..."
	# set-acl -path "$file_path" -aclobject $acl
	# $new_owner = $acl.owner
	# $owner_changed++
}

# shares
function list_shares{
}
function control_shares{
}

# built-in
function ver{
	write-host "`nWhat version of Crypto do you have?"
	$sel_co = 0
	$sel_ar = @("Locky","Zepto","Thor","Wallet","Other / Unknown")
	$sel_ext = @("locky","zepto","*.thor","*.wallet")
	# $sel_hlp = @("_*_HELP*.html","_*_HELP*.html","_*is.html")

	$sel_ar_count = ($sel_ar).count
	$sel_count = ($sel_ext).count

	$sel_ar | foreach ($_){
		write-host "`t[$sel_co] $_"
		$sel_co++
	}
	# $sel_get = "From File ($src_file)"
	# $sel_cog = $sel_co
	# # write-host "`t[$sel_cog] $sel_get"
	$sel_ver = read-host -prompt "Selection"

	if($sel_ver -eq ($sel_ar_count -1) -or $sel_ver -gt ($sel_ar_count -1)){
		$str_ext = read-host -prompt "Extension"
		# $str_html = read-host -prompt "HTML Format (e.g. HELP_DECRYPT.html)"
		$hidden_str = read-host -prompt "Search hidden shares [Y]/[N]?"

		$strs_ar = @()
		$strs = {$strs_ar}.invoke()
		$strs.add("$str_ext")
		# $strs.add("$str_html")

		write-host -nonewline "Finding files that match "
		write-host $strs[0] -foregroundcolor yellow
		# write-host -nonewline " and "
		# write-host $strs[1] -foregroundcolor yellow

		$sel_check = read-host -prompt "Is this correct [Y/N]?"

		if($sel_check -eq "Y" -or $sel_check -eq "y"){
			if($report_init -eq "1"){
				report
			}
			else{
				main
			}
		}
		else{
			ver
		}
	}
	else{
		$strs_ar = @()
		$strs = {$strs_ar}.invoke()
		write-host -nonewline "Finding files that match "
		write-host $sel_ext[$sel_ver] -foregroundcolor yellow
		# write-host -nonewline " and "
		# write-host $sel_hlp[$sel_ver] -foregroundcolor yellow
		$strs.add($sel_ext[$sel_ver])
		# $strs.add($sel_hlp[$sel_ver])
		$hidden_str = read-host -prompt "Search hidden shares [Y]/[N]?"
		if($report_init -eq "1"){
			report
		}
		else{
			main
		}
	}
}
# $src_file = read-host -prompt "Path to Source File"
if($src_file -eq $null){
	$src_file = "null"
}
else{
	$src_file = $src_file
}

# init
function init{
	$type = read-host -prompt "Report [R] or Action [A]?"

	# report_init
	if($type -eq "R" -or $type -eq "r"){
		$report_init = 1
		ver
	}

	# action
	if($type -eq "A" -or $type -eq "a"){
		$report_init = 0
		ver
	}
	# else goto ver
	else{
		init
	}
}
banner
blurb

## not needed (POC)
# $execution = get-executionpolicy
# function prime{
	# if($execution -ne "Unrestricted"){
		# $execution_change = read-host -prompt "ExecutionPolicy is set to $execution and needs to be Unrestricted. Adjust [Y/N]?"
		# if($execution_change -eq "Y" -or $execution_change -eq "y"){
			# set-executionpolicy unrestricted
			# init
		# }
		# if($execution_change -eq "N" -or $execution_change -eq "n"){
			# write-host "Goodbye!"
		# }
		# else{
			# prime
		# }
	# }
	# else{
		# init
	# }
# }
# prime
