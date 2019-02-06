## Install AlientVault Agent

# globals
function globals{
	param(
		[string]$cni = $args[0]
	)
	# set-executionpolicy -scope process -executionpolicy unrestricted
	# $vb = read-host -prompt "Verbose Mode [Y/N]?""
	$ldt = get-date -format "MM-dd-yyyy_hh-mm-ss"
	$gn = "install_av-agent"
	$lf = "$gn-$ldt.txt"
	$log = "0"
	$err = "0"
	if($err -eq "0"){
		$erroractionpreference = "silentlycontinue"
		$warningpreference = "silentlycontinue"
	}

	# adm
	if(!(get-module activedirectory)){
		import-module activedirectory >$null 2>&1
	}
	if($log -eq "1"){
		start-transcript -path $lf -append | out-null
	}
	if(!$cni){
		write-host -foregroundcolor cyan "`n`! WARNING : ControlNodeID has NOT been specified. Installations will not process.`n"
		$cni = "NULL"
	}
	if($(($cni).length -ne 36) -and $cni -ne "NULL"){
		write-host -foregroundcolor cyan "`n`! WARNING : ControlNodeID is NOT valid. Installations will not process.`n"
		$cni = "NULL"
	}
	if($(($cni).length -eq 36) -and $cni -ne "NULL"){
		write-host -foregroundcolor cyan "`n`! ControlNodeID : $cni`n"
	}
	scope $cni
}

function scope{
	param(
		[string]$cni = $args[0]
	)
	$scp = read-host -prompt "[S]ervers or [W]orkstations?"
	if($scp -eq "S" -or $scp -eq "s"){
		init_av-agent $cni "s"
	}
	if($scp -eq "W" -or $scp -eq "w"){
		init_av-agent $cni "w"
	}
	else{
		scope
	}
}
#

# init_enum
function init_av-agent{
	param(
		[string]$cni = $args[0],
		[string]$scp = $args[1]
	)
	write-host -nonewline "Acquiring nodes... "
	try{
		if($scp -eq "s"){
			$nodes = get-adcomputer -filter {(enabled -eq $true -and operatingsystem -like "*Server*")}
		}
		if($scp -eq "w"){
			$nodes = get-adcomputer -filter {(enabled -eq $true -and operatingsystem -notlike "*Server*")}
		}
		$nc = ($nodes).count
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
		break
	}
	if($nodes -ne $null){
		write-host -foregroundcolor green "OK! ($nc)`n"
	}
	else{
		write-host -foregroundcolor red "Failed!"
	}

	# init
	$ni = 0
	$nodes | % {
		$ni++
		$n = $(($_).name)
		write-host -nonewline "[$ni/$nc] Checking $n... "
		try{
			if(test-connection $n -count 1 -quiet){
				write-host -foregroundcolor green "ONLINE"
				write-host -nonewline "`tChecking remote management status... "
				if($(gwmi win32_service -computer $n) -ne $null){
					write-host -foregroundcolor green "OK!"
					write-host -nonewline "`tChecking installation status... "
					if($(gwmi win32_service -computer $n | ? {$_.name -match "osqueryd"}) -ne $null){
						write-host -foregroundcolor green "OK!"
					}
					else{
						write-host -foregroundcolor yellow "Not Installed!"
						if($cni -eq "NULL"){
							write-host -foregroundcolor cyan "`tControlNodeID is NOT specified; installation skipped."
						}
						else{
							install_av-agent
						}
					}
				}
				else{
					write-host -foregroundcolor red "Failed! (check WinRM)"
				}
			}
			else{
				write-host -foregroundcolor red "OFFLINE"
			}
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
	write-host "`n:END"
	break
}

# install
function install_av-agent{
	write-host "`t- Attempting installation..."
	invoke-command -computername $n -script {
		$n = $args[0]
		$avu = $args[1]
		$cni = $args[2]
		# prep
		write-host -nonewline "`t-- Preparing host... "
		try{
			set-executionpolicy -scope process unrestricted -confirm:$false
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
			break
		}

		# install
		write-host -nonewline "`t-- Attempting install... "
		try{
			# install_av -controlnodeid $cni | out-null
	    $base = "c:\ProgramData\osquery"
	    $manage_script = $(join-path $base "manage-osqueryd.ps1")
	    $managed_script = $(join-path $base "managed-osqueryd.ps1")
	    $secretfile = $(join-path $base "secret")
	    $flagfile = $(join-path $base "osquery.flags")

	    if([string]::isnullorempty($hostid)){
	    	$hostid = $assetid
	    }
	    if([string]::isnullorempty($apikey)){
	    	$apikey = $cni
	    }
	    if([string]::isnullorempty($apikey)){
	    	if([system.io.file]::exists("$secretfile")){
	      	$apikey = [io.file]::readalltext("$secretfile").trim()
	      }
	    }

	    # TLS 1.2
	    [net.servicepointmanager]::securityprotocol = [net.securityprotocoltype]::tls12

	    # sysmon
	    $source = "https://download.sysinternals.com/files/Sysmon.zip"
	    $file = "$($env:TEMP)\Sysmon.zip"
	    invoke-webrequest $source -outfile $file | out-null

	    unblock-file -path $file
	    $targetondisk = "$($env:USERPROFILE)\Documents\Sysmon\"
	    new-item -itemtype directory -force -path $targetondisk | out-null
	    $shell_app=new-object -com shell.application
	    $zip_file = $shell_app.namespace($file)
	    $destination = $shell_app.namespace($targetondisk)
	    $destination.Copyhere($zip_file.items(), 0x10)

	    $source = "https://www.alienvault.com/documentation/resources/downloads/sysmon_config_schema4_0.xml"
	    $destination = [system.io.path]::gettempfilename()
	    invoke-webrequest $source -outfile $destination | out-null

	    if((gci $destination).length -eq 0){
	       $command = "& '$targetondisk\sysmon' -accepteula -h md5 -n -l -i"
	    }
	    else{
	       $command = "& '$targetondisk\sysmon' -accepteula -h md5 -n -l -i '$destination'"
	    }
	    iex $command | out-null

	    # osquery
	    if(test-path $managed_script){
	    	try{
	      	invoke-expression -command "$managed_script -stop"
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

	    $webclient = new-object system.net.webclient
	    $webclient.downloadfile("https://s3-us-west-2.amazonaws.com/prod-otxb-portal-osquery/repo/windows/alienvault-agent-1.0.1.msi", "$env:TEMP\alienvault-agent.msi")

	    try{
	        start-process c:\windows\system32\msiexec.exe -argumentlist "/i $env:TEMP\alienvault-agent.msi ALLUSERS=1 /qn /l*v .\install.log" -wait
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

	    $osquerydservice = gwmi -class win32_service -filter "Name='osqueryd'"
	    if ($osquerydservice){
	      try{
	      	invoke-expression -command "$managed_script -uninstall"
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

	    [io.file]::writealllines("$secretfile", $apikey)
	    if([string]::isnullorempty($hostid)){
	    	if([system.io.file]::exists($flagfile)){
	      	$match = (select-string -path $flagfile -pattern "specified_identifier=(.*)")
	        if ($match.matches.groups.success) {
	        	$hostid = $match.matches.groups[1].value.trim()
	          # write-Host "Detected and re-using previously selected host id from ${flagfile}: $hostid"
	        }
					else{
	        	# write-Host "Existing host id not found in ${flagfile}"
	        }
	      }
	    }
	    copy $base\osquery.flags.example $flagfile
	    if([string]::isnullorempty($hostid)){
	    	$hostid="00000000-9bf4-4102-957b-08a4e3d99fa6"
	    }
	    $output = "--tls_hostname=api.agent.alienvault.cloud/osquery-api/eu-west-2", "--host_identifier=specified", "--specified_identifier=$hostid"
	    [io.file]::appendalllines([string]$flagfile, [string[]]$output)

			(get-content $manage_script) | % {
				$_ -replace "write-","# write"
			} | set-content $managed_script

	    invoke-expression "$managed_script -install -startupArgs '--flagfile C:\ProgramData\osquery\osquery.flags'" | out-null
	    invoke-expression "$managed_script -start" | out-null
	    del $env:TEMP\alienvault-agent.msi

			start-sleep 2
			if($(gwmi win32_service -computer $n | ? {$_.name -match "osqueryd"}) -ne $null){
				write-host -foregroundcolor green "OK!"
			}
			else{
				write-host -foregroundcolor yellow "Failed!"
			}
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
	} -argumentlist $n,$avu,$cni
	if($log -eq "1"){
		stop-transcript
	}
}

# init_main
globals
