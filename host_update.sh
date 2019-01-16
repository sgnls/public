#!/bin/bash
# Host Update

uh(){
	# u136365.your-storagebox.de
	F=/etc/hosts
	IQ=$(grep "$1" $F | awk '{print $1}')
	IP=$(dig +noall +answer $2 | awk {'print $5'})

	echo "Bound IP for $1 is $IQ. Target IP will be $IP."	
	sed -i 's/$IQ/$IP/g' $F
}

uh $1 $2
