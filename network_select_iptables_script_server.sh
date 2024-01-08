# !/bin/bash

# checking if script is run as root
if [[ $(id -u) -ne 0 ]]
then 
    echo script is not run as root, exiting...
    exit
else
	:
fi


###
### general
###

# ruleblocks in this file follow a certain order: as it is a table of rules, the first rule has precedence.
# If the first rule disallows everything then nothing else afterwards will matter.
# INIVIDUAL REJECTS FIRST
# THEN OPEN IT UP
# BLOCK ALL


###
### ports
###
# input ports separated by a single whitespace
# services_all opens the port for all ips (internal and external)
# services_internal opens the port for the specified subnet, the tun and tap devices

# input udp all
INPUT_SERVICES_UDP_ALL="1196 1197 5349 10000 51820"
# input tcp all
INPUT_SERVICES_TCP_ALL="80 443 4443 5349"
# input udp internal
INPUT_SERVICES_UDP_INTERNAL="9 53 137 138"
# input tcp internal
INPUT_SERVICES_TCP_INTERNAL="21 22 139 445 889 3306 4430 5900 60000:60100"
# output udp all dport
OUTPUT_SERVICES_UDP_ALL_DPORT="9 53 67 123 137 138 443 1196 1197 5353 5349 10000 49200:49300"
# output tcp all dport
OUTPUT_SERVICES_TCP_ALL_DPORT="21 22 43 53 80 139 443 445 515 587 631 873 889 3389 4430 4443 5349 5900 8000 8085 9100 9418 11371 60000:60100"
OUTPUT_SERVICES_TCP_ALL_DPORT_FTP="1024:"
# output udp all sport
OUTPUT_SERVICES_UDP_ALL_SPORT="9 53 67 123 137 138 443 1196 1197 5349 10000 49200:49300"
# output tcp all sport
OUTPUT_SERVICES_TCP_ALL_SPORT="21 22 53 80 139 443 445 515 631 889 3389 4430 4443 5349 5900 8085 9100 9418 11371 60000:60100"
OUTPUT_SERVICES_TCP_ALL_SPORT_FTP="1024:"
# output udp internal
OUTPUT_SERVICES_UDP_INTERNAL=""
# output tcp internal
OUTPUT_SERVICES_TCP_INTERNAL=""
# forward udp internal
FORWARD_SERVICES_UDP_INTERNAL="3478 5055:5059 5060 5353 16384:32767"
# forward tcp internal
FORWARD_SERVICES_TCP_INTERNAL="80 443 515 631 993 995 3000 3389 5051 5061 5222 5900 8000 8443 9100 24998"
# exclude from postrouting vpn udp
EXCLUDE_POSTROUTING_UDP_DPORT="5349"
# exclude from postrouting vpn tcp
EXCLUDE_POSTROUTING_TCP_DPORT="5349"
# postrouting vpn udp
POSTROUTING_VPN_UDP=$(for ENTRY in "${OUTPUT_SERVICES_UDP_ALL_DPORT[@]}" "${FORWARD_SERVICES_UDP_INTERNAL[@]}"; do echo "$ENTRY"; done | sort -nu)
# postrouting vpn tcp
POSTROUTING_VPN_TCP=$(for ENTRY in "${OUTPUT_SERVICES_TCP_ALL_DPORT[@]}" "${FORWARD_SERVICES_TCP_INTERNAL[@]}"; do echo "$ENTRY"; done | sort -nu)
# service subnet
#RESCUE_SUBNET="172.25.143.0/24"
#INPUT_SERVICES_UDP_RESCUE_INTERNAL=""
#INPUT_SERVICES_TCP_RESCUE_INTERNAL="22"
#OUTPUT_SERVICES_UDP_RESCUE_INTERNAL=""
#OUTPUT_SERVICES_TCP_RESCUE_INTERNAL="22"

# documentation implemented services
#       ssh                     		TCP             			22
#       DNS hostname            		TCP             			53
#       samba                   		TCP             			139 445
#       samba                   		UDP             			137 138
#       ftp                     		TCP             			21 60000:60100
#       http / https            		TCP             			80 443
#       openvpn                			UDP             			1194 1195 1196 1197
#       vnc                     		TCP             			5900
#       3dm2 raid               		TCP             			889
#       cubesql                 		TCP             			4430
#       ntp / systemd-timesyncd         UDPs, UDPd      			123
#       mailserver              		TCP             			25 993 995
#       get and send mails via vpn      TCP             			587 993 995
#       plex                    		TCP             			3005 8324 32400 32469
#       plex                    		UDP             			1900 5353 32410 32412 32413 32414
#       unified remote          		TCP             			9510 9512
#       unified remote          		UDP             			9511 9512
#       qnap-ts412		        		TCP            				8085
#		synology						TCP							5051
#		cups							TCP							631 
#		cups							UDP							5353
# 		git								TCP							9418
#		gpg								TCP							11371
#		openzone wifi network			TCP							8443
#		smtp (msmtp)					TCPd						587
#		whois							TCPd						43
#		ftp passive (aur updates)		TCPd						1024: (means all unprivileged ports 1024:32535)
#		dhcp, dhclient					UDPd out all				67
#		dnscrypt						UDP							53 443
#		vpnc							UDPs out					500, 4500
#		wireguard server				UDP in all					51820
#		wireguard client				UDPd out all				51820
#		mariadb							TCPd in internal			3306
#		magic packet (wol)				UDPs						9 (internal in + outd + outs + socat)
#		clamav signatures (rsync)		TCPd out					873 (rsync) 443 (curl & wget)

# forwarding for vpn connections
#       http / https            		TCP             			80 443
#       remote desktop          		TCP             			3389, 49000:50000
#       lexmark printer         		TCP             			80 443 515 631 9100 50000:60000
#		canon printer web interface		TCP							8000
#       printer, bonjour, mdns, avahi	UDP							5353
																	# only working with tap, tun cannot multicast / bonjour
																	# printer has to be connected via ip for tun connections
#       telephone macos					UDP							5060			
#       softphone ios					TCP							5061
#										TCP							24998
#		rtp	voice						UDP							16384:32767
#		ios apps						TCP 						3000 (dxb smart)
#										UDP 						5055:5059 (yatzy)
#										TCP							8443 (dkb)	
#		whatsapp incl. voice calls		TCP							443 5222
#										UDP							3478
																	
#		jitsi							UDP	in & out				10000			# media traffic
#										TCP	in & out				80 443 4443
#		coturn and jitsi				UDP	in & out				5349			# tls
#										UDPs out					49200:49300		# limited with --min-port/--max-port, default 49152:65535
#										UDPd out					49200:49300		# limited with --min-port/--max-port, default 49152:65535
#										exclude POSTROUTING UDP		3847 5349		# without this jitsi-videobrige does not work
#										exclude POSTROUTING TCP		3847 5349		# without this jitsi-videobrige does not work



###
### network
###

# variable definition if run as standalone script
if [[ $NETWORKINTERFACE == "" ]]
then
	NETWORKINTERFACE=$(ip route | grep default.* | sed '1!d' | grep -Po '(?<=dev\s)\w+')
	if [[ $NETWORKINTERFACE == "" ]]
	then
	    export PS3="no default network interface present, please select it: "
	    select NETWORKINTERFACE in ""$(ls /sys/class/net/ | sort --version-sort -f)""
    	do
        	echo you selected default network interface "$NETWORKINTERFACE".
        	echo ""
        break
    	done
	else
		:
	fi
	if [[ $NETWORKINTERFACE == "" ]]
	then
		echo "no valid default interface selected, exiting..."
		exit 1
	else
		:
	fi
else
	:
fi

if [[ $SUBNET_ONLINE == "" ]]
then
	DEFAULTNETWORKINTERFACE="$NETWORKINTERFACE"
	#echo DEFAULTNETWORKINTERFACE is $DEFAULTNETWORKINTERFACE
	INT_IP_ONLINE=$(ip -o -4 addr list dev $DEFAULTNETWORKINTERFACE | awk '{print $4}' | cut -d/ -f1)
	#echo INT_IP_ONLINE is $INT_IP_ONLINE
	if [[ $INT_IP_ONLINE == "" ]]
	then
		read -r -p "no local network connection, please enter your subnet like this xxx.xxx.xxx.xxx, e.g. 192.168.1.0: " INT_IP_ONLINE
		#echo INT_IP_ONLINE is $INT_IP_ONLINE
		if echo "$INT_IP_ONLINE" | grep -Eo '(^| )(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])($|[[:space:]])' > /dev/null 2>&1
		then
    		VALID_IP_ADDRESS="$(echo $INT_IP_ONLINE | awk -F'.' '$1 <=255 && $2 <= 255 && $3 <= 255 && $4 <= 255')"
    		if [ -z "$VALID_IP_ADDRESS" ]
    		then
    			echo "no valid ip address entered, exiting..."
				exit 1
    		else
				:
    		fi
		else
    		echo "no valid ip address entered, exiting..."
			exit 1
		fi
	else
		:
	fi
	SUBNET_ONLINE=$(echo $INT_IP_ONLINE | cut -d"." -f1-3)
	#echo SUBNET_ONLINE is $SUBNET_ONLINE
else
	:
fi

if [[ $TUN_SUBNET0 == "" ]]
then
	TUN0=tun0
	if [[ $(ls -1 /sys/class/net/ | grep "$TUN0") == "" ]]
	then
		:
	else
		IP_TUN0=$(ip -o -4 addr list dev $TUN0 | awk '{print $4}' | cut -d/ -f1)
		#echo IP_TUN0 is $IP_TUN0
		TUN_SUBNET0=$(echo $(echo $IP_TUN0 | cut -d"." -f1-3).0)
		#echo TUN_SUBNET0 is $TUN_SUBNET0
	fi
else
	:
fi

if [[ $TUN_SUBNET1 == "" ]]
then
	TUN1=tun1
	if [[ $(ls -1 /sys/class/net/ | grep "$TUN1") == "" ]]
	then
		:
	else
		IP_TUN1=$(ip -o -4 addr list dev $TUN1 | awk '{print $4}' | cut -d/ -f1)
		#echo IP_TUN1 is $IP_TUN1
		TUN_SUBNET1=$(echo $(echo $IP_TUN1 | cut -d"." -f1-3).0)
		#echo TUN_SUBNET1 is $TUN_SUBNET1
	fi
else
	:
fi

if [[ $WG_SUBNET0 == "" ]]
then
	WG0=wg0
	if [[ $(ls -1 /sys/class/net/ | grep "$WG0") == "" ]]
	then
		:
	else
		IP_WG0=$(ip -o -4 addr list dev $WG0 | awk '{print $4}' | cut -d/ -f1)
		#echo IP_WG0 is $IP_WG0
		WG_SUBNET0=$(echo $(echo $IP_WG0 | cut -d"." -f1-3).0)
		#echo WG_SUBNET0 is $WG_SUBNET0
	fi
else
	:
fi

if [[ $WG_SUBNET1 == "" ]]
then
	WG1=wg1
	if [[ $(ls -1 /sys/class/net/ | grep "$WG1") == "" ]]
	then
		:
	else
		IP_WG1=$(ip -o -4 addr list dev $WG1 | awk '{print $4}' | cut -d/ -f1)
		#echo IP_WG1 is $IP_WG1
		WG_SUBNET1=$(echo $(echo $IP_WG1 | cut -d"." -f1-3).0)
		#echo WG_SUBNET1 is $WG_SUBNET1
	fi
else
	:
fi

# variables
CONNECTED_SUBNET="$SUBNET_ONLINE.0/24"
if [[ $TUN_SUBNET0 != "" ]]; then CONNECTED_TUN_SUBNET0="$TUN_SUBNET0/24"; else CONNECTED_TUN_SUBNET0=""; fi
if [[ $TUN_SUBNET1 != "" ]]; then CONNECTED_TUN_SUBNET1="$TUN_SUBNET1/24"; else CONNECTED_TUN_SUBNET1=""; fi
if [[ $WG_SUBNET0 != "" ]]; then CONNECTED_WG_SUBNET0="$WG_SUBNET0/24"; else CONNECTED_WG_SUBNET0=""; fi
if [[ $WG_SUBNET1 != "" ]]; then CONNECTED_WG_SUBNET1="$WG_SUBNET1/24"; else CONNECTED_WG_SUBNET1=""; fi
# CONNECTED_WG_SUBNET1 is not configured as an incoming (server), but outgoing (client) connection, therefore it does not have to be added to IPTABLES_VPN_SUBNETS
IPTABLES_VPN_SUBNETS=$(echo "$CONNECTED_TUN_SUBNET0 $CONNECTED_TUN_SUBNET1 $CONNECTED_WG_SUBNET0" | tr ' ' '\n' | cat)
IPTABLES_SUBNETS=$(echo "$CONNECTED_SUBNET $IPTABLES_VPN_SUBNETS" | tr ' ' '\n' | cat)
#IPTABLES_SUBNETS=$(echo "$CONNECTED_SUBNET $CONNECTED_TUN_SUBNET0 $CONNECTED_TUN_SUBNET1" | tr ' ' '\n' | cat)


###
### at first delete all present rules & configs and start with clean config
###

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X
iptables -t security -F
iptables -t security -X
#iptables -P INPUT ACCEPT
#iptables -P FORWARD ACCEPT
#iptables -P OUTPUT ACCEPT


### setting default filter policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP


###
### defining tables
###

### reject packages
# using reject instead of drop is better in almost all cases and rfc comliant (see archwiki)
# creating table "reject_packages"
iptables -N reject_packages
# rejecting tcp packages, rfc compliant and imitate default linux behavior
iptables -A reject_packages -p tcp -j REJECT --reject-with tcp-reset
# rejecting udp packages, rfc compliant and imitate default linux behavior
iptables -A reject_packages -p udp -j REJECT --reject-with icmp-port-unreachable
# rejecting icmp packages, rfc compliant and imitate default linux behavior
iptables -A reject_packages -p icmp -j REJECT --reject-with icmp-host-unreachable
# rejecting all other packages that are using icmp
iptables -A reject_packages -j REJECT --reject-with icmp-proto-unreachable
# leaving table "reject_packages"
iptables -A reject_packages -p ALL -j RETURN


### logging
# log all input rejected packages
# 2/m
# 5/m
# 10/m
# 10/s
iptables -N input_log_reject
iptables -A input_log_reject -j LOG -m limit --limit 10/m --log-prefix "INPUT:DROP: " --log-level 6
iptables -A input_log_reject -j reject_packages
iptables -A input_log_reject -p ALL -j RETURN
# log all output rejected packages
iptables -N output_log_reject
iptables -A output_log_reject -j LOG -m limit --limit 10/m --log-prefix "OUTPUT:DROP: " --log-level 6
iptables -A output_log_reject -j reject_packages
iptables -A output_log_reject -p ALL -j RETURN


### security
# port scanning
##	1/s		-
#	1/s		2
#	2/s		2
iptables -N port_scanning
iptables -A port_scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
# the following seconds / hitcount rule could cause problems with owncloud or other web services
#iptables -A INPUT -p tcp --tcp-flags SYN SYN -m conntrack --ctstate NEW -m recent --set
#iptables -A INPUT -p tcp --tcp-flags SYN SYN -m conntrack --ctstate NEW -m recent --update --seconds 20 --hitcount 10 -j DROP
iptables -A port_scanning -j DROP
# ddos
# 50/m	200
# 60/s	20
iptables -N ddos
iptables -A ddos -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j RETURN
iptables -A ddos -j DROP
# syn flood tcp
##	1/s		-
#	1/s		3
# 	5/s		10
iptables -N synflood_tcp
# smaller values led to issues, e.g. carddav syncing all contacts
iptables -A synflood_tcp -p tcp -m limit --limit 10/s --limit-burst 4 -j RETURN
iptables -A synflood_tcp -p tcp -j DROP
# syn flood udp
iptables -N synflood_udp
iptables -A synflood_udp -p udp -m limit --limit 10/s --limit-burst 4 -j RETURN
iptables -A synflood_udp -p udp -j DROP
# http limits
# 10/s	100
# 25/m	100
iptables -N http_limits
# do not enable hitcount 60 / 10 can cause timout problems
#iptables -A http_limits -p tcp --dport 80 -m conntrack --ctstate NEW -m recent --set
#iptables -A http_limits -p tcp --dport 80 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
iptables -A http_limits -p tcp --dport 80 -m connlimit --connlimit-above 10 -j DROP
iptables -A http_limits -p tcp --dport 80 -m connlimit --connlimit-above 100 --connlimit-mask 0 -j DROP
iptables -A http_limits -p tcp --dport 80 -m limit --limit 10/second --limit-burst 100 -j RETURN
iptables -A http_limits -p tcp --dport 80 -j DROP
# https limits
iptables -N https_limits
# do not enable hitcount 60 / 10 can cause timout problems
#iptables -A https_limits -p tcp --dport 443 -m conntrack --ctstate NEW -m recent --set
#iptables -A https_limits -p tcp --dport 443 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
iptables -A https_limits -p tcp --dport 443 -m connlimit --connlimit-above 10 -j DROP
iptables -A https_limits -p tcp --dport 443 -m connlimit --connlimit-above 100 --connlimit-mask 0 -j DROP
iptables -A https_limits -p tcp --dport 443 -m limit --limit 10/second --limit-burst 100 -j RETURN
iptables -A https_limits -p tcp --dport 443 -j DROP
# ssh limits
iptables -N ssh_limits
# limiting ssh connections, drop all requests that are more than --hitcount x tries within --seconds y
# if ssh port is closed, packages are sent to input_log_reject if not matching the spefcified criteria, after that they are dropped without log
iptables -A ssh_limits -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A ssh_limits -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A ssh_limits -p tcp --dport 22 -m connlimit --connlimit-above 2 -j DROP
iptables -A ssh_limits -p tcp --dport 22 -m connlimit --connlimit-above 10 --connlimit-mask 0 -j DROP
iptables -A ssh_limits -p tcp --dport 22 -j RETURN
# reject limits
# do not reject when many packages arrive, because each reject would send a feedback and this can exceed the upload
# everything that is bigger than the limit does not get rejected, it will be dropped without log
iptables -N reject_limits
iptables -A reject_limits -p ALL -m limit --limit 10/s -j input_log_reject
iptables -A reject_limits -p ALL -j RETURN

### services input all
# creating table "input_services_all"
iptables -N input_services_all 
# applying rules
if [ "$INPUT_SERVICES_TCP_ALL" != "" ]
then
	echo "setting input all tcp port openings"
	for port in $INPUT_SERVICES_TCP_ALL
	do
	       	# for tcp connections allow specified port
	       	iptables -A input_services_all -p tcp --dport $port -j ACCEPT
	done
else
	:
fi
if [ "$INPUT_SERVICES_UDP_ALL" != "" ]
then
	echo "setting input all udp port openings"
	for port in $INPUT_SERVICES_UDP_ALL
	do
	       	# for udp connections allow specified port
	       	iptables -A input_services_all -p udp --dport $port -j ACCEPT
	done
else
	:
fi
# leaving table "input_services_all"
iptables -A input_services_all -p ALL -j RETURN 


### services input internal
# creating table "input_services_internal"
iptables -N input_services_internal
# applying rules 
if [ "$IPTABLES_SUBNETS" != "" ]
then
    for i in $IPTABLES_SUBNETS;
    do
        if [ "$i" != "" ]
        then
            # variable not empty
			if [ "$INPUT_SERVICES_TCP_INTERNAL" != "" ]
			then
	            echo "setting input internal tcp port openings for $i"
	            for port in $INPUT_SERVICES_TCP_INTERNAL
	            do
	               	# for tcp connections allow specified port
	               	iptables -A input_services_internal -p tcp -s $i --dport $port -j ACCEPT
	            done
	        else
	        	:
	        fi
	        if [ "$INPUT_SERVICES_UDP_INTERNAL" != "" ]
			then
				echo "setting input internal udp port openings for $i"
	            for port in $INPUT_SERVICES_UDP_INTERNAL
	            do
	               	# for udp connections allow specified port
	               	iptables -A input_services_internal -p udp -s $i --dport $port -j ACCEPT
	            done
	        else
	        	:
	        fi
        else
            # variable empty
            echo 'no entry for $i, skipping setting internal input port openings...'
            :
        fi
    done
else
    :
fi
# leaving table "input_services_internal"
iptables -A input_services_internal -p ALL -j RETURN 


### services input internal rescue subnet
# applying rules
if [ "$RESCUE_SUBNET" != "" ]
then
    # variable not empty
    echo "setting input internal port openings for $RESCUE_SUBNET"
    # creating table "input_services_internal_rescue"
	iptables -N input_services_internal_rescue
	if [ "$INPUT_SERVICES_TCP_RESCUE_INTERNAL" != "" ]
	then
	    for port in $INPUT_SERVICES_TCP_RESCUE_INTERNAL
	    do
	       	# for tcp connections allow specified port
	       	iptables -A input_services_internal_rescue -p tcp -s $RESCUE_SUBNET --dport $port -j ACCEPT
	    done
	else
	     :
	fi
	if [ "$INPUT_SERVICES_UDP_RESCUE_INTERNAL" != "" ]
	then
	    for port in $INPUT_SERVICES_UDP_RESCUE_INTERNAL
	    do
	       	# for udp connections allow specified port
	       	iptables -A input_services_internal_rescue -p udp -s $RESCUE_SUBNET --dport $port -j ACCEPT
	    done
    else
		:
	fi
    # leaving table "input_services_internal"
	iptables -A input_services_internal_rescue -p ALL -j RETURN 
else
    # variable empty
    :
fi


### services output all
# creating table "output_services_all"
iptables -N output_services_all 
# applying rules
if [ "$OUTPUT_SERVICES_TCP_ALL_DPORT" != "" ]
then
	echo "setting output all tcp dport openings"
	for port in $OUTPUT_SERVICES_TCP_ALL_DPORT
	do
	       	# for tcp connections allow specified port
	       	iptables -A output_services_all -p tcp --dport $port -j ACCEPT
	done
else
	:
fi
if [ "$OUTPUT_SERVICES_UDP_ALL_DPORT" != "" ]
then
	echo "setting output all udp dport openings"
	for port in $OUTPUT_SERVICES_UDP_ALL_DPORT
	do
	       	# for udp connections allow specified port
	       	iptables -A output_services_all -p udp --dport $port -j ACCEPT
	done
else
	:
fi
if [ "$OUTPUT_SERVICES_TCP_ALL_SPORT" != "" ]
then
	echo "setting output all tcp sport openings"
	for port in $OUTPUT_SERVICES_TCP_ALL_SPORT
	do
	       	# for tcp connections allow specified port
	       	iptables -A output_services_all -p tcp --sport $port -j ACCEPT
	done
else
	:
fi
if [ "$OUTPUT_SERVICES_UDP_ALL_SPORT" != "" ]
then
	echo "setting output all udp sport openings"
	for port in $OUTPUT_SERVICES_UDP_ALL_SPORT
	do
	       	# for udp connections allow specified port
	        iptables -A output_services_all -p udp --sport $port -j ACCEPT
	done
else
	:
fi
iptables -A output_services_all -p tcp --sport $OUTPUT_SERVICES_TCP_ALL_SPORT_FTP --dport $OUTPUT_SERVICES_TCP_ALL_DPORT_FTP -j ACCEPT
# leaving table "output_services_all"
iptables -A output_services_all -p ALL -j RETURN 


### services output internal
# creating table "output_services_internal"
iptables -N output_services_internal
# applying rules 
if [ "$IPTABLES_SUBNETS" != "" ]
then
    for i in $IPTABLES_SUBNETS;
    do
        if [ "$i" != "" ]
        then
			if [ "$OUTPUT_SERVICES_TCP_INTERNAL" != "" ]
			then
	            echo "setting output internal tcp port openings for $i"
	            for port in $OUTPUT_SERVICES_TCP_INTERNAL
	            do
	               	# for tcp connections allow specified port
	               	iptables -A output_services_internal -p tcp -s $i --dport $port -j ACCEPT
	            done
	        else
	        	:
	        fi
	        if [ "$OUTPUT_SERVICES_UDP_INTERNAL" != "" ]
			then
	            echo "setting output internal udp port openings for $i"
	            for port in $OUTPUT_SERVICES_UDP_INTERNAL
	            do
	               	# for udp connections allow specified port
	               	iptables -A output_services_internal -p udp -s $i --dport $port -j ACCEPT
	            done
	        else
	        	:
	        fi
        else
            # variable empty
            echo 'no entry for $i, skipping setting internal input port openings...'
            :
        fi
    done
else
    :
fi
# leaving table "output_services_internal"
iptables -A output_services_internal -p ALL -j RETURN 


### services output internal rescue subnet
# applying rules
if [ "$RESCUE_SUBNET" != "" ]
then
    # variable not empty
    echo "setting output internal port openings for $RESCUE_SUBNET"
    # creating table "output_services_internal_rescue"
	iptables -N output_services_internal_rescue
	if [ "$OUTPUT_SERVICES_TCP_RESCUE_INTERNAL" != "" ]
	then
	    for port in $OUTPUT_SERVICES_TCP_RESCUE_INTERNAL
	    do
	       	# for tcp connections allow specified port
	       	iptables -A output_services_internal_rescue -p tcp -s $RESCUE_SUBNET --dport $port -j ACCEPT
	        iptables -A output_services_internal_rescue -p tcp -s $RESCUE_SUBNET --sport $port -j ACCEPT
	    done
	else
	     :
	fi
	if [ "$OUTPUT_SERVICES_UDP_RESCUE_INTERNAL" != "" ]
	then
	    for port in $OUTPUT_SERVICES_UDP_RESCUE_INTERNAL
	    do
	       	# for udp connections allow specified port
	       	iptables -A output_services_internal_rescue -p udp -s $RESCUE_SUBNET --dport $port -j ACCEPT
	        iptables -A output_services_internal_rescue -p udp -s $RESCUE_SUBNET --sport $port -j ACCEPT
	    done
    else
		:
	fi
    # leaving table "output_services_internal"
	iptables -A output_services_internal_rescue -p ALL -j RETURN 
else
    # variable empty
    :
fi


### services FORWARD for openvpn connections
if [ "$IPTABLES_SUBNETS" != "" ]
then
	# creating table "forward_services_internal"
	iptables -N forward_services_internal
    for i in $IPTABLES_SUBNETS;
    do
        if [ "$i" != "" ]
        then
            # variable not empty
            echo "setting internal port tcp forwardings for $i"
            if [ "$FORWARD_SERVICES_TCP_INTERNAL" != "" ]
			then
	            for port in $FORWARD_SERVICES_TCP_INTERNAL
	            do
	            	# for tcp connections allow specified port
	            	iptables -A forward_services_internal -p tcp -s $i --dport $port -j ACCEPT
	            done
	      	else
				:
			fi 
			if [ "$FORWARD_SERVICES_UDP_INTERNAL" != "" ]
			then   
			    echo "setting internal port udp forwardings for $i"
            	for port in $FORWARD_SERVICES_UDP_INTERNAL
	            do
	               # for udp connections allow specified port
	               iptables -A forward_services_internal -p udp -s $i --dport $port -j ACCEPT
	            done
	      	else
				:
			fi  
        else
            # variable empty
            echo 'no entry for $i, skipping setting internal port forwardings...'
            :
        fi
    done
	# leaving table "forward_services_internal"
	iptables -A forward_services_internal -p ALL -j RETURN 
else
    :
fi


###
### prerouting
###


# https://javapipe.com/iptables-ddos-protection
# the best solution to dramatically increase the performance of iptables rules and therefore the amount of (tcp) ddos attack traffic they can filter is to use the mangle table and the PREROUTING chain and with this moving the anti-ddos rules as far up the chains as possible.
# the issue with other approaches is that the INPUT chain is only processed after the PREROUTING and FORWARD chains and therefore only applies if the packet doesn't match any of these two chains. This causes a delay in the filtering of the packet which consumes resources.
# however, the filter table doesn't support the PREROUTING chain. To get around this problem, simply use the mangle table instead of the filter table for anti-ddos iptables rules. It supports most if not all rules that the filter table supports while also supporting all iptables chains.


### security / hardening
# do not reject when many packages arrive, because each reject would send a feedback and this can exceed the upload
# making sure new incoming tcp connections are syn packages, drop all non-syn packages
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
# invalid packages                                                                
iptables -t mangle -A PREROUTING -p ALL -m conntrack --ctstate INVALID -j DROP
# syn packages with suspicious mss value
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
# packages with bogus tcp flags
# null packages, fin packages, xmas packages, ...
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
# spoofed packages
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
#iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
#iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
#iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
#iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
# fragments
iptables -t mangle -A PREROUTING -f -j DROP

# ftp
# enable this if you want to use passive ftp without opening further ports than 21
# be sure that kernel module nf_conntrack_ftp is loadad additionally
# lsmod | grep nf_conntrack
# modprobe nf_conntrack
# modprobe nf_conntrack_ftp
# echo nf_conntrack_ftp > /etc/modules-load.d/nf_conntrack_ftp.conf
# unfortunately a range of ports has to be opened if ftps is used because nf_conntrack_ftp cannot handle opening ports on encrypted connections
#iptables -A PREROUTING -t raw -p tcp --dport 21 -j CT --helper ftp


###
### loopback and ping
###

#### loopback interface
# allow unlimited input
iptables -A INPUT -i lo -j ACCEPT
# reject input to localhost that does not originate from loopback
iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j input_log_reject
# allow unlimited output
iptables -A OUTPUT -o lo -j ACCEPT


### icpm
# allowing internal ping
if [ "$IPTABLES_SUBNETS" != "" ]
then
    for i in $IPTABLES_SUBNETS;
    do
        if [ "$i" != "" ]
        then
			# input
			#iptables -A INPUT -p icmp -j ACCEPT
			iptables -A INPUT -s $i -p icmp -m conntrack --ctstate NEW,ESTABLISHED,RELATED --icmp-type 8 -m limit --limit 1/s -j ACCEPT
			iptables -A OUTPUT -s $i -p icmp -m conntrack --ctstate ESTABLISHED,RELATED --icmp-type 0 -j ACCEPT
			# ping flood
			iptables -A INPUT -s $i -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
			iptables -A INPUT -s $i -p icmp --icmp-type echo-reply -m limit --limit 1/s -j ACCEPT
			#iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
			# output
			iptables -A OUTPUT -s $i -p icmp -m conntrack --ctstate NEW,ESTABLISHED,RELATED --icmp-type 8  -j ACCEPT
			iptables -A INPUT -s $i -p icmp -m conntrack --ctstate ESTABLISHED,RELATED --icmp-type 0 -m limit --limit 1/s -j ACCEPT
		else
            echo 'no entry for $i, skipping allowing internal ping...'
            :
		fi
	done
else
	:
fi
# rest for pings
iptables -A INPUT -p icmp -m conntrack --ctstate ESTABLISHED,RELATED --icmp-type 0 -m limit --limit 1/s -j ACCEPT
iptables -A OUTPUT -p icmp -m conntrack --ctstate ESTABLISHED,RELATED --icmp-type 0 -j ACCEPT
iptables -A OUTPUT -p icmp -m conntrack --ctstate NEW,ESTABLISHED,RELATED --icmp-type 8  -j ACCEPT
# rest of input pings
# does not have an effect for ping on ip or dns if the server is not the gateway and is behind a router
# in this case the router has to be configured to (not) answer the ping
iptables -A INPUT -p icmp --icmp-type 8 -j DROP
iptables -A INPUT -p icmp --icmp-type 0 -j DROP


###
### input
###

### allowing only all existing ESTABLISHED and RELATED connections, not NEW
iptables -A INPUT -p ALL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# this limits all established tcp connections including samba, etc. to a certain speed
#iptables -A INPUT -p ALL -m conntrack --ctstate ESTABLISHED,RELATED -m limit --limit 50/s --limit-burst 50 -j ACCEPT


#### broadcast & multicast
if [ "$IPTABLES_SUBNETS" != "" ]
then
    for i in $IPTABLES_SUBNETS;
    do
        if [ "$i" != "" ]
        then
			#iptables -A INPUT -s "$i" -m pkttype --pkt-type broadcast -j ACCEPT
			iptables -A INPUT -s "$i" -m pkttype --pkt-type multicast -j ACCEPT
		else
            echo 'no entry for $i, skipping allowing multicast locally...'
            :
		fi
	done
else
	:
fi
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -m pkttype --pkt-type multicast -j DROP


#### limit connections per source ip
iptables -A INPUT -p tcp -m connlimit --connlimit-above 20 -j DROP
# limit connections overall
iptables -A INPUT -p tcp -m connlimit --connlimit-above 200 --connlimit-mask 0 -j DROP


### sending packages through tables
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j port_scanning
iptables -A INPUT -p tcp -j ddos
iptables -A INPUT -p tcp -j synflood_tcp
iptables -A INPUT -p udp -j synflood_udp
iptables -A INPUT -p tcp -j ssh_limits
iptables -A INPUT -p tcp -j http_limits
iptables -A INPUT -p tcp -j https_limits
iptables -A INPUT -p ALL -j input_services_all
iptables -A INPUT -p ALL -j input_services_internal
if [ "$RESCUE_SUBNET" != "" ]
then
	iptables -A INPUT -p ALL -j input_services_internal_rescue
else
	:
fi
iptables -A INPUT -p ALL -j reject_limits


###
### output
###

### allowing only all ESTABLISHED AND RELATED existing connections, not NEW
iptables -A OUTPUT -p ALL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### security
# invalid packages
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
# invalid syn packages
iptables -A OUTPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
iptables -A OUTPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A OUTPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
# allowing only sym packages
iptables -A OUTPUT -p tcp ! --syn -m state --state NEW -j DROP
# fragments
iptables -A OUTPUT -f -j DROP
# xmas packages
iptables -A OUTPUT -p tcp --tcp-flags ALL ALL -j DROP
# malformed null packages
iptables -A OUTPUT -p tcp --tcp-flags ALL NONE -j DROP

### sending packages through tables
iptables -A OUTPUT -p ALL -j output_services_all
iptables -A OUTPUT -p ALL -j output_services_internal
if [ "$RESCUE_SUBNET" != "" ]
then
	iptables -A OUTPUT -p ALL -j output_input_services_internal_rescue
else
	:
fi


###
### forward
###

### allowing only all ESTABLISHED AND RELATED existing connections, not NEW
iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT


### dropping invalid packages
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP


### sending packages through tables
iptables -A FORWARD -p ALL -j forward_services_internal


### alternatives
# alternatively allow all traffic on all tun interfaces
#iptables -A INPUT -i tun+ -j ACCEPT
#iptables -A FORWARD -i tun+ -j ACCEPT

# alternatively allow all traffic on all tap interfaces
#iptables -A INPUT -i tap+ -j ACCEPT
#iptables -A FORWARD -i tap+ -j ACCEPT

# alternatively allow all internal traffic on all tap interfaces
#iptables -A INPUT -i tap+ -s $CONNECTED_SUBNET -j ACCEPT
#iptables -A FORWARD -i tap+ -s $CONNECTED_SUBNET -j ACCEPT


### openvpn tap ping
# allowing ping from and to vpn interfaces
iptables -A FORWARD -s $CONNECTED_SUBNET -p icmp -m conntrack --ctstate NEW --icmp-type 8 -j ACCEPT
iptables -A FORWARD -s $CONNECTED_SUBNET -p icmp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


### vpn routing
if [ "$IPTABLES_VPN_SUBNETS" != "" ]
then
    for i in $IPTABLES_VPN_SUBNETS;
    do
        if [ "$i" != "" ]
        then
            # variable not empty
            if [[ "$i" == "$CONNECTED_TUN_SUBNET0" ]] 
            then 
            	VPN_INTERFACE="$TUN0" 
            elif [[ "$i" == "$CONNECTED_TUN_SUBNET1" ]]
            then 
            	VPN_INTERFACE="$TUN1"
            elif [[ "$i" == "$CONNECTED_WG_SUBNET0" ]]
            then 
            	VPN_INTERFACE="$WG0"
           	else 
           		:
           	fi
           	
            echo "configuring vpn $VPN_INTERFACE for $i"
            # https://community.openvpn.net/openvpn/wiki/BridgingAndRouting
            iptables -I FORWARD -i $VPN_INTERFACE -o $NETWORKINTERFACE -s $i -m conntrack --ctstate NEW -j ACCEPT
            # already done above
            #iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            
            # with MASQUERADE or SNAT enabled on all ports some apps may not work correctly (e.g. stun/turn server)
            # therefore only MASQUERADE/SNAT the allowed forwarded and allowed outgoing dports and specifically exclude (by deleting the rule) specific ports (e.g. stun/turn server)
     
            #iptables -t nat -A POSTROUTING -s $i -o $NETWORKINTERFACE -j MASQUERADE
            # or (even better with less overhead)
            # https://terrywang.net/2016/02/02/new-iptables-gotchas.html
            #iptables -t nat -A POSTROUTING -s "$i" -o $NETWORKINTERFACE -j SNAT --to-source $INT_IP_ONLINE
            # equivalent
          	#iptables -t nat -A POSTROUTING -s $i -o $NETWORKINTERFACE -p tcp --dport 1:65535 -j SNAT --to-source $INT_IP_ONLINE
          	#iptables -t nat -A POSTROUTING -s $i -o $NETWORKINTERFACE -p udp --dport 1:65535 -j SNAT --to-source $INT_IP_ONLINE

            echo "setting postrouting vpn snat tcp ports for $i"
            if [ "$FORWARD_SERVICES_TCP_INTERNAL" != "" ]
			then
	            for port in $POSTROUTING_VPN_TCP
	            do
	            	# for tcp connections postroute/snat specified port
	            	iptables -t nat -A POSTROUTING -s $i -o $NETWORKINTERFACE -p tcp --dport $port -j SNAT --to-source $INT_IP_ONLINE
	            	:
	            done
	      	else
				:
			fi 
			if [ "$FORWARD_SERVICES_UDP_INTERNAL" != "" ]
			then   
			    echo "setting postrouting vpn snat udp ports for $i"
            	for port in $POSTROUTING_VPN_UDP
	            do
	               # for udp connections postroute/snat specified port
	               iptables -t nat -A POSTROUTING -s $i -o $NETWORKINTERFACE -p udp --dport $port -j SNAT --to-source $INT_IP_ONLINE
	               :
	            done
	      	else
				:
			fi
			
			# postrouting exclusions
			if [ "$EXCLUDE_POSTROUTING_TCP_DPORT" != "" ]
			then   
			    echo "excluding postrouting vpn snat tcp ports for $i"
            	for port in $EXCLUDE_POSTROUTING_TCP_DPORT
	            do
	               iptables -t nat -D POSTROUTING -s $i -o $NETWORKINTERFACE -p tcp --dport $port -j SNAT --to-source $INT_IP_ONLINE
	            done
	      	else
				:
			fi  
			if [ "$EXCLUDE_POSTROUTING_UDP_DPORT" != "" ]
			then   
			    echo "excluding postrouting vpn snat udp ports for $i"
            	for port in $EXCLUDE_POSTROUTING_UDP_DPORT
	            do
	               iptables -t nat -D POSTROUTING -s $i -o $NETWORKINTERFACE -p udp --dport $port -j SNAT --to-source $INT_IP_ONLINE
	            done
	      	else
				:
			fi
        else
            # variable empty
            echo 'no entry for $i, skipping vpn routing configuration...'
            :
        fi
    done
else
    :
fi



###
### checking
###

### checking config examples
# touch /var/log/iptables.rules.log
# echo "" > /var/log/iptables.rules.log
# iptables -L input_services_all -n -v --line-numbers > /var/log/iptables.rules.log
# iptables -L input_services_internal -n -v --line-numbers > /var/log/iptables.rules.log
# iptables -L input_services_internal_rescue -n -v --line-numbers > /var/log/iptables.rules.log
# iptables -L INPUT -n -v --line-numbers > /var/log/iptables.rules.log
# iptables -L FORWARD -n -v --line-numbers > /var/log/iptables.rules.log
# iptables -t nat -L POSTROUTING -n -v --line-numbers > /var/log/iptables.rules.log
# rm /var/log/iptables.rules.log


###
### testing
###

# sudo nmap -v -f FIREWALL-IP
# sudo nmap -v -sX FIREWALL-IP
# sudo nmap -v -sN FIREWALL-IP
# sudo hping2 -X FIREWALL-IP
# sudo hping3 -S FIREWALL-IP -p 443 --flood


###
### defining what to do with everything else
###

iptables -A INPUT -p ALL -j DROP
iptables -A FORWARD -p ALL -j DROP
iptables -A OUTPUT -p ALL -j DROP


###
### saving and restarting iptables
###

# save iptables-rules and restart service
iptables-save > /etc/iptables/iptables.rules
#iptables-save > /etc/iptables/rules.v4
#ip6tables-save > /etc/iptables/rules.v6
systemctl enable iptables.service
systemctl stop iptables.service
# delete ipsets
#ipset destroy
systemctl start iptables.service
	
#
