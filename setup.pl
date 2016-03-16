my $IPSEC_PSK='123456789';
my $VPN_USER='yang';
my $VPN_PASSWORD='yang';

my $SWAN_VER=3.16;

my $UNAME=`uname`;
if ($UNAME eq "Darwin"){
	print "DO NOT run this script on your Mac! It Should be run on on a server.\n";
	exit 0;
}

#========================================
#check env
#

print "[INFO]Checking ENV...\n===============================\n";

my $SYSTEM=`lsb_release -si`;
if($SYSTEM ne "Ubuntu" && $SYSTEM ne "Debian"){
	print "[ERROR]	Looks like you aren't running this script on a Ubuntu or Debian system.\n";
	#exit 0;
}else{
	print "[0]	System Checked:$SYSTEM\n"
}

my $ROOT=`id -u`;
if ($ROOT !=0){
	print "[ERROR]	You neeed to run this script as root\n";
	exit 0;
}else{
	print "[1]	Root Role Checked\n"
}

if ($IPSEC_PSK eq "" || $VPN_USER eq "" || $VPN_PASSWORD eq ""){
	print "[ERROR]	VPN credentials cannot be enpty.Edit the script.\n";
	exit 0;
}else{
	print "[2]	VPN Setting Checked\n"
}

mkdir '/opt/libreswan';
chdir '/opt/libreswan' or die "can not chdir to /opt/libreswan :$!";

#=========================================
#install wget and dnsutils for get ip address.
#

print "[INFO]	apt-get update and install ...\n===============================\n";
#`apt-get -y update`;
#`apt-get -y install wget dnsutils`;

#========================================
#you can edit the address to skip the auto detection.
#if your server only have public IP,set the private same.
#
my $PUBLIC_IP=undef;
my $PRIVATE_IP=undef;

print "[INFO]	get public ip and private ip.\n===============================\n";

$PUBLIC_IP=`wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com` if !defined($PUBLIC_IP);
$PUBLIC_IP=`wget -t 3 -T 15 -qO- http://ipecho.net/plain.com` if !defined($PUBLIC_IP);

$cmdout=`ip -4 route get 1`;
$cmdout=~m/etho src (([0-9]*\.){3}[0-9]*)(?)/;
$PRIVATE_IP=$1 if !defined($PRIVATE_IP);
$cmdout=`ifconfig eth0`;
$cmdout=~m/inet addr:(([0-9]*\.){3}[0-9]*)(?)/;
$PRIVATE_IP=$1 if !defined($PRIVATE_IP);

#check IP format
unless ($PUBLIC_IP=~m/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/){
	print "[ERROR]	Public Ip $PUBLIC_IP is not valid,please edit the script \n" ;
	exit 1;
}
unless ($PRIVATE_IP=~m/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/){
	print "[ERROR]	PRIVATE Ip $PRIVATE_IP is not valid,please edit the script \n" ;
	exit 1;
}

print "[3]	Read Ip adress : \n public ip --$PUBLIC_IP \n private ip --$PRIVATE_IP\n";

print "[INFO]	apt-get update and install ...\n===============================\n";

# Install necessary packages
`apt-get -y install libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev libgmp3-dev flex bison gcc make libunbound-dev libnss3-tools libevent-dev`;
`apt-get -y --no-install-recommends install xmlto`;
`apt-get -y install xl2tpd`;

# Install Fail2Ban to protect SSH
`apt-get -y install fail2ban`;

print "[INFO]	Compile and install Libreswan ...\n===============================\n";
# Compile and install Libreswan
my $SWAN_FILE="libreswan-$SWAN_VER.tar.gz";
my $SWAN_URL="https://download.libreswan.org/$SWAN_FILE";

`wget -t 3 -T 30 -nv -O "$SWAN_FILE" "$SWAN_URL"`;
`tar xvzf "$SWAN_FILE" && rm -f "$SWAN_FILE"`;
chdir "libreswan-$SWAN_VER" or die $!;
`make programs && make install`;

# Check if Libreswan install was successful
$cmdout=`/usr/local/sbin/ipsec --version`;
unless ($cmdout=~m/$SWAN_VER/){
	print "Sorry, Libreswan $SWAN_VER failed to build. Aborting.";
	exit 1;
}
print "[5]	Libreswan $SWAN_VER install successfully\n";
print "[INFO]	Prepare various config files ...\n===============================\n";
#check if the file include the target 
sub ifadd{
	my $in =shift;
	my $target=shift;
	
	if(!open in_fh,'<',$in){
		die $!;
	}
	while(<in_fh>){
		chomp;
		if($_=~/$target/ig){
			close in_fh;
			return 0;
		}
	}
	close in_fh;
	return 1;
}

#check if the path exist
sub ifexist{
	my $path=shift;
	if(-e $path){
		return 1;
	}else{
		return 0;
	}
}

#write file
sub writefile{
	my $file=shift;
	my $text=shift;
	open fh,'>',$file;
	print fh $text;
	close fh;
}

sub appendfile{
	my $file=shift;
	my $text=shift;
	open fh,'>>',$file;
	print fh $text;
	close fh;
}

# Prepare various config files
# Create IPsec (Libreswan) config
print "[INFO]	Create IPsec (Libreswan) config.\n";
my $SYS_DT=`/bin/date +%Y-%m-%d`;
`/bin/cp -f /etc/ipsec.conf /etc/ipsec.conf.old.$SYS_DT`;

my $etc_ipsec_conf=<<EOF
version 2.0
config setup
  dumpdir=/var/run/pluto/
  nat_traversal=yes
  virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!192.168.42.0/24
  oe=off
  protostack=netkey
  nhelpers=0
  interfaces=%defaultroute
conn vpnpsk
  connaddrfamily=ipv4
  auto=add
  left=$PRIVATE_IP
  leftid=$PUBLIC_IP
  leftsubnet=$PRIVATE_IP/32
  leftnexthop=%defaultroute
  leftprotoport=17/1701
  rightprotoport=17/%any
  right=%any
  rightsubnetwithin=0.0.0.0/0
  forceencaps=yes
  authby=secret
  pfs=no
  type=transport
  auth=esp
  ike=3des-sha1,aes-sha1
  phase2alg=3des-sha1,aes-sha1
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
EOF
;
writefile("/etc/ipsec.conf",$etc_ipsec_conf);


# Specify IPsec PSK
print "[INFO]	Specify IPsec PSK\n";
`/bin/cp -f /etc/ipsec.secrets /etc/ipsec.secrets.old-$SYS_DT`;
my $etc_ipsec_secrets= <<EOF
$PUBLIC_IP  %any  : PSK "$IPSEC_PSK"
EOF
;
writefile("/etc/ipsec.secrets",$etc_ipsec_secrets);


# Create xl2tpd config
print "[INFO]	Create xl2tpd config\n";
`/bin/cp -f /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.old-$SYS_DT`;
my $etc_xl2tpd_xl2tpd_conf= <<EOF
[global]
port = 1701
;debug avp = yes
;debug network = yes
;debug state = yes
;debug tunnel = yes
[lns default]
ip range = 192.168.100.10-192.168.100.255
local ip = 192.168.100.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
;ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
;

writefile("/etc/xl2tpd/xl2tpd.conf",$etc_xl2tpd_xl2tpd_conf);

# Specify xl2tpd options
print "[INFO]	Specify xl2tpd options\n";
`/bin/cp -f /etc/ppp/options.xl2tpd /etc/ppp/options.xl2tpd.old-$SYS_DT`;
my $etc_ppp_options_xl2tpd= <<EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
crtscts
idle 1800
mtu 1280
mru 1280
lock
lcp-echo-failure 10
lcp-echo-interval 60
connect-delay 5000
EOF
;

writefile('/etc/ppp/options.xl2tpd',$etc_ppp_options_xl2tpd);

# Create VPN credentials
print "[INFO]	Create VPN credentials\n";
`/bin/cp -f /etc/ppp/chap-secrets /etc/ppp/chap-secrets.old-$SYS_DT`;
my $etc_ppp_chap_secrets = <<EOF
# Secrets for authentication using CHAP
# client  server  secret  IP addresses
"$VPN_USER" l2tpd "$VPN_PASSWORD" *
EOF
;
writefile('/etc/ppp/chap-secrets',$etc_ppp_chap_secrets);

# Update sysctl settings for VPN and performance
print "[INFO]	Update sysctl settings for VPN and performance\n";
if (ifadd('/etc/sysctl.conf','11110000 VPN script')){
`/bin/cp -f /etc/sysctl.conf /etc/sysctl.conf.old-$SYS_DT`;
my $etc_sysctl_conf =<<EOF
# Added by 11110000 VPN script
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.lo.send_redirects = 0
net.ipv4.conf.eth0.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.rp_filter = 0
net.ipv4.conf.eth0.rp_filter = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.core.wmem_max = 12582912
net.core.rmem_max = 12582912
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
EOF
;
appendfile('/etc/sysctl.conf',$etc_sysctl_conf);
}

# Create basic IPTables rules. First check if there are existing rules.
# 1. If IPTables is "empty", write out the new set of rules.
# 2. If *not* empty, insert new rules and save them together with existing ones.
print "[INFO]	create basic IPTables rules\n";

`/bin/cp -f /etc/iptables.rules /etc/iptables.rules.old-$SYS_DT`;
`/usr/sbin/service fail2ban stop`;

`iptables -I INPUT 1 -p udp -m multiport --dports 500,4500 -j ACCEPT`;
`iptables -I INPUT 2 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT`;
`iptables -I INPUT 3 -p udp --dport 1701 -j DROP`;
`iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP`;
`iptables -I FORWARD 2 -i eth+ -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`;
`iptables -I FORWARD 3 -i ppp+ -o eth+ -j ACCEPT`;
`iptables -A FORWARD -j DROP`;
`iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth+ -j SNAT --to-source "$PRIVATE_IP"`;

`echo "# Modified by 11110000 VPN script" > /etc/iptables.rules`;
`/sbin/iptables-save >> /etc/iptables.rules`;

# Update rules for iptables-persistent
if (ifexist('/etc/iptables/rules.v4')){
`/bin/cp -f /etc/iptables/rules.v4 /etc/iptables/rules.v4.old-$SYS_DT`;
`/bin/cp -f /etc/iptables.rules /etc/iptables/rules.v4`;
}

# Create basic IP6Tables (IPv6) rules
print "[INFO]	Create basic IP6Tables (IPv6) rules\n";
if (!ifexist('/etc/ip6tables.rules')||ifadd('/etc/ip6tables.rules','11110000 VPN script')){
`/bin/cp -f /etc/ip6tables.rules "/etc/ip6tables.rules.old-$SYS_DT" 2>/dev/null`;
my $etc_ip6tables_rules= <<EOF
# Added by 11110000 VPN script
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -m rt --rt-type 0 -j DROP
-A INPUT -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -j DROP
COMMIT
EOF
;
appendfile('/etc/ip6tables.rules',$etc_ip6tables_rules);


if (ifexist('/etc/iptables/rules.v6')){
`/bin/cp -f /etc/iptables/rules.v6 /etc/iptables/rules.v6.old-$SYS_DT`;
`/bin/cp -f /etc/ip6tables.rules /etc/iptables/rules.v6`;
}

}

# Load IPTables rules at system boot
$etc_network_ifpreup_d_iptablesload= <<EOF
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.rules
exit 0
EOF
;
writefile('/etc/network/if-pre-up.d/iptablesload',$etc_network_ifpreup_d_iptablesload);


my $etc_network_ifpreup_d_ip6tablesload =<<EOF
#!/bin/sh
/sbin/ip6tables-restore < /etc/ip6tables.rules
exit 0
EOF
;
writefile('/etc/network/if-pre-up.d/ip6tablesload',$etc_network_ifpreup_d_ip6tablesload);

# Update rc.local to start services at boot
if (ifadd('/etc/rc.local','11110000 VPN script')){
`/bin/cp -f /etc/rc.local "/etc/rc.local.old-$SYS_DT" 2>/dev/null`;
`/bin/sed --follow-symlinks -i -e '/^exit 0/d' /etc/rc.local`;

my $etc_rc_local =<<EOF
# Added by 11110000 VPN script
/usr/sbin/service fail2ban restart || /bin/true
/usr/sbin/service ipsec start
/usr/sbin/service xl2tpd start
echo 1 > /proc/sys/net/ipv4/ip_forward
exit 0
EOF
;
appendfile('/etc/rc.local',$etc_rc_local);
}

# Initialize Libreswan DB
if (ifexist('/etc/ipsec.d/cert8.db')){
   `echo > /var/tmp/libreswan-nss-pwd`;
   `/usr/bin/certutil -N -f /var/tmp/libreswan-nss-pwd -d /etc/ipsec.d`;
   `/bin/rm -f /var/tmp/libreswan-nss-pwd`;
}

# Reload sysctl.conf
`/sbin/sysctl -p`;

# Update file attributes
`/bin/chmod +x /etc/rc.local`;
`/bin/chmod +x /etc/network/if-pre-up.d/iptablesload`;
`/bin/chmod +x /etc/network/if-pre-up.d/ip6tablesload`;
`/bin/chmod 600 /etc/ipsec.secrets* /etc/ppp/chap-secrets*`;

# Apply new IPTables rules
`/sbin/iptables-restore < /etc/iptables.rules`;
`/sbin/ip6tables-restore < /etc/ip6tables.rules >/dev/null 2>&1`;

# Restart services
`/usr/sbin/service fail2ban stop >/dev/null 2>&1`;
`/usr/sbin/service ipsec stop >/dev/null 2>&1`;
`/usr/sbin/service xl2tpd stop >/dev/null 2>&1`;
`/usr/sbin/service fail2ban start`;
`/usr/sbin/service ipsec start`;
`/usr/sbin/service xl2tpd start`;

print "[6]	Configure files set successfully \n";
print 'Congratulations! IPsec/L2TP VPN server setup is complete!';
#exit 0;
