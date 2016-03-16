my $IPSEC_PSK='';
my $VPN_USER='';
my $VPN_PASSWORD='';

my $UNAME=`uname`;
if ($UNAME eq "Darwin"){
	print "DO NOT run this script on your Mac! It Should be run on on a server.\n";
	exit 0;
}

#exit 1;

print "Checking ENV...\n";

my $SYSTEM=`lsb_release -si`;
if($SYSTEM ne "Ubuntu" && $SYSTEM ne "Debian"){
	print "[ERROR]Looks like you aren't running this script on a Ubuntu or Debian system.\n";
	#exit 0;
}else{
	print "[0]	System Checked:$SYSTEM\n"
}

my $ROOT=`id -u`;
if ($ROOT !=0){
	print "[ERROR]You neeed to run this script as root\n";
	exit 0;
}else{
	print "[1]	Root Role Checked\n"
}

if ($IPSEC_PSK eq "" || $VPN_USER eq "" || $VPN_PASSWORD eq ""){
	print "[ERROR]VPN credentials cannot be enpty.Edit the script."
	#exit 0;
}else{
	print "[3]	VPN Setting Checked\n"
}

print "apt-get update and install ...\n";
`apt-get -y update`;
`apt-get -y install wget dnsutils`;


