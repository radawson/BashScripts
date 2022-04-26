#!/bin/bash
# Ubuntu VM desktop setup script
# R. Dawson 2021
# v2.2.2

## Variables
#TODO: This works for a VM, but needs a better method
ADAPTER1=$(ls /sys/class/net | grep e) 	# 1st Ethernet adapter on VM
BRANCH="main"							# Default to main branch
CHECK_IP="8.8.8.8"						# Test ping to google DNS
DATE_VAR=$(date +'%y%m%d-%H%M')			# Today's Date and time
FLATPAK="false" 						# Do not install flakpak by default
LOG_FILE="${DATE_VAR}_install.log"  	# Log File name
VPN_INSTALL="false"						# Do not install VPN clients by default

## Functions
check_internet() {
	# SETTINGS
	TEST="${1}"       

	# Report 
	LOG_FILE=~/Documents/ReportInternet.log

	# Messages
	MESSAGE1="Attempting to restore connectivity"
	MESSAGE2="This could take up to 2 minutes"
	MESSAGE3="No Internet connection detected"
	MESSAGE4="Internet connection detected"

	# Date
	TODAY=$(date "+%r %d-%m-%Y")

	# Show IP Public Address
	IPv4ExternalAddr1=$(ip addr list $ADAPTER1 |grep "inet " |cut -d' ' -f6|cut -d/ -f1)
	IPv6ExternalAddr1=$(ip addr list $ADAPTER1 |grep "inet6 " |cut -d' ' -f6|cut -d/ -f1)

	# Alarm
	alarm() {
		beep -f 1500 -l 200;beep -f 1550 -l 200;beep -f 1500 -l 200;beep -f 1550 -l 200;beep -f 1500 -l 200;beep -f 1550 -l 200;beep -f 1500 -l 200;beep -f 1550$
	}

	# Restoring Connectivity
	resolve() {
		clear
		echo "$MESSAGE1" | tee /dev/fd/3
		sudo ifconfig $ADAPTER1 up; sudo dhclient -r $ADAPTER1; sleep 5; sudo dhclient $ADAPTER1
		echo "$MESSAGE2"
		sleep 120
	}

	# Execution of work
	while true; do
		if [[ "$(cat /sys/class/net/${ADAPTER1}/operstate)" != "up" ]]; then
			alarm
			clear
			echo "================================================================================" 
			echo "$MESSAGE3 - $TODAY"                                                               | tee /dev/fd/3
			echo "================================================================================"
			sleep 10
			resolve
		else
			clear
			echo "================================================================================" 
			echo "$MESSAGE4 - $TODAY - IPv4 Addr: $IPv4ExternalAddr1 - IPv6 Addr: $IPv6ExternalAddr1" | tee /dev/fd/3
			echo "================================================================================" 
			break
		fi
	done
}

check_root() {
  # Check to ensure script is not run as root
  if [[ "${UID}" -eq 0 ]]; then
    UNAME=$(id -un)
    printf "\nThis script must not be run as root.\n\n" >&2
    usage
  fi
}

echo_out() {
  local MESSAGE="${@}"
  if [[ "${VERBOSE}" = 'true' ]]; then
    printf "${MESSAGE}\n"
  fi
}

install_airvpn () {
  echo_out "Installing AirVPN client."
  wget -qO - https://eddie.website/repository/keys/eddie_maintainer_gpg.key | sudo apt-key add - | tee /dev/fd/3
  echo "deb http://eddie.website/repository/apt stable main" | sudo tee /etc/apt/sources.list.d/eddie.website.list | tee /dev/fd/3
  sudo apt-get update | tee /dev/fd/3
  sudo apt-get -y install eddie-ui | tee /dev/fd/3
  echo_out "AirVPN Installation Complete"
}

install_flatpak () {
  sudo apt-get -y install flatpak
  sudo apt-get -y install gnome-software-plugin-flatpak
  flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
}

install_ivpn() {
  echo_out "Installing IVPN client."
  wget -O - https://repo.ivpn.net/stable/ubuntu/generic.gpg | gpg --dearmor > ~/ivpn-archive-keyring.gpg | tee /dev/fd/3
  sudo mv ~/ivpn-archive-keyring.gpg /usr/share/keyrings/ivpn-archive-keyring.gpg | tee /dev/fd/3
  wget -O - https://repo.ivpn.net/stable/ubuntu/generic.list | sudo tee /etc/apt/sources.list.d/ivpn.list | tee /dev/fd/3
  sudo apt update | tee /dev/fd/3
  sudo apt-get -y install ivpn-ui | tee /dev/fd/3
  echo_out "IVPN Installation Complete"
}

install_mullvad () {
  echo_out "Installing Mullvad VPN client."
  wget --content-disposition https://mullvad.net/download/app/deb/latest | tee /dev/fd/3
  MV_PACKAGE=$(cat ls | grep Mullvad)
  sudo apt-get -y install ./"${MV_PACKAGE}" | tee /dev/fd/3
  echo_out "Mullvad Installation VPN Complete"
}

install_nordvpn () {
  echo_out "Installing Nord VPN client."
  sh <(curl -sSf https://downloads.nordcdn.com/apps/linux/install.sh) | tee /dev/fd/3
  sudo usermod -aG nordvpn $USER | tee /dev/fd/3
  echo_out "Nord VPN Installation Complete"
}
install_openvpn () {
  echo_out "Installing OpenVPNclient."
  sudo curl -fsSL https://swupdate.openvpn.net/repos/openvpn-repo-pkg-key.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/openvpn-repo-pkg-keyring.gpg | tee /dev/fd/3
  sudo curl -fsSL https://swupdate.openvpn.net/community/openvpn3/repos/openvpn3-$DISTRO.list >/etc/apt/sources.list.d/openvpn3.list | tee /dev/fd/3
  sudo apt-get update
  sudo apt-get -y install openvpn3 | tee /dev/fd/3
  echo_out "OpenVPN Installation Complete"
}

install_protonvpn () {
  echo_out "Installing ProtonVPNclient."
  wget https://protonvpn.com/download/protonvpn-stable-release_1.0.1-1_all.deb
  sudo apt install protonvpn-stable-release_1.0.1-1_all.deb | tee /dev/fd/3
  sudo apt update | tee /dev/fd/3
  sudo apt-get -y install protonvpn | tee /dev/fd/3
  echo_out "ProtonVPN Installation Complete"
}

usage() {
  echo "Usage: ${0} [-cf] [-p VPN_name] " >&2
  echo "Sets up Ubuntu Desktop with useful apps."
  #echo "Do not run as root."
  echo
  echo "-c 			Check internet connection before starting."
  echo "-f			Install Flatpak."
  echo "-p VPN_NAME	Install VPN client(s) or 'all'."
  echo "-v 			Verbose mode."
  exit 1
}

## MAIN
# Create a log file with current date and time
touch ${LOG_FILE}

# Provide usage statement if no parameters
while getopts cdfp:p OPTION; do
  case ${OPTION} in
	c)
	# Check for internet connection
	  check_internet "${CHECK_IP}"
	  ;;
	d)
	# Set installation to dev branch
	  BRANCH="dev"
	  echo_out "Branch set to dev branch"
	  ;;
	f)
	# Flag for flatpak installation
	  FLATPAK="true"
	  echo_out "Flatpak use set to true"
	  install_flatpak
	  ;;  
	p)
	  VPN_INSTALL="${OPTARG}"
	  ;;
	v)
      # Verbose is first so any other elements will echo as well
      VERBOSE='true'
      echo_out "Verbose mode on."
      ;;
    ?)
      echo "invalid option" >&2
      usage
      ;;
  esac
done

# Clear the options from the arguments
shift "$(( OPTIND - 1 ))"

# Redirect outputs
exec 3>&1 1>>${LOG_FILE} 2>&1

# Start installation message
printf "\nConfiguring Ubuntu Desktop\n\n" 1>&3
printf "\nThis may take some time and the system may appear to be unresponsive\n\n" 1>&3
printf "\nPlease be patient\n\n" 1>&3

# Add Repositories
printf "Adding Repositories\n" | tee /dev/fd/3
sudo add-apt-repository multiverse | tee /dev/fd/3
sudo add-apt-repository -y ppa:unit193/encryption | tee /dev/fd/3
sudo add-apt-repository -y ppa:yubico/stable | tee /dev/fd/3
sudo add-apt-repository -y ppa:nextcloud-devs/client | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

# Update the base OS
printf "Updating base OS\n" | tee /dev/fd/3
sudo apt-get update | tee /dev/fd/3
sudo apt-get -y install software-properties-common | tee /dev/fd/3
sudo apt-get -y dist-upgrade | tee /dev/fd/3
sudo apt-get -y install apt-transport-https | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

# Install VirtualBox Guest Additions:
printf "Installing VirtualBox Guest Additions\n" | tee /dev/fd/3
sudo apt-get -y install virtualbox-guest-dkms | tee /dev/fd/3
sudo apt-get -y install virtualbox-guest-x11 | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

# Install Tor Browser:
printf "Installing TOR browser bundle\n" | tee /dev/fd/3
## You may need this if you get a key error
# gpg --homedir "$HOME/.local/share/torbrowser/gnupg_homedir" --refresh-keys --keyserver keyserver.ubuntu.com
sudo apt-get -y install torbrowser-launcher | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

# GTKHash:
printf "Installing GTKHash\n" | tee /dev/fd/3
sudo snap install gtkhash | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

# Veracrypt:
printf "Installing Veracrypt\n" | tee /dev/fd/3
sudo apt-get -y install libwxgtk3.0-gtk3-0v5 | tee /dev/fd/3
sudo apt-get -y install exfat-fuse exfat-utils | tee /dev/fd/3
# Use either of these options but not both
## Option 1
sudo apt-get -y install veracrypt | tee /dev/fd/3
## Option 2
#sudo wget https://launchpad.net/veracrypt/trunk/1.24-update7/+download/veracrypt-console-1.24-Update7-Ubuntu-20.04-amd64.deb
#sudo apt-get -y install ./veracrypt-console-1.24-Update7-Ubuntu-20.04-amd64.deb | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

# Onionshare:
#TODO: troubleshoot onionshare snap installation
printf "Installing Onionshare\n" | tee /dev/fd/3
# Github install ** TESTING ONLY **
#curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python - | tee /dev/fd/3
#git clone https://github.com/onionshare/onionshare.git | tee /dev/fd/3
#cd onionshare/desktop
#poetry install
#poetry run ./scripts/get-tor-linux.py
#curl -sSL https://go.dev/dl/go1.18.1.linux-amd64.tar.gz
#sudo rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.1.linux-amd64.tar.gz
#echo 'export PATH=$PATH:/usr/local/go/bin' | tee -a .bashrc .profile

# Flatpak install
if [[ ${FLATPAK} == 'true' ]]; then
  flatpak install flathub org.onionshare.OnionShare | tee /dev/fd/3
else
# Snap install
  sudo snap install onionshare | tee /dev/fd/3
  sudo snap connect onionshare:removable-media | tee /dev/fd/3
fi
printf "Complete\n\n" | tee /dev/fd/3

# KeepassXC:
printf "Installing KeePassXC\n" | tee /dev/fd/3
sudo apt-get -y install keepassxc | tee /dev/fd/3
#TODO: Confirm this works with 22.04
#sudo snap install keepassxc | tee /dev/fd/3
#sudo snap connect keepassxc:raw-usb | tee /dev/fd/3
#sudo snap connect keepassxc:removable-media | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

#Yubikey:
printf "Installing Yubikey\n" | tee /dev/fd/3
sudo apt-get -y install yubikey-manager | tee /dev/fd/3
sudo apt-get -y install libykpers-1-1 | tee /dev/fd/3
##For yubikey authorization
sudo apt-get -y install libpam-u2f | tee /dev/fd/3
wget https://raw.githubusercontent.com/Yubico/libu2f-host/master/70-u2f.rules | tee /dev/fd/3
sudo mv 70-u2f.rules /etc/udev/rules.d/70-u2f.rules | tee /dev/fd/3
sudo mkdir -p ~/.config/Yubico | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

#Nextcloud:
printf "Installing Nextcloud Client\n" | tee /dev/fd/3
sudo apt-get -y install nextcloud-client | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

# VPN Clients
case ${VPN_INSTALL} in
  false)
    return
	;;
  all)
    install_airvpn
	install_ivpn
    install_mullvad
    install_openvpn
	install_nordvpn
	install_protonvpn
    ;;
  airvpn)
    install_airvpn
	;;
  ivpn)
    install_ivpn
	;;
  mullvad)
    install_mullvad
	;;
  nordvpn)
    install_nordvpn
	;;
  openvpn)
    install_openvpn
	;;
  protonvpn)
    install_protonvpn
	;;
  *)
    printf "\nUnrecognized VPN option ${VPN_INSTALL}.\n" 
	;;
esac

# Cleanup
printf "Cleaning up\n" | tee /dev/fd/3
sudo apt-get -y autoremove | tee /dev/fd/3
sudo apt-get -y clean | tee /dev/fd/3
sudo rm 70-u2f.rules | tee /dev/fd/3
printf "Complete\n\n" | tee /dev/fd/3

printf "\n\tPress [Enter] to reboot\n" 1>&3
read throwaway

sudo reboot