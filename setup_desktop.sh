#!/bin/bash
# Ubuntu VM desktop setup script
# R. Dawson 2021-2023
# Updated for Ubuntu 24.04 compatibility
VERSION="3.0.2"

## Variables
#TODO: ADAPTER: This works for a VM, but needs a better method
ADAPTER1=$(ls /sys/class/net | grep e) 	# 1st Ethernet adapter on VM
BRANCH="main"							    # Default to main branch
CHECK_IP="8.8.8.8"						# Test ping to google DNS
DATE_VAR=$(date +'%y%m%d-%H%M')	# Today's Date and time
REBOOT_COMPLETE="true"          # Reboot when complete by default
LOG_FILE="${DATE_VAR}_desktop_install.log"  	# Log File name
PACKAGE="apt" 							  # Install snaps by default
JRE_INSTALL="false"						# Do not install default JRE by default
RDP_ENABLE="false"            # Do not enable RTP by default
VPN_INSTALL="false"						# Do not install VPN clients by default
WIFI_TOOLS="false"						# Do not install wifi tools by default
DISTRO="noble"              # Ubuntu 24.04 codename
INTERACTIVE="false"         # Interactive mode off by default

# Application installation flags (default to yes in non-interactive mode)
INSTALL_TOR="y"
INSTALL_GTKHASH="y"
INSTALL_VERACRYPT="y"
INSTALL_ONIONSHARE="y"
INSTALL_KEEPASSXC="y"
INSTALL_YUBIKEY="y"
INSTALL_NEXTCLOUD="y"
INSTALL_ONLYOFFICE="y"

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
		beep -f 1500 -l 200;beep -f 1550 -l 200;beep -f 1500 -l 200;beep -f 1550 -l 200;beep -f 1500 -l 200;beep -f 1550 -l 200;beep -f 1500 -l 200;beep -f 1550 -l 200
	}

	# Restoring Connectivity
	resolve() {
		clear
		echo "$MESSAGE1" | tee /dev/fd/3
		sudo ip link set $ADAPTER1 up; sudo dhclient -r $ADAPTER1; sleep 5; sudo dhclient $ADAPTER1
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
    printf "\nThis script should not be run as root.\n\n" >&2
    usage
  fi
}

echo_out() {
  # Get input from stdin OR $1
  local MESSAGE=${1:-$(</dev/stdin)}
  
  # Check to see if we need a \n
  if [[ "${2}" == 'n' ]]; then
    :
  else
    MESSAGE="${MESSAGE}\n"
  fi
  
  # Decide if we output to console and log or just log
  if [[ "${VERBOSE}" = 'true' ]]; then
    # Check if fd 3 is available, if not use stdout
    if [ -e /dev/fd/3 ]; then
      printf "${MESSAGE}" | tee /dev/fd/3
    else
      printf "${MESSAGE}" | tee -a ${LOG_FILE}
    fi
  else 
    printf "${MESSAGE}" >> ${LOG_FILE}
  fi
}

install_airvpn () {
  printf "Installing AirVPN client.\n" | tee /dev/fd/3
  # Updated method using signed-by with explicit key import
  curl -fsSL https://eddie.website/repository/keys/eddie_maintainer_gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/eddie-keyring.gpg | echo_out
  # Import the key explicitly to fix GPG error
  curl -fsSL https://eddie.website/repository/keys/eddie_maintainer_gpg.key | sudo apt-key add - | echo_out
  # Add the repository with signed-by
  echo "deb [signed-by=/usr/share/keyrings/eddie-keyring.gpg] http://eddie.website/repository/apt stable main" | sudo tee /etc/apt/sources.list.d/eddie.website.list | echo_out
  sudo apt-get update | echo_out
  sudo apt-get -y install eddie-ui | echo_out
  printf "AirVPN Installation Complete.\n\n" | tee /dev/fd/3
}

install_browsers () {
  printf "Additional browser installation has been disabled.\n" | tee /dev/fd/3
  printf "No additional browsers will be installed.\n\n" | tee /dev/fd/3
}

install_flatpak () {
  printf "Installing Flatpak.\n" | tee -a ${LOG_FILE}
  if [ -e /dev/fd/3 ]; then
    printf "Installing Flatpak.\n" >&3
  fi
  
  sudo apt-get -y install flatpak | echo_out
  sudo apt-get -y install gnome-software-plugin-flatpak | echo_out
  flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo | echo_out
  
  printf "Flatpak Installation Complete.\n\n" | tee -a ${LOG_FILE}
  if [ -e /dev/fd/3 ]; then
    printf "Flatpak Installation Complete.\n\n" >&3
  fi
}

install_ivpn() {
  printf "Installing IVPN client.\n" | tee /dev/fd/3
  # Updated method using signed-by
  wget -O - https://repo.ivpn.net/stable/ubuntu/generic.gpg | sudo gpg --dearmor -o /usr/share/keyrings/ivpn-archive-keyring.gpg | echo_out
  echo "deb [signed-by=/usr/share/keyrings/ivpn-archive-keyring.gpg] https://repo.ivpn.net/stable/ubuntu/generic $DISTRO main" | sudo tee /etc/apt/sources.list.d/ivpn.list | echo_out
  sudo apt update | echo_out
  sudo apt-get -y install ivpn-ui | echo_out
  printf "IVPN Installation Complete.\n\n" | tee /dev/fd/3
}

install_mullvad () {
  printf "Installing Mullvad VPN client.\n" | tee /dev/fd/3
  wget --content-disposition https://mullvad.net/download/app/deb/latest | echo_out
  MV_PACKAGE=$(ls | grep Mullvad)
  sudo apt-get -y install ./"${MV_PACKAGE}" | echo_out
  printf "Mullvad Installation VPN Complete.\n\n" | tee /dev/fd/3
}

install_nordvpn () {
  printf "Installing Nord VPN client.\n" | tee /dev/fd/3
  sh <(curl -sSf https://downloads.nordcdn.com/apps/linux/install.sh) | echo_out
  sudo usermod -aG nordvpn $USER | echo_out
  printf "Nord VPN Installation Complete.\n\n" | tee /dev/fd/3
}

install_openvpn () {
  printf "Installing OpenVPN client.\n" | tee /dev/fd/3
  # Updated method using signed-by
  sudo curl -fsSL https://swupdate.openvpn.net/repos/openvpn-repo-pkg-key.pub | sudo gpg --dearmor -o /usr/share/keyrings/openvpn-repo-pkg-keyring.gpg | echo_out
  echo "deb [signed-by=/usr/share/keyrings/openvpn-repo-pkg-keyring.gpg] https://swupdate.openvpn.net/community/openvpn3/repos/openvpn3-$DISTRO $DISTRO main" | sudo tee /etc/apt/sources.list.d/openvpn3.list | echo_out
  sudo apt-get update | echo_out
  sudo apt-get -y install openvpn3 | echo_out
  printf "OpenVPN Installation Complete.\n\n" | tee /dev/fd/3
}

install_protonvpn () {
  printf "Installing ProtonVPN client.\n" | tee /dev/fd/3
  # Updated installation method
  wget -q -O - https://repo.protonvpn.com/debian/public_key.asc | sudo gpg --dearmor -o /usr/share/keyrings/protonvpn-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/protonvpn-keyring.gpg] https://repo.protonvpn.com/debian stable main" | sudo tee /etc/apt/sources.list.d/protonvpn-stable.list
  sudo apt update
  sudo apt-get -y install protonvpn
  printf "ProtonVPN Installation Complete.\n\n" | tee /dev/fd/3
}

install_wifi_tools() {
  printf "Installing WiFi tools.\n" | tee /dev/fd/3
  # Updated for Ubuntu 24.04 (noble)
  wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/kismet-keyring.gpg | echo_out
  echo "deb [signed-by=/usr/share/keyrings/kismet-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/noble noble main" | sudo tee /etc/apt/sources.list.d/kismet.list | echo_out
  sudo apt update
  sudo apt-get -y install kismet
  pip install kismet_rest
  
  # Kismon installation
  sudo apt-get -y install python3-simplejson
  sudo apt-get -y install gir1.2-osmgpsmap-1.0
  cd ~
  git clone https://github.com/radawson/kismon.git kismon
  cd kismon
  sudo make install
  printf "Kismet and Kismon Installation Complete.\n\n" | tee /dev/fd/3
}

usage() {
  echo "Usage: ${0} [-bcfhjrsvwxi] [-p VPN_name] " >&2
  echo "Sets up Ubuntu Desktop with useful apps."
  #echo "Do not run as root."
  echo
  echo "-b 			Install multiple browsers."
  echo "-c 			Check internet connection before starting."
  echo "-f			Install Flatpak (not Snaps)."
  echo "-h 			Help (this list)."
  echo "-i      Interactive mode (select what to install)."
  echo "-j      Install default JRE."
  echo "-p      VPN_NAME	  Install VPN client(s) or 'all'."
  echo "-r      Install and enable RDP."
  echo "-s			Install Snaps (not flatpak)"
  echo "-v 			Verbose mode."
  echo "-w			WiFi tools (kismet)."
  echo "-x      Do not reboot when complete."
  exit 1
}

# Interactive menu function
interactive_menu() {
  # Set up file descriptor 3 for this function
  exec 3>&1
  
  clear
  echo "==================================================="
  echo "       Ubuntu 24.04 Desktop Setup Script"
  echo "==================================================="
  echo "Please select which components to install:"
  echo
  
  # Package manager selection
  echo -n "Use Flatpak instead of Snaps? (y/n): "
  read -r package_choice
  if [[ "$package_choice" =~ ^[Yy]$ ]]; then
    PACKAGE="flatpak"
    echo_out "Flatpak use set to true"
    # Temporarily set VERBOSE to true for install_flatpak
    local ORIG_VERBOSE="${VERBOSE}"
    VERBOSE="true"
    install_flatpak
    VERBOSE="${ORIG_VERBOSE}"
  fi
  
  # JRE selection
  echo -n "Install default Java Runtime Environment? (y/n): "
  read -r jre_choice
  if [[ "$jre_choice" =~ ^[Yy]$ ]]; then
    JRE_INSTALL="true"
  fi
  
  # Application selections
  echo
  echo "Select applications to install:"
  
  echo -n "Install Tor Browser? (y/n): "
  read -r tor_choice
  INSTALL_TOR=${tor_choice,,}
  
  echo -n "Install GTKHash? (y/n): "
  read -r gtkhash_choice
  INSTALL_GTKHASH=${gtkhash_choice,,}
  
  echo -n "Install Veracrypt? (y/n): "
  read -r veracrypt_choice
  INSTALL_VERACRYPT=${veracrypt_choice,,}
  
  echo -n "Install Onionshare? (y/n): "
  read -r onionshare_choice
  INSTALL_ONIONSHARE=${onionshare_choice,,}
  
  echo -n "Install KeePassXC? (y/n): "
  read -r keepassxc_choice
  INSTALL_KEEPASSXC=${keepassxc_choice,,}
  
  echo -n "Install Yubikey support? (y/n): "
  read -r yubikey_choice
  INSTALL_YUBIKEY=${yubikey_choice,,}
  
  echo -n "Install Nextcloud Client? (y/n): "
  read -r nextcloud_choice
  INSTALL_NEXTCLOUD=${nextcloud_choice,,}
  
  echo -n "Install OnlyOffice? (y/n): "
  read -r onlyoffice_choice
  INSTALL_ONLYOFFICE=${onlyoffice_choice,,}
  
  # VPN selection
  echo
  echo "VPN client options:"
  echo "0. None"
  echo "1. AirVPN"
  echo "2. IVPN"
  echo "3. Mullvad"
  echo "4. NordVPN"
  echo "5. OpenVPN"
  echo "6. ProtonVPN"
  echo "7. All VPNs"
  echo -n "Select VPN to install (0-7): "
  read -r vpn_choice
  
  case $vpn_choice in
    1) VPN_INSTALL="airvpn" ;;
    2) VPN_INSTALL="ivpn" ;;
    3) VPN_INSTALL="mullvad" ;;
    4) VPN_INSTALL="nordvpn" ;;
    5) VPN_INSTALL="openvpn" ;;
    6) VPN_INSTALL="protonvpn" ;;
    7) VPN_INSTALL="all" ;;
    *) VPN_INSTALL="false" ;;
  esac
  
  # RDP selection
  echo -n "Install and enable Remote Desktop Protocol? (y/n): "
  read -r rdp_choice
  if [[ "$rdp_choice" =~ ^[Yy]$ ]]; then
    RDP_ENABLE="true"
  fi
  
  # WiFi tools selection
  echo -n "Install WiFi tools (Kismet)? (y/n): "
  read -r wifi_choice
  if [[ "$wifi_choice" =~ ^[Yy]$ ]]; then
    WIFI_TOOLS="true"
  fi
  
  # Reboot selection
  echo -n "Reboot when installation is complete? (y/n): "
  read -r reboot_choice
  if [[ "$reboot_choice" =~ ^[Nn]$ ]]; then
    REBOOT_COMPLETE="false"
  fi
  
  echo
  echo "Setup will now proceed with your selections."
  echo "Press Enter to continue..."
  read -r
}

## MAIN
# Create a log file with current date and time
touch ${LOG_FILE}

# Provide usage statement if no parameters
while getopts bcdfhijp:rsvwx OPTION; do
  case ${OPTION} in
  b)
    # Install browser packages
      install_browsers
      ;;
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
	  PACKAGE="flatpak"
	  echo_out "Flatpak use set to true"
	  ;;  
	h)
  # Help statement
	  usage
	  ;;
  i)
    # Interactive mode
    INTERACTIVE="true"
    ;;
  j)
    # Install default JRE
    JRE_INSTALL="true"
    ;;
	p)
	  VPN_INSTALL="${OPTARG}"
    echo_out "${OPTARG} configured for VPN client install"
	  ;;
  r)
    RDP_ENABLE="true"
    echo_out "Remote Desktop Protocol daemon installation enabled"
    ;;
	s)
	# Flag for snap installation
	  PACKAGE="snap"
	  echo_out "Snap use set to true"
	  ;; 
	v)
    VERBOSE='true'
    echo_out "Verbose mode on."
    ;;
	w)
	  WIFI_TOOLS='true'
	  echo_out "WiFi tools will be installed"
	  ;;
  x)
    REBOOT_COMPLETE="false"
    echo_out "Reboot on complete disabled"
    ;;
  ?)
    echo "invalid option" >&2
    usage
    ;;
  esac
done

# Clear the options from the arguments
shift "$(( OPTIND - 1 ))"

# If interactive mode is enabled, show the menu
if [[ "$INTERACTIVE" == "true" ]]; then
  interactive_menu
fi

# Redirect outputs
exec 3>&1 1>>${LOG_FILE} 2>&1

# Start installation message
echo_out "Script version ${VERSION}\n"
printf "\nConfiguring Ubuntu Desktop\n" 1>&3
printf "\nThis may take some time and the system may appear to be unresponsive\n" 1>&3
printf "\nPlease be patient\n\n" 1>&3

# Add Repositories
printf "Adding Repositories\n" | tee /dev/fd/3
echo_out "1" n
sudo add-apt-repository -y multiverse
echo_out "\b2" n
# Updated PPA method for Ubuntu 24.04
sudo add-apt-repository -y ppa:unit193/encryption
echo_out "\b3" n
sudo add-apt-repository -y ppa:yubico/stable
echo_out "\b4"
sudo add-apt-repository -y ppa:nextcloud-devs/client
printf "Complete\n\n" | tee /dev/fd/3

# Update the base OS
printf "Updating base OS\n" | tee /dev/fd/3
sudo apt-get update | echo_out
sudo apt-get -y install software-properties-common | echo_out
sudo apt-get -y dist-upgrade | echo_out
sudo apt-get -y install apt-transport-https | echo_out
if [[ "$JRE_INSTALL" == "true" ]]; then
  sudo apt-get -y install default-jre | echo_out
fi
printf "Complete\n\n" | tee /dev/fd/3

# Install git
if [[ $(which git) == "" ]]; then
  printf "Installing git\n" | tee /dev/fd/3
  sudo apt-get -y install git
  printf "Complete\n\n" | tee /dev/fd/3
fi

# Install flatpak
if [[ ${PACKAGE} == "flatpak" ]]; then
  printf "Installing flatpak\n" | tee /dev/fd/3
  install_flatpak
  printf "Complete\n\n" | tee /dev/fd/3
fi

# Install python PIP
printf "Installing python PIP\n" | tee /dev/fd/3
sudo apt-get -y install python3-pip | echo_out
printf "Complete\n\n" | tee /dev/fd/3

# Install Tor Browser:
if [[ "$INSTALL_TOR" =~ ^[Yy]$ ]]; then
  printf "Installing TOR browser bundle\n" | tee /dev/fd/3
  ## You may need this if you get a key error
  # gpg --homedir "$HOME/.local/share/torbrowser/gnupg_homedir" --refresh-keys --keyserver keyserver.ubuntu.com

  # Always use Flatpak for Tor Browser
  if ! command -v flatpak &> /dev/null; then
    printf "Flatpak not found. Installing Flatpak first...\n" | tee /dev/fd/3
    sudo apt-get -y install flatpak | echo_out
    sudo apt-get -y install gnome-software-plugin-flatpak | echo_out
    flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo | echo_out
  fi
  flatpak install flathub com.github.micahflee.torbrowser-launcher -y | echo_out
  printf "Complete\n\n" | tee /dev/fd/3
else
  printf "Skipping TOR browser installation\n" | tee /dev/fd/3
fi

# GTKHash:
if [[ "$INSTALL_GTKHASH" =~ ^[Yy]$ ]]; then
  printf "Installing GTKHash\n" | tee /dev/fd/3
  sudo apt-get install -y gtkhash | echo_out
  printf "Complete\n\n" | tee /dev/fd/3
else
  printf "Skipping GTKHash installation\n" | tee /dev/fd/3
fi

# Veracrypt:
if [[ "$INSTALL_VERACRYPT" =~ ^[Yy]$ ]]; then
  printf "Installing Veracrypt\n" | tee /dev/fd/3
  # Updated for Ubuntu 24.04
  sudo apt-get -y install libwxgtk3.2-1 | echo_out
  sudo apt-get -y install exfat-fuse | echo_out
  # Use either of these options but not both
  ## Option 1
  sudo apt-get -y install veracrypt | echo_out
  printf "Complete\n\n" | tee /dev/fd/3
else
  printf "Skipping Veracrypt installation\n" | tee /dev/fd/3
fi

# Onionshare:
if [[ "$INSTALL_ONIONSHARE" =~ ^[Yy]$ ]]; then
  printf "Installing Onionshare\n" | tee /dev/fd/3

  # Always use Flatpak for Onionshare
  if ! command -v flatpak &> /dev/null; then
    printf "Flatpak not found. Installing Flatpak first...\n" | tee /dev/fd/3
    sudo apt-get -y install flatpak | echo_out
    sudo apt-get -y install gnome-software-plugin-flatpak | echo_out
    flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo | echo_out
  fi
  flatpak install flathub org.onionshare.OnionShare -y | echo_out
  printf "Complete\n\n" | tee /dev/fd/3
else
  printf "Skipping Onionshare installation\n" | tee /dev/fd/3
fi

# KeepassXC:
if [[ "$INSTALL_KEEPASSXC" =~ ^[Yy]$ ]]; then
  printf "Installing KeePassXC\n" | tee /dev/fd/3
  sudo snap install keepassxc | echo_out
  sudo snap connect keepassxc:raw-usb | echo_out
  sudo snap connect keepassxc:removable-media | echo_out
  printf "Complete\n\n" | tee /dev/fd/3
else
  printf "Skipping KeePassXC installation\n" | tee /dev/fd/3
fi

#Yubikey:
if [[ "$INSTALL_YUBIKEY" =~ ^[Yy]$ ]]; then
  printf "Installing Yubikey\n" | tee /dev/fd/3
  sudo apt-get -y install yubikey-manager | echo_out
  sudo apt-get -y install libykpers-1-1 | echo_out

  #For yubikey authorization
  sudo apt-get -y install libpam-u2f | echo_out
  # Updated udev rules method
  sudo wget -O /etc/udev/rules.d/70-u2f.rules https://raw.githubusercontent.com/Yubico/libfido2/main/udev/70-u2f.rules | echo_out
  sudo mkdir -p ~/.config/Yubico | echo_out
  printf "Complete\n\n" | tee /dev/fd/3
else
  printf "Skipping Yubikey installation\n" | tee /dev/fd/3
fi

# Nextcloud:
if [[ "$INSTALL_NEXTCLOUD" =~ ^[Yy]$ ]]; then
  printf "Installing Nextcloud Client\n\nThis can take a while\n" | tee /dev/fd/3
  sudo apt-get -y install nextcloud-client | echo_out
  printf "Complete\n\n" | tee /dev/fd/3
else
  printf "Skipping Nextcloud Client installation\n" | tee /dev/fd/3
fi

# OnlyOffice:
if [[ "$INSTALL_ONLYOFFICE" =~ ^[Yy]$ ]]; then
  printf "Installing OnlyOffice\n" | tee /dev/fd/3

  case ${PACKAGE} in
    flatpak)
      flatpak install flathub org.onlyoffice.desktopeditors -y | echo_out
    ;;
    *)
      sudo snap install onlyoffice-desktopeditors | echo_out
    ;;
  esac
  printf "Complete\n\n" | tee /dev/fd/3
else
  printf "Skipping OnlyOffice installation\n" | tee /dev/fd/3
fi

# Remote Desktop Protocol
if [[ "$RDP_ENABLE" == "true" ]]; then
  printf "Installing and Enabling RDP\n" | tee /dev/fd/3
  sudo apt-get -y install xrdp | echo_out
  sudo systemctl enable xrdp --now | echo_out
  printf "Complete\n\n" | tee /dev/fd/3
fi

# VPN Clients
case ${VPN_INSTALL} in
  false)
    :
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

# WiFi Tools
if [[ ${WIFI_TOOLS} == "true" ]]; then
  install_wifi_tools
fi  

# Create update.sh file
printf "Creating update.sh\n" | tee /dev/fd/3
cat << @EOF > ~/update.sh
#!/bin/bash
sudo apt-get update
sudo apt-get -y dist-upgrade
sudo apt-get -y autoremove --purge
sudo apt-get -y clean
echo "Update complete"
@EOF
sudo chmod 744 ~/update.sh
printf "Complete\n\n" | tee /dev/fd/3

# Cleanup
printf "Cleaning up\n" | tee /dev/fd/3
sudo apt-get -y autoremove --purge | echo_out
sudo apt-get -y clean | echo_out
printf "Complete\n\n" | tee /dev/fd/3

# Flatpak message
if [[ ${PACKAGE} == "flatpak" ]]; then
  printf "Flatpak apps will be visible in Launcher after reboot\n" | tee /dev/fd/3
fi

# Reboot by default
if [[ ${REBOOT_COMPLETE} == "true" ]]; then
  printf "\n\tPress [Enter] to reboot\n" 1>&3
  read throwaway
  sudo reboot
fi 