#!/bin/bash
#v1.0.0
# (c) 2025 Richard Dawson, Technical Operations Group
# This script sets up a CDN server with NGINX, PowerDNS, and PostgreSQL backend.

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 <DOMAIN> [IP]"
    exit 1
fi

# Function to wait for apt locks to be released
wait_for_apt() {
  echo "Checking for apt/dpkg locks:"
  while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 || sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    printf "Waiting for other apt/dpkg processes to complete..."
    sleep 5
    printf "."
  done
  echo -e "\n\nLocks released, proceeding with installation."
}

# Set variables
DOMAIN=${1}
if [[ ! "${DOMAIN}" =~ ^[a-zA-Z0-9.-]+$ ]]; then
  echo "Error: Invalid domain name format."
  exit 1
fi

# Set IP address
if [[ $# -eq 2 ]]; then
    IP=${2}
else
    IP=$(ip -o -4 addr | grep -E ' (en|eth)[^ ]+' | head -n1 | awk '{print $4}' | cut -d/ -f1)
fi
if [[ -z "${IP}" ]]; then
    echo "Unable to determine IP address. Please provide it as the second argument."
    exit 1
fi

FQDN="origin.${DOMAIN}"

echo "Setting up CDN origin server with FQDN ${FQDN} and IP ${IP}"

## System Preparation
# Update and upgrade the system
echo "Updating and upgrading the system"
wait_for_apt
sudo apt update
wait_for_apt
sudo apt-get -y dist-upgrade
wait_for_apt
sudo apt-get -y autoremove

# Set hostname
echo "Setting hostname"
sudo hostnamectl hostname ${FQDN}
echo "${IP} ${FQDN}" | sudo tee -a /etc/hosts

# Configure Firewall
echo "Configuring firewall"
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 51822/udp # WireGuard
sudo ufw --force enable

## Repository Preparation
# Ensure support for apt repositories served via HTTPS
echo "Installing apt-transport-https"
sudo apt-get install -y apt-transport-https

# Update package list
sudo apt-get update

## Software Installation
# Install CertBot
echo "Installing CertBot (snap)"
sudo apt-get remove -y certbot --purge
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Install NGINX
echo "Installing NGINX"
wait_for_apt
sudo apt-get -y install nginx
sudo systemctl stop nginx

# Install WireGuard
echo "Installing WireGuard"
wait_for_apt
sudo apt-get -y install wireguard wireguard-tools

## Software configuration
# Create content directory
echo "Creating content directory"
sudo mkdir -p /var/www/content
sudo chown -R www-data:www-data /var/www/content

# Get SSL certificate
echo "Obtaining SSL certificate for ${FQDN}"
sudo certbot certonly --standalone --non-interactive --agree-tos --email admin@${DOMAIN} \
  -d ${FQDN} --preferred-challenges http-01

# Configure NGINX for origin server
if [ ! -f /etc/letsencrypt/live/${FQDN}/fullchain.pem ]; then
    echo "Certificate generation failed!"
else
    echo "Creating NGINX configuration for ${FQDN}"
    sudo tee /etc/nginx/sites-available/${FQDN} > /dev/null <<EOF 
server {
    listen 80;
    server_name ${FQDN};

    location ~ /\.well-known/acme-challenge {
        allow all;
    }

    return 301 https://\$host\$request_uri; # Redirect all HTTP to HTTPS
}

server {
    listen 443 ssl http2;
    server_name ${FQDN};

    ssl_certificate /etc/letsencrypt/live/${FQDN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${FQDN}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'HIGH:!aNULL:!MD5';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    
    # Origin server configuration
    location / {
        root /var/www/content;
        index index.html index.htm;
        
        # Cache headers
        add_header X-Origin-Server "true";
        add_header Cache-Control "public, max-age=3600";
    }

    location ~ /\.well-known/acme-challenge {
        allow all;
    }
    
    # Static content with longer cache times
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg)$ {
        root /var/www/content;
        expires 7d;
        add_header Cache-Control "public, max-age=604800";
        access_log off;
    }
}
EOF

    # Enable the site
    sudo ln -sf /etc/nginx/sites-available/${FQDN} /etc/nginx/sites-enabled/
fi

# Restart nginx
sudo systemctl start nginx

# Create sample content
sudo tee /var/www/content/index.html > /dev/null <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>CDN Origin Server - ${FQDN}</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
    </style>
</head>
<body>
    <h1>CDN Origin Server: ${FQDN}</h1>
    <p>This server is the origin server for the Technical Operations Group CDN network.</p>
    <p>IP Address: ${IP}</p>
    <p>Current time: <span id="timestamp"></span></p>
    
    <script>
        // Update timestamp every second to verify content is being refreshed properly
        function updateTimestamp() {
            document.getElementById('timestamp').innerText = new Date().toLocaleString();
        }
        setInterval(updateTimestamp, 1000);
        updateTimestamp();
    </script>
</body>
</html>
EOF

# Restart NGINX to apply the new configuration
echo "Restarting NGINX"
sudo systemctl restart nginx

# Configure WireGuard
echo "Configuring WireGuard server"

# Generate server private key
wg genkey | sudo tee /etc/wireguard/server_private.key
sudo chmod 600 /etc/wireguard/server_private.key

# Generate server public key
sudo cat /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key

# Create server configuration
WG_CONFIG="/etc/wireguard/wg0.conf"
PRIVATE_KEY=$(sudo cat /etc/wireguard/server_private.key)
if [ -z "${PRIVATE_KEY}" ]; then
    echo "Error: Failed to generate WireGuard private key."
    exit 1
fi

echo "Creating WireGuard server configuration file"
sudo tee "${WG_CONFIG}" > /dev/null <<EOF
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = 10.10.0.1/24
ListenPort = 51822
SaveConfig = false

# CDN nodes will be added here with:
# [Peer]
# PublicKey = <cdn_node_public_key>
# AllowedIPs = 10.10.0.X/32
EOF

# Create script to add new CDN nodes
echo "Creating CDN node management scripts"
sudo tee /usr/local/bin/add-cdn-node > /dev/null <<EOF
#!/bin/bash
# Script to add a new CDN edge node to the WireGuard configuration

if [[ \$# -ne 2 ]]; then
    echo "Usage: \$0 <NODE_NUMBER> <NODE_PUBLIC_KEY>"
    exit 1
fi

NODE_NUMBER=\$1
NODE_PUBLIC_KEY=\$2

# Validate inputs
if [[ ! "\${NODE_NUMBER}" =~ ^[0-9]+\$ ]]; then
    echo "Error: NODE_NUMBER must be a positive integer."
    exit 1
fi

if [[ "\${NODE_NUMBER}" -lt 2 || "\${NODE_NUMBER}" -gt 254 ]]; then
    echo "Error: NODE_NUMBER must be between 2 and 254."
    exit 1
fi

if [[ "\${#NODE_PUBLIC_KEY}" -ne 44 ]]; then
    echo "Error: NODE_PUBLIC_KEY must be 44 characters long."
    exit 1
fi

# Check if the node already exists
if grep -q "\${NODE_PUBLIC_KEY}" /etc/wireguard/wg0.conf; then
    echo "Error: Node with this public key already exists."
    exit 1
fi

# Add the node to WireGuard configuration
echo "Adding CDN node \${NODE_NUMBER} with IP 10.10.0.\${NODE_NUMBER}"
echo "" | sudo tee -a /etc/wireguard/wg0.conf
echo "[Peer]" | sudo tee -a /etc/wireguard/wg0.conf
echo "PublicKey = \${NODE_PUBLIC_KEY}" | sudo tee -a /etc/wireguard/wg0.conf
echo "AllowedIPs = 10.10.0.\${NODE_NUMBER}/32" | sudo tee -a /etc/wireguard/wg0.conf
echo "PersistentKeepalive = 25" | sudo tee -a /etc/wireguard/wg0.conf

# Apply changes without disconnecting existing peers
sudo wg addconf wg0 <(sudo wg-quick strip wg0)

echo "CDN node \${NODE_NUMBER} added successfully."
echo "IP: 10.10.0.\${NODE_NUMBER}"
EOF

sudo tee /usr/local/bin/list-cdn-nodes > /dev/null <<EOF
#!/bin/bash
# Script to list all CDN edge nodes

echo "CDN Edge Nodes:"
echo "==============="
echo "Number | IP Address  | Public Key                                  | Last Handshake"
echo "----------------------------------------------------------------------"

sudo wg show wg0 | grep -A 3 peer | while read -r line; do
    if [[ "\$line" == peer* ]]; then
        PEER=\$(echo "\$line" | awk '{print \$2}')
        read -r endpoint_line
        read -r allowed_ips_line
        read -r handshake_line
        
        IP=\$(echo "\$allowed_ips_line" | awk '{print \$2}' | cut -d '/' -f 1)
        NODE_NUMBER=\$(echo "\$IP" | cut -d '.' -f 4)
        HANDSHAKE=\$(echo "\$handshake_line" | cut -d ':' -f 2-)
        
        echo "\$NODE_NUMBER | \$IP | \$PEER | \$HANDSHAKE"
    fi
done
EOF

sudo chmod +x /usr/local/bin/add-cdn-node
sudo chmod +x /usr/local/bin/list-cdn-nodes

# Enable and start WireGuard
echo "Enabling WireGuard"
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Save configuration information
PUBLIC_KEY=$(sudo cat /etc/wireguard/server_public.key)
echo "Saving configuration data"
cat <<EOF >~/origin_server_config.txt
-- CDN Origin Server Configuration --
FQDN: ${FQDN}
IP Address: ${IP}
WireGuard Public Key: ${PUBLIC_KEY}
WireGuard Endpoint: ${IP}:51822

Configuration Files:
    NGINX: /etc/nginx/sites-available/${FQDN}
    WireGuard: /etc/wireguard/wg0.conf
    Content Directory: /var/www/content

Management Scripts:
    Add CDN Node: /usr/local/bin/add-cdn-node <NODE_NUMBER> <NODE_PUBLIC_KEY>
    List CDN Nodes: /usr/local/bin/list-cdn-nodes
EOF

echo "CDN origin server setup complete!"
echo "==================================="
echo "To add content to your CDN, place files in: /var/www/content/"
echo "To add a CDN edge node, use: /usr/local/bin/add-cdn-node <NODE_NUMBER> <NODE_PUBLIC_KEY>"
echo "To list connected CDN edge nodes, use: /usr/local/bin/list-cdn-nodes"
echo ""
echo "Your WireGuard public key is: ${PUBLIC_KEY}"
echo "Your WireGuard endpoint is: ${IP}:51822"
echo ""
echo "Configuration information saved to: ~/origin_server_config.txt"