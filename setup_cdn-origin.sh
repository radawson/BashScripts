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

# Install Yamllint
echo "Installing yamllint"
wait_for_apt
sudo apt-get -y install yamllint

## Software configuration
# Create content directory
echo "Creating content directory"
sudo mkdir -p /var/www/content
sudo chown -R www-data:www-data /var/www/content

# Try to get SSL certificate
echo "Attempting to obtain SSL certificate for ${FQDN}"
sudo certbot certonly --standalone --non-interactive --agree-tos --email admin@${DOMAIN} \
  -d ${FQDN} --preferred-challenges http-01

# Configure NGINX regardless of certificate success
echo "Creating NGINX configuration for ${FQDN}"
if sudo test -f /etc/letsencrypt/live/${FQDN}/fullchain.pem; then
    # SSL configuration
    sudo tee /etc/nginx/sites-available/${FQDN} > /dev/null <<EOF 
server {
    listen 80 default_server;
    server_name ${FQDN};

    location ~ /\.well-known/acme-challenge {
        allow all;
    }

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2 default_server;
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

    # For testing purposes, return client information as JSON
    location = /remote-info {
        default_type application/json;
        
        # Create JSON with client information
        return 200 '{"ip": "$remote_addr", "server": "$hostname", "headers": {"User-Agent": "$http_user_agent", "Accept-Language": "$http_accept_language", "Host": "$host", "Referer": "$http_referer", "X-Forwarded-For": "$http_x_forwarded_for", "X-Real-IP": "$http_x_real_ip", "Via": "$http_via", "X-Cache-Status": "$upstream_cache_status"}}';
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
else
    # HTTP-only configuration (no SSL)
    echo "Warning: SSL certificate not available. Creating HTTP-only configuration."
    sudo tee /etc/nginx/sites-available/${FQDN} > /dev/null <<EOF 
server {
    listen 80 default_server;
    server_name ${FQDN};
    
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
fi

# Enable the site and disable default
sudo ln -sf /etc/nginx/sites-available/${FQDN} /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

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

# Create a remote.html file in the content directory
sudo tee /var/www/content/remote.html > /dev/null << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CDN Remote Client Information</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }
        h1 {
            color: #0066cc;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        h2 {
            color: #0099cc;
            margin-top: 25px;
        }
        .info-section {
            background-color: #f8f8f8;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .info-row {
            display: flex;
            margin-bottom: 8px;
            border-bottom: 1px solid #eee;
            padding-bottom: 8px;
        }
        .info-label {
            font-weight: bold;
            width: 200px;
            color: #555;
        }
        .info-value {
            flex: 1;
        }
        #map-container {
            height: 300px;
            margin-top: 20px;
            display: none;
        }
        .server-tag {
            display: inline-block;
            padding: 4px 8px;
            background-color: #28a745;
            color: white;
            border-radius: 4px;
            font-size: 14px;
            margin-left: 10px;
        }
        .error {
            color: #dc3545;
        }
    </style>
</head>
<body>
    <h1>CDN Remote Client Information <span id="origin-tag" class="server-tag">Origin Server</span></h1>
    
    <div class="info-section">
        <h2>Connection Information</h2>
        <div class="info-row">
            <div class="info-label">Your IP Address:</div>
            <div id="ip-address" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">CDN Server:</div>
            <div id="cdn-server" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Protocol:</div>
            <div id="protocol" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Connection Type:</div>
            <div id="connection-type" class="info-value">Loading...</div>
        </div>
    </div>

    <div class="info-section">
        <h2>Browser Information</h2>
        <div class="info-row">
            <div class="info-label">User Agent:</div>
            <div id="user-agent" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Browser:</div>
            <div id="browser" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Operating System:</div>
            <div id="os" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Screen Resolution:</div>
            <div id="screen-resolution" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Window Size:</div>
            <div id="window-size" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Color Depth:</div>
            <div id="color-depth" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Timezone:</div>
            <div id="timezone" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Language:</div>
            <div id="language" class="info-value">Loading...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Cookies Enabled:</div>
            <div id="cookies" class="info-value">Loading...</div>
        </div>
    </div>

    <div class="info-section">
        <h2>Performance Data</h2>
        <div class="info-row">
            <div class="info-label">Page Load Time:</div>
            <div id="load-time" class="info-value">Calculating...</div>
        </div>
        <div class="info-row">
            <div class="info-label">Network Latency:</div>
            <div id="latency" class="info-value">Measuring...</div>
        </div>
    </div>

    <div class="info-section">
        <h2>HTTP Headers</h2>
        <div id="headers-container">Loading headers...</div>
    </div>

    <script>
        const startTime = performance.now();
        
        // Basic information collection
        document.getElementById('protocol').textContent = window.location.protocol.replace(':', '');
        document.getElementById('user-agent').textContent = navigator.userAgent;
        document.getElementById('screen-resolution').textContent = `${screen.width}x${screen.height}`;
        document.getElementById('window-size').textContent = `${window.innerWidth}x${window.innerHeight}`;
        document.getElementById('color-depth').textContent = `${screen.colorDepth} bits`;
        document.getElementById('timezone').textContent = Intl.DateTimeFormat().resolvedOptions().timeZone;
        document.getElementById('language').textContent = navigator.language || navigator.userLanguage;
        document.getElementById('cookies').textContent = navigator.cookieEnabled ? 'Enabled' : 'Disabled';

        // Detect browser - FIXED FUNCTION
        function detectBrowser() {
            const userAgent = navigator.userAgent;
            let browserName;
            
            if (userAgent.match(/chrome|chromium|crios/i)) {
                browserName = "Chrome";
            } else if (userAgent.match(/firefox|fxios/i)) {
                browserName = "Firefox";
            } else if (userAgent.match(/safari/i)) {
                browserName = "Safari";
            } else if (userAgent.match(/opr\//i)) {
                browserName = "Opera";
            } else if (userAgent.match(/edg/i)) {
                browserName = "Edge";
            } else if (userAgent.match(/msie|trident/i)) {
                browserName = "Internet Explorer";
            } else {
                browserName = "Unknown";
            }
            
            return browserName;
        }

        // Detect OS
        function detectOS() {
            const userAgent = navigator.userAgent;
            let os = "Unknown";
            
            if (userAgent.indexOf("Win") != -1) os = "Windows";
            if (userAgent.indexOf("Mac") != -1) os = "MacOS";
            if (userAgent.indexOf("Linux") != -1) os = "Linux";
            if (userAgent.indexOf("Android") != -1) os = "Android";
            if (userAgent.indexOf("like Mac") != -1) os = "iOS";
            
            return os;
        }

        document.getElementById('browser').textContent = detectBrowser();
        document.getElementById('os').textContent = detectOS();

        // Fetch connection info and headers
        fetch('/remote-info', {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            document.getElementById('ip-address').textContent = data.ip || 'Not available';
            document.getElementById('cdn-server').textContent = data.server || 'Origin Server';
            
            // Display all headers
            const headersContainer = document.getElementById('headers-container');
            headersContainer.innerHTML = '';
            
            if (data.headers && Object.keys(data.headers).length > 0) {
                Object.entries(data.headers).forEach(([key, value]) => {
                    const row = document.createElement('div');
                    row.className = 'info-row';
                    
                    const label = document.createElement('div');
                    label.className = 'info-label';
                    label.textContent = key;
                    
                    const val = document.createElement('div');
                    val.className = 'info-value';
                    val.textContent = value;
                    
                    row.appendChild(label);
                    row.appendChild(val);
                    headersContainer.appendChild(row);
                });
            } else {
                headersContainer.textContent = 'No header information available';
            }
        })
        .catch(error => {
            document.getElementById('ip-address').textContent = 'Error: Could not fetch client information';
            document.getElementById('headers-container').innerHTML = `<div class="error">Error fetching headers: ${error.message}</div>`;
        });

        // Network information
        if ('connection' in navigator) {
            const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            if (connection) {
                document.getElementById('connection-type').textContent = connection.effectiveType || 'Unknown';
            }
        } else {
            document.getElementById('connection-type').textContent = 'API not supported';
        }

        // Measure page load time
        window.addEventListener('load', () => {
            const loadTime = performance.now() - startTime;
            document.getElementById('load-time').textContent = `${loadTime.toFixed(2)} ms`;
            
            // Measure latency with a small ping request
            const pingStart = performance.now();
            fetch('/remote.html?ping=' + new Date().getTime(), { method: 'HEAD' })
                .then(() => {
                    const pingTime = performance.now() - pingStart;
                    document.getElementById('latency').textContent = `${pingTime.toFixed(2)} ms`;
                })
                .catch(() => {
                    document.getElementById('latency').textContent = 'Failed to measure';
                });
        });
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
sudo wg-quick down wg0
sudo wg-quick up wg0

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


# Create the GeoIP configuration directory and base configuration file
echo "Creating GeoIP configuration"
sudo mkdir -p /etc/powerdns
sudo tee /etc/powerdns/geo-zones.yaml > /dev/null <<EOF
---
# GeoIP Configuration for ${DOMAIN} CDN
zones:
  cdn.techopsgroup.com:
    domain: cdn.techopsgroup.com
    ttl: 300
    records:
      # CDN node records with public IPs
      cdn001:
        - content: 149.154.27.178
          type: A
      cdn002:
        - content: 155.138.211.253
          type: A
      
      # Geographic routing - Countries
      us:
        - content: 155.138.211.253
          type: A
      ca:
        - content: 155.138.211.253
          type: A
      gb:
        - content: 149.154.27.178
          type: A
      
      # Geographic routing - Continents
      north-america:
        - content: 155.138.211.253
          type: A
      europe:
        - content: 149.154.27.178
          type: A
      
      # Default fallback
      default:
        - content: 149.154.27.178
          type: A
    
    # Service mappings
    services:
      # Main CDN hostname
      "${FQDN}":
        - "%co.${FQDN}"
        - "%cn.${FQDN}"
        - "default.${FQDN}"
      
      # All subdomains
      "*.${FQDN}":
        - "%co.${FQDN}"
        - "%cn.${FQDN}"
        - "default.${FQDN}"
EOF

# Set proper permissions for the geo-zones.yaml file
sudo chmod 644 /etc/powerdns/geo-zones.yaml

# Create a script to update the geo configuration with regional assignments
sudo tee /usr/local/bin/update-geo-regions > /dev/null <<EOF
#!/bin/bash
# Script to update regional assignments in the GeoIP configuration

if [[ \$# -ne 3 ]]; then
    echo "Usage: \$0 <NODE_NUMBER> <REGION> <CONTINENT>"
    echo "Example: \$0 2 us-east north-america"
    exit 1
fi

NODE_NUMBER=\$1
REGION=\$2
CONTINENT=\$3

# Update the geo-zones.yaml file with regional assignment
sudo sed -i "s/        \$REGION:\\n          - content: 10.10.0.[0-9]\\+/        \$REGION:\\n          - content: 10.10.0.\$NODE_NUMBER/g" /etc/powerdns/geo-zones.yaml
sudo sed -i "s/        \$CONTINENT:\\n          - content: 10.10.0.[0-9]\\+/        \$CONTINENT:\\n          - content: 10.10.0.\$NODE_NUMBER/g" /etc/powerdns/geo-zones.yaml

echo "Updated \$REGION and \$CONTINENT to point to CDN node \$NODE_NUMBER (10.10.0.\$NODE_NUMBER)"
EOF

sudo chmod +x /usr/local/bin/add-cdn-node
sudo chmod +x /usr/local/bin/list-cdn-nodes
sudo chmod +x /usr/local/bin/update-geo-regions

# Setup SSH for Edge Node Pulls
echo "Setting up SSH for edge node pulls"
sudo -u root ssh-keygen -f /root/.ssh/id_ed25519 -N "" -t ed25519


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
    GeoIP Configuration: /etc/powerdns/geo-zones.yaml

Management Scripts:
    Add CDN Node: /usr/local/bin/add-cdn-node <NODE_NUMBER> <NODE_PUBLIC_KEY>
    List CDN Nodes: /usr/local/bin/list-cdn-nodes
    Update Region: /usr/local/bin/update-geo-regions <NODE_NUMBER> <REGION> <CONTINENT>
EOF

echo "CDN origin server setup complete!"
echo "==================================="
echo "To add content to your CDN, place files in: /var/www/content/"
echo "To add a CDN edge node, use: /usr/local/bin/add-cdn-node <NODE_NUMBER> <NODE_PUBLIC_KEY>"
echo "To list connected CDN edge nodes, use: /usr/local/bin/list-cdn-nodes"
echo "To update region assignments, use: /usr/local/bin/update-geo-regions <NODE_NUMBER> <REGION> <CONTINENT>"
echo ""
echo "Your WireGuard public key is: ${PUBLIC_KEY}"
echo "Your WireGuard endpoint is: ${IP}:51822"
echo ""
echo "Configuration information saved to: ~/origin_server_config.txt"
echo ""
echo "IMPORTANT: For edge nodes to pull the GeoIP configuration, add this public key to"
echo "           their /root/.ssh/authorized_keys file:"
sudo cat /root/.ssh/id_ed25519.pub