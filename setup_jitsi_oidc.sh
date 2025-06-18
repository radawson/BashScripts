#!/bin/bash
#
# Script to add OIDC authentication to existing Jitsi Meet installation
# Run this after your initial Jitsi setup is complete
# v1.0.0

# Stop on errors
set -Eeuo pipefail
trap 'echo "❌  error in $BASH_SOURCE:$LINENO: $BASH_COMMAND"' ERR

# Validate number of arguments
if [[ $# -ne 4 ]]; then
    echo "❌ Error: This script requires exactly 4 arguments" >&2
    echo "Usage: $0 <DNS DOMAIN> <OIDC PROVIDER> <client-id> <client-secret>" >&2
    echo "Example: $0 meet.example.com sso.example.com meet-ex 1q2w3e4r" >&2
    exit 1
fi

# Validate domain name format
DOMAIN=${1}
if [[ ! "${DOMAIN}" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
    echo "❌ Invalid domain name format. Domain must:" >&2
    echo "   - Start and end with a letter or number" >&2
    echo "   - Contain only letters, numbers, dots, and hyphens" >&2
    echo "   - Not contain consecutive dots or hyphens" >&2
    exit 1
fi

# Validate OIDC provider format
OIDC_PROVIDER=${2}
if [[ ! "${OIDC_PROVIDER}" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
    echo "❌ Invalid OIDC provider format. Provider must:" >&2
    echo "   - Start and end with a letter or number" >&2
    echo "   - Contain only letters, numbers, dots, and hyphens" >&2
    echo "   - Not contain consecutive dots or hyphens" >&2
    exit 1
fi

# Validate client ID
OIDC_CLIENT_ID=${3}
if [[ -z "${OIDC_CLIENT_ID}" ]]; then
    echo "❌ Error: Client ID cannot be empty" >&2
    exit 1
fi

# Validate client secret
OIDC_CLIENT_SECRET=${4}
if [[ -z "${OIDC_CLIENT_SECRET}" ]]; then
    echo "❌ Error: Client secret cannot be empty" >&2
    exit 1
fi

if [[ "${DOMAIN}" == meet.* ]]; then
    FQDN="${DOMAIN}"
else
    FQDN="meet.${DOMAIN}"
fi 

OIDC_PROVIDER_URL="https://${OIDC_PROVIDER}"  # Your OIDC provider URL
OIDC_ISSUER="https://${OIDC_PROVIDER}"  # OIDC issuer URL

# Validate FQDN resolution
if ! dig +short A "$FQDN" >/dev/null; then
    echo "❌ Error: ${FQDN} does not resolve to an IP address" >&2
    exit 1
fi

# Validate OIDC provider resolution
if ! dig +short A "$OIDC_PROVIDER" >/dev/null; then
    echo "❌ Error: ${OIDC_PROVIDER} does not resolve to an IP address" >&2
    exit 1
fi

echo "🔧 Adding OIDC authentication to Jitsi Meet at $FQDN"

JWT_SECRET="your-jitsi-jwt-secret"  # Your existing Jitsi JWT secret

# Choose approach: "prosody" or "adapter"
APPROACH="adapter"  # Recommended: more stable and easier to maintain

echo "🔧 Adding OIDC authentication to Jitsi Meet at $FQDN using $APPROACH approach"

# Validate inputs
if [[ -z "$FQDN" || -z "$OIDC_PROVIDER_URL" || -z "$OIDC_CLIENT_ID" || -z "$OIDC_CLIENT_SECRET" ]]; then
    echo "❌ Please configure all OIDC variables at the top of this script"
    exit 1
fi

# Function to wait for apt locks
wait_for_apt() {
    while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 || sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        echo "Waiting for apt locks to be released..."
        sleep 5
    done
}

# Backup existing configurations
echo "💾 Creating configuration backups..."
sudo cp /etc/jitsi/meet/${FQDN}-config.js /etc/jitsi/meet/${FQDN}-config.js.backup
sudo cp /etc/nginx/sites-available/${FQDN}.conf /etc/nginx/sites-available/${FQDN}.conf.backup

if [[ "$APPROACH" == "prosody" ]]; then
    echo "📦 Installing Prosody Community Modules approach..."
    
    # Install mercurial for cloning prosody-modules
    wait_for_apt
    sudo apt-get update
    sudo apt-get install -y mercurial
    
    # Clone prosody-modules repository
    cd /tmp
    hg clone https://hg.prosody.im/prosody-modules/ prosody-modules
    
    # Create prosody modules directory if it doesn't exist
    sudo mkdir -p /usr/lib/prosody/modules-enabled
    
    # Check for available OIDC/OAuth modules
    echo "📋 Available authentication modules:"
    ls prosody-modules/ | grep -E "(auth|oauth|oidc)" || echo "Checking for OIDC modules..."
    
    # Install HTTP OAuth2 module (most stable OIDC option)
    if [ -d "prosody-modules/mod_http_oauth2" ]; then
        echo "Installing mod_http_oauth2..."
        sudo cp -r prosody-modules/mod_http_oauth2 /usr/lib/prosody/modules/
        sudo chown -R prosody:prosody /usr/lib/prosody/modules/mod_http_oauth2
    fi
    
    # Install auth modules
    for module in mod_auth_custom_http mod_auth_external_insecure; do
        if [ -d "prosody-modules/$module" ]; then
            echo "Installing $module..."
            sudo cp -r prosody-modules/$module /usr/lib/prosody/modules/
            sudo chown -R prosody:prosody /usr/lib/prosody/modules/$module
        fi
    done
    
    # Alternative: Install the rwth-acis OIDC module
    echo "📥 Installing rwth-acis OIDC module as fallback..."
    wget -O /tmp/mod_auth_openid_connect.lua https://raw.githubusercontent.com/rwth-acis/prosody-auth-OIDC/master/mod_auth_openid_connect.lua
    sudo cp /tmp/mod_auth_openid_connect.lua /usr/lib/prosody/modules/
    sudo chown prosody:prosody /usr/lib/prosody/modules/mod_auth_openid_connect.lua
    
    # Configure Prosody for OIDC
    echo "🔐 Configuring Prosody for OIDC..."
    sudo cp /etc/prosody/conf.avail/${FQDN}.cfg.lua /etc/prosody/conf.avail/${FQDN}.cfg.lua.backup
    
    # Update authentication method
    sudo sed -i 's/authentication.*=.*"internal_hashed"/authentication = "openid_connect"/' /etc/prosody/conf.avail/${FQDN}.cfg.lua
    
    # Add OIDC configuration
    cat <<EOF | sudo tee -a /etc/prosody/conf.avail/${FQDN}.cfg.lua

-- OIDC Configuration
oidc_issuer = "${OIDC_ISSUER}"
oidc_client_id = "${OIDC_CLIENT_ID}"
oidc_client_secret = "${OIDC_CLIENT_SECRET}"
oidc_userinfo_endpoint = "${OIDC_PROVIDER_URL}/userinfo"

modules_enabled = {
    -- Core modules (keep existing ones)
    "roster"; "saslauth"; "tls"; "dialback"; "disco";
    "posix"; "private"; "vcard4"; "vcard_legacy"; "version";
    "uptime"; "time"; "ping"; "pep"; "register"; "admin_adhoc";
    
    -- Jitsi modules
    "bosh"; "pubsub"; "speakerstats"; "conference_duration";
    "end_conference"; "external_services";
    
    -- HTTP and OIDC modules
    "http"; "http_files";
}
EOF

elif [[ "$APPROACH" == "adapter" ]]; then
    echo "📦 Installing Python OIDC Adapter approach (Recommended)..."
    
    # Install required packages
    wait_for_apt
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip git python3-venv
    
    # Create application directory
    sudo mkdir -p /opt/jitsi-oidc-adapter
    cd /opt/jitsi-oidc-adapter
    
    # Clone the OIDC adapter
    sudo git clone https://github.com/aadpM2hhdixoJm3u/jitsi-OIDC-adapter.git .
    
    # Create virtual environment and install dependencies
    sudo python3 -m venv venv
    sudo ./venv/bin/pip install -r requirements.txt
    
    # Create configuration file
    cat <<EOF | sudo tee app.conf
[oauth]
client_id = ${OIDC_CLIENT_ID}
client_secret = ${OIDC_CLIENT_SECRET}
issuer = ${OIDC_ISSUER}
scope = openid email profile

[urls]
jitsi_base = https://${FQDN}
oidc_discovery = ${OIDC_PROVIDER_URL}/.well-known/openid-configuration

[jwt]
audience = jitsi
issuer = ${FQDN}
subject = ${FQDN}
secret_key = ${JWT_SECRET}

[logging]
level = INFO
filename = /var/log/jitsi-oidc-adapter.log
filemode = a
EOF
    
    # Copy custom body.html
    sudo cp body.html /etc/jitsi/meet/
    
    # Create systemd service
    cat <<EOF | sudo tee /etc/systemd/system/jitsi-oidc-adapter.service
[Unit]
Description=Jitsi OIDC Adapter
After=network.target

[Service]
Type=exec
User=jitsi-meet
Group=jitsi-meet
WorkingDirectory=/opt/jitsi-oidc-adapter
ExecStart=/opt/jitsi-oidc-adapter/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 2 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Create log directory
    sudo mkdir -p /var/log
    sudo touch /var/log/jitsi-oidc-adapter.log
    sudo chown jitsi-meet:jitsi-meet /var/log/jitsi-oidc-adapter.log
    
    # Set ownership
    sudo chown -R jitsi-meet:jitsi-meet /opt/jitsi-oidc-adapter
    
    # Configure Nginx for OIDC endpoints
    echo "🌍 Configuring Nginx for OIDC adapter..."
    
    # Add OIDC location blocks
    sudo sed -i '/server_name '"${FQDN}"';/a\
\
    # OIDC Authentication endpoints\
    location /oidc/ {\
        proxy_pass http://127.0.0.1:8000;\
        proxy_set_header Host $host;\
        proxy_set_header X-Real-IP $remote_addr;\
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\
        proxy_set_header X-Forwarded-Proto $scheme;\
        proxy_buffering off;\
    }\
\
    # Custom body.html location\
    location = /body.html {\
        alias /etc/jitsi/meet/body.html;\
    }' /etc/nginx/sites-available/${FQDN}.conf
    
    # Enable and start the service
    sudo systemctl daemon-reload
    sudo systemctl enable jitsi-oidc-adapter
    sudo systemctl start jitsi-oidc-adapter
fi

# Update Jitsi Meet configuration for JWT authentication
echo "🌐 Configuring Jitsi Meet for JWT authentication..."

# Enable JWT authentication in Jitsi config
sudo sed -i '/var config = {/a\
    // JWT Authentication\
    authentication: {\
        enabled: true,\
        type: "JWT"\
    },\
    \
    // Enable moderator features\
    requireAuthentication: true,\
    \
    // Lobby configuration\
    lobby: {\
        enabled: true,\
        autoKnock: false\
    },' /etc/jitsi/meet/${FQDN}-config.js

# Test configurations
echo "🧪 Testing configurations..."
sudo nginx -t

# Restart services
echo "🔄 Restarting services..."
sudo systemctl restart nginx

if [[ "$APPROACH" == "prosody" ]]; then
    sudo systemctl restart prosody
    sudo systemctl restart jicofo
    sudo systemctl restart jitsi-videobridge2
fi

# Wait for services to start
sleep 10

# Verify services are running
echo "✅ Verifying services..."
for service in nginx; do
    if sudo systemctl is-active --quiet $service; then
        echo "✅ $service is running"
    else
        echo "❌ $service is not running"
        sudo systemctl status $service
    fi
done

if [[ "$APPROACH" == "adapter" ]]; then
    if sudo systemctl is-active --quiet jitsi-oidc-adapter; then
        echo "✅ jitsi-oidc-adapter is running"
    else
        echo "❌ jitsi-oidc-adapter is not running"
        sudo systemctl status jitsi-oidc-adapter
    fi
fi

if [[ "$APPROACH" == "prosody" ]]; then
    for service in prosody jicofo jitsi-videobridge2; do
        if sudo systemctl is-active --quiet $service; then
            echo "✅ $service is running"
        else
            echo "❌ $service is not running"
            sudo systemctl status $service
        fi
    done
fi

echo ""
echo "🎉 OIDC authentication setup complete using $APPROACH approach!"
echo ""
echo "📋 Next steps:"
echo "1. Configure your OIDC provider with these settings:"
if [[ "$APPROACH" == "adapter" ]]; then
    echo "   - Redirect URI: https://${FQDN}/oidc/redirect"
else
    echo "   - Redirect URI: https://${FQDN}/_prosody-auth-oidc/redirect"
fi
echo "   - Client ID: ${OIDC_CLIENT_ID}"
echo "   - Allowed origins: https://${FQDN}"
echo ""
echo "2. Test authentication by visiting: https://${FQDN}"
echo ""
echo "3. Check logs if issues occur:"
echo "   - Nginx: sudo tail -f /var/log/nginx/error.log"
if [[ "$APPROACH" == "adapter" ]]; then
    echo "   - OIDC Adapter: sudo journalctl -u jitsi-oidc-adapter -f"
    echo "   - OIDC Adapter logs: sudo tail -f /var/log/jitsi-oidc-adapter.log"
else
    echo "   - Prosody: sudo journalctl -u prosody -f"
    echo "   - Jicofo: sudo journalctl -u jicofo -f"
fi
echo ""
echo "📁 Configuration backups saved with .backup extension"
echo ""
if [[ "$APPROACH" == "adapter" ]]; then
    echo "💡 The OIDC Adapter approach is recommended as it:"
    echo "   - Uses stable JWT authentication (your setup already has PostgreSQL)"
    echo "   - Doesn't require experimental Prosody modules"
    echo "   - Provides better error handling and logging"
    echo "   - Is easier to maintain and debug"
fi