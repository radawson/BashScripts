#!/bin/bash
#
# Script to add OIDC authentication to existing Jitsi Meet installation
# Run this after your initial Jitsi setup is complete
# v1.0.0

# Stop on errors
set -Eeuo pipefail
trap 'echo "❌  error in $BASH_SOURCE:$LINENO: $BASH_COMMAND"' ERR

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 <DNS DOMAIN> <OIDC PROVIDER> <client-id> <client-secret>"
    echo "Example: $0 meet.example.com sso.example.com meet-ex 1q2w3e4r"
    echo "meet. will be added to the domain"
    exit 1
fi

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

# Function to wait for apt locks
wait_for_apt() {
    while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 || sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        echo "Waiting for apt locks to be released..."
        sleep 5
    done
}

# Install required packages
echo "📦 Installing required packages..."
wait_for_apt
sudo apt-get update
sudo apt-get install -y lua-cjson prosody-modules

# Backup existing configurations
echo "💾 Creating configuration backups..."
sudo cp /etc/prosody/conf.avail/${FQDN}.cfg.lua /etc/prosody/conf.avail/${FQDN}.cfg.lua.backup
sudo cp /etc/jitsi/meet/${FQDN}-config.js /etc/jitsi/meet/${FQDN}-config.js.backup
sudo cp /etc/jitsi/jicofo/jicofo.conf /etc/jitsi/jicofo/jicofo.conf.backup

# Configure Prosody for OIDC
echo "🔐 Configuring Prosody for OIDC authentication..."

# Create OIDC configuration for Prosody
cat <<EOF | sudo tee /etc/prosody/conf.d/95-oidc-auth.cfg.lua
-- OIDC Authentication Configuration
local json = require "util.json"

oidc_issuer = "${OIDC_ISSUER}"
oidc_client_id = "${OIDC_CLIENT_ID}"
oidc_client_secret = "${OIDC_CLIENT_SECRET}"
oidc_redirect_uri = "https://${FQDN}/_prosody-auth-oidc/redirect"

-- OIDC Discovery (automatically fetch configuration)
oidc_discovery_url = "${OIDC_PROVIDER_URL}/.well-known/openid-configuration"

-- Token validation
oidc_token_endpoint = "${OIDC_PROVIDER_URL}/oauth2/token"
oidc_authorization_endpoint = "${OIDC_PROVIDER_URL}/oauth2/auth"
oidc_userinfo_endpoint = "${OIDC_PROVIDER_URL}/oauth2/userinfo"

-- User mapping (adjust based on your OIDC provider's claims)
oidc_username_field = "preferred_username"  -- or "email", "sub", etc.
oidc_displayname_field = "name"
EOF

# Update main Prosody configuration for the domain
echo "📝 Updating Prosody domain configuration..."

# Remove the old authentication line and add OIDC
sudo sed -i '/authentication.*=.*"internal_hashed"/d' /etc/prosody/conf.avail/${FQDN}.cfg.lua

# Add OIDC authentication configuration to the main domain
cat <<EOF | sudo tee -a /etc/prosody/conf.avail/${FQDN}.cfg.lua

-- OIDC Authentication
authentication = "oidc"
oidc_issuer = "${OIDC_ISSUER}"
oidc_client_id = "${OIDC_CLIENT_ID}"
oidc_client_secret = "${OIDC_CLIENT_SECRET}"
oidc_redirect_uri = "https://${FQDN}/_prosody-auth-oidc/redirect"

-- Required modules for OIDC
modules_enabled = {
    -- Core modules
    "roster";
    "saslauth";
    "tls";
    "dialback";
    "disco";
    "posix";
    "private";
    "vcard4";
    "vcard_legacy";
    "version";
    "uptime";
    "time";
    "ping";
    "pep";
    "register";
    "admin_adhoc";
    
    -- Jitsi modules
    "bosh";
    "pubsub";
    "ping";
    "speakerstats";
    "conference_duration";
    "end_conference";
    "external_services";
    
    -- OIDC modules
    "http";
    "http_files";
    "auth_oidc";
}

-- HTTP configuration for OIDC callbacks
http_paths = {
    ["_prosody-auth-oidc"] = "/usr/lib/prosody/modules/mod_auth_oidc/http.lua";
}

-- Enable secure HTTP
https_ports = { 5281 }
http_ports = { 5280 }

-- Cross-domain configuration for OIDC
cross_domain_bosh = true
cross_domain_websocket = true

EOF

# Configure Jitsi Meet frontend for OIDC
echo "🌐 Configuring Jitsi Meet frontend..."

# Update Jitsi Meet configuration
sudo tee /tmp/jitsi-oidc-config.js > /dev/null <<EOF
// OIDC Authentication Configuration
config.authentication = {
    enabled: true,
    type: 'XMPP'
};

// Enable authentication for all meetings
config.hosts = {
    domain: '${FQDN}',
    anonymousdomain: 'guest.${FQDN}',
    authdomain: '${FQDN}',
    muc: 'conference.${FQDN}',
    focus: 'focus.${FQDN}'
};

// OIDC specific configuration
config.oidc = {
    enabled: true,
    issuer: '${OIDC_ISSUER}',
    clientId: '${OIDC_CLIENT_ID}',
    redirectUri: 'https://${FQDN}/_prosody-auth-oidc/redirect',
    scope: 'openid profile email',
    responseType: 'code',
    prompt: 'login'
};

// Enable lobby for unauthenticated users
config.lobby = {
    enabled: true,
    autoKnock: false
};

// Require authentication to create meetings
config.requireAuthentication = true;

EOF

# Merge the OIDC configuration with existing config
echo "// OIDC Configuration - Added by setup script" | sudo tee -a /etc/jitsi/meet/${FQDN}-config.js
cat /tmp/jitsi-oidc-config.js | sudo tee -a /etc/jitsi/meet/${FQDN}-config.js
rm /tmp/jitsi-oidc-config.js

# Update Jicofo configuration
echo "⚙️  Configuring Jicofo for OIDC..."

cat <<EOF | sudo tee -a /etc/jitsi/jicofo/jicofo.conf

# OIDC Authentication configuration
authentication: {
  enabled: true
  type: XMPP
  login-url: https://${FQDN}
}

# Enable lobby for authenticated meetings
lobby: {
  enabled: true
}

# Conference configuration
conference: {
  enable-auto-owner: false
  auto-owner-pattern: "@${FQDN}"
}

EOF

# Configure nginx for OIDC callbacks
echo "🌍 Configuring Nginx for OIDC..."

# Add OIDC location blocks to nginx configuration
sudo tee /tmp/nginx-oidc.conf > /dev/null <<EOF
    # OIDC Authentication endpoints
    location /_prosody-auth-oidc/ {
        proxy_pass http://127.0.0.1:5280/_prosody-auth-oidc/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }

    # Prosody BOSH endpoint for authenticated connections
    location /http-bind {
        proxy_pass http://127.0.0.1:5280/http-bind;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }

EOF

# Insert OIDC configuration into existing nginx config
sudo sed -i '/location.*\/.*{/r /tmp/nginx-oidc.conf' /etc/nginx/sites-available/${FQDN}.conf
rm /tmp/nginx-oidc.conf

# Install prosody OIDC module if not already present
echo "📋 Installing Prosody OIDC module..."
if [ ! -f /usr/lib/prosody/modules/mod_auth_oidc.lua ]; then
    cd /tmp
    wget https://hg.prosody.im/prosody-modules/raw-file/tip/mod_auth_oidc/mod_auth_oidc.lua
    sudo mkdir -p /usr/lib/prosody/modules/mod_auth_oidc/
    sudo mv mod_auth_oidc.lua /usr/lib/prosody/modules/mod_auth_oidc/
    sudo chown -R prosody:prosody /usr/lib/prosody/modules/mod_auth_oidc/
fi

# Set proper permissions
echo "🔒 Setting proper permissions..."
sudo chown -R prosody:prosody /etc/prosody/conf.d/
sudo chmod 640 /etc/prosody/conf.d/95-oidc-auth.cfg.lua

# Test configurations
echo "🧪 Testing configurations..."
sudo prosodyctl check config
sudo nginx -t

# Restart services
echo "🔄 Restarting services..."
sudo systemctl restart prosody
sudo systemctl restart nginx
sudo systemctl restart jicofo
sudo systemctl restart jitsi-videobridge2

# Wait for services to start
sleep 10

# Verify services are running
echo "✅ Verifying services..."
for service in prosody nginx jicofo jitsi-videobridge2; do
    if sudo systemctl is-active --quiet $service; then
        echo "✅ $service is running"
    else
        echo "❌ $service is not running"
        sudo systemctl status $service
    fi
done

echo ""
echo "🎉 OIDC authentication setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Configure your OIDC provider with these settings:"
echo "   - Redirect URI: https://${FQDN}/_prosody-auth-oidc/redirect"
echo "   - Client ID: ${OIDC_CLIENT_ID}"
echo "   - Allowed origins: https://${FQDN}"
echo ""
echo "2. Test authentication by visiting: https://${FQDN}"
echo ""
echo "3. Check logs if issues occur:"
echo "   - Prosody: sudo journalctl -u prosody -f"
echo "   - Jicofo: sudo journalctl -u jicofo -f"
echo "   - Nginx: sudo tail -f /var/log/nginx/error.log"
echo ""
echo "📁 Configuration backups saved with .backup extension"