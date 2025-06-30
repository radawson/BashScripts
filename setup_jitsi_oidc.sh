#!/bin/bash
#
# Script to add OIDC authentication to existing Jitsi Meet installation
# Run this after your initial Jitsi setup is complete
# PREREQUISITE: JWT authentication must be enabled first (run the JWT script)
# This script provides two approaches: Prosody Community Modules or OIDC Adapter
# v1.0.11

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

# Auto-detect JWT secret from Prosody config (or set manually)
JWT_SECRET=$(sudo grep "app_secret" /etc/prosody/conf.avail/$(hostname -f).cfg.lua 2>/dev/null | sed 's/.*app_secret = "\([^"]*\)".*/\1/' || echo "")

# Choose approach: "prosody" or "adapter"
APPROACH="adapter"  # Recommended: more stable and easier to maintain

echo "🔧 Adding OIDC authentication to Jitsi Meet at $FQDN using $APPROACH approach"

# Check if JWT is already configured
if [[ -z "$JWT_SECRET" ]]; then
    echo "❌ JWT authentication is not configured yet!"
    echo "   Please run the JWT enablement script first:"
    echo "   1. Save and run the 'Enable JWT Authentication' script"
    echo "   2. Then return to run this OIDC script"
    echo ""
    echo "   Or manually set JWT_SECRET variable if you know your app_secret"
    exit 1
fi

echo "✅ Found JWT secret: ${JWT_SECRET:0:8}..." # Show first 8 chars only

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
    sudo apt-get install -y python3 python3-pip git python3-venv gunicorn
    
    # Stage 2: Now add JWT tokens (modifies existing Prosody config)
    echo "Stage 2: Adding JWT authentication..."
    sudo debconf-set-selections <<EOF
    jitsi-meet-tokens jitsi-meet-tokens/app-id string ${APP_ID}
    jitsi-meet-tokens jitsi-meet-tokens/app-secret string ${APP_SECRET}
    EOF

    # Verify settings
    echo "Verifying debconf settings were applied:"
    sudo debconf-show jitsi-meet-tokens | grep -E "(app-id|app-secret)" | tee ~/jwt.txt

    sudo DEBIAN_FRONTEND=noninteractive apt-get -y install jitsi-meet-tokens

    # Stage 3: Add remaining components
    echo "Stage 3: Installing additional components..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y install \
        jitsi-meet-turnserver \
        lua-dbi-postgresql \
        lua-cjson \
        lua-zlib



    # Create application directory
    sudo mkdir -p /opt/jitsi-oidc-adapter
    cd /opt/jitsi-oidc-adapter
    
    # Try multiple OIDC adapter repositories (with fallback)
    echo "📥 Attempting to clone OIDC adapter..."
    if sudo git clone https://github.com/nordeck/jitsi-oidc-adapter.git . 2>/dev/null; then
        echo "✅ Successfully cloned nordeck/jitsi-oidc-adapter"
    elif sudo git clone https://github.com/jitsi-contrib/jitsi-oidc-adapter.git . 2>/dev/null; then
        echo "✅ Successfully cloned jitsi-contrib/jitsi-oidc-adapter"
    else
        echo "⚠️  Could not clone adapter, creating minimal implementation..."
        # Create a minimal OIDC adapter if git repos are unavailable
        cat <<'EOFPYTHON' | sudo tee app.py
#!/usr/bin/env python3
import os
import jwt
import time
import requests
from flask import Flask, request, redirect, session, jsonify
from urllib.parse import urlencode
import logging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key')

# Configuration
OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID')
OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET') 
OIDC_ISSUER = os.environ.get('OIDC_ISSUER')
JWT_SECRET = os.environ.get('JWT_SECRET')
JITSI_DOMAIN = os.environ.get('JITSI_DOMAIN')

@app.route('/oidc/login')
def login():
    auth_url = f"{OIDC_ISSUER}/auth?" + urlencode({
        'client_id': OIDC_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': f'https://{JITSI_DOMAIN}/oidc/redirect'
    })
    return redirect(auth_url)

@app.route('/oidc/redirect')
def redirect_handler():
    code = request.args.get('code')
    if not code:
        return 'Authorization failed', 400
    
    # Exchange code for token
    token_response = requests.post(f"{OIDC_ISSUER}/token", data={
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': OIDC_CLIENT_ID,
        'client_secret': OIDC_CLIENT_SECRET,
        'redirect_uri': f'https://{JITSI_DOMAIN}/oidc/redirect'
    })
    
    if token_response.status_code != 200:
        return 'Token exchange failed', 400
    
    tokens = token_response.json()
    
    # Get user info
    userinfo_response = requests.get(f"{OIDC_ISSUER}/userinfo", 
                                   headers={'Authorization': f"Bearer {tokens['access_token']}"})
    
    if userinfo_response.status_code != 200:
        return 'Failed to get user info', 400
    
    userinfo = userinfo_response.json()
    
    # Generate JWT for Jitsi
    payload = {
        'iss': JITSI_DOMAIN,
        'aud': JITSI_DOMAIN,
        'sub': JITSI_DOMAIN,
        'room': '*',
        'exp': int(time.time()) + 3600,
        'context': {
            'user': {
                'name': userinfo.get('name', userinfo.get('email')),
                'email': userinfo.get('email'),
                'id': userinfo.get('sub')
            }
        }
    }
    
    jitsi_token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    
    # Redirect back to Jitsi with token
    return redirect(f'https://{JITSI_DOMAIN}?jwt={jitsi_token}')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000)
EOFPYTHON

        # Create requirements.txt
        cat <<EOF | sudo tee requirements.txt
Flask==2.3.3
PyJWT==2.8.0
requests==2.31.0
gunicorn==21.2.0
EOF
    fi
    
    # Create virtual environment and install dependencies
    sudo python3 -m venv venv
    sudo ./venv/bin/pip install --upgrade pip
    sudo ./venv/bin/pip install -r requirements.txt
    
    # Create configuration file or environment file
    if [ -f "app.conf" ]; then
        # If cloned repo has app.conf template
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
    else
        # Create environment file for minimal implementation
        cat <<EOF | sudo tee .env
OIDC_CLIENT_ID=${OIDC_CLIENT_ID}
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
OIDC_ISSUER=${OIDC_ISSUER}
JWT_SECRET=${JWT_SECRET}
JITSI_DOMAIN=${FQDN}
SECRET_KEY=$(openssl rand -hex 32)
EOF
    fi
    
    # Copy or create custom body.html if it exists
    if [ -f "body.html" ]; then
        sudo cp body.html /etc/jitsi/meet/
    else
        # Create a simple custom body.html
        cat <<EOF | sudo tee /etc/jitsi/meet/body.html
<!DOCTYPE html>
<html>
<head>
    <title>Jitsi Meet Authentication</title>
</head>
<body>
    <h2>Authenticating...</h2>
    <p>Please wait while we redirect you to login...</p>
    <script>
        // Auto-redirect to OIDC login
        window.location.href = '/oidc/login';
    </script>
</body>
</html>
EOF
    fi
    
    # Create systemd service (FIXED: use www-data instead of jitsi-meet)
    cat <<EOF | sudo tee /etc/systemd/system/jitsi-oidc-adapter.service
[Unit]
Description=Jitsi OIDC Adapter
After=network.target

[Service]
Type=exec
User=www-data
Group=www-data
WorkingDirectory=/opt/jitsi-oidc-adapter
Environment=FLASK_APP=app.py
EnvironmentFile=/opt/jitsi-oidc-adapter/.env
ExecStart=/opt/jitsi-oidc-adapter/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 2 app:app
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Create log directory and file
    sudo mkdir -p /var/log
    sudo touch /var/log/jitsi-oidc-adapter.log
    sudo chown www-data:www-data /var/log/jitsi-oidc-adapter.log
    
    # Set ownership (FIXED: use www-data)
    sudo chown -R www-data:www-data /opt/jitsi-oidc-adapter
    
    # Configure Nginx for OIDC endpoints (IMPROVED)
    echo "🌍 Configuring Nginx for OIDC adapter..."
    
    # More robust nginx configuration update
    if ! sudo grep -q "location /oidc/" /etc/nginx/sites-available/${FQDN}.conf; then
        # Add OIDC location blocks before the root location
        sudo sed -i '/location ~ \^\/\[\^\/\]\*\$ {/i\
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
    }\
' /etc/nginx/sites-available/${FQDN}.conf
    fi
    
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
echo "📋 Complete Setup Summary:"
echo "1. ✅ JWT authentication (prerequisite) - DONE"
echo "2. ✅ OIDC integration - DONE"
echo ""
echo "🔗 Next steps:"
echo "1. Configure your OIDC provider with these settings:"
if [[ "$APPROACH" == "adapter" ]]; then
    echo "   - Redirect URI: https://${FQDN}/oidc/redirect"
else
    echo "   - Redirect URI: https://${FQDN}/_prosody-auth-oidc/redirect"
fi
echo "   - Client ID: ${OIDC_CLIENT_ID}"
echo "   - Allowed origins: https://${FQDN}"
echo "   - Required scopes: openid email profile"
echo ""
echo "2. Test the complete flow:"
echo "   - Visit: https://${FQDN}"
echo "   - Click 'I am the host' to trigger OIDC authentication"
echo "   - After OIDC login, you should be able to create rooms"
echo "   - Guests can join rooms without authentication"
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


echo ""
echo "🎉 JWT authentication enabled successfully!"
echo ""
echo "📋 Important notes:"
echo "1. Your JWT credentials are saved in ~/server_config.txt"
echo "2. APP_SECRET is what you'll use as JWT_SECRET in OIDC setup"
echo "3. Meetings now require authentication to CREATE rooms"
echo "4. Guests can still JOIN rooms without authentication"
echo ""
echo "📝 Your JWT credentials:"
echo "   APP_ID: $APP_ID"
echo "   APP_SECRET: $APP_SECRET"
echo ""
echo "🔧 Next steps:"
echo "1. Test that you can still access: https://${FQDN}"
echo "2. Try creating a room (should prompt for authentication)"
echo "3. Now you can proceed with OIDC setup using APP_SECRET above"
echo ""
echo "🛠️  If you encounter issues, check logs:"
echo "   - Prosody: sudo journalctl -u prosody -f"
echo "   - Jicofo: sudo journalctl -u jicofo -f"