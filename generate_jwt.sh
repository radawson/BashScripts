#!/bin/bash
# Generate a test JWT token for your Jitsi instance

# Read your APP_SECRET from the config file
if [[ -f ~/server_config.txt ]]; then
    APP_SECRET=$(grep "APP_SECRET:" ~/server_config.txt | cut -d: -f2 | tr -d ' ')
    APP_ID=$(grep "APP_ID:" ~/server_config.txt | cut -d: -f2 | tr -d ' ')
    FQDN=$(grep "FQDN:" ~/server_config.txt | cut -d: -f2 | tr -d ' ')
else
    echo "❌ server_config.txt not found. Please provide APP_SECRET manually."
    read -p "Enter your APP_SECRET: " APP_SECRET
    read -p "Enter your APP_ID: " APP_ID
    read -p "Enter your FQDN: " FQDN
fi

# Install Node.js and jsonwebtoken if needed
if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# Create JWT generator script
cat > /tmp/generate_jwt.js << 'EOF'
const crypto = require('crypto');

function generateJWT(appId, appSecret, userEmail, userName, fqdn, roomName = '*') {
    const header = {
        "alg": "HS256",
        "typ": "JWT"
    };
    
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        "iss": appId,
        "aud": appId,
        "exp": now + 3600, // Expires in 1 hour
        "iat": now,
        "sub": fqdn,
        "room": roomName,
        "context": {
            "user": {
                "email": userEmail,
                "name": userName
            }
        }
    };
    
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    const signature = crypto
        .createHmac('sha256', appSecret)
        .update(headerB64 + '.' + payloadB64)
        .digest('base64url');
    
    return headerB64 + '.' + payloadB64 + '.' + signature;
}

const args = process.argv.slice(2);
const [appId, appSecret, userEmail, userName, fqdn, roomName] = args;

if (args.length < 5) {
    console.log('Usage: node generate_jwt.js <APP_ID> <APP_SECRET> <USER_EMAIL> <USER_NAME> <FQDN> [ROOM_NAME]');
    process.exit(1);
}

const jwt = generateJWT(appId, appSecret, userEmail, userName, fqdn, roomName);
console.log('\n🎫 Your JWT Token:');
console.log(jwt);
console.log('\n🌐 Test URL:');
console.log(`https://${fqdn}/testroom?jwt=${jwt}`);
console.log('\n⏰ Token expires in 1 hour');
EOF

# Generate a test token
echo "🎫 Generating test JWT token..."
USER_EMAIL="test@${FQDN#meet.}"
USER_NAME="Test User"
ROOM_NAME="testroom"

node /tmp/generate_jwt.js "$APP_ID" "$APP_SECRET" "$USER_EMAIL" "$USER_NAME" "$FQDN" "$ROOM_NAME"

echo ""
echo "🧪 How to test:"
echo "1. Copy the Test URL above and open it in your browser"
echo "2. You should be able to create and join the room"
echo "3. Share the room link with others (they can join without tokens)"

# Cleanup
rm /tmp/generate_jwt.js