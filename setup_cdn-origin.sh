#!/bin/bash
#v1.1.0
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

# Install Node.js and npm
echo "Installing Node.js and npm"
wait_for_apt

# Download and install nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash

# in lieu of restarting the shell
\. "$HOME/.nvm/nvm.sh"

# Download and install Node.js:
nvm install 22

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

# Create the admin interface files directory
sudo mkdir -p /var/www/admin

# Install Node.js and npm
sudo apt-get update
sudo apt-get install -y nodejs npm

# Create the application directory
sudo mkdir -p /var/www/admin
cd /var/www/admin

# Initialize a new Node.js project
sudo npm init -y

# Install required packages
sudo npm install express express-fileupload morgan cors helmet multer bcrypt jsonwebtoken dotenv

# Create the admin application
sudo tee /var/www/admin/app.js > /dev/null << 'EOF'
const express = require('express');
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs');
const morgan = require('morgan');
const helmet = require('helmet');
const basicAuth = require('./middleware/basicAuth');

const app = express();
const PORT = process.env.PORT || 3000;
const CONTENT_DIR = '/var/www/content';

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload({
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1GB max file size
  abortOnLimit: true,
  useTempFiles: true,
  tempFileDir: '/tmp/',
  createParentPath: true
}));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Routes - All routes require authentication
app.use(basicAuth);

// List files
app.get('/api/list', (req, res) => {
  try {
    let requestPath = req.query.path || '/';
    
    // Normalize path and prevent directory traversal
    requestPath = path.normalize('/' + requestPath.replace(/^\/+/, '')).replace(/\.\.\//g, '');
    const fullPath = path.join(CONTENT_DIR, requestPath);
    
    // Ensure the path is within the content directory
    if (!fullPath.startsWith(CONTENT_DIR)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Check if directory exists
    if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isDirectory()) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    // Read directory contents
    const items = fs.readdirSync(fullPath)
      .filter(item => item !== '.' && item !== '..')
      .map(item => {
        const itemPath = path.join(fullPath, item);
        const stats = fs.statSync(itemPath);
        const isDir = stats.isDirectory();
        
        return {
          name: item,
          is_dir: isDir,
          size: isDir ? 0 : stats.size,
          modified: Math.floor(stats.mtime.getTime() / 1000)
        };
      });
    
    res.json(items);
  } catch (error) {
    console.error('Error listing files:', error);
    res.status(500).json({ error: 'Failed to list files' });
  }
});

// Upload files
app.post('/api/upload', (req, res) => {
  try {
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: 'No files were uploaded' });
    }
    
    let uploadPath = req.body.path || '/';
    
    // Normalize path and prevent directory traversal
    uploadPath = path.normalize('/' + uploadPath.replace(/^\/+/, '')).replace(/\.\.\//g, '');
    const fullPath = path.join(CONTENT_DIR, uploadPath);
    
    // Ensure the path is within the content directory
    if (!fullPath.startsWith(CONTENT_DIR)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
    }
    
    let uploadedFiles = req.files.files;
    if (!Array.isArray(uploadedFiles)) {
      uploadedFiles = [uploadedFiles];
    }
    
    const promises = uploadedFiles.map(file => {
      return new Promise((resolve, reject) => {
        const filePath = path.join(fullPath, file.name);
        
        file.mv(filePath, err => {
          if (err) return reject(err);
          resolve(file.name);
        });
      });
    });
    
    Promise.all(promises)
      .then(fileNames => {
        res.json({ 
          error: false, 
          message: `Successfully uploaded ${fileNames.length} files`,
          files: fileNames
        });
      })
      .catch(err => {
        console.error('Error uploading files:', err);
        res.status(500).json({ error: true, message: 'Failed to upload files' });
      });
  } catch (error) {
    console.error('Error handling upload:', error);
    res.status(500).json({ error: true, message: 'Internal server error' });
  }
});

// Download file
app.get('/api/download', (req, res) => {
  try {
    let requestPath = req.query.path || '';
    
    // Normalize path and prevent directory traversal
    requestPath = path.normalize('/' + requestPath.replace(/^\/+/, '')).replace(/\.\.\//g, '');
    const fullPath = path.join(CONTENT_DIR, requestPath);
    
    // Ensure the path is within the content directory
    if (!fullPath.startsWith(CONTENT_DIR)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Check if file exists
    if (!fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    res.download(fullPath);
  } catch (error) {
    console.error('Error downloading file:', error);
    res.status(500).json({ error: 'Failed to download file' });
  }
});

// Create directory
app.post('/api/mkdir', (req, res) => {
  try {
    const { path: dirPath, name } = req.body;
    
    if (!dirPath || !name) {
      return res.status(400).json({ error: true, message: 'Missing required fields' });
    }
    
    // Normalize path and prevent directory traversal
    const normalizedPath = path.normalize('/' + dirPath.replace(/^\/+/, '')).replace(/\.\.\//g, '');
    const fullPath = path.join(CONTENT_DIR, normalizedPath);
    
    // Ensure the path is within the content directory
    if (!fullPath.startsWith(CONTENT_DIR)) {
      return res.status(403).json({ error: true, message: 'Access denied' });
    }
    
    // Validate directory name
    if (!name || name.includes('/')) {
      return res.status(400).json({ error: true, message: 'Invalid directory name' });
    }
    
    const newDirPath = path.join(fullPath, name);
    
    // Check if directory already exists
    if (fs.existsSync(newDirPath)) {
      return res.status(409).json({ error: true, message: 'Directory already exists' });
    }
    
    fs.mkdirSync(newDirPath, { recursive: true });
    res.json({ error: false, message: 'Directory created' });
  } catch (error) {
    console.error('Error creating directory:', error);
    res.status(500).json({ error: true, message: 'Failed to create directory' });
  }
});

// Delete file/directory
app.post('/api/delete', (req, res) => {
  try {
    const { path: filePath } = req.body;
    
    if (!filePath) {
      return res.status(400).json({ error: true, message: 'Missing path parameter' });
    }
    
    // Normalize path and prevent directory traversal
    const normalizedPath = path.normalize('/' + filePath.replace(/^\/+/, '')).replace(/\.\.\//g, '');
    const fullPath = path.join(CONTENT_DIR, normalizedPath);
    
    // Ensure the path is within the content directory
    if (!fullPath.startsWith(CONTENT_DIR)) {
      return res.status(403).json({ error: true, message: 'Access denied' });
    }
    
    // Check if file/directory exists
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: true, message: 'File or directory not found' });
    }
    
    const isDir = fs.statSync(fullPath).isDirectory();
    
    if (isDir) {
      fs.rmdirSync(fullPath, { recursive: true });
    } else {
      fs.unlinkSync(fullPath);
    }
    
    res.json({ 
      error: false, 
      message: isDir ? 'Directory deleted' : 'File deleted' 
    });
  } catch (error) {
    console.error('Error deleting file/directory:', error);
    res.status(500).json({ error: true, message: 'Failed to delete file/directory' });
  }
});

// Rename file/directory
app.post('/api/rename', (req, res) => {
  try {
    const { path: filePath, newName } = req.body;
    
    if (!filePath || !newName) {
      return res.status(400).json({ error: true, message: 'Missing required parameters' });
    }
    
    // Normalize path and prevent directory traversal
    const normalizedPath = path.normalize('/' + filePath.replace(/^\/+/, '')).replace(/\.\.\//g, '');
    const fullPath = path.join(CONTENT_DIR, normalizedPath);
    
    // Ensure the path is within the content directory
    if (!fullPath.startsWith(CONTENT_DIR)) {
      return res.status(403).json({ error: true, message: 'Access denied' });
    }
    
    // Check if file exists
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: true, message: 'File not found' });
    }
    
    // Validate new name
    if (!newName || newName.includes('/')) {
      return res.status(400).json({ error: true, message: 'Invalid file name' });
    }
    
    // Get directory and build new path
    const dirname = path.dirname(fullPath);
    const newPath = path.join(dirname, newName);
    
    // Check if destination already exists
    if (fs.existsSync(newPath)) {
      return res.status(409).json({ error: true, message: 'A file with this name already exists' });
    }
    
    fs.renameSync(fullPath, newPath);
    res.json({ error: false, message: 'File renamed' });
  } catch (error) {
    console.error('Error renaming file:', error);
    res.status(500).json({ error: true, message: 'Failed to rename file' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
EOF

# Create basic auth middleware
sudo mkdir -p /var/www/admin/middleware
sudo tee /var/www/admin/middleware/basicAuth.js > /dev/null << 'EOF'
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Store credentials in a file
const CREDENTIALS_FILE = path.join(__dirname, '../config/credentials.json');

// Function to verify credentials
function verifyCredentials(username, password) {
  try {
    if (!fs.existsSync(CREDENTIALS_FILE)) {
      // If file doesn't exist, create with default admin/admin
      const defaultHash = crypto.createHash('sha256').update('admin').digest('hex');
      const credentials = {
        admin: defaultHash
      };
      
      // Create directory if it doesn't exist
      const configDir = path.dirname(CREDENTIALS_FILE);
      if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true });
      }
      
      fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(credentials, null, 2));
      console.log('Created default credentials file');
    }
    
    const credentialsRaw = fs.readFileSync(CREDENTIALS_FILE);
    const credentials = JSON.parse(credentialsRaw);
    
    // Hash the provided password
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    
    // Check if username exists and password matches
    return credentials[username] === hash;
  } catch (error) {
    console.error('Error verifying credentials:', error);
    return false;
  }
}

module.exports = (req, res, next) => {
  // Get authorization header
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="CDN Admin"');
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Decode credentials
  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
  const [username, password] = credentials.split(':');
  
  if (!verifyCredentials(username, password)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="CDN Admin"');
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Authentication successful
  next();
};
EOF

# Create the frontend files
sudo mkdir -p /var/www/admin/public
sudo tee /var/www/admin/public/index.html > /dev/null << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CDN Origin Admin Console</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <header class="d-flex justify-content-between align-items-center pb-3 mb-4 border-bottom">
            <h1 class="fw-bold">CDN Origin Admin Console</h1>
            <span class="badge bg-primary">Node.js v1.0</span>
        </header>

        <div class="row">
            <div class="col-md-12">
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">File Manager</h5>
                        <button id="refresh-btn" class="btn btn-sm btn-outline-secondary">Refresh</button>
                    </div>
                    <div class="card-body">
                        <div class="current-path" id="current-path">/</div>
                        
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb" id="path-breadcrumb">
                                <li class="breadcrumb-item active" data-path="/">Root</li>
                            </ol>
                        </nav>
                        
                        <div class="file-list" id="file-list">
                            <div class="text-center p-5">
                                <div class="spinner-border text-primary" role="status">
                                    <span class="visually-hidden">Loading...</span>
                                </div>
                                <p class="mt-2">Loading files...</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Upload Files</h5>
                    </div>
                    <div class="card-body">
                        <form id="upload-form">
                            <div class="mb-3">
                                <label for="file-upload" class="form-label">Select files to upload</label>
                                <input class="form-control" type="file" id="file-upload" multiple>
                            </div>
                            <button type="submit" class="btn btn-primary">Upload Files</button>
                            
                            <div id="upload-progress" class="mt-3">
                                <div class="progress">
                                    <div id="upload-progress-bar" class="progress-bar" role="progressbar" style="width: 0%"></div>
                                </div>
                                <small id="upload-status" class="text-muted mt-1">Preparing upload...</small>
                            </div>
                        </form>
                    </div>
                </div>
                
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Create Directory</h5>
                    </div>
                    <div class="card-body">
                        <form id="mkdir-form" class="d-flex">
                            <input type="text" class="form-control me-2" id="new-dir-name" placeholder="Directory name">
                            <button type="submit" class="btn btn-success">Create</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modal for file operations -->
    <div class="modal fade" id="file-modal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="file-modal-title">File Operations</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p id="file-modal-path"></p>
                    <div class="d-grid gap-2">
                        <button id="btn-download" class="btn btn-primary">Download</button>
                        <button id="btn-rename" class="btn btn-warning">Rename</button>
                        <button id="btn-delete" class="btn btn-danger">Delete</button>
                    </div>
                    
                    <div id="rename-form-container" class="mt-3" style="display:none;">
                        <form id="rename-form">
                            <div class="mb-3">
                                <label for="new-name" class="form-label">New name</label>
                                <input type="text" class="form-control" id="new-name">
                            </div>
                            <button type="submit" class="btn btn-success">Save</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script src="app.js"></script>
</body>
</html>
EOF

# Create the CSS file
sudo tee /var/www/admin/public/styles.css > /dev/null << 'EOF'
body {
    padding-top: 20px;
    padding-bottom: 40px;
}
.file-list {
    max-height: 600px;
    overflow-y: auto;
}
.breadcrumb-item {
    cursor: pointer;
}
.file-entry {
    cursor: pointer;
    padding: 8px;
    border-bottom: 1px solid #eee;
    display: flex;
    align-items: center;
}
.file-entry:hover {
    background-color: #f8f9fa;
}
.file-icon {
    width: 24px;
    margin-right: 10px;
}
.file-actions {
    margin-left: auto;
}
.current-path {
    font-family: monospace;
    padding: 8px;
    background-color: #f8f9fa;
    border-radius: 4px;
    margin-bottom: 16px;
}
#upload-progress {
    display: none;
    margin-top: 10px;
}
EOF

# Create the JavaScript file
sudo tee /var/www/admin/public/app.js > /dev/null << 'EOF'
// Global variables
let currentPath = '/';
let selectedFile = null;
let fileModal = null;

// Helper function to format file sizes
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Helper function to get file icon
function getFileIcon(item) {
    if (item.is_dir) return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-folder" viewBox="0 0 16 16"><path d="M.54 3.87.5 3a2 2 0 0 1 2-2h3.672a2 2 0 0 1 1.414.586l.828.828A2 2 0 0 0 9.828 3h3.982a2 2 0 0 1 1.992 2.181l-.637 7A2 2 0 0 1 13.174 14H2.826a2 2 0 0 1-1.991-1.819l-.637-7a1.99 1.99 0 0 1 .342-1.31zM2.19 4a1 1 0 0 0-.996 1.09l.637 7a1 1 0 0 0 .995.91h10.348a1 1 0 0 0 .995-.91l.637-7A1 1 0 0 0 13.81 4H2.19zm4.69-1.707A1 1 0 0 0 6.172 2H2.5a1 1 0 0 0-1 .981l.006.139C1.72 3.042 1.95 3 2.19 3h5.396l-.707-.707z"/></svg>';
    
    const ext = item.name.split('.').pop().toLowerCase();
    const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'];
    const textExts = ['txt', 'md', 'html', 'css', 'js', 'json', 'xml'];
    const docExts = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'];
    
    if (imageExts.includes(ext)) {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-image" viewBox="0 0 16 16"><path d="M8.002 5.5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z"/><path d="M12 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2zM3 2a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v8l-2.083-2.083a.5.5 0 0 0-.76.063L8 11 5.835 9.7a.5.5 0 0 0-.611.076L3 12V2z"/></svg>';
    } else if (textExts.includes(ext)) {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-text" viewBox="0 0 16 16"><path d="M5 4a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1H5zm-.5 2.5A.5.5 0 0 1 5 6h6a.5.5 0 0 1 0 1H5a.5.5 0 0 1-.5-.5zM5 8a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1H5zm0 2a.5.5 0 0 0 0 1h3a.5.5 0 0 0 0-1H5z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2zm10-1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1z"/></svg>';
    } else if (docExts.includes(ext)) {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-earmark-text" viewBox="0 0 16 16"><path d="M5.5 7a.5.5 0 0 0 0 1h5a.5.5 0 0 0 0-1h-5zM5 9.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm0 2a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1h-2a.5.5 0 0 1-.5-.5z"/><path d="M9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V4.5L9.5 0zm0 1v2A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5z"/></svg>';
    } else {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file" viewBox="0 0 16 16"><path d="M4 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H4zm0 1h8a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1z"/></svg>';
    }
}

// Load files from the server
async function loadFiles(path) {
    try {
        const response = await fetch(`/api/list?path=${encodeURIComponent(path)}`);
        if (!response.ok) throw new Error('Failed to load files');
        
        const data = await response.json();
        
        // Update current path
        currentPath = path;
        document.getElementById('current-path').textContent = path;
        
        // Update breadcrumb
        updateBreadcrumb(path);
        
        // Render file list
        const fileList = document.getElementById('file-list');
        
        if (data.length === 0) {
            fileList.innerHTML = '<div class="text-center p-5">This directory is empty</div>';
            return;
        }
        
        // Sort: directories first, then files alphabetically
        data.sort((a, b) => {
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            return a.name.localeCompare(b.name);
        });
        
        let html = '';
        data.forEach(item => {
            html += `
                <div class="file-entry" data-path="${path}${item.name}${item.is_dir ? '/' : ''}" data-is-dir="${item.is_dir}">
                    <div class="file-icon">${getFileIcon(item)}</div>
                    <div>
                        <div>${item.name}${item.is_dir ? '/' : ''}</div>
                        <small class="text-muted">${item.is_dir ? 'Directory' : formatBytes(item.size)} · ${new Date(item.modified * 1000).toLocaleString()}</small>
                    </div>
                    <div class="file-actions">
                        ${!item.is_dir ? `<button class="btn btn-sm btn-outline-primary download-btn" data-path="${path}${item.name}">Download</button>` : ''}
                    </div>
                </div>
            `;
        });
        
        fileList.innerHTML = html;
        
        // Add event listeners to file entries
        document.querySelectorAll('.file-entry').forEach(entry => {
            entry.addEventListener('click', function(e) {
                if (e.target.classList.contains('download-btn')) return; // Don't handle if clicked on download button
                
                const path = this.getAttribute('data-path');
                const isDir = this.getAttribute('data-is-dir') === 'true';
                
                if (isDir) {
                    loadFiles(path);
                } else {
                    // Show file operations modal
                    selectedFile = path;
                    document.getElementById('file-modal-path').textContent = path;
                    document.getElementById('file-modal-title').textContent = path.split('/').pop();
                    fileModal.show();
                }
            });
        });
        
        // Add event listeners to download buttons
        document.querySelectorAll('.download-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const path = this.getAttribute('data-path');
                window.location.href = `/api/download?path=${encodeURIComponent(path)}`;
            });
        });
        
    } catch (error) {
        console.error('Error loading files:', error);
        document.getElementById('file-list').innerHTML = 
            `<div class="alert alert-danger" role="alert">
                Failed to load files: ${error.message}
            </div>`;
    }
}

// Update breadcrumb based on current path
function updateBreadcrumb(path) {
    const parts = path.split('/').filter(Boolean);
    const breadcrumb = document.getElementById('path-breadcrumb');
    
    // Clear existing items except Root
    while (breadcrumb.children.length > 1) {
        breadcrumb.removeChild(breadcrumb.lastChild);
    }
    
    // Reset Root as active if we're at the root
    if (path === '/') {
        breadcrumb.firstChild.classList.add('active');
    } else {
        breadcrumb.firstChild.classList.remove('active');
    }
    
    // Add parts
    let currentPath = '/';
    parts.forEach((part, index) => {
        currentPath += part + '/';
        
        const li = document.createElement('li');
        li.className = 'breadcrumb-item';
        li.setAttribute('data-path', currentPath);
        li.textContent = part;
        
        // Set the last item as active
        if (index === parts.length - 1) {
            li.classList.add('active');
        }
        
        breadcrumb.appendChild(li);
    });
    
    // Add click event to breadcrumb items
    document.querySelectorAll('#path-breadcrumb .breadcrumb-item').forEach(item => {
        item.addEventListener('click', function() {
            const path = this.getAttribute('data-path');
            loadFiles(path);
        });
    });
}

// Create directory function
async function createDirectory(dirName) {
    try {
        const response = await fetch('/api/mkdir', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                path: currentPath,
                name: dirName
            }),
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to create directory');
        }
        
        // Reload files
        loadFiles(currentPath);
        return true;
    } catch (error) {
        console.error('Error creating directory:', error);
        alert(`Failed to create directory: ${error.message}`);
        return false;
    }
}

// Delete file function
async function deleteFile(path) {
    try {
        const response = await fetch('/api/delete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ path }),
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to delete file');
        }
        
        // Reload files
        loadFiles(currentPath);
        return true;
    } catch (error) {
        console.error('Error deleting file:', error);
        alert(`Failed to delete file: ${error.message}`);
        return false;
    }
}

// Rename file function
async function renameFile(path, newName) {
    try {
        const response = await fetch('/api/rename', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                path,
                newName
            }),
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to rename file');
        }
        
        // Reload files
        loadFiles(currentPath);
        return true;
    } catch (error) {
        console.error('Error renaming file:', error);
        alert(`Failed to rename file: ${error.message}`);
        return false;
    }
}

// On page load
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Bootstrap modal
    fileModal = new bootstrap.Modal(document.getElementById('file-modal'));
    
    // Load initial files
    loadFiles('/');
    
    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', () => {
        loadFiles(currentPath);
    });
    
    // Upload form
    document.getElementById('upload-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const fileInput = document.getElementById('file-upload');
        if (fileInput.files.length === 0) {
            alert('Please select at least one file to upload');
            return;
        }
        
        const formData = new FormData();
        for (const file of fileInput.files) {
            formData.append('files', file);
        }
        formData.append('path', currentPath);
        
        // Show progress
        const progressContainer = document.getElementById('upload-progress');
        const progressBar = document.getElementById('upload-progress-bar');
        const statusText = document.getElementById('upload-status');
        
        progressContainer.style.display = 'block';
        progressBar.style.width = '0%';
        statusText.textContent = 'Starting upload...';
        
        try {
            const xhr = new XMLHttpRequest();
            
            xhr.open('POST', '/api/upload', true);
            
            xhr.upload.onprogress = function(e) {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    progressBar.style.width = percent + '%';
                    statusText.textContent = `Uploading: ${percent}%`;
                }
            };
            
            xhr.onload = function() {
                if (xhr.status === 200) {
                    statusText.textContent = 'Upload completed successfully!';
                    fileInput.value = '';
                    loadFiles(currentPath);
                    
                    // Hide progress after a delay
                    setTimeout(() => {
                        progressContainer.style.display = 'none';
                    }, 3000);
                } else {
                    try {
                        const response = JSON.parse(xhr.responseText);
                        statusText.textContent = `Error: ${response.message || 'Upload failed'}`;
                    } catch (e) {
                        statusText.textContent = 'Error: Upload failed';
                    }
                }
            };
            
            xhr.onerror = function() {
                statusText.textContent = 'Error: Connection failed';
            };
            
            xhr.send(formData);
            
        } catch (error) {
            console.error('Error uploading files:', error);
            statusText.textContent = `Error: ${error.message}`;
        }
    });
    
    // Create directory form
    document.getElementById('mkdir-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const dirNameInput = document.getElementById('new-dir-name');
        const dirName = dirNameInput.value.trim();
        
        if (!dirName) {
            alert('Please enter a directory name');
            return;
        }
        
        createDirectory(dirName).then(success => {
            if (success) {
                dirNameInput.value = '';
            }
        });
    });
    
    // File operations
    document.getElementById('btn-download').addEventListener('click', function() {
        window.location.href = `/api/download?path=${encodeURIComponent(selectedFile)}`;
    });
    
    document.getElementById('btn-delete').addEventListener('click', function() {
        if (confirm('Are you sure you want to delete this file?')) {
            deleteFile(selectedFile).then(success => {
                if (success) {
                    fileModal.hide();
                }
            });
        }
    });
    
    document.getElementById('btn-rename').addEventListener('click', function() {
        const renameForm = document.getElementById('rename-form-container');
        renameForm.style.display = 'block';
        
        const fileName = selectedFile.split('/').pop();
        document.getElementById('new-name').value = fileName;
    });
    
    document.getElementById('rename-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const newName = document.getElementById('new-name').value.trim();
        if (!newName) {
            alert('Please enter a new name');
            return;
        }
        
        renameFile(selectedFile, newName).then(success => {
            if (success) {
                document.getElementById('rename-form-container').style.display = 'none';
                fileModal.hide();
            }
        });
    });
    
    // Reset rename form when modal is closed
    document.getElementById('file-modal').addEventListener('hidden.bs.modal', function() {
        document.getElementById('rename-form-container').style.display = 'none';
    });
});
EOF

# Create a systemd service file
sudo tee /etc/systemd/system/cdn-admin.service > /dev/null << EOF
[Unit]
Description=CDN Admin Panel
After=network.target

[Service]
ExecStart=/usr/bin/node /var/www/admin/app.js
WorkingDirectory=/var/www/admin
Restart=always
User=www-data
Group=www-data
Environment=PATH=/usr/bin:/usr/local/bin
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Create config directory
sudo mkdir -p /var/www/admin/config

# Set correct permissions
sudo chown -R www-data:www-data /var/www/admin

# Update Nginx configuration for the admin interface
sudo tee -a /etc/nginx/sites-available/${FQDN} > /dev/null << EOF

    # Admin area with Node.js backend
    location /admin {
        auth_basic "Restricted Admin Area";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://localhost:3000/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
EOF

# Create htpasswd file for admin area
sudo apt-get install -y apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin

# Enable systemd service
sudo systemctl enable cdn-admin
sudo systemctl start cdn-admin

# Try to get SSL certificate
echo "Attempting to obtain SSL certificate for ${FQDN}"
sudo certbot certonly --standalone --non-interactive --agree-tos --email admin@${DOMAIN} \
  -d ${FQDN} --preferred-challenges http-01

# Enhance NGINX config for fast transfers
echo "Creating enhanced NGINX configuration for fast transfers"
sudo tee -a /etc/nginx/conf.d/file-transfer-optimizations.conf > /dev/null << 'EOF'
# Optimizations for large file transfers
sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 65;
types_hash_max_size 2048;

# File upload optimizations
client_max_body_size 1024M;
client_body_buffer_size 128k;
client_body_timeout 300s;
client_header_timeout 300s;

# FastCGI optimizations
fastcgi_buffers 8 16k;
fastcgi_buffer_size 32k;
fastcgi_connect_timeout 300s;
fastcgi_send_timeout 300s;
fastcgi_read_timeout 300s;
EOF

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

        // Detect browser 
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