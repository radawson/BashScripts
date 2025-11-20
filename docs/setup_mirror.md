# Ubuntu Repository Mirror Setup

This script sets up a local mirror of the Ubuntu package repository using `apt-mirror` and serves it via nginx. This is useful for:

- Reducing bandwidth usage across multiple systems
- Faster package installations on local networks
- Offline package availability
- Network isolation scenarios

## Prerequisites

- Ubuntu/Debian-based system
- Root or sudo access
- Sufficient disk space (Ubuntu repository mirrors can require 100GB+)
- Network connectivity to download the initial mirror

## Installation

Run the script with your domain name:

```bash
sudo ./setup_mirror.sh yourdomain.com
```

**Note:** The script will:

1. Install `apt-mirror` and `nginx`
2. Configure apt-mirror to sync Ubuntu Jammy (22.04) repositories by default
3. Set up nginx to serve the mirror
4. Start the initial mirror sync (this can take several hours)

**For Ubuntu 24.04 (Noble):** After running the script, edit `/etc/apt/mirror.list` and change `jammy` to `noble` before running `apt-mirror`. See the Customization section below.

## Server Configuration

The mirror is stored at: `/var/spool/apt-mirror/mirror/archive.ubuntu.com/ubuntu/`

The nginx server is configured to serve the repository at: `http://mirror.yourdomain.com/ubuntu/`

If you're accessing via IP address (e.g., `10.10.10.20`), the repository will be available at:

- `http://10.10.10.20/ubuntu/`

## Client Configuration

On client machines that will use this mirror, configure apt sources as follows:

**Important:** Replace `10.10.10.20` with your actual mirror server IP address or hostname.

### Ubuntu 24.04 (Noble) - New Format

Ubuntu 24.04 uses a structured sources.list format. Edit `/etc/apt/sources.list`:

```bash
sudo nano /etc/apt/sources.list
```

Replace the contents with:

```text
Types: deb
URIs: http://10.10.10.20/ubuntu/
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://10.10.10.20/ubuntu/
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
```

**Note:** The security updates use the same URI as the main repository when using a local mirror. The script mirrors `jammy-security` from `security.ubuntu.com` into the same mirror structure.

### Ubuntu 22.04 (Jammy) and Earlier - Traditional Format

For Ubuntu 22.04 and earlier versions, use the traditional one-line format:

```bash
sudo nano /etc/apt/sources.list
```

Replace the contents with:

```text
deb http://10.10.10.20/ubuntu jammy main restricted universe multiverse
deb http://10.10.10.20/ubuntu jammy-updates main restricted universe multiverse
deb http://10.10.10.20/ubuntu jammy-backports main restricted universe multiverse
deb http://10.10.10.20/ubuntu jammy-security main restricted universe multiverse
```

### Option 2: Add as additional source (for fallback)

Instead of replacing the main sources.list, you can add the mirror as an additional source:

**For Ubuntu 24.04 (Noble):**

Create `/etc/apt/sources.list.d/local-mirror.sources`:

```bash
sudo nano /etc/apt/sources.list.d/local-mirror.sources
```

Add:

```text
Types: deb
URIs: http://10.10.10.20/ubuntu/
Suites: noble noble-updates noble-backports noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
```

**For Ubuntu 22.04 (Jammy) and earlier:**

Create `/etc/apt/sources.list.d/local-mirror.list`:

```bash
sudo nano /etc/apt/sources.list.d/local-mirror.list
```

Add:

```text
deb http://10.10.10.20/ubuntu jammy main restricted universe multiverse
deb http://10.10.10.20/ubuntu jammy-updates main restricted universe multiverse
deb http://10.10.10.20/ubuntu jammy-backports main restricted universe multiverse
deb http://10.10.10.20/ubuntu jammy-security main restricted universe multiverse
```

### Update and Verify

After configuring sources, update the package list:

```bash
sudo apt update
```

Verify the mirror is working:

```bash
apt-cache policy | grep 10.10.10.20
```

You should see your mirror server listed in the output.

## Repository Structure

The mirror contains:

- **`dists/`** - Distribution metadata (Release files, Packages files) - **Required by apt**
- **`pool/`** - Actual .deb package files

**Note:** While `http://10.10.10.20/pool/main/` may be accessible for browsing, apt requires the full repository structure including the `dists/` directory. Always use the base path `http://10.10.10.20/ubuntu` in your sources.list.

## Maintenance

### Update the Mirror

To sync updates from the upstream Ubuntu repositories:

```bash
sudo apt-mirror
```

This can be automated with a cron job. Add to crontab:

```bash
sudo crontab -e
```

Add a daily sync (runs at 2 AM):

```text
0 2 * * * /usr/bin/apt-mirror > /var/log/apt-mirror.log 2>&1
```

### Check Mirror Status

View the mirror log:

```bash
sudo tail -f /var/log/apt-mirror.log
```

Check disk usage:

```bash
du -sh /var/spool/apt-mirror/mirror/archive.ubuntu.com/ubuntu/
```

### Clean Old Packages

The mirror configuration includes a clean script. Run it periodically to remove outdated packages:

```bash
sudo /var/spool/apt-mirror/var/clean.sh
```

## Troubleshooting

### Client can't reach the mirror

1. Verify nginx is running:

   ```bash
   sudo systemctl status nginx
   ```

2. Test HTTP access from client:

   ```bash
   # For Ubuntu 22.04 (Jammy)
   curl http://10.10.10.20/ubuntu/dists/jammy/Release
   
   # For Ubuntu 24.04 (Noble)
   curl http://10.10.10.20/ubuntu/dists/noble/Release
   ```

3. Check firewall rules on the mirror server (ensure port 80 is open)

### apt update fails with "Release file not found"

- Verify the mirror sync completed successfully
- Check that `/var/spool/apt-mirror/mirror/archive.ubuntu.com/ubuntu/dists/` exists
- Ensure nginx is serving the correct directory
- Verify the URL in sources.list matches the nginx configuration

### Mirror sync is slow or fails

- Check network connectivity
- Verify sufficient disk space: `df -h`
- Review the mirror log: `sudo tail /var/log/apt-mirror.log`
- Consider adjusting `nthreads` in `/etc/apt/mirror.list` (default is 20)

## Customization

### Change Ubuntu Release

Edit `/etc/apt/mirror.list` and change `jammy` to your desired release:

- `focal` for Ubuntu 20.04
- `jammy` for Ubuntu 22.04
- `noble` for Ubuntu 24.04

**Example for Ubuntu 24.04 (Noble):**

Change lines 39-42 in `/etc/apt/mirror.list` from:

```text
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
```

To:

```text
deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu noble-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse
```

Then re-run: `sudo apt-mirror`

### Change Nginx Configuration

Edit `/etc/nginx/sites-available/ubuntu-mirror` and reload:

```bash
sudo nginx -t
sudo nginx -s reload
```

## Disk Space Requirements

Approximate space requirements for a full Ubuntu mirror:

- **Main repository**: ~50-80 GB
- **Updates**: ~10-20 GB
- **Security updates**: ~5-10 GB
- **Backports**: ~5-10 GB

**Total**: ~70-120 GB (varies by release and components)

## Security Notes

- The mirror serves packages over HTTP (not HTTPS) by default
- For production use, consider:

  - Setting up HTTPS with Let's Encrypt
  - Restricting access via firewall rules
  - Using authentication if exposing to untrusted networks

## Additional Resources

- [apt-mirror documentation](https://apt-mirror.github.io/)
- [Ubuntu Repository Structure](https://wiki.ubuntu.com/RepositoryFormat)
- [Debian Repository HOWTO](https://www.debian.org/doc/manuals/repository-howto/)
