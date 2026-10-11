# Deployment Guide for get.bitcoinghost.org

## Prerequisites
- DNS A record for `get.bitcoinghost.org` pointing to your Web VM IP (already done)
- Ubuntu 22.04+ or Debian 12+ server
- Nginx installed
- Certbot installed

## Deployment Steps

### 1. Copy files to the Web VM

```bash
# From your local machine
scp -r get/* user@web-vm:/tmp/ghost-get/

# On the Web VM
sudo mkdir -p /var/www/get.bitcoinghost.org
sudo cp /tmp/ghost-get/install.sh /var/www/get.bitcoinghost.org/
sudo cp /tmp/ghost-get/wallet.sh /var/www/get.bitcoinghost.org/
sudo chown -R www-data:www-data /var/www/get.bitcoinghost.org
sudo chmod 644 /var/www/get.bitcoinghost.org/*.sh
```

### 2. Install nginx configuration

```bash
# Copy nginx config
sudo cp /tmp/ghost-get/nginx.conf /etc/nginx/sites-available/get.bitcoinghost.org

# Enable the site
sudo ln -s /etc/nginx/sites-available/get.bitcoinghost.org /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t
```

### 3. Get SSL certificate with Certbot

```bash
# Temporarily comment out SSL lines in nginx config for initial certbot run
# Or use webroot method:
sudo certbot --nginx -d get.bitcoinghost.org

# Certbot will automatically update the nginx config with certificate paths
```

### 4. Reload nginx

```bash
sudo systemctl reload nginx
```

### 5. Test the installation

```bash
# Test install script
curl -sSL https://get.bitcoinghost.org/install.sh | head -20

# Test wallet script
curl -sSL https://get.bitcoinghost.org/wallet.sh | head -20

# Test health endpoint
curl https://get.bitcoinghost.org/health
```

## File Structure

After deployment, the structure should be:

```
/var/www/get.bitcoinghost.org/
├── install.sh      # Full node installer
├── wallet.sh       # Light wallet installer
└── keys/           # (optional) GPG keys for signatures
    └── release.asc
```

## Optional: Add GPG Signatures

If you want to provide signed install scripts:

```bash
# Generate signatures
gpg --armor --detach-sign install.sh
gpg --armor --detach-sign wallet.sh

# Export public key
gpg --armor --export your-key-id > keys/release.asc

# Copy to server
scp install.sh.sig wallet.sh.sig keys/release.asc user@web-vm:/var/www/get.bitcoinghost.org/
```

Users can then verify:
```bash
curl -sSL https://get.bitcoinghost.org/keys/release.asc | gpg --import
curl -sSL https://get.bitcoinghost.org/install.sh > install.sh
curl -sSL https://get.bitcoinghost.org/install.sh.sig > install.sh.sig
gpg --verify install.sh.sig install.sh
```

---

# Pool VM: API Proxy Configuration

The stats page at `https://bitcoinghost.org/stats.html` fetches data from
`https://pool.bitcoinghost.org/api/v1/stats`. You need to configure nginx
on the Pool VM to proxy these requests to ghost-mining.

Add this to your Pool VM nginx configuration:

```nginx
# Add this location block to your pool.bitcoinghost.org server block

location /api/v1/ {
    proxy_pass http://127.0.0.1:8080/api/v1/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # CORS headers for stats page
    add_header Access-Control-Allow-Origin "https://bitcoinghost.org" always;
    add_header Access-Control-Allow-Methods "GET, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type" always;

    # Handle preflight requests
    if ($request_method = 'OPTIONS') {
        add_header Access-Control-Allow-Origin "https://bitcoinghost.org";
        add_header Access-Control-Allow-Methods "GET, OPTIONS";
        add_header Access-Control-Allow-Headers "Content-Type";
        add_header Content-Length 0;
        return 204;
    }
}
```

Then reload nginx on the Pool VM:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Testing the Stats API

```bash
# Direct test (from Pool VM)
curl http://localhost:8080/api/v1/stats

# Via nginx proxy
curl https://pool.bitcoinghost.org/api/v1/stats

# Test nodes endpoint
curl https://pool.bitcoinghost.org/api/v1/network/public-nodes
```

## Troubleshooting

### Stats page shows placeholders
- Check if ghost-mining is running: `systemctl status ghost-mining`
- Check pool logs: `journalctl -u ghost-mining -f`
- Verify nginx proxy: `curl -v https://pool.bitcoinghost.org/api/v1/stats`

### CORS errors in browser console
- Ensure the CORS headers are properly set in nginx
- Check that the Origin header matches exactly

### Install script not downloading
- Check nginx error logs: `tail -f /var/log/nginx/get.bitcoinghost.org.error.log`
- Verify file permissions: `ls -la /var/www/get.bitcoinghost.org/`
- Test locally: `curl -I https://get.bitcoinghost.org/install.sh`
