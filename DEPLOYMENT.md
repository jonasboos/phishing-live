# Deployment Guide

This guide covers deploying the Phishing Email Scanner to an Ubuntu server using Docker and automated CI/CD.

## Prerequisites

### Server Requirements
- Ubuntu 20.04 LTS or newer
- Docker and Docker Compose installed
- At least 2GB RAM
- 10GB free disk space
- SSH access with sudo privileges

### GitHub Repository Secrets

Configure the following secrets in your GitHub repository (Settings → Secrets and variables → Actions):

- `SERVER_HOST`: Your Ubuntu server IP address or domain
- `SERVER_USER`: SSH username (e.g., `ubuntu` or `root`)
- `SERVER_SSH_KEY`: Private SSH key for authentication

## Initial Server Setup

### 1. Install Docker and Docker Compose

```bash
# Update package index
sudo apt update

# Install dependencies
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add your user to docker group
sudo usermod -aG docker $USER

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### 2. Create Application Directory

```bash
# Create directory for the application
sudo mkdir -p /opt/phishing-scanner
sudo chown $USER:$USER /opt/phishing-scanner
cd /opt/phishing-scanner

# Clone repository (or copy docker-compose.yml manually)
git clone https://github.com/YOUR_USERNAME/phising-mails.git .
```

### 3. Configure Environment

Create a `.env` file if needed:

```bash
cat > .env << EOF
PORT=8080
EOF
```

## SSL/TLS Configuration (Optional but Recommended)

### Using Let's Encrypt with Certbot

```bash
# Install Certbot
sudo apt install -y certbot

# Generate certificate (replace with your domain)
sudo certbot certonly --standalone -d your-domain.com

# Create SSL directory
mkdir -p nginx/ssl

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/
sudo chown -R $USER:$USER nginx/ssl
```

Then uncomment the HTTPS server block in `nginx/nginx.conf` and update the `server_name`.

### Auto-renewal Setup

```bash
# Add cron job for certificate renewal
(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && docker-compose -f /opt/phishing-scanner/docker-compose.yml restart nginx") | crontab -
```

## Manual Deployment

```bash
cd /opt/phishing-scanner

# Build and start containers
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

## Automated Deployment (CI/CD)

Once you've configured GitHub secrets and set up the server:

1. Push to `main` branch
2. GitHub Actions will automatically:
   - Build Docker image
   - Push to GitHub Container Registry
   - SSH to your server
   - Pull latest image
   - Restart containers
   - Verify health check

## Verification

### Check Application Status

```bash
# Check if containers are running
docker-compose ps

# View application logs
docker-compose logs app

# View nginx logs
docker-compose logs nginx

# Test health endpoint
curl http://localhost/health
```

### Access the Application

- **HTTP**: `http://your-server-ip`
- **HTTPS** (if configured): `https://your-domain.com`

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs app

# Rebuild image
docker-compose build --no-cache
docker-compose up -d
```

### Nginx 502 Bad Gateway

```bash
# Check if app container is running
docker-compose ps

# Check app logs
docker-compose logs app

# Restart services
docker-compose restart
```

### Permission Issues

```bash
# Fix data directory permissions
sudo chown -R 1000:1000 data/

# Restart containers
docker-compose restart
```

### SSL Certificate Issues

```bash
# Verify certificate files exist
ls -la nginx/ssl/

# Check nginx configuration
docker-compose exec nginx nginx -t

# Reload nginx
docker-compose exec nginx nginx -s reload
```

## Maintenance

### Update Application

```bash
cd /opt/phishing-scanner

# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f app
docker-compose logs -f nginx
```

### Backup Data

```bash
# Backup linguistic stats and test emails
tar -czf backup-$(date +%Y%m%d).tar.gz data/
```

### Clean Up

```bash
# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Remove unused networks
docker network prune
```

## Security Recommendations

1. **Firewall**: Configure UFW to only allow ports 80, 443, and SSH
   ```bash
   sudo ufw allow 22/tcp
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

2. **SSH**: Disable password authentication, use key-based auth only

3. **Updates**: Keep system and Docker updated
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

4. **Monitoring**: Set up monitoring with tools like Prometheus/Grafana

5. **Backups**: Implement regular automated backups

## Support

For issues or questions, please open an issue on GitHub.
