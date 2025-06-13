#!/bin/bash
# GCP Linux VM Startup Script for Ransomware Detector
# - Downloads script from GCS bucket
# - Sets up cron job to run every 3 minutes as root
# - Configures Ops Agent to monitor log file

sudo -i

# Configuration
BUCKET_NAME="essential-scripts" 
ZIP_FILE="Ransomware-detection-on_VMs.tar"
INSTALL_DIR="/opt/ransomware-detector"
LOG_DIR="/var/log"
LOG_FILE="$LOG_DIR/enc-files.log"
SCRIPT_PATH="$INSTALL_DIR/ransomware_detector.py"

# Create installation directory
mkdir -p $INSTALL_DIR
mkdir -p $(dirname $LOG_FILE)
touch $LOG_FILE
chmod 644 $LOG_FILE

# Install unzip if not already installed
if command -v apt-get &>/dev/null; then
    while sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        echo "Waiting for apt-get lock to be released..."
        sleep 5
    done
    apt-get update
fi
# Download and extract script from GCS bucket
gsutil cp gs://$BUCKET_NAME/$ZIP_FILE /tmp/$ZIP_FILE
mkdir -p $INSTALL_DIR
tar -xf /tmp/$ZIP_FILE -C $INSTALL_DIR
rm /tmp/$ZIP_FILE

# Install Python if not already installed (for some minimal images)
if ! command -v python3 &>/dev/null; then
    if command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y python3
    elif command -v yum &>/dev/null; then
        yum install -y python3
    fi
fi



# Set permissions
chmod +x $SCRIPT_PATH
chmod -R 700 $INSTALL_DIR

# Create cron job to run every 3 minutes
CRON_JOB="*/3 * * * * root python3 $SCRIPT_PATH"
echo "$CRON_JOB" > /etc/cron.d/ransomware-detector
chmod 644 /etc/cron.d/ransomware-detector

# Configure Ops Agent for log monitoring
# Google Cloud Ops Agent uses /etc/google-cloud-ops-agent/config.yaml as the main config file
# We can append our config to it or backup and replace it

# Backup existing config if it exists
if [ -f "/etc/google-cloud-ops-agent/config.yaml" ]; then
    cp /etc/google-cloud-ops-agent/config.yaml /etc/google-cloud-ops-agent/config.yaml.bak
fi

# Create new Ops Agent config file with proper formatting
cat > /etc/google-cloud-ops-agent/config.yaml << EOF
# Ops Agent Configuration

logging:
  receivers:
    ransomware_logs:
      type: files
      include_paths:
        - /var/log/enc-files.log
    authlog:
      type: files
      include_paths:
        - /var/log/auth.log
  service:
    pipelines:
      ransomware_pipeline:
        receivers: [ransomware_logs]
      auth_pipeline:
        receivers: [authlog]
EOF



# Set SELinux context if SELinux is enabled
if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
    chcon -t var_log_t $LOG_FILE || true
fi