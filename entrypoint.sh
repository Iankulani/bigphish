#!/bin/sh
# BIG-PHISH Docker Entrypoint

set -e

echo "🐋 Starting BIG-PHISH..."

# Create necessary directories
mkdir -p .bigphish reports logs config wordlists phishing_templates
mkdir -p captured_credentials ssh_keys traffic_logs nikto_results

# Check if config exists
if [ ! -f "config/config.json" ]; then
    echo "Creating default configuration..."
    cp config.example.json config/config.json 2>/dev/null || cat > config/config.json <<'EOF'
{
    "monitoring": {"enabled": true, "port_scan_threshold": 10},
    "scanning": {"default_ports": "1-1000", "timeout": 30},
    "security": {"auto_block": false, "log_level": "INFO"},
    "nikto": {"enabled": true, "timeout": 300},
    "traffic_generation": {"enabled": true, "max_duration": 300, "allow_floods": false},
    "social_engineering": {"enabled": true, "default_port": 8080, "capture_credentials": true},
    "crunch": {"enabled": true, "max_file_size_mb": 1024, "default_output_dir": "wordlists"},
    "ssh": {"enabled": true, "default_timeout": 30, "max_connections": 5}
}
EOF
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    cp .env.example .env
fi

# Initialize database
echo "Initializing database..."
python3 -c "
import sqlite3
conn = sqlite3.connect('.bigphish/bigphish.db')
conn.execute('CREATE TABLE IF NOT EXISTS workspaces (id INTEGER PRIMARY KEY, name TEXT, created_at TIMESTAMP)')
conn.execute('INSERT OR IGNORE INTO workspaces (id, name) VALUES (1, \"default\")')
conn.commit()
conn.close()
"

# Set permissions
chmod -R 755 .bigphish reports logs config

# Start supervisord if in production mode
if [ "$BIGPHISH_ENV" = "production" ]; then
    echo "Starting in production mode with supervisord..."
    exec /usr/bin/supervisord -c /app/supervisord.conf
else
    echo "Starting in development mode..."
    # Start dashboard in background
    python3 metrics_dashboard.py &
    # Start main application
    exec python3 bigphish.py
fi