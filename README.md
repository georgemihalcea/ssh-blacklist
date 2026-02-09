# SSH Blacklist

A centralized service for collecting and serving IP addresses that attempt unauthorized SSH access. Multiple servers report failed SSH login attempts to a central REST API, which maintains a blacklist with attempt counts, a full report log, and a statistics dashboard.

## Project Structure

```
ssh-blacklist/
├── server/
│   ├── app.py                         # Flask REST API server
│   ├── requirements.txt               # flask, gunicorn
│   └── ssh-blacklist-server.service   # systemd unit
└── client/
    ├── reporter.py                    # Log watcher & reporter
    ├── requirements.txt               # requests
    └── ssh-blacklist-reporter.service # systemd unit
```

## Server (`server/app.py`)

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/report` | POST | Report IPs — accepts `{"ip": "x.x.x.x"}` or `{"ips": [...]}` for batch |
| `/api/blacklist` | GET | Get blacklist — optional `?days=N` for time filtering |
| `/api/stats` | GET | Statistics dashboard (HTML) — optional `?server=x.x.x.x` for per-server detail |

### Features

- In-memory dict for fast blacklist access, loaded from SQLite on startup
- SQLite with WAL mode: `blacklist` table (IP + attempts + timestamps) and `reports_log` table (IP + timestamp + reporter IP)
- Thread-safe in-memory updates via lock
- Respects `X-Forwarded-For` / `X-Real-IP` headers for reporter identification

### Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `BLACKLIST_DB` | `/var/lib/ssh-blacklist/blacklist.db` | Path to SQLite database |
| `BLACKLIST_HOST` | `0.0.0.0` | Bind address |
| `BLACKLIST_PORT` | `5000` | Bind port |

## Client (`client/reporter.py`)

- Tail-follows `/var/log/auth.log` starting from the **end** (ignores old entries)
- Regex matches failed SSH password attempts in both traditional syslog and ISO 8601 timestamp formats:
  - `Feb  9 20:09:17 web7 sshd[60062]: Failed password for root from 166.171.122.252 port 20758 ssh2`
  - `Feb  9 20:13:07 web7 sshd[60489]: Failed password for invalid user admin from 166.171.122.252 port 32126 ssh2`
  - `2026-02-09T19:42:21.499070+02:00 bmwzone sshd[61072]: Failed password for invalid user emmanuel from 20.193.141.133 port 18932 ssh2`
- Batches detected IPs every 5 seconds (configurable with `--interval`)
- Handles log rotation (detects inode change)
- Retries failed sends on next batch cycle
- Graceful shutdown on SIGTERM/SIGINT

### Command-Line Options

| Option | Default | Description |
|---|---|---|
| `--log-file` | `/var/log/auth.log` | Path to auth log |
| `--server` | `http://localhost:5000` | Blacklist server URL |
| `--interval` | `5` | Batch send interval in seconds |
| `-v` / `--verbose` | off | Enable debug logging |

Environment variables `AUTH_LOG`, `BLACKLIST_SERVER`, and `REPORT_INTERVAL` can also be used.

## Deployment

### Server Setup

```bash
# Create system user and directories
sudo useradd -r -s /bin/false ssh-blacklist
sudo mkdir -p /opt/ssh-blacklist /var/lib/ssh-blacklist
sudo chown ssh-blacklist:ssh-blacklist /var/lib/ssh-blacklist

# Install application
sudo cp -r server /opt/ssh-blacklist/
cd /opt/ssh-blacklist/server
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt

# Install and start service
sudo cp ssh-blacklist-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-blacklist-server
```

### Client Setup (on each monitored server)

```bash
# Install application
sudo mkdir -p /opt/ssh-blacklist
sudo cp -r client /opt/ssh-blacklist/
cd /opt/ssh-blacklist/client
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt

# Edit the service file: replace YOUR_BLACKLIST_SERVER with the actual server IP/hostname
sudo vim /opt/ssh-blacklist/client/ssh-blacklist-reporter.service
sudo cp ssh-blacklist-reporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-blacklist-reporter
```

### Quick Test (without systemd)

```bash
# Terminal 1: start the server
cd server
BLACKLIST_DB=./blacklist.db python3 app.py

# Terminal 2: report an IP manually
curl -X POST http://localhost:5000/api/report \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4"}'

# Get the blacklist
curl http://localhost:5000/api/blacklist

# Get blacklist for last 7 days
curl http://localhost:5000/api/blacklist?days=7

# View statistics in a browser
# Open http://localhost:5000/api/stats
```
