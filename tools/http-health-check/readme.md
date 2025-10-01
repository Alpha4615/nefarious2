# IRCd Health Check Service

A lightweight HTTPS health check service for IRC daemons (IRCd).

## What It Does

This service provides a web endpoint that reports the health status of your IRC daemon based on two critical checks:

1. **Client Port Availability**: Tests TCP connectivity to the IRC client port on `127.0.0.1`
2. **Server-to-Server (S2S) Connections**: Monitors established S2S connections via `/proc/net/tcp*` (Linux only)

The health endpoint returns HTTP 200 only when **BOTH** checks pass, making it suitable for load balancers, orchestration systems, and monitoring tools.

### Key Features

- **Zero Dependencies**: Pure Python stdlib - no pip install required
- **HTTPS Support**: Uses your existing TLS certificates (e.g., Let's Encrypt)
- **Hot Certificate Reload**: Automatically picks up renewed certificates without downtime
- **Connection Stability Tracking**: Prevents false positives from flapping S2S connections
- **Two Operating Modes**:
  - **Live**: Computes health on every request (lower latency, higher CPU)
  - **Cached**: Background polling with instant responses (recommended for production)

### Response Format

```json
{
  "clientValid": true,
  "s2sValid": true,
  "routable": true,
  "warm": true
}
```

- `clientValid`: Client port accepts connections
- `s2sValid`: At least one stable S2S connection exists
- `routable`: Both checks pass (determines HTTP status code)
- `warm`: `false` during initial warmup period, `true` once connections meet stability requirements

**Security**: The endpoint is designed for public exposure - no ports, peer IPs, connection counts, or error details are leaked.

## Requirements

- Python 3.6+
- Linux (for S2S connection checking via `/proc/net/tcp*`)
  - Non-Linux platforms will report `s2sValid = false`
  - Client port checking works on all platforms

## Quick Start

### Basic Usage (HTTP, No Certificates)

```bash
python3 health-check.py \
  --listen 127.0.0.1:8080 \
  --client-port 6667 \
  --s2s-ports 7000 \
  --allow-http
```

Test it:

```bash
curl http://127.0.0.1:8080/health
```

### Production Usage (HTTPS, Cached Mode)

```bash
python3 health-check.py \
  --listen 0.0.0.0:8443 \
  --client-port 6668 \
  --s2s-ports 7000,7001 \
  --cert /etc/letsencrypt/live/irc.example.org/fullchain.pem \
  --key /etc/letsencrypt/live/irc.example.org/privkey.pem \
  --mode cached \
  --poll-interval 15 \
  --stable-duration 10 \
  --foreground
```

## Command Line Options

### Required Options

| Option          | Description                                        | Default        | Example        |
| --------------- | -------------------------------------------------- | -------------- | -------------- |
| `--listen`      | Bind address and port                              | `0.0.0.0:8080` | `0.0.0.0:8443` |
| `--client-port` | IRC client port to test (TCP connect on 127.0.0.1) | `6667`         | `6668`         |
| `--s2s-ports`   | Comma-separated S2S port list                      | `4497`         | `7000,7001`    |

### TLS/HTTPS Options

| Option                    | Description                                      | Default            |
| ------------------------- | ------------------------------------------------ | ------------------ |
| `--cert`                  | TLS certificate chain file (e.g., fullchain.pem) | None               |
| `--key`                   | TLS private key file (e.g., privkey.pem)         | None               |
| `--allow-http`            | Allow plain HTTP when cert/key not provided      | False (HTTPS only) |
| `--reload-check-interval` | Seconds between cert/key change checks           | `30`               |

### Health Check Behavior

| Option              | Description                                                | Default |
| ------------------- | ---------------------------------------------------------- | ------- |
| `--mode`            | `live` (compute per request) or `cached` (background poll) | `live`  |
| `--poll-interval`   | Seconds between polls in cached mode (≥5s)                 | `15`    |
| `--timeout-ms`      | Per-check timeout in milliseconds (client connect)         | `500`   |
| `--stable-duration` | Require S2S connection stable for N seconds before healthy | `10`    |

### Other Options

| Option          | Description                                                    | Default   |
| --------------- | -------------------------------------------------------------- | --------- |
| `--health-path` | Path for health endpoint                                       | `/health` |
| `--foreground`  | Stay in foreground with blocking loop (useful without systemd) | False     |

## Endpoints

### `GET /health` (or custom `--health-path`)

Returns health status JSON:

- **HTTP 200**: Both client and S2S checks pass (`routable: true`)
- **HTTP 503**: One or both checks failed (`routable: false`)

### `GET /` or `GET /_info`

Returns service information:

```json
{
  "name": "ircd-web-health",
  "healthPath": "/health",
  "mode": "cached",
  "https": true
}
```

## How It Works

### Client Port Check

Attempts a TCP connection to `127.0.0.1:<client-port>` with configurable timeout. Passes if connection succeeds.

### S2S Connection Check (Linux Only)

1. Parses `/proc/net/tcp` and `/proc/net/tcp6` for ESTABLISHED connections
2. Filters for connections on configured S2S ports (local or remote)
3. Tracks connections by socket inode to detect connection flapping
4. Requires connections to remain stable for `--stable-duration` seconds

**Warmup Period**: During initial startup, the service optimistically reports `s2sValid=true` if any S2S connection exists, even if not yet stable (`warm=false`). Once a connection exceeds the stability duration, warmup ends (`warm=true`).

### Certificate Hot-Reload

When using HTTPS, the service watches certificate and key file modification times. When changes are detected (e.g., Let's Encrypt renewal), it gracefully restarts the HTTPS listener in-process without dropping health check state.

## Platform Support

- **Linux**: Full functionality (client + S2S checks)
- **Other platforms**: Client port checking only (S2S always reports `false`)

## Testing

Start a netcat listener to simulate IRC:

```bash
nc -l 6667
```

Run the health check:

```bash
python3 health-check.py --listen 127.0.0.1:8080 --client-port 6667 --allow-http --stable-duration 5
```

Query the endpoint:

```bash
curl http://127.0.0.1:8080/health
# Expected during warmup: {"clientValid": true, "s2sValid": false, "routable": false, "warm": false}
# HTTP 503
```

Kill netcat and query again to see `clientValid: false`.

## License

This is a single-file utility script provided as-is. Modify freely for your IRC network's needs.
