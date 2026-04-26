# Tenable Security Center — Spring Boot Client

A Spring Boot REST API wrapper for the [Tenable Security Center](https://www.tenable.com/products/security-center) vulnerability management platform. Exposes simple HTTP endpoints that authenticate with one or more Tenable SC instances (by region), query vulnerabilities, and return the results as JSON.

---

## Features

- **Multi-region support** — configure separate SC endpoints per region (APAC, EMEA, AMER, etc.), each with independent credentials and auth settings
- **Two authentication modes** per endpoint:
  - **API Key** — stateless `x-apikey` header; no login/logout session overhead
  - **Session Token** — `POST /rest/token` to acquire, always released in `finally`
- Query vulnerabilities by severity, scan, IP address, plugin ID, or custom filters
- Auto-pagination to fetch complete result sets across all pages
- Plugin-to-IP mapping: find every host affected by a set of plugin IDs
- Optional SSL verification bypass for dev/lab environments
- Configurable HTTP timeouts and connection pooling (Apache HttpClient 5)
- Structured JSON error responses via global exception handler

---

## Requirements

- Java 17+
- Maven 3.8+
- Tenable Security Center instance with API access

---

## Configuration

Edit `src/main/resources/application.yaml`. Each named region under `endpoints` maps to one Security Center instance:

```yaml
tenable:
  sc:
    # Default auth mode for all endpoints (TOKEN | API_KEY).
    # Override per endpoint with auth-mode inside the endpoint block.
    auth-mode: API_KEY

    # Shared HTTP settings
    ssl-verification-disabled: false   # set true only for self-signed certs in dev/lab
    connect-timeout: 10000             # milliseconds
    read-timeout: 60000                # milliseconds
    default-page-size: 100

    endpoints:
      APAC:
        base-url: https://sc-apac.example.com
        access-key: your-apac-access-key    # required when auth-mode is API_KEY
        secret-key: your-apac-secret-key

      EMEA:
        base-url: https://sc-emea.example.com
        access-key: your-emea-access-key
        secret-key: your-emea-secret-key

      AMER:
        base-url: https://sc-amer.example.com
        access-key: your-amer-access-key
        secret-key: your-amer-secret-key

      APAC-GOV:
        base-url: https://sc-apac-gov.example.com
        auth-mode: TOKEN                    # per-endpoint override
        username: your-username             # required when auth-mode is TOKEN
        password: your-password

server:
  port: 8080
```

### Auth mode reference

| `auth-mode` | Required fields | Behaviour |
|-------------|----------------|-----------|
| `API_KEY` | `access-key`, `secret-key` | Sends `x-apikey: accesskey=…; secretkey=…` on every request. No session is created or destroyed. |
| `TOKEN` | `username`, `password` | Calls `POST /rest/token` to obtain a session, then `DELETE /rest/token` after every request (even on error). |

> The application fails fast with a clear error message if the required credentials for the chosen auth mode are missing or blank.

---

## Build & Run

```bash
# Build
mvn clean package

# Run
mvn spring-boot:run

# Or run the JAR directly
java -jar target/tenable-sc-client-*.jar
```

---

## API Endpoints

All endpoints are under `/api/v1/vulnerabilities`. **Every endpoint requires a `region` query parameter** that selects which configured Security Center instance to query.

### Endpoint reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/vulnerabilities` | Paged cumulative vulnerability list |
| `GET` | `/api/v1/vulnerabilities/all` | All vulnerabilities (auto-paginated) |
| `GET` | `/api/v1/vulnerabilities/critical` | Critical severity (4) only |
| `GET` | `/api/v1/vulnerabilities/high` | High severity (3) only |
| `GET` | `/api/v1/vulnerabilities/summary/severity` | Vulnerability counts grouped by severity |
| `GET` | `/api/v1/vulnerabilities/scan/{scanId}` | Vulnerabilities from a specific scan run |
| `GET` | `/api/v1/vulnerabilities/ip/{ipAddress}` | All vulnerabilities found on a specific host |
| `GET` | `/api/v1/vulnerabilities/by-plugin` | IP → plugin ID map for a set of plugin IDs |
| `POST` | `/api/v1/vulnerabilities/filter` | Query with a custom filter list |

---

### Common query parameters

| Parameter | Applies to | Required | Default | Description |
|-----------|-----------|----------|---------|-------------|
| `region` | All endpoints | Yes | — | Target SC region (e.g. `APAC`, `EMEA`, `AMER`) |
| `startOffset` | Paged endpoints | No | `0` | Start index for pagination |
| `endOffset` | Paged endpoints | No | `100` | End index for pagination |
| `view` | `/scan/{scanId}` | No | `all` | `all` \| `new` \| `patched` |
| `pluginIds` | `/by-plugin` | Yes | — | One or more plugin IDs (repeat param or comma-separated) |

---

### `GET /api/v1/vulnerabilities/ip/{ipAddress}`

Returns every vulnerability detected on the specified host, including the raw plugin output text.

```
GET /api/v1/vulnerabilities/ip/192.168.1.10?region=APAC
```

**Response:**
```json
[
  {
    "pluginId":   "51192",
    "pluginName": "SSL Certificate Cannot Be Trusted",
    "pluginText": "The following certificate was at the top of the certificate\nchain sent by the remote host...",
    "severity":   "High",
    "ip":         "192.168.1.10",
    "port":       "443",
    "protocol":   "tcp",
    "dnsName":    "host.example.com",
    "synopsis":   "The SSL certificate cannot be trusted.",
    "firstSeen":  "1700000000",
    "lastSeen":   "1710000000"
  }
]
```

---

### `GET /api/v1/vulnerabilities/by-plugin`

Finds every host where any of the specified plugins have been detected. Returns a sorted map of IP address to a deduplicated list of matched plugin IDs. If the same plugin is found on multiple ports of a host, it appears once in the list.

```
GET /api/v1/vulnerabilities/by-plugin?region=APAC&pluginIds=10881&pluginIds=51192
```

Comma-separated plugin IDs are also accepted:

```
GET /api/v1/vulnerabilities/by-plugin?region=APAC&pluginIds=10881,51192
```

**Response:**
```json
{
  "10.0.0.5":    ["10881", "51192"],
  "10.0.0.12":   ["51192"],
  "192.168.1.3": ["10881"]
}
```

Returns `400 Bad Request` when `pluginIds` is missing or empty.

---

### `POST /api/v1/vulnerabilities/filter`

Query with an arbitrary list of Tenable SC field filters.

```
POST /api/v1/vulnerabilities/filter?region=EMEA&startOffset=0&endOffset=100
```

**Request body:**
```json
[
  { "filterName": "severity",        "operator": "=",    "value": "4"    },
  { "filterName": "exploitAvailable","operator": "=",    "value": "true" },
  { "filterName": "ip",              "operator": "like", "value": "10.0" }
]
```

---

## Project Structure

```
src/main/java/com/example/tenable/
├── config/
│   ├── TenableProperties.java       # Multi-region config binding; EndpointConfig inner class
│   └── RestClientConfig.java        # RestTemplate with SSL/timeout setup
├── client/
│   ├── TenableAuthClient.java       # Token create/delete + API key header builder
│   ├── TenableAnalysisClient.java   # Vulnerability query & auto-pagination
│   └── TenableApiException.java     # Custom API exception
├── service/
│   └── VulnerabilityService.java    # Business logic; withAuth() handles both auth modes
├── controller/
│   ├── VulnerabilityController.java # REST endpoints
│   └── GlobalExceptionHandler.java  # Exception → JSON error response
├── dto/
│   ├── TenableApiResponse.java      # Generic Tenable SC response envelope
│   ├── VulnerabilityByIpResult.java # Typed result for /ip/{ipAddress}
│   ├── token/                       # Auth request/response DTOs
│   └── analysis/                    # Query request/response/filter DTOs
└── TenableSecurityCenterApplication.java
```

---

## How It Works

### Request flow

Every API call resolves the target endpoint from the `region` parameter, then authenticates using the mode configured for that endpoint:

```
Request → Controller → Service.withAuth(endpoint)
                         │
                         ├── [API_KEY mode]
                         │     └── Attach x-apikey header → AnalysisClient.query()
                         │
                         └── [TOKEN mode]
                               ├── AuthClient.createToken()     POST /rest/token
                               ├── AnalysisClient.query(token)  POST /rest/analysis
                               └── AuthClient.deleteToken() [finally]  DELETE /rest/token
```

The session token (TOKEN mode) is always released in a `finally` block, even if the query throws an exception.

### Pagination

`queryAll()` loops over pages automatically until `fetched >= totalRecords` or the page returns zero records, collecting all results into a single list.

---

## Error Responses

All errors are returned as JSON:

```json
{ "error": "description of the problem" }
```

| Scenario | HTTP Status |
|----------|-------------|
| Unknown or unconfigured `region` | `400 Bad Request` |
| Missing or empty `pluginIds` | `400 Bad Request` |
| Missing credentials for the chosen auth mode | `500 Internal Server Error` |
| Tenable SC unreachable | `503 Service Unavailable` |
| Tenable SC API error (non-zero `error_code`) | `502 Bad Gateway` |
| Tenable SC 4xx response | mirrors Tenable's HTTP status |
| Tenable SC 5xx response | `502 Bad Gateway` |

---

## Running Tests

```bash
mvn test
```

Unit tests use Mockito to verify token lifecycle, API key auth, region routing, filter construction, result mapping, and error handling — without requiring a live Tenable SC instance.

---

## License

MIT
