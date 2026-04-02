# Tenable Security Center — Spring Boot Client

A Spring Boot REST API wrapper for the [Tenable Security Center](https://www.tenable.com/products/security-center) vulnerability management platform. Exposes simple HTTP endpoints that authenticate with Tenable SC, query vulnerabilities, and return the results as JSON.

---

## Features

- Session token lifecycle management (auto-acquire and release)
- Query vulnerabilities by severity, scan, or custom filters
- Auto-pagination to fetch complete result sets
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

Edit `src/main/resources/application.yaml` before running:

```yaml
tenable:
  sc:
    base-url: https://your-security-center-host
    username: your-username
    password: your-password
    ssl-verification-disabled: true   # set false in production with valid certs
    connect-timeout: 10000            # milliseconds
    read-timeout: 60000               # milliseconds
    default-page-size: 100

server:
  port: 8080
```

> All three fields `base-url`, `username`, and `password` are required. The application will fail to start if any are blank.

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

All endpoints are under `/api/v1/vulnerabilities`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/vulnerabilities` | Paged vulnerability list |
| `GET` | `/api/v1/vulnerabilities/all` | All vulnerabilities (auto-paginated) |
| `GET` | `/api/v1/vulnerabilities/critical` | Critical severity only |
| `GET` | `/api/v1/vulnerabilities/high` | High severity only |
| `GET` | `/api/v1/vulnerabilities/summary/severity` | Vulnerability counts by severity |
| `GET` | `/api/v1/vulnerabilities/scan/{scanId}` | Vulnerabilities from a specific scan |
| `POST` | `/api/v1/vulnerabilities/filter` | Query with custom filters |

### Query Parameters (`GET /`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `startOffset` | `0` | Start index for pagination |
| `endOffset` | `100` | End index for pagination |

### Custom Filter Request (`POST /filter`)

```json
[
  {
    "filterName": "severity",
    "operator": "=",
    "value": "4"
  },
  {
    "filterName": "exploitAvailable",
    "operator": "=",
    "value": "true"
  }
]
```

---

## Project Structure

```
src/main/java/com/example/tenable/
├── config/
│   ├── TenableProperties.java       # Configuration binding & validation
│   └── RestClientConfig.java        # RestTemplate with SSL/timeout setup
├── client/
│   ├── TenableAuthClient.java       # Session token create/delete
│   ├── TenableAnalysisClient.java   # Vulnerability query execution
│   └── TenableApiException.java     # Custom API exception
├── service/
│   └── VulnerabilityService.java    # Business logic & token lifecycle
├── controller/
│   ├── VulnerabilityController.java # REST endpoints
│   └── GlobalExceptionHandler.java  # Exception → JSON error response
├── dto/
│   ├── TenableApiResponse.java      # Generic Tenable SC response envelope
│   ├── token/                       # Auth request/response DTOs
│   └── analysis/                    # Query request/response/filter DTOs
└── TenableSecurityCenterApplication.java
```

---

## How It Works

Each API call follows this flow:

```
Request → Controller → Service
                         ├── AuthClient.createToken()        POST /rest/token
                         ├── AnalysisClient.query(token)     POST /rest/analysis
                         └── AuthClient.deleteToken() [finally]  DELETE /rest/token
```

The session token is always released in a `finally` block, even if the query fails.

---

## Error Responses

Errors are returned as JSON:

```json
{
  "error": "Service Unavailable",
  "message": "Cannot connect to Tenable SC at https://your-host"
}
```

| Scenario | HTTP Status |
|----------|-------------|
| Tenable SC unreachable | `503 Service Unavailable` |
| Tenable SC client error | mirrors Tenable's status |
| Tenable SC server error | `502 Bad Gateway` |

---

## Running Tests

```bash
mvn test
```

Unit tests use Mockito to verify token lifecycle, filter application, and error handling without a live Tenable SC instance.

---

## License

MIT
