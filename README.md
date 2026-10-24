# F5 API Log Redactor

A rule-based log redaction service written in Python. It processes NDJSON HTTP transactions and protects sensitive information using configurable YAML rules.

The project includes a CLI, streaming HTTP API, automated tests, and Docker/Kubernetes deployment configurations.

## Features

- Recursive redaction of nested JSON, headers, arrays, and embedded content.
- YAML-configurable key and value rules.
- Four actions: `mask`, `partial`, `hash` (SHA-256), and `remove`.
- Credit-card detection with Luhn validation.
- JWT and sensitive-pattern detection.
- Streaming NDJSON processing with an 8 MiB per-record limit.
- Fail-closed error handling and idempotent redaction.
- Per-rule statistics written to stderr.

## 1. Setup & Usage

**Requirements:** Python 3.12+ and the dependencies in `requirements.txt`.

```bash
python -m venv .venv
python -m pip install -r requirements.txt
```

Activate the virtual environment before running the application.

**CLI — Process an NDJSON file:**

```bash
python -m redactor.cli --rules rules.yaml input.ndjson > redacted.ndjson
```

Input is processed line by line. Redacted records are written to stdout, while statistics and errors are written to stderr.

**HTTP — Start the service:**

```bash
python -m redactor.service --rules rules.yaml
```

Available endpoints:

- `GET /health` — Returns `{"status":"ok"}`.
- `POST /redact` — Accepts NDJSON and returns streamed, redacted NDJSON.

Example:

```bash
curl -X POST http://127.0.0.1:8080/redact \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @input.ndjson
```

## 2. Configuration & Architecture

The `rules.yaml` file defines key-based and value-based rules, including matching scope, regex patterns, and redaction actions.

The application is organized into three main components:

- `rules.py` — Loads and validates rule configuration.
- `engine.py` — Recursively applies redaction rules.
- `cli.py` / `service.py` — Provide streaming CLI and HTTP interfaces.

NDJSON records are processed individually rather than loading the complete input into memory.

The engine handles nested JSON, sensitive HTTP headers, embedded JSON strings, and supported textual/form-encoded content.


### Design Decisions & Trade-offs

I used recursive traversal to handle nested dictionaries and arrays, keeping the implementation simple and readable. The trade-off is Python's recursion depth limit, which is handled safely as a processing failure.

Rules are loaded from YAML and regex patterns are compiled once during initialization. Key rules match field names, while value rules detect sensitive content within strings. Overlapping text matches are resolved deterministically, prioritizing the leftmost match and key-based assignments over value patterns.

NDJSON is processed one record at a time rather than loading the entire input into memory. Failed records produce a safe error marker instead of returning potentially sensitive original data.

### Time & Space Complexity

Let `N` be the size of a single record, `R` the number of configured rules, and `M` the number of candidate text matches.

- **Time:** Approximately `O(R × N + M log M)` per record, assuming typical linear regex matching. Worst-case performance depends on the configured regex patterns.
- **Space:** Approximately `O(N + M)` per record for parsing, traversal, and match processing. CLI memory usage does not grow with the total number of input records.

Individual input records are limited to 8 MiB. In HTTP mode, buffered diagnostic messages can also consume memory proportional to the number of failed records in a request.

### Why Python?

I chose Python because I have stronger experience with it, while Go is relatively new to me. Given the assignment's time constraints, Python allowed me to focus on correctness, security, and comprehensive testing.

Python's JSON processing and regex support also made it suitable for this rule-driven solution. The trade-off is potentially higher runtime overhead compared with a compiled implementation, particularly under heavy production workloads.

## 3. Security & Failure Handling

The application follows a **fail-closed** approach: failures must never cause original sensitive data to be returned unchanged.

- Missing or invalid rules prevent startup.
- Invalid JSON, duplicate keys, unsafe constants, and malformed records produce `{"error":"redaction_failed"}`.
- Oversized records are rejected (8 MiB limit).
- Processing continues after invalid records when possible.
- Failed records do not contribute to successful redaction counts.
- HTTP stream failures terminate the connection rather than returning the original input.

The redaction process is designed to be idempotent, so already-redacted records remain unchanged when processed again.

## 4. JWT Bug Investigation

The original JWT regex missed some valid tokens because it used standard Base64 characters (`+` and `/`), while JWTs use Base64URL (`-` and `_`).

**Fix:** Updated the regex in `rules.yaml` to support Base64URL characters while retaining the three-segment JWT structure.

**Verification:** Added the regression test `test_base64url_jwt_redacted_in_embedded_body` and verified the corrected behavior against the provided NDJSON sample.

This fixes the observed matching issue; the regex is not intended to validate JWT signatures.

## 5. Docker & Kubernetes

**Docker:**

```bash
docker build -t f5-log-redactor:1.0 .
docker run --rm -p 8080:8080 f5-log-redactor:1.0
```

The Docker image uses Python 3.12 Slim and runs as a non-root user.

**Kubernetes:**

```bash
kubectl create configmap f5-redaction-rules \
  --from-file=rules.yaml=./rules.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f k8s/
kubectl rollout status deployment/f5-log-redactor
```

The Kubernetes manifests define two replicas, a ClusterIP Service, health probes, CPU/memory limits, and security restrictions including non-root execution and a read-only root filesystem.

**Deployment verification:** Successfully deployed to Docker Desktop Kubernetes v1.32.2. Both Pods reached `1/1 Ready`, and `/health` and `/redact` were tested successfully through port-forwarding.

## 6. Testing

Run:

```bash
python -m pytest -q
```

**Verified result: 79 tests passed.**

Tests cover rule validation, recursive redaction, CLI and HTTP integration, malformed inputs, JWT regression, fail-closed behavior, and idempotency.

Docker execution and startup failure with missing rules were also verified.

## 7. Limitations & Production Considerations

- HTTP requests require `Content-Length`; chunked request uploads are not supported.
- The HTTP server uses Python's standard library and is not intended to be exposed directly to the internet without production-grade infrastructure.
- Regex-based detection is limited to the configured rules and supported input formats.
- The 8 MiB limit applies per NDJSON record.
- Kubernetes uses a local image reference; remote deployments require a container registry.
- Rule ConfigMap changes require a Pod rollout due to the `subPath` mount.

With more time, I would expand the test coverage with fuzz and property-based testing, benchmark the system with larger workloads, and improve HTTP diagnostic handling to avoid accumulating error messages in memory. I would prioritize these improvements based on measured performance and reliability needs.


### Sub-millisecond latency
Sub-millisecond production latency has not been measured or demonstrated. If this system had to run inline on live production traffic with a sub-millisecond budget per request, I would first benchmark representative records and measure p50, p95, and p99 latency. I would then profile JSON parsing, serialization, recursive traversal, regex matching, hashing, and memory allocations to identify the main bottlenecks. Based on the results, I would consider faster libraries or a compiled implementation such as Go, while testing under concurrent load and ensuring that optimizations preserve fail-closed behavior. The current implementation prioritizes correctness, security, and maintainability over unverified latency claims.