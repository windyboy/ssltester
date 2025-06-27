# SSL Test Tool

A powerful SSL certificate verification and HTTPS connection testing tool for checking server SSL/TLS configuration, certificate chains, and hostname verification.

## Features

- HTTPS connection verification
- SSL/TLS handshake testing
- Certificate chain validation
- Hostname verification
- Multiple output formats (Text, JSON, YAML)

## System Requirements

- Java 11 or higher
- Supported operating systems: Windows, macOS, Linux

## Installation and Build

```bash
# Clone the project
$ git clone <your-repo-url>
$ cd ssl

# Build with Gradle
$ ./gradlew clean build
```

## Project Structure

```
app/src/main/kotlin/org/example/
  SSLTest.kt                # Main entry point
  SSLTestCommand.kt         # Command line arguments and dispatch
  DefaultSSLConnectionTester.kt # SSL connection testing core logic
  model/                    # Data models
  exception/                # Exception definitions
  formatter/                # Output formatters (TXT/JSON/YAML)
  cli/                      # Command line related
```

## Basic Usage

```bash
# Basic SSL test
./gradlew run --args="github.com --port 443 --format TXT"

# Specify output file
./gradlew run --args="github.com --port 443 --format JSON --output result.json"

# Using the built JAR
java -jar app/build/libs/ssl-test-0.0.2-all.jar github.com --port 443 --format YAML
```

## Output Formats
- **TXT** (colored text, suitable for terminal)
- **JSON** (structured data)
- **YAML** (human-readable structured data)

## Command Line Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `<host>` | Target host to test SSL/TLS connection | - | Yes |
| `-p, --port` | Port number | 443 | No |
| `--connect-timeout` | Connection timeout in milliseconds | 5000 | No |
| `-f, --format` | Output format (txt, json, yaml) | TXT | No |
| `-o, --output` | Output file path | - | No |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Connection or SSL error |
| 2 | Invalid parameters |

## Output Examples

### Text Output (Default)

```
SSL Test Results for github.com:443
==================================================
Connection Status: SUCCESS
Protocol Version: TLSv1.3
Cipher Suite: TLS_AES_256_GCM_SHA384
Handshake Time: 245ms
Hostname Verification: PASSED

Certificate Chain:
[1] Subject: CN=github.com, O="GitHub, Inc.", L=San Francisco, ST=California, C=US
    Issuer: CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US
    Valid From: 2023-01-15T00:00:00Z
    Valid To: 2024-01-15T23:59:59Z
    Fingerprint (SHA-256): 3A:40:F5:9E:84:2E:...
```

### JSON Output

```json
{
  "host": "github.com",
  "port": 443,
  "protocol": "TLSv1.3",
  "cipherSuite": "TLS_AES_256_GCM_SHA384",
  "handshakeTime": "PT0.245S",
  "isSecure": true,
  "certificateChain": [
    {
      "position": 1,
      "subject": "CN=github.com, O=\"GitHub, Inc.\", L=San Francisco, ST=California, C=US",
      "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
      "validFrom": "2023-01-15T00:00:00Z",
      "validTo": "2024-01-15T23:59:59Z",
      "fingerprintSHA256": "3A:40:F5:9E:84:2E:..."
    }
  ]
}
```

## Development

- **No dependency injection framework** - all dependencies are directly instantiated for simplicity
- All formatters are in the `org.example.formatter` package for easy extension
- Main business logic is concentrated in `SSLTestCommand` and `DefaultSSLConnectionTester`
- Code includes standard Kotlin documentation comments for IDE/tool hints

## Building and Testing

```bash
# Build the project
./gradlew build

# Run tests
./gradlew test

# Run with coverage
./gradlew test jacocoTestReport

# Build fat JAR
./gradlew shadowJar
```

## Using Taskfile

This project includes a comprehensive Taskfile for common development tasks:

```bash
# Show all available tasks
task help

# Development workflow
task dev

# Run the application
task run HOST=github.com PORT=443 FORMAT=JSON

# Complete CI workflow
task ci

# Create a release
task release VERSION=1.0.0
```

## Contributing

Welcome to submit issues or pull requests!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
