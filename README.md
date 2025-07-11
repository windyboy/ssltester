# SSL Test Tool

A simple SSL certificate verification and HTTPS connection testing tool for checking website SSL/TLS configuration and certificate chains.

## Features

- HTTPS connection verification
- SSL/TLS handshake testing
- Certificate chain validation
- Hostname verification
- Multiple output formats (Text, JSON, YAML, Emoji)

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
  formatter/                # Output formatters (TXT/JSON/YAML/EMOJI)
  cli/                      # Command line related
```

## Basic Usage

```bash
# Basic SSL test (default port 443)
./gradlew run --args="github.com --format TXT"

# Test with custom port
./gradlew run --args="github.com --port 8443 --format JSON"

# Specify output file
./gradlew run --args="github.com --port 443 --format JSON --output result.json"

# Using the built JAR
java -jar app/build/libs/ssl-test-0.0.2-all.jar github.com --port 9443 --format YAML
```

## Output Formats
- **TXT** (colored text, suitable for terminal)
- **JSON** (structured data)
- **YAML** (human-readable structured data)
- **EMOJI** (emoji-based output for quick visual feedback)

## Command Line Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `<host>` | Target host to test SSL/TLS connection | - | Yes |
| `-p, --port` | Port number | 443 | No |
| `--connect-timeout` | Connection timeout in milliseconds | 5000 | No |
| `-f, --format` | Output format (txt, json, yaml, emoji) | TXT | No |
| `-o, --output` | Output file path | - | No |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Connection error |
| 2 | Invalid parameters |

## Examples

```bash
# Test a website's SSL certificate (default port 443)
./gradlew run --args="google.com"

# Test with custom port
./gradlew run --args="github.com --port 8443 --format json"

# Test with custom timeout
./gradlew run --args="example.com --port 9443 --connect-timeout 10000"

# Save results to file
./gradlew run --args="stackoverflow.com --port 443 --format yaml --output ssl_test.yaml"
```

## Development

```bash
# Run tests
./gradlew test

# Build JAR
./gradlew build

# Run with custom arguments
./gradlew run --args="your-website.com --port 8443 --format json"
```
