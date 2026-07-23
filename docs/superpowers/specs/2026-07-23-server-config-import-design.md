# Server Config Import Design

## Goal

Add `sbtpl server -i <path>` and `sbtpl server --import <path>` so an existing sing-box server JSON configuration can replace sbtpl's managed server protocol and log configuration.

## CLI Contract

- `-i` and `--import` accept one filesystem path to a JSON configuration.
- Import is a top-level `server` option and cannot be combined with `add`, `remove`, `list`, `set`, or `gen`.
- `--meta <path>` remains supported so tests and advanced users can select a non-default sbtpl metadata file.
- A successful import exits after saving and reports imported and skipped inbound counts.
- A failed import exits non-zero and leaves the metadata file unchanged.

## Data Mapping

The importer replaces `meta.protocols` with supported inbounds while preserving `meta.ip` and unrelated metadata fields.

Supported inbound mappings:

- `vmess`: `listen_port` and exactly one user's `uuid`.
- `trojan`: `listen_port`, exactly one user's `password`, TLS server name, and either ACME or certificate-file mode. Certificate and key paths are retained so regenerating the server configuration does not overwrite custom paths.
- `shadowsocks`: `listen_port`, `method`, and `password`, mapped to sbtpl's internal `ss` type.

The importer maps sing-box log `level`, `timestamp`, and `output` to sbtpl settings. Missing log fields use sbtpl defaults instead of retaining stale settings from the previous managed configuration.

Unsupported inbound types are skipped with warnings. Import fails if no supported inbound remains.

## Validation and Conflict Handling

The entire external JSON object is parsed and validated before any write:

- The root must be an object and `inbounds` must be an array.
- Ports must be integers from 1 through 65535.
- Required credentials and Shadowsocks method must be non-empty strings.
- VMess and Trojan inbounds must contain exactly one user because sbtpl's metadata model represents one credential per protocol.
- Only one inbound of each supported sbtpl protocol may be imported.
- Trojan must have enabled TLS and exactly one representable TLS mode: ACME with a domain, or both certificate and key paths.
- Log fields, when present, must have the expected primitive types.

Validation errors identify the inbound index and field without printing credential values.

## Write Safety

Import builds a complete next metadata object in memory. The metadata file is written only after parsing and validation succeed, so malformed input and unsupported duplicate shapes cannot partially replace existing configuration.

## Testing

Unit tests cover complete mapping, preserved IP, skipped unsupported inbounds, ACME and certificate-file Trojan modes, log settings, duplicate protocols, malformed credentials, and the absence of supported inbounds. A filesystem-level test covers `-i`, custom `--meta`, and failure preserving the original metadata file. Existing generation tests verify imported certificate paths and log level round-trip into generated server configuration.

## Documentation

README examples and the server subcommand table will document both import flag forms, replacement behavior, preserved IP, and the supported inbound types.
