# Go Go Okta Inspector

A multi-framework compliance audit tool for Okta, written in Go. Single binary, zero dependencies, runs anywhere.

> *"Go Go Gadget... compliance audit!"*

## Frameworks

- **FedRAMP** (NIST 800-53) — U.S. Federal identity and access management
- **DISA STIG** V1R1 — Defense Information Systems Agency security requirements
- **IRAP** — Australian Government ISM controls and Essential Eight
- **ISMAP** — Japanese Government ISO 27001:2013 cloud security
- **SOC 2** — Trust Service Criteria for service organizations
- **PCI-DSS 4.0** — Payment Card Industry Data Security Standard

## Install

### Download a release binary

Grab the latest binary for your platform from [Releases](https://github.com/ethanolivertroy/go-go-okta-inspector/releases).

```bash
# Linux (amd64)
curl -Lo go-go-okta-inspector https://github.com/ethanolivertroy/go-go-okta-inspector/releases/latest/download/go-go-okta-inspector_linux_amd64
chmod +x go-go-okta-inspector

# macOS (Apple Silicon)
curl -Lo go-go-okta-inspector https://github.com/ethanolivertroy/go-go-okta-inspector/releases/latest/download/go-go-okta-inspector_darwin_arm64
chmod +x go-go-okta-inspector
```

### Cloud Shell (AWS, GCP, Azure)

```bash
curl -Lo go-go-okta-inspector https://github.com/ethanolivertroy/go-go-okta-inspector/releases/latest/download/go-go-okta-inspector_linux_amd64
chmod +x go-go-okta-inspector
./go-go-okta-inspector audit -d your-org.okta.com -t $OKTA_API_TOKEN
```

### Build from source

```bash
go install github.com/ethanolivertroy/go-go-okta-inspector@latest
```

Or clone and build:

```bash
git clone https://github.com/ethanolivertroy/go-go-okta-inspector.git
cd go-go-okta-inspector
make build
```

## Quick Start

```bash
# Run a compliance audit
go-go-okta-inspector audit -d your-org.okta.com -t YOUR_API_TOKEN

# Launch interactive TUI
go-go-okta-inspector interactive -d your-org.okta.com -t YOUR_API_TOKEN

# Generate reports from a saved snapshot
go-go-okta-inspector report -s snapshot.json -f markdown

# Start MCP server for AI assistant integration
go-go-okta-inspector serve-mcp
```

## Commands

| Command | Description |
|---------|-------------|
| `audit` | Run compliance audit against an Okta tenant |
| `interactive` | Launch interactive TUI with real-time dashboard |
| `report` | Generate reports from saved snapshot data |
| `serve-mcp` | Start Model Context Protocol server for Claude/Cursor |
| `config` | Manage configuration (init, set, show) |
| `build` | Compile restricted binaries using capability manifest |
| `version` | Print version information |

## Features

- **70+ automated compliance checks** across 6 frameworks
- **Single binary** — no runtime dependencies, no Python, no pip
- **Interactive TUI** — browse findings with a real-time dashboard
- **Snapshot replay** — save API responses for offline analysis
- **MCP server** — integrate with Claude Code, Cursor, and other AI tools
- **Rate limiting** — automatic handling with exponential backoff
- **Pagination** — handles large Okta tenants with thousands of users
- **Build restrictions** — create least-privilege binaries via capability manifest

## Compliance Coverage

### FedRAMP (NIST 800-53)
- **Access Control**: AC-2, AC-7, AC-8, AC-11, AC-12
- **Audit and Accountability**: AU-2, AU-3, AU-4, AU-6
- **Identification and Authentication**: IA-2, IA-5
- **System and Communications**: SC-13
- **System and Information Integrity**: SI-4

### DISA STIG V1R1
- 24 requirements checked (19 fully automated, 4 partially automated, 1 manual-only)
- Session management, authentication, password policy, logging, advanced auth

### IRAP (Australian ISM)
- Information Security Manual controls
- Essential Eight assessment
- Domain verification for .gov.au

### ISMAP (Japanese ISO 27001:2013)
- Cloud service security controls
- Domain verification for .go.jp

### SOC 2
- CC6 Trust Service Criteria (logical and physical access)

### PCI-DSS 4.0
- Requirements 7 (access control) and 8 (authentication)

## API Permissions Required

### Creating a Read-Only API Token

1. Log in to your Okta Admin Console
2. Navigate to **Security** > **API** > **Tokens**
3. Click **Create Token**
4. Name your token (e.g., "Audit Read-Only")
5. Copy the token value immediately

### Required Permissions

**User Management**
- `okta.users.read` — Read user profiles and status
- `okta.groups.read` — Read group memberships
- `okta.apps.read` — Read application assignments

**Authentication & Security**
- `okta.authenticators.read` — Read authenticator configurations
- `okta.authorizationServers.read` — Read authorization server settings
- `okta.idps.read` — Read identity provider configurations
- `okta.trustedOrigins.read` — Read trusted origins

**Policies**
- `okta.policies.read` — Read all policy types (sign-on, password, MFA, access, lifecycle, authentication)

**Logging & Monitoring**
- `okta.logs.read` — Read system logs
- `okta.eventHooks.read` — Read event hook configurations
- `okta.logStreams.read` — Read log streaming configurations

**System Configuration**
- `okta.orgs.read` — Read organization settings
- `okta.factors.read` — Read factor configurations
- `okta.deviceAssurance.read` — Read device assurance policies
- `okta.networkZones.read` — Read network zones
- `okta.behaviors.read` — Read behavior detection settings

### Alternative: Admin Roles

Instead of granular permissions, use one of these read-only admin roles:
- **Read-Only Administrator** — Full read access
- **Compliance Administrator** — Designed for compliance auditing
- **Report Administrator** — Access to reports and logs

### Token Security

- Use a dedicated service account, not personal credentials
- Rotate tokens every 90 days
- Store tokens via environment variables or secrets management (`OKTA_API_TOKEN`)
- Monitor usage through Okta system logs
- Revoke immediately when no longer needed

## Output Structure

```
audit_results/
├── core_data/              # Raw API responses (JSON)
├── analysis/               # Processed findings
├── compliance/             # Framework-specific reports
│   ├── executive_summary.md
│   ├── unified_compliance_matrix.md
│   ├── disa_stig/
│   ├── irap/
│   ├── ismap/
│   ├── soc2/
│   └── pci_dss/
└── QUICK_REFERENCE.md
```

## Prior Art

This is a ground-up Go rewrite of [okta-inspector](https://github.com/ethanolivertroy/okta-inspector) (archived), which was originally written in Python and Bash.

## License

GNU General Public License v3.0 — see [COPYING](COPYING).

## Acknowledgments

- [Okta Developer API](https://developer.okta.com/) for comprehensive documentation
- Built with [Cobra](https://github.com/spf13/cobra), [Bubble Tea](https://github.com/charmbracelet/bubbletea), and [Lip Gloss](https://github.com/charmbracelet/lipgloss)
