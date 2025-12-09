# Leakos

![](leakos.png)

**Multi-tool secret scanner that searches for secrets in GitHub repositories and web responses using gitleaks, trufflehog, Rex, noseyparker, ggshield, and kingfisher.**

## 🚀 Features

- **Multiple Secret Scanning Tools**: Integrates 6 powerful tools:
  - [gitleaks](https://github.com/gitleaks/gitleaks) - Fast and configurable secrets scanner
  - [trufflehog](https://github.com/trufflesecurity/trufflehog) - Find credentials with verification
  - [Rex](https://github.com/JaimePolop/RExpository) - Custom regex-based scanner
  - [noseyparker](https://github.com/praetorian-inc/noseyparker) - High-precision secret detection
  - [ggshield](https://github.com/GitGuardian/ggshield) - GitGuardian's secret scanner
  - [kingfisher](https://github.com/mongodb/kingfisher) - Fast, Rust-based secret detection with validation
  
- **Automatic Deduplication**: Combines results from all tools and removes duplicates
- **GitHub Integration**: Scan entire organizations, users, and repositories
- **Web Scanning**: Find secrets in HTTP responses
- **Docker Support**: Pre-built container with all tools included
- **JSON Output**: Export findings for further processing

## 📦 Installation

### Option 1: Using Docker (Recommended)

Pull the pre-built image with all tools included:

```bash
docker pull ghcr.io/carlospolop/leakos:latest

# Run a scan
docker run -v $(pwd):/output ghcr.io/carlospolop/leakos:latest --help
```

### Option 2: Local Installation

Install all required tools and Python dependencies:

```bash
pip3 install -r requirements.txt

```bash
pip3 install -r requirements.txt

# Install scanning tools (choose your platform):

# macOS (using Homebrew)
brew install gitleaks trufflehog noseyparker ggshield kingfisher
go install github.com/JaimePolop/RExpository@latest && mv $(go env GOPATH)/bin/RExpository $(go env GOPATH)/bin/Rex

# Linux (manual installation)
# See tool-specific documentation for installation instructions
```

## 🔧 Usage

### Basic Usage

```bash
python3 leakos.py --help
```

### Scan GitHub Organization

```bash
# Scan all repos in an organization
python3 leakos.py --github-token YOUR_TOKEN --github-orgs myorg --json-file results.json

# Scan specific user repositories
python3 leakos.py --github-token YOUR_TOKEN --github-users username --json-file results.json

# Scan specific repositories
python3 leakos.py --github-token YOUR_TOKEN --github-repos owner/repo1,owner/repo2
```

### Scan Web URLs

```bash
# From a file containing URLs
python3 leakos.py --urls-file urls.txt --json-file results.json

# From stdin
cat urls.txt | python3 leakos.py --stdin-urls --json-file results.json
```

### Tool Selection

By default, all tools are used. You can disable specific tools:

```bash
# Disable specific tools
python3 leakos.py --not-gitleaks --not-trufflehog --github-token TOKEN --github-repos myrepo

# Use only verified results (trufflehog only)
python3 leakos.py --only-verified --github-token TOKEN --github-repos myrepo
```

### Advanced Options

```bash
# Avoid specific secret types
python3 leakos.py --avoid-sources "generic,test" --github-token TOKEN --github-repos myrepo

# Increase threads for faster scanning
python3 leakos.py --threads 20 --github-token TOKEN --github-orgs myorg

# Limit repos from an org or user (useful for large orgs)
python3 leakos.py --github-token TOKEN --github-orgs bigorg --max-repos 20

# Stop after 10 minutes and return results found so far
python3 leakos.py --github-token TOKEN --github-orgs bigorg --max-timeout 600

# Debug mode
python3 leakos.py --debug --github-token TOKEN --github-repos myrepo
```

## 🐳 Docker Usage

### Basic Scan

```bash
docker run -v $(pwd):/output ghcr.io/carlospolop/leakos:latest \
  --github-token YOUR_TOKEN \
  --github-orgs myorg \
  --json-file /output/results.json
```

### Web Scan

```bash
docker run -v $(pwd):/output ghcr.io/carlospolop/leakos:latest \
  --urls-file /output/urls.txt \
  --json-file /output/results.json
```

## 🔄 Deduplication

Leakos automatically deduplicates findings across all tools. When the same secret is found by multiple tools:
- The first detection is stored with its tool name
- Subsequent detections of the same secret are ignored
- Results include which tool found each unique secret

This significantly reduces noise and review time when using multiple scanners.

## 📊 Output Format

Results are stored in JSON format:

```json
{
  "secret_value": {
    "name": "secret_value",
    "match": "AKIAIOSFODNN7EXAMPLE",
    "description": "AWS Access Key",
    "url": "https://github.com/org/repo",
    "verified": true,
    "tool": "trufflehog"
  }
}
```

## 🔑 GitHub Token

For GitHub scanning, you need a personal access token. The token **doesn't need any permissions** unless you need to access private repositories.

Generate a token at: https://github.com/settings/tokens

## 🛠️ Command-Line Options

### GitHub Options
- `--github-token` - GitHub personal access token
- `--github-orgs` - Comma-separated organization names
- `--github-users` - Comma-separated user names
- `--github-repos` - Comma-separated repository names (owner/repo format)
- `--github-orgs-file` - File containing organization names
- `--github-users-file` - File containing user names
- `--github-repos-file` - File containing repository names

### Web Scanning Options
- `--urls-file` - File containing URLs to scan
- `--stdin-urls` - Read URLs from stdin
- `--not-exts` - Comma-separated extensions to skip (default: archives, images, etc.)
- `--max-urls` - Maximum number of URLs to scan
- `--max-repos` - Maximum number of repos to check from orgs/users (default: 50)
- `--max-timeout` - Maximum total execution time in seconds (0 for unlimited, default: 0)

### Tool Selection
- `--not-gitleaks` - Disable gitleaks
- `--not-trufflehog` - Disable trufflehog
- `--not-rex` - Disable Rex
- `--not-noseyparker` - Disable noseyparker
- `--not-ggshield` - Disable ggshield
- `--not-kingfisher` - Disable kingfisher
- `--only-verified` - Only show verified secrets (trufflehog only)
- `--from-trufflehog-only-verified` - Get only verified results from trufflehog

### Output Options
- `--json-file` - Save results to JSON file
- `--debug` - Enable debug output
- `--threads` - Number of concurrent threads (default: 10)

### Filtering Options
- `--avoid-sources` - Comma-separated list of source types to ignore
- `--max-secret-length` - Maximum length of secrets to report (default: 1500)
- `--generic-leak-in-web` - Accept generic leaks in web scanning
- `--add-org-repos-forks` - Include forked repositories from organizations
- `--add-user-repos-forks` - Include forked repositories from users

### Tool-Specific Options
- `--rex-regex-path` - Custom regex file for Rex
- `--rex-all-regexes` - Use all Rex regexes (more results, more noise)
- `--tools-timeout` - Timeout in seconds for tool execution (default: 300)

## 🏗️ Building the Docker Image

To build the Docker image locally:

```bash
docker build -t leakos:local .
```

The image includes all six scanning tools and is updated weekly via GitHub Actions.

## 🔗 Related Projects

If you like **Leakos**, check out:
- **[Gorks](https://github.com/carlospolop/Gorks)** - GitHub Organization Recon and Knowledge Scanner
- **[Pastos](https://github.com/carlospolop/Pastos)** - Pastebin scraper for sensitive information

## 📝 License

See LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or pull requests.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always ensure you have permission before scanning any systems or repositories.

