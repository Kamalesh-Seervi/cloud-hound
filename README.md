![GitHub License](https://img.shields.io/github/license/Kamalesh-Seervi/cloudhound)
![Go version](https://img.shields.io/badge/Go-1.16%2B-blue)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

**Cloudhound** is an advanced cloud storage bucket scanner that discovers publicly accessible AWS S3 and Google Cloud Storage buckets. It uses sophisticated techniques to identify exposed data while efficiently deduplicating content and prioritizing potentially sensitive information.

## 🚨 Responsible Usage Notice

This tool is designed for security researchers, penetration testers, and organizations assessing their own cloud security posture. Only use it to discover buckets that are intentionally configured for public access. Always:

- Respect rate limits
- Follow responsible disclosure principles
- Adhere to applicable laws and regulations

## ✨ Features

- **Multi-cloud support**: Scan both AWS S3 and Google Cloud Storage
- **Advanced bucket discovery**: Uses permutations, common patterns, company names, and dictionary-based approaches
- **Intelligent prioritization**: Ranks discovered files by potential sensitivity (credentials, configs, databases first)
- **Database-backed deduplication**: Avoids redundant downloads through content hashing
- **Concurrent scanning**: Configurable parallelism for performance optimization
- **Persistent tracking**: Maintains a database of discovered buckets and objects between runs

## 📋 Requirements

- Go 1.16 or higher
- SQLite3 development libraries
- Sufficient disk space for downloads

## 🔧 Installation

### Option 1: Build from source

```bash
# Clone the repository
git clone https://github.com/yourusername/cloudhound.git
cd cloudhound

# Install dependencies
go get github.com/mattn/go-sqlite3

# Build the binary
go build -o cloudhound cmd/cloudhound.go
```

### Option 2: Using go install

```bash
go install github.com/yourusername/cloudhound@latest
```

### Option 3: Download pre-built binary

Visit the [Releases](https://github.com/yourusername/cloudhound/releases) page to download a pre-built binary for your platform.

## 🚀 Usage

### Basic usage

```bash
# Run with default settings (scans AWS and GCP, uses built-in name generation)
./cloudhound

# Specify an output directory
./cloudhound --output ./discovered_files
```

### Advanced usage

```bash
# Focus on AWS buckets with higher concurrency
./cloudhound --provider aws --concurrent 50

# Use a custom wordlist along with generated names
./cloudhound --wordlist wordlists/my_custom_list.txt --permutations

# Maximum discovery mode
./cloudhound --common-prefixes --dictionary --random --random-count 1000

# Targeted discovery mode (more efficient)
./cloudhound --permutations false --dictionary true --common-prefixes true --random false

# Skip video files and limit max file size
./cloudhound --skip-videos --max-video-size 50
```

### All available options

```
Usage of cloudhound:
  --provider string        Cloud provider to scan: aws, gcp, or both (default "both")
  --skip-videos           Skip downloading video files
  --max-video-size int    Maximum video size to download in MB (default 100)
  --wordlist string       Path to wordlist file with bucket names to try
  --concurrent int        Maximum number of concurrent bucket checks (default 20)
  --output string         Directory to save downloaded files (default "downloads")
  --permutations          Generate permutations of common bucket names (default true)
  --common-prefixes       Use common company prefixes/suffixes (default true)
  --dictionary            Use internal dictionary of high-value bucket names (default true)
  --random                Include random bucket name generation (default true)
  --random-count int      Number of random bucket names to generate (default 500)
  --max-per-bucket int    Maximum files to download per bucket (default 50)
```

## 📝 Custom Wordlists

While Cloudhound includes built-in name generation, you can provide custom wordlists in simple text format:

```
# Example wordlist.txt
company-backups
customer-data
assets-prod
deployment-files
config-backups
database-dumps
```

## 📊 Understanding Results

When Cloudhound runs, it creates several important files:

- `bucket_scanner.db`: SQLite database containing all discovered buckets and objects
- `bucket_scanner.log`: Detailed log of all operations
- `public_buckets.txt`: Simple list of all discovered public buckets
- `downloads/`: Directory containing all downloaded files, organized by provider and bucket

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Commit your changes**:
   ```bash
   git commit -m 'Add some amazing feature'
   ```
4. **Push to the branch**:
   ```bash
   git push origin feature/amazing-feature
   ```
5. **Open a Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/cloudhound.git
cd cloudhound

# Install development dependencies
go get -u github.com/golangci/golangci-lint/cmd/golangci-lint

# Run tests
go test ./...

# Run linter
golangci-lint run
```

### Code Style

We follow standard Go coding conventions. Please run `gofmt` on your code before submitting a PR.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Security

If you discover a security vulnerability within Cloudhound, please send an email to security@example.com. All security vulnerabilities will be promptly addressed.

## 📚 Documentation

For more detailed documentation, visit our [Wiki](https://github.com/yourusername/cloudhound/wiki).

## ✨ Acknowledgements

- The Go community for the excellent language and libraries
- All our [contributors](https://github.com/yourusername/cloudhound/graphs/contributors)
- Inspiration from similar tools like S3Scanner, GCPBucketBrute, and others

---

⭐ If you find Cloudhound useful, please consider giving it a star on GitHub!
