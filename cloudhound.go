package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Configuration constants
const (
	LogFile           = "bucket_scanner.log"
	DownloadDir       = "downloads"
	DatabasePath      = "bucket_scanner.db"
	MaxDownloadSizeGB = 5
	MaxDownloadSizeKB = MaxDownloadSizeGB * 1024 * 1024
	MaxVideoSizeMB    = 100 // Skip videos larger than this
	UserAgent         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	Timeout           = 15 * time.Second
	ScanRateLimit     = 200 * time.Millisecond // Limit scan rate to avoid IP blocking
)

// CLI flags
var (
	cloudProvider        string
	skipVideoFlag        bool
	maxVideoSizeMB       int
	wordlistPath         string
	maxGoroutines        int
	outputDir            string
	permutationsFlag     bool
	useCommonPrefixes    bool
	useDictionary        bool
	checkShodan          bool
	randomScanFlag       bool
	randomScanCount      int
	maxDownloadPerBucket int
)

var (
	logger  *log.Logger
	logFile *os.File
	db      *sql.DB
)

// Cloud provider response structures
type S3ListBucketResult struct {
	XMLName  xml.Name    `xml:"ListBucketResult"`
	Contents []S3Content `xml:"Contents"`
}

type S3Content struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	Size         int64  `xml:"Size"`
}

type GCSListBucketResult struct {
	Kind  string    `json:"kind"`
	Items []GCSItem `json:"items"`
}

type GCSItem struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Size string `json:"size,omitempty"`
}

// CloudObject represents a file in cloud storage
type CloudObject struct {
	Key        string
	Size       int64
	Provider   string
	URL        string
	BucketName string
	Hash       string
}

// BucketResult represents the result of a bucket check
type BucketResult struct {
	Name        string
	IsPublic    bool
	Provider    string
	ObjectCount int
	Error       error
}

func init() {
	flag.StringVar(&cloudProvider, "provider", "both", "Cloud provider to scan: aws, gcp, or both")
	flag.BoolVar(&skipVideoFlag, "skip-videos", false, "Skip downloading video files")
	flag.IntVar(&maxVideoSizeMB, "max-video-size", MaxVideoSizeMB, "Maximum video size to download (MB)")
	flag.StringVar(&wordlistPath, "wordlist", "", "Path to wordlist file with bucket names to try")
	flag.IntVar(&maxGoroutines, "concurrent", 20, "Maximum number of concurrent bucket checks")
	flag.StringVar(&outputDir, "output", DownloadDir, "Directory to save downloaded files")
	flag.BoolVar(&permutationsFlag, "permutations", true, "Generate permutations of common bucket names")
	flag.BoolVar(&useCommonPrefixes, "common-prefixes", true, "Use common company prefixes/suffixes")
	flag.BoolVar(&useDictionary, "dictionary", true, "Use internal dictionary of high-value bucket names")
	flag.BoolVar(&checkShodan, "shodan", false, "Query Shodan for potential buckets (requires SHODAN_API_KEY env var)")
	flag.BoolVar(&randomScanFlag, "random", true, "Include random bucket name generation")
	flag.IntVar(&randomScanCount, "random-count", 500, "Number of random bucket names to generate")
	flag.IntVar(&maxDownloadPerBucket, "max-per-bucket", 50, "Maximum files to download per bucket")
}

func setupLogger() error {
	var err error
	logFile, err = os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	logger = log.New(logFile, "", 0)
	return nil
}

func logMessage(message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")
	logger.Printf("[%s] %s", timestamp, message)
	fmt.Println(message)
}

// Initialize the database
func setupDatabase() error {
	var err error
	db, err = sql.Open("sqlite3", DatabasePath)
	if err != nil {
		return err
	}

	// Create tables if they don't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS buckets (
			name TEXT PRIMARY KEY,
			provider TEXT,
			discovery_time TIMESTAMP,
			object_count INTEGER,
			last_checked TIMESTAMP
		);
		
		CREATE TABLE IF NOT EXISTS objects (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			bucket_name TEXT,
			provider TEXT,
			key_name TEXT,
			size INTEGER,
			hash TEXT,
			downloaded BOOLEAN,
			download_time TIMESTAMP,
			UNIQUE(bucket_name, provider, key_name)
		);
		
		CREATE INDEX IF NOT EXISTS idx_object_hash ON objects(hash);
	`)

	return err
}

// Checks if an object with the same hash already exists in the database
func isDuplicateObject(hash string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM objects WHERE hash = ?", hash).Scan(&count)
	return count > 0, err
}

// Store a bucket in the database
func storeBucket(name, provider string, objectCount int) error {
	_, err := db.Exec(
		"INSERT OR REPLACE INTO buckets (name, provider, discovery_time, object_count, last_checked) VALUES (?, ?, ?, ?, ?)",
		name, provider, time.Now(), objectCount, time.Now())
	return err
}

// Store an object in the database
func storeObject(object CloudObject, downloaded bool) error {
	_, err := db.Exec(
		"INSERT OR REPLACE INTO objects (bucket_name, provider, key_name, size, hash, downloaded, download_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
		object.BucketName, object.Provider, object.Key, object.Size, object.Hash, downloaded, time.Now())
	return err
}

// Check if a bucket has already been discovered
func isBucketKnown(name, provider string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM buckets WHERE name = ? AND provider = ?", name, provider).Scan(&count)
	return count > 0, err
}

// Update a bucket's last checked time
func updateBucketLastChecked(name, provider string) error {
	_, err := db.Exec("UPDATE buckets SET last_checked = ? WHERE name = ? AND provider = ?",
		time.Now(), name, provider)
	return err
}

// Get file hash
func getFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Get data hash
func getDataHash(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

// Check if an AWS S3 bucket is publicly accessible and return its objects
func checkS3Bucket(bucketName string) (bool, []CloudObject, error) {
	s3Endpoint := fmt.Sprintf("https://%s.s3.amazonaws.com", bucketName)

	client := &http.Client{Timeout: Timeout}
	req, err := http.NewRequest("GET", s3Endpoint, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	// Check if bucket exists and is accessible
	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("bucket returned status: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}

	// Try to parse as bucket listing XML
	var result S3ListBucketResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return false, nil, err
	}

	// Check if we got any contents
	if len(result.Contents) == 0 {
		return true, []CloudObject{}, nil // Bucket exists but is empty
	}

	var objects []CloudObject
	for _, item := range result.Contents {
		// Generate a hash for deduplication based on content characteristics
		hashInput := fmt.Sprintf("%s:%s:%d", bucketName, item.Key, item.Size)
		hash := getDataHash([]byte(hashInput))

		objects = append(objects, CloudObject{
			Key:        item.Key,
			Size:       item.Size,
			Provider:   "aws",
			URL:        fmt.Sprintf("%s/%s", s3Endpoint, item.Key),
			BucketName: bucketName,
			Hash:       hash,
		})
	}

	return true, objects, nil
}

// Check if a GCP Storage bucket is publicly accessible and return its objects
func checkGCSBucket(bucketName string) (bool, []CloudObject, error) {
	// Try the JSON API endpoint
	jsonEndpoint := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o", bucketName)

	client := &http.Client{Timeout: Timeout}
	req, err := http.NewRequest("GET", jsonEndpoint, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	// Check if bucket exists and is accessible
	if resp.StatusCode != http.StatusOK {
		// Try alternative direct access
		directEndpoint := fmt.Sprintf("https://storage.googleapis.com/%s", bucketName)
		directReq, err := http.NewRequest("GET", directEndpoint, nil)
		if err != nil {
			return false, nil, err
		}
		directReq.Header.Set("User-Agent", UserAgent)

		directResp, err := client.Do(directReq)
		if err != nil {
			return false, nil, err
		}
		defer directResp.Body.Close()

		if directResp.StatusCode != http.StatusOK {
			return false, nil, fmt.Errorf("bucket returned status: %d", directResp.StatusCode)
		}

		// Bucket is accessible but can't list via API
		return true, []CloudObject{}, nil
	}

	var result GCSListBucketResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return true, []CloudObject{}, nil
	}

	var objects []CloudObject
	for _, item := range result.Items {
		size, _ := strconv.ParseInt(item.Size, 10, 64)

		// Generate a hash for deduplication
		hashInput := fmt.Sprintf("%s:%s:%d", bucketName, item.Name, size)
		hash := getDataHash([]byte(hashInput))

		objects = append(objects, CloudObject{
			Key:        item.Name,
			Size:       size,
			Provider:   "gcp",
			URL:        fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucketName, item.Name),
			BucketName: bucketName,
			Hash:       hash,
		})
	}

	return true, objects, nil
}

// Download a file from a cloud storage object
func downloadCloudObject(object CloudObject, skipLargeVideos bool, maxVideoSize int) error {
	// Check if file is a video
	isVideoFile := isVideo(object.Key)
	if isVideoFile && skipLargeVideos && isLargeFile(object.Size, maxVideoSize) {
		logMessage(fmt.Sprintf("Skipping large video file: %s (%.2f MB) from %s bucket %s",
			object.Key, float64(object.Size)/(1024*1024), object.Provider, object.BucketName))
		return nil
	}

	// Create destination path
	destination := filepath.Join(outputDir, object.Provider, object.BucketName, object.Key)
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Download the file
	client := &http.Client{Timeout: Timeout}
	req, err := http.NewRequest("GET", object.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Read content into memory first for hash verification
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Verify content hash to ensure we don't save duplicates
	contentHash := getDataHash(content)
	isDuplicate, err := isDuplicateObject(contentHash)
	if err != nil {
		return err
	}

	if isDuplicate {
		// Update object record but skip downloading
		object.Hash = contentHash
		storeObject(object, false)
		return fmt.Errorf("duplicate content detected, skipping download")
	}

	// Save the file
	err = ioutil.WriteFile(destination, content, 0644)
	if err != nil {
		return err
	}

	// Update object hash with actual content hash
	object.Hash = contentHash
	err = storeObject(object, true)
	if err != nil {
		return err
	}

	return nil
}

// Check if filename is a video based on extension
func isVideo(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	videoExts := map[string]bool{
		".mp4": true, ".avi": true, ".mov": true, ".wmv": true,
		".flv": true, ".mkv": true, ".webm": true, ".m4v": true,
		".3gp": true, ".mpg": true, ".mpeg": true, ".ts": true,
	}

	if videoExts[ext] {
		return true
	}

	// Also check MIME type
	mimeType := mime.TypeByExtension(ext)
	return strings.HasPrefix(mimeType, "video/")
}

// Check if file size exceeds threshold
func isLargeFile(size int64, maxSizeMB int) bool {
	return size > int64(maxSizeMB*1024*1024) // Convert MB to bytes
}

// Generate bucket name permutations
func generateBucketPermutations() []string {
	// Common company identifiers
	companies := []string{"company", "corp", "inc", "llc", "ltd", "limited", "gmbh", "plc", "co"}

	// Common cloud storage types
	types := []string{"backup", "archive", "storage", "data", "files", "media", "assets", "images", "docs", "backups"}

	// Common environments
	envs := []string{"prod", "dev", "test", "staging", "uat", "qa"}

	// Common prefixes/suffixes
	prefixes := []string{"", "my-", "our-", "the-", "public-", "private-", "internal-", "external-"}
	suffixes := []string{"", "-01", "-02", "-1", "-2", "-old", "-new", "-backup", "-archive"}

	// Additional high-value targets
	targets := []string{"config", "configs", "configuration", "secrets", "credentials", "customer", "customers",
		"user", "users", "admin", "administrator", "financial", "report", "reports", "analytics",
		"database", "databases", "db", "sql", "backup", "backups", "archive", "archives",
		"production", "development", "test", "testing", "staging", "demo", "beta", "alpha",
		"internal", "external", "public", "private", "secure", "upload", "uploads", "download", "downloads",
		"temp", "tmp", "temporary", "log", "logs", "static", "assets", "media", "content", "site",
		"website", "web", "mobile", "app", "application", "api", "cdn", "storage"}

	// Generate unique permutations
	bucketSet := make(map[string]bool)

	// Basic permutations
	for _, prefix := range prefixes {
		for _, t := range types {
			for _, suffix := range suffixes {
				bucketSet[prefix+t+suffix] = true
			}
		}

		for _, env := range envs {
			for _, t := range types {
				bucketSet[prefix+env+"-"+t] = true
				bucketSet[prefix+t+"-"+env] = true
			}
		}

		for _, company := range companies {
			for _, t := range types {
				bucketSet[prefix+company+"-"+t] = true
				bucketSet[prefix+t+"-"+company] = true
			}
		}

		for _, target := range targets {
			bucketSet[prefix+target] = true
		}
	}

	// Special permutations for high-value targets
	years := []string{"2020", "2021", "2022", "2023"}
	for _, year := range years {
		for _, t := range types {
			bucketSet[t+"-"+year] = true
			bucketSet[year+"-"+t] = true
		}
	}

	// Convert set to slice
	var buckets []string
	for b := range bucketSet {
		buckets = append(buckets, b)
	}

	return buckets
}

// Generate common company-specific bucket names
func generateCompanyBuckets() []string {
	// Common company name prefixes/suffixes in bucket names
	commonPrefixes := []string{
		"amazon", "aws", "azure", "google", "gcp", "ms", "microsoft", "apple", "github", "gitlab",
		"bitbucket", "jira", "atlassian", "dropbox", "box", "salesforce", "oracle", "sap", "ibm",
		"adobe", "netflix", "spotify", "uber", "lyft", "airbnb", "twitter", "facebook", "fb", "meta",
		"instagram", "linkedin", "snapchat", "tiktok", "reddit", "slack", "zoom", "shopify", "stripe",
		"paypal", "square", "twilio", "heroku", "digitalocean", "cloudflare", "akamai", "fastly",
	}

	// Storage related suffixes
	storageSuffixes := []string{
		"-backup", "-backups", "-data", "-storage", "-archive", "-archives", "-assets", "-static",
		"-media", "-images", "-files", "-docs", "-documents", "-content", "-public", "-private",
		"-internal", "-external", "-dev", "-prod", "-staging", "-test", "-qa", "-uat", "-beta",
	}

	var buckets []string
	for _, prefix := range commonPrefixes {
		// Add the base name
		buckets = append(buckets, prefix)

		// Add with suffixes
		for _, suffix := range storageSuffixes {
			buckets = append(buckets, prefix+suffix)
		}

		// Add bucket.io style
		buckets = append(buckets, prefix+"-bucket")
		buckets = append(buckets, prefix+".bucket")
		buckets = append(buckets, prefix+"-storage")
		buckets = append(buckets, prefix+".storage")
	}

	return buckets
}

// Add high-value target bucket names
func addHighValueTargets() []string {
	return []string{
		// Sensitive data
		"passwords", "password", "secret", "secrets", "credentials", "credential", "creds", "keys", "key",
		"apikey", "api-key", "api-keys", "apikeys", "token", "tokens", "auth", "oauth", "jwt",

		// Configuration & code
		"config", "configs", "configuration", "settings", "env", "environment", "env-vars",
		"terraform", "cloudformation", "iac", "infrastructure", "src", "source", "code", "repo",

		// Security
		"security", "pentest", "penetration-test", "vulnerability", "vulnerabilities", "scan", "scans",
		"report", "reports", "audit", "audits", "compliance", "pci", "hipaa", "gdpr", "soc",

		// Customer data
		"customer", "customers", "user", "users", "account", "accounts", "profile", "profiles",
		"client", "clients", "member", "members", "subscriber", "subscribers", "patient", "patients",

		// Financial
		"finance", "financial", "accounting", "invoice", "invoices", "payment", "payments",
		"transaction", "transactions", "receipt", "receipts", "tax", "taxes",

		// Corporate
		"hr", "human-resources", "employee", "employees", "staff", "personnel", "payroll",
		"contract", "contracts", "legal", "document", "documents", "board", "executive",

		// Logs and analytics
		"logging", "logs", "error", "errors", "exception", "exceptions", "analytics", "metrics",
		"monitoring", "alert", "alerts", "grafana", "kibana", "splunk", "datadog", "newrelic",

		// Databases
		"database", "databases", "db", "mysql", "postgres", "postgresql", "mongodb", "mongo",
		"redis", "elasticsearch", "dynamo", "dynamodb", "cassandra", "mariadb", "rds", "dump",

		// Generic high value
		"admin", "administrator", "root", "internal-only", "confidential", "restricted",
		"private", "sensitive", "personal", "pii", "phi", "ssn", "health", "healthcare",
	}
}

// Generate random bucket names
func generateRandomBucketNames(count int) []string {
	buckets := make([]string, count)

	rand.Seed(time.Now().UnixNano())

	// Character sets
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	hyphen := "-"
	allChars := lowercase + digits + hyphen

	for i := 0; i < count; i++ {
		// Random bucket name length between 5 and 20 characters
		length := rand.Intn(16) + 5

		name := make([]byte, length)

		// First character must be alphanumeric
		name[0] = lowercase[rand.Intn(len(lowercase))]

		// Rest of the characters
		for j := 1; j < length; j++ {
			// Avoid consecutive hyphens
			if j > 0 && name[j-1] == '-' {
				c := lowercase + digits
				name[j] = c[rand.Intn(len(c))]
			} else {
				name[j] = allChars[rand.Intn(len(allChars))]
			}
		}

		// Last character can't be a hyphen
		if name[length-1] == '-' {
			c := lowercase + digits
			name[length-1] = c[rand.Intn(len(c))]
		}

		buckets[i] = string(name)
	}

	return buckets
}

// Read bucket names from a wordlist file
func readBucketWordlist(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var buckets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		bucketName := strings.TrimSpace(scanner.Text())
		if bucketName != "" && !strings.HasPrefix(bucketName, "#") {
			buckets = append(buckets, bucketName)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return buckets, nil
}

// Worker function to check buckets
func bucketWorker(id int, buckets <-chan string, results chan<- BucketResult, provider string, wg *sync.WaitGroup) {
	defer wg.Done()

	for bucket := range buckets {
		// Rate limiting to avoid getting blocked
		time.Sleep(ScanRateLimit)

		// Check if bucket already known
		isKnown, err := isBucketKnown(bucket, "aws")
		if err == nil && isKnown && provider == "aws" {
			updateBucketLastChecked(bucket, "aws")
			continue
		}

		isKnown, err = isBucketKnown(bucket, "gcp")
		if err == nil && isKnown && provider == "gcp" {
			updateBucketLastChecked(bucket, "gcp")
			continue
		}

		// Check AWS S3 buckets
		if provider == "aws" || provider == "both" {
			isPublic, objects, err := checkS3Bucket(bucket)
			if err == nil && isPublic {
				logMessage(fmt.Sprintf("Found public AWS S3 bucket: %s with %d objects", bucket, len(objects)))
				storeBucket(bucket, "aws", len(objects))

				results <- BucketResult{
					Name:        bucket,
					IsPublic:    true,
					Provider:    "aws",
					ObjectCount: len(objects),
					Error:       nil,
				}
				continue // Found as AWS bucket, no need to check GCP
			}
		}

		// Check GCP Storage buckets
		if provider == "gcp" || provider == "both" {
			isPublic, objects, err := checkGCSBucket(bucket)
			if err == nil && isPublic {
				logMessage(fmt.Sprintf("Found public GCP Storage bucket: %s with %d objects", bucket, len(objects)))
				storeBucket(bucket, "gcp", len(objects))

				results <- BucketResult{
					Name:        bucket,
					IsPublic:    true,
					Provider:    "gcp",
					ObjectCount: len(objects),
					Error:       nil,
				}
				continue
			}
		}
	}
}

// Process a public bucket by downloading content
func processBucket(bucket string, provider string, skipVideos bool, maxVideoSize int, maxFiles int) error {
	var objects []CloudObject
	var err error
	var isPublic bool

	if provider == "aws" {
		isPublic, objects, err = checkS3Bucket(bucket)
	} else if provider == "gcp" {
		isPublic, objects, err = checkGCSBucket(bucket)
	} else {
		return fmt.Errorf("unknown provider: %s", provider)
	}

	if err != nil || !isPublic {
		return fmt.Errorf("bucket is not accessible: %v", err)
	}

	if len(objects) == 0 {
		return fmt.Errorf("bucket is empty")
	}

	// Sort objects by potential interest (looking for config, credentials, etc)
	sortObjectsByInterest(objects)

	// Limit number of files to download per bucket
	if len(objects) > maxFiles {
		logMessage(fmt.Sprintf("Limiting to %d files out of %d total in %s bucket %s",
			maxFiles, len(objects), provider, bucket))
		objects = objects[:maxFiles]
	}

	logMessage(fmt.Sprintf("Downloading up to %d files from %s bucket %s", len(objects), provider, bucket))

	downloadCount := 0
	for _, obj := range objects {
		// Check if this object is already in our database
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM objects WHERE bucket_name = ? AND provider = ? AND key_name = ?",
			bucket, provider, obj.Key).Scan(&count)

		if err == nil && count > 0 {
			// Skip already processed objects
			logMessage(fmt.Sprintf("Skipping already processed file: %s", obj.Key))
			continue
		}

		// Download the object
		logMessage(fmt.Sprintf("Downloading: %s (%.2f MB) from %s bucket %s",
			obj.Key, float64(obj.Size)/(1024*1024), provider, bucket))

		err = downloadCloudObject(obj, skipVideos, maxVideoSize)
		if err != nil {
			logMessage(fmt.Sprintf("Error downloading %s: %v", obj.Key, err))
			// Still track the object even if download fails
			storeObject(obj, false)
			continue
		}

		downloadCount++
	}

	logMessage(fmt.Sprintf("Successfully downloaded %d files from %s bucket %s", downloadCount, provider, bucket))
	return nil
}

// Sort objects by potential interest (puts interesting files first)
func sortObjectsByInterest(objects []CloudObject) {
	// Patterns that suggest interesting content
	interestingPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|secret|credential|key|token|auth)`),
		regexp.MustCompile(`(?i)(config|setting|env|environment)`),
		regexp.MustCompile(`(?i)(backup|dump|export|sql|database|db)`),
		regexp.MustCompile(`(?i)(user|customer|client|account|profile)`),
		regexp.MustCompile(`(?i)\.(json|yaml|yml|xml|ini|env|conf|cfg|config)$`),
		regexp.MustCompile(`(?i)\.(sql|db|sqlite|bak|backup)$`),
		regexp.MustCompile(`(?i)\.(pem|key|cert|crt|p12|pfx|jks)$`),
		regexp.MustCompile(`(?i)\.(csv|xls|xlsx|doc|docx|pdf|txt)$`),
	}

	// Score each object by how many patterns it matches
	type scoredObject struct {
		object CloudObject
		score  int
	}

	scoredObjects := make([]scoredObject, len(objects))
	for i, obj := range objects {
		score := 0
		for _, pattern := range interestingPatterns {
			if pattern.MatchString(obj.Key) {
				score++
			}
		}

		// Add score boost for files at root level (often more interesting)
		if !strings.Contains(obj.Key, "/") {
			score += 2
		}

		// Penalize large files a bit
		if obj.Size > 50*1024*1024 { // 50MB
			score -= 3
		} else if obj.Size > 10*1024*1024 { // 10MB
			score -= 1
		}

		scoredObjects[i] = scoredObject{object: obj, score: score}
	}

	// Sort descending by score
	sort.Slice(scoredObjects, func(i, j int) bool {
		return scoredObjects[i].score > scoredObjects[j].score
	})

	// Replace original objects with sorted ones
	for i, s := range scoredObjects {
		objects[i] = s.object
	}
}

// Collect bucket names from all sources
func collectBucketNames() []string {
	var allBuckets []string
	var bucketSet = make(map[string]bool)

	// Add from wordlist if provided
	if wordlistPath != "" {
		wordlistBuckets, err := readBucketWordlist(wordlistPath)
		if err == nil {
			logMessage(fmt.Sprintf("Loaded %d bucket names from wordlist", len(wordlistBuckets)))
			for _, b := range wordlistBuckets {
				bucketSet[b] = true
			}
		} else {
			logMessage(fmt.Sprintf("Error reading wordlist: %v", err))
		}
	}

	// Add from permutations if enabled
	if permutationsFlag {
		permutations := generateBucketPermutations()
		logMessage(fmt.Sprintf("Generated %d bucket name permutations", len(permutations)))
		for _, b := range permutations {
			bucketSet[b] = true
		}
	}

	// Add common company prefixes if enabled
	if useCommonPrefixes {
		companyBuckets := generateCompanyBuckets()
		logMessage(fmt.Sprintf("Generated %d company-specific bucket names", len(companyBuckets)))
		for _, b := range companyBuckets {
			bucketSet[b] = true
		}
	}

	// Add high-value targets if enabled
	if useDictionary {
		targets := addHighValueTargets()
		logMessage(fmt.Sprintf("Added %d high-value target bucket names", len(targets)))
		for _, b := range targets {
			bucketSet[b] = true
		}
	}

	// Add random bucket names if enabled
	if randomScanFlag && randomScanCount > 0 {
		randomBuckets := generateRandomBucketNames(randomScanCount)
		logMessage(fmt.Sprintf("Generated %d random bucket names", len(randomBuckets)))
		for _, b := range randomBuckets {
			bucketSet[b] = true
		}
	}

	// Convert set to slice
	for b := range bucketSet {
		allBuckets = append(allBuckets, b)
	}

	// Randomize order to distribute workload evenly
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(allBuckets), func(i, j int) {
		allBuckets[i], allBuckets[j] = allBuckets[j], allBuckets[i]
	})

	logMessage(fmt.Sprintf("Total bucket names to check: %d", len(allBuckets)))
	return allBuckets
}

func main() {
	flag.Parse()

	// Setup logger
	if err := setupLogger(); err != nil {
		fmt.Printf("Error setting up logger: %v\n", err)
		return
	}
	defer logFile.Close()

	logMessage("----- Starting Optimized Public Bucket Scraper -----")

	// Setup database
	if err := setupDatabase(); err != nil {
		logMessage(fmt.Sprintf("Error setting up database: %v", err))
		return
	}
	defer db.Close()

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logMessage(fmt.Sprintf("Error creating output directory: %v", err))
		return
	}

	// Collect bucket names from all sources
	bucketNames := collectBucketNames()
	if len(bucketNames) == 0 {
		logMessage("No bucket names to check. Exiting.")
		return
	}

	// Create channels for workload distribution
	bucketChan := make(chan string, maxGoroutines*2)
	resultChan := make(chan BucketResult, maxGoroutines*2)

	// Create worker pool
	var wg sync.WaitGroup
	for i := 0; i < maxGoroutines; i++ {
		wg.Add(1)
		go bucketWorker(i, bucketChan, resultChan, cloudProvider, &wg)
	}

	// Create a channel to signal when all workers are done
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Start sending buckets to workers
	go func() {
		for _, bucket := range bucketNames {
			bucketChan <- bucket
		}
		close(bucketChan)
	}()

	// Process results as they come in
	publicBuckets := make(map[string]string) // bucket name -> provider
	resultsCount := 0
	maxResults := len(bucketNames)
	progressInterval := maxResults / 20 // Report progress every 5%
	if progressInterval < 1 {
		progressInterval = 1
	}

	// Process results until all workers are done
checkResults:
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				break checkResults
			}

			resultsCount++
			if result.IsPublic {
				publicBuckets[result.Name] = result.Provider
				logMessage(fmt.Sprintf("[%d/%d] Found public %s bucket: %s with %d objects",
					resultsCount, maxResults, result.Provider, result.Name, result.ObjectCount))

				// Process bucket immediately to avoid waiting
				go func(bucket string, provider string) {
					processBucket(bucket, provider, skipVideoFlag, maxVideoSizeMB, maxDownloadPerBucket)
				}(result.Name, result.Provider)
			} else if resultsCount%progressInterval == 0 {
				logMessage(fmt.Sprintf("[%d/%d] Checked buckets... Found %d public buckets so far",
					resultsCount, maxResults, len(publicBuckets)))
			}

		case <-done:
			// All workers finished
			close(resultChan)
			for result := range resultChan {
				if result.IsPublic {
					publicBuckets[result.Name] = result.Provider
				}
			}
			break checkResults
		}
	}

	logMessage(fmt.Sprintf("Finished checking. Found %d public buckets.", len(publicBuckets)))

	// Save list of public buckets
	if len(publicBuckets) > 0 {
		publicBucketsFile, err := os.Create("public_buckets.txt")
		if err == nil {
			for bucket, provider := range publicBuckets {
				publicBucketsFile.WriteString(fmt.Sprintf("%s:%s\n", provider, bucket))
			}
			publicBucketsFile.Close()
			logMessage("Saved list of public buckets to public_buckets.txt")
		}
	}

	logMessage("----- Finished -----")
}
