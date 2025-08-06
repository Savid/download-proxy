package main

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Metrics
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests made.",
		},
		[]string{"method", "endpoint", "status_code"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	fileDownloadsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "file_downloads_total",
			Help: "Total number of files downloaded.",
		},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(fileDownloadsTotal)
}

const (
	defaultPort = "5050"
)

var (
	port                    = getEnv("PORT", defaultPort)
	watcherPath             = getEnv("DOWNLOAD_PATH", "./watched/")
	token                   = getEnv("AUTH_TOKEN", "")
	upstreamDomain          = getEnv("UPSTREAM_DOMAIN", "")
	downloadURLPattern      = getEnv("DOWNLOAD_URL_PATTERN", "")
	detailsURLPattern       = getEnv("DETAILS_URL_PATTERN", "")
	downloadFileExtension   = getEnv("DOWNLOAD_FILE_EXTENSION", "")
	downloadLinkPatterns    = getEnv("DOWNLOAD_LINK_PATTERNS", "")
	upstreamRandomSubdomain = getEnv("UPSTREAM_RANDOM_SUBDOMAIN", "false")
	upstreamHost            string // Will be constructed from domain and subdomain
	injectCode              string
	client                  = &http.Client{
		Timeout: 30 * time.Second,
	}

	// Client that doesn't follow redirects for proxy requests
	proxyClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Variables for rotating subdomain
	currentRandomHost string
	lastRotation      time.Time
	rotationMutex     sync.RWMutex
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getUpstreamHost() string {
	if upstreamRandomSubdomain == "true" {
		rotationMutex.RLock()
		// Check if we need to rotate (10 minutes have passed)
		if time.Since(lastRotation) > 10*time.Minute || currentRandomHost == "" {
			rotationMutex.RUnlock()

			// Need to rotate, acquire write lock
			rotationMutex.Lock()
			// Double check after acquiring write lock
			if time.Since(lastRotation) > 10*time.Minute || currentRandomHost == "" {
				// Generate new random subdomain
				randomBytes := make([]byte, 10)
				if _, err := rand.Read(randomBytes); err != nil {
					log.Printf("[ERROR] Failed to generate random subdomain: %v", err)
					currentRandomHost = getDefaultUpstreamHost()
				} else {
					randomSubdomain := hex.EncodeToString(randomBytes)
					currentRandomHost = fmt.Sprintf("http://%s.%s", randomSubdomain, upstreamDomain)
					log.Printf("[INFO] Rotating to new upstream host: %s", currentRandomHost)
				}
				lastRotation = time.Now()
			}
			rotationMutex.Unlock()
			return currentRandomHost
		}

		// No rotation needed, return current host
		host := currentRandomHost
		rotationMutex.RUnlock()
		return host
	}
	return getDefaultUpstreamHost()
}

func getDefaultUpstreamHost() string {
	// Use the domain as-is with https by default
	if strings.HasPrefix(upstreamDomain, "http://") || strings.HasPrefix(upstreamDomain, "https://") {
		return upstreamDomain
	}
	return "https://" + upstreamDomain
}

type ApiResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Category string `json:"category,omitempty"`
	Error    string `json:"error,omitempty"`
}

func initInjectionCode() {
	// Variables to be filled
	var cssSelector, jsSelector, regexPattern string

	// Validate environment variable
	if downloadLinkPatterns == "" {
		log.Fatal("DOWNLOAD_LINK_PATTERNS environment variable is required")
	}

	// Parse download link patterns
	patterns := strings.Split(downloadLinkPatterns, ",")
	log.Printf("[DEBUG] Raw downloadLinkPatterns: '%s'", downloadLinkPatterns)
	for i, p := range patterns {
		patterns[i] = strings.TrimSpace(p)
	}
	log.Printf("[DEBUG] Parsed patterns: %v", patterns)

	// Ensure we have patterns
	if len(patterns) == 0 || (len(patterns) == 1 && patterns[0] == "") {
		log.Fatal("DOWNLOAD_LINK_PATTERNS cannot be empty after parsing")
	}

	// Build CSS selector for download links
	cssSelectors := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern != "" {
			cssSelectors = append(cssSelectors, fmt.Sprintf(`a[href*="%s"]`, pattern))
		}
	}
	cssSelector = strings.Join(cssSelectors, ", ")

	// Build JavaScript selectors
	jsSelectors := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern != "" {
			// Escape any quotes in the pattern
			escapedPattern := strings.ReplaceAll(pattern, `"`, `\"`)
			jsSelectors = append(jsSelectors, fmt.Sprintf(`a[href*="%s"]`, escapedPattern))
		}
	}
	jsSelector = strings.Join(jsSelectors, ", ")

	// Build regex pattern for JavaScript matching
	regexParts := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern != "" {
			// Escape dots and other regex special characters
			escaped := strings.ReplaceAll(pattern, ".", "\\.")
			escaped = strings.ReplaceAll(escaped, "/", "\\/")
			regexParts = append(regexParts, escaped)
		}
	}
	regexPattern = fmt.Sprintf("/(%s)\\/\\d+\\/.+\\.\\w+$/", strings.Join(regexParts, "|"))

	// Ensure selectors are valid
	if cssSelector == "" || jsSelector == "" {
		log.Fatal("Failed to generate valid selectors from DOWNLOAD_LINK_PATTERNS")
	}

	// Debug logging - print with quotes to see empty strings
	log.Printf("[DEBUG] CSS Selector: '%s' (len=%d)", cssSelector, len(cssSelector))
	log.Printf("[DEBUG] JS Selector: '%s' (len=%d)", jsSelector, len(jsSelector))
	log.Printf("[DEBUG] Regex Pattern: '%s' (len=%d)", regexPattern, len(regexPattern))

	// Everything in one injection - styles and modal
	injectCode = fmt.Sprintf(`
<style>
/* Mobile improvements for the site */
@media (max-width: 768px) {
  /* Make the site more responsive */
  body {
    font-size: 14px !important;
    -webkit-text-size-adjust: 100%% !important;
  }

  /* Fix tables on mobile */
  table {
    display: block !important;
    overflow-x: auto !important;
    -webkit-overflow-scrolling: touch !important;
  }

  /* Improve tap targets */
  a, button, input[type="submit"], input[type="button"] {
    min-height: 44px !important;
    min-width: 44px !important;
    padding: 8px 12px !important;
  }

  /* Fix overflowing content */
  div, td, th {
    word-wrap: break-word !important;
    overflow-wrap: break-word !important;
  }

  /* Make download links easier to tap */
  %s {
    display: inline-block !important;
    padding: 10px !important;
    margin: 5px 0 !important;
  }

  /* Improve form inputs */
  input[type="text"], input[type="password"], select, textarea {
    font-size: 16px !important; /* Prevents zoom on iOS */
    max-width: 100%% !important;
  }

  /* Better spacing */
  td, th {
    padding: 8px 5px !important;
  }

  /* Make images responsive */
  img {
    max-width: 100%% !important;
    height: auto !important;
  }

  /* Fix navigation */
  .nav, .menu, nav {
    display: flex !important;
    flex-wrap: wrap !important;
  }

  /* Hide non-essential columns on mobile */
  @media (max-width: 480px) {
    td:nth-child(n+6), th:nth-child(n+6) {
      display: none !important;
    }
  }
}

#ipt-modal-overlay {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%%;
  height: 100%%;
  background-color: rgba(0, 0, 0, 0.7);
  z-index: 999999;
}

#ipt-modal-overlay.show {
  display: block;
}

#ipt-modal {
  position: fixed;
  top: 50%%;
  left: 50%%;
  transform: translate(-50%%, -50%%);
  background: #fff;
  padding: 30px;
  border-radius: 10px;
  box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
  text-align: center;
  min-width: 300px;
  max-width: 90%%;
  max-height: 90vh;
  overflow-y: auto;
}

@media (max-width: 600px) {
  #ipt-modal {
    padding: 20px;
    min-width: 280px;
    max-width: 95%%;
  }

  #ipt-modal h3 {
    font-size: 1.2em;
    margin: 0 0 15px 0;
  }

  #ipt-modal p {
    font-size: 0.95em;
    margin: 10px 0;
  }

  #ipt-modal button {
    width: 100%%;
    margin: 5px 0;
    padding: 15px 20px;
    font-size: 16px; /* Prevents zoom on iOS */
  }
}

#ipt-modal h3 {
  margin: 0 0 20px 0;
  color: #333;
}

#ipt-modal button {
  margin: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  font-size: 16px;
  transition: background-color 0.3s;
}

#ipt-modal button:hover {
  opacity: 0.9;
}

#ipt-modal button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

#ipt-server-btn {
  background-color: #4CAF50;
  color: white;
}

#ipt-local-btn {
  background-color: #2196F3;
  color: white;
}

#ipt-close-btn {
  background-color: #f44336;
  color: white;
}

#ipt-loader {
  display: none;
  margin: 20px auto;
  border: 4px solid #f3f3f3;
  border-radius: 50%%;
  border-top: 4px solid #3498db;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0%% { transform: rotate(0deg); }
  100%% { transform: rotate(360deg); }
}

#ipt-status {
  margin-top: 15px;
  font-weight: bold;
}

.success { color: #4CAF50; }
.error { color: #f44336; }
</style>

<div id="ipt-modal-overlay">
  <div id="ipt-modal">
    <h3>Download Options</h3>
    <p>Choose your download method:</p>
    <button id="ipt-server-btn">Download Server-side</button>
    <button id="ipt-local-btn">Download Locally</button>
    <button id="ipt-close-btn">Cancel</button>
    <div id="ipt-loader"></div>
    <div id="ipt-status"></div>
  </div>
</div>

<script>
(function() {
  var currentUrl = null;
  var hideTimer = null; // Timer for auto-hiding modal
  var modal = document.getElementById('ipt-modal-overlay');
  var loader = document.getElementById('ipt-loader');
  var status = document.getElementById('ipt-status');
  var serverBtn = document.getElementById('ipt-server-btn');
  var localBtn = document.getElementById('ipt-local-btn');
  var closeBtn = document.getElementById('ipt-close-btn');

  function showModal(url) {
    console.log('[IPT] Showing modal for:', url);
    currentUrl = url;
    resetModal();
    modal.className = 'show';
  }

  function hideModal() {
    console.log('[IPT] Hiding modal');
    modal.className = '';
    // Clear any pending hide timer
    if (hideTimer) {
      clearTimeout(hideTimer);
      hideTimer = null;
    }
  }

  function resetModal() {
    loader.style.display = 'none';
    status.textContent = '';
    status.className = '';
    serverBtn.disabled = false;
    localBtn.disabled = false;
    // Clear any pending hide timer
    if (hideTimer) {
      clearTimeout(hideTimer);
      hideTimer = null;
    }
  }
  
  function showLoader() {
    loader.style.display = 'block';
    serverBtn.disabled = true;
    localBtn.disabled = true;
  }
  
  function hideLoader() {
    loader.style.display = 'none';
    serverBtn.disabled = false;
    localBtn.disabled = false;
  }
  
  function showStatus(message, isError) {
    status.textContent = message;
    status.className = isError ? 'error' : 'success';
  }
  
  // Button handlers
  serverBtn.onclick = function() {
    if (currentUrl) {
      console.log('[IPT] Original URL:', currentUrl);

      showLoader();
      showStatus('Downloading to server...', false);

      fetch('/api/download', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: currentUrl })
      })
      .then(function(response) {
        return response.json();
      })
      .then(function(data) {
        hideLoader();
        if (data.success) {
          var message = 'Downloaded to server';
          if (data.category) {
            message += ' (' + data.category + ')';
          } else {
            message += ' (root)';
          }
          showStatus(message, false);
          hideTimer = setTimeout(hideModal, 3000);
        } else {
          showStatus(data.error || 'Failed to download', true);
        }
      })
      .catch(function(error) {
        hideLoader();
        showStatus('Error: ' + error.message, true);
      });
    }
  };
  
  localBtn.onclick = function() {
    if (currentUrl) {
      console.log('[IPT] Local download URL:', currentUrl);
      window.location.href = currentUrl;
    }
  };
  
  closeBtn.onclick = hideModal;

  // Click outside to close
  modal.onclick = function(e) {
    if (e.target === modal) {
      hideModal();
    }
  };

  // Touch support for mobile
  var touchStartY = 0;
  modal.addEventListener('touchstart', function(e) {
    if (e.target === modal) {
      touchStartY = e.touches[0].clientY;
    }
  });

  modal.addEventListener('touchend', function(e) {
    if (e.target === modal && touchStartY) {
      var touchEndY = e.changedTouches[0].clientY;
      // Only close if it's a tap, not a scroll
      if (Math.abs(touchEndY - touchStartY) < 10) {
        hideModal();
      }
      touchStartY = 0;
    }
  });

  // Keyboard event handlers
  document.addEventListener('keydown', function(e) {
    if (modal.className === 'show') {
      // Escape key
      if (e.key === 'Escape' || e.keyCode === 27) {
        e.preventDefault();
        hideModal();
      }
    }
  });

  // Prevent clicks inside the modal from closing it
  document.getElementById('ipt-modal').onclick = function(e) {
    e.stopPropagation();
  };

  // Prevent touch events inside the modal from closing it
  document.getElementById('ipt-modal').addEventListener('touchstart', function(e) {
    e.stopPropagation();
  });
  
  // Hijack download links
  function hijackLinks() {
    // Look for all links that match the download patterns
    var links = document.querySelectorAll('%s');
    var count = 0;

    for (var i = 0; i < links.length; i++) {
      var href = links[i].getAttribute('href');

      // Check if the link matches the download patterns:
      if (href && href.match(%s)) {
        if (!links[i].hasAttribute('data-ipt-hijacked')) {
          links[i].setAttribute('data-ipt-hijacked', 'true');
          links[i].addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();

            // Get the full URL (in case href is relative)
            var fullUrl = this.href || (window.location.origin + this.getAttribute('href'));
            console.log('[IPT] Hijacking click for:', fullUrl);
            showModal(fullUrl);
            return false;
          });
          count++;
        }
      }
    }

    if (count > 0) {
      console.log('[IPT] Hijacked', count, 'download links matching pattern');
    }
  }
  
  // Initial hijack
  console.log('[IPT] Initializing...');
  hijackLinks();
  
  // Watch for new links
  setInterval(hijackLinks, 1000);
  
  // Test that elements exist
  console.log('[IPT] Modal found:', !!modal);
  console.log('[IPT] Server button found:', !!serverBtn);
})();
</script>
`, cssSelector, jsSelector, regexPattern)

	// Debug the final injection code
	log.Printf("[DEBUG] First 200 chars of injection code: %s", injectCode[:200])
}

func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(wrapped.statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func main() {
	if token == "" {
		log.Fatal("AUTH_TOKEN environment variable is required")
	}

	if upstreamDomain == "" {
		log.Fatal("UPSTREAM_DOMAIN environment variable is required")
	}

	if downloadURLPattern == "" {
		log.Fatal("DOWNLOAD_URL_PATTERN environment variable is required")
	}

	if detailsURLPattern == "" {
		log.Fatal("DETAILS_URL_PATTERN environment variable is required")
	}

	if downloadFileExtension == "" {
		log.Fatal("DOWNLOAD_FILE_EXTENSION environment variable is required")
	}

	if downloadLinkPatterns == "" {
		log.Fatal("DOWNLOAD_LINK_PATTERNS environment variable is required")
	}

	// Initialize upstream host
	if upstreamRandomSubdomain == "true" {
		// Initialize the first random host
		_ = getUpstreamHost()
		log.Printf("Using upstream domain: %s with random subdomain rotation (every 10 minutes)", upstreamDomain)
	} else {
		upstreamHost = getDefaultUpstreamHost()
		log.Printf("Using upstream host: %s", upstreamHost)
	}

	// Clean up watcherPath and ensure it exists
	absWatcherPath, err := filepath.Abs(watcherPath)
	if err != nil {
		log.Printf("[WARN] Could not get absolute path for %s: %v", watcherPath, err)
		absWatcherPath = watcherPath
	}
	watcherPath = absWatcherPath

	if err := os.MkdirAll(watcherPath, 0755); err != nil {
		log.Fatalf("Failed to create watcher directory %s: %v", watcherPath, err)
	}
	log.Printf("Using download path: %s", watcherPath)

	initInjectionCode()

	router := mux.NewRouter()
	router.Use(prometheusMiddleware)

	// Metrics endpoint
	router.Handle("/metrics", promhttp.Handler())

	// API endpoint for server-side download
	router.HandleFunc("/api/download", handleAPIDownload).Methods("POST")

	// All other requests proxy to IPT
	router.PathPrefix("/").HandlerFunc(handleProxy)

	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatal(err)
	}
}

func handleAPIDownload(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] API download request from %s", r.RemoteAddr)

	// Parse request
	var requestData struct {
		URL string `json:"url"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read request body: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ApiResponse{
			Success: false,
			Error:   "Failed to read request body",
		})
		return
	}

	log.Printf("[DEBUG] Request body: %s", string(body))

	if err := json.Unmarshal(body, &requestData); err != nil {
		log.Printf("[ERROR] Failed to parse JSON: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ApiResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	log.Printf("[DEBUG] Requested URL: %s", requestData.URL)

	// Extract ID from URL
	parts := strings.Split(requestData.URL, "/")
	log.Printf("[DEBUG] URL parts: %v", parts)

	var id string
	patterns := strings.Split(downloadLinkPatterns, ",")

	// Try each pattern to find the ID
	for i, part := range parts {
		for _, pattern := range patterns {
			pattern = strings.TrimSpace(pattern)
			if part == pattern && i+1 < len(parts) {
				filenameWithQuery := parts[i+1]
				log.Printf("[DEBUG] Filename with query: %s", filenameWithQuery)

				// Split by dots to get the ID (first part before file extension)
				idParts := strings.Split(filenameWithQuery, ".")
				if len(idParts) > 0 {
					id = idParts[0]
				}
				break
			}
		}
		if id != "" {
			break
		}
	}

	if id == "" {
		log.Printf("[ERROR] Could not extract ID from URL: %s", requestData.URL)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ApiResponse{
			Success: false,
			Error:   "Could not extract file ID from URL",
		})
		return
	}

	log.Printf("[DEBUG] Extracted file ID: %s", id)

	// Download file synchronously and get the result
	category, err := downloadFile(id)

	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		log.Printf("[ERROR] Download failed: %v", err)
		json.NewEncoder(w).Encode(ApiResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	// Return success with category information
	response := ApiResponse{
		Success: true,
		Message: "File downloaded to server",
	}

	if category != "" {
		response.Category = category
		response.Message = fmt.Sprintf("File added to %s folder", category)
	} else {
		response.Message = "File added to root folder"
	}

	json.NewEncoder(w).Encode(response)
	log.Printf("[DEBUG] Sent success response for file ID: %s with category: %s", id, category)
}

func downloadFile(id string) (string, error) {
	log.Printf("[DEBUG] Starting download for file ID: %s", id)
	fileDownloadsTotal.Inc()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Get upstream host (rotates every 10 minutes if random subdomain is enabled)
	dynamicHost := getUpstreamHost()

	// Get file details from the details page using the configured pattern
	detailsURL := fmt.Sprintf(detailsURLPattern, dynamicHost, id)
	req, err := http.NewRequestWithContext(ctx, "GET", detailsURL, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create details request: %v", err)
		return "", fmt.Errorf("failed to create details request: %w", err)
	}

	// Extract hostname from upstream URL for Host header
	if u, err := url.Parse(dynamicHost); err == nil {
		req.Header.Set("Host", u.Host)
	}
	req.Header.Set("Referer", dynamicHost)
	req.Header.Set("Cookie", fmt.Sprintf("uid=1105849; pass=%s; hideCats=0; hideTop=0", token))

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch details: %v", err)
		return "", fmt.Errorf("failed to fetch details: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] Details response status: %d", resp.StatusCode)
	log.Printf("[DEBUG] Details response headers: %v", resp.Header)

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] Bad status code from details page: %d", resp.StatusCode)
		// Try to read error response
		errorBody, _ := io.ReadAll(resp.Body)
		log.Printf("[ERROR] Error response: %s", string(errorBody))
		return "", fmt.Errorf("bad status code %d: %s", resp.StatusCode, string(errorBody))
	}

	// Handle compressed responses
	var reader io.Reader = resp.Body
	encoding := resp.Header.Get("Content-Encoding")

	switch encoding {
	case "gzip":
		log.Printf("[DEBUG] Response is gzip encoded")
		if gr, err := gzip.NewReader(resp.Body); err == nil {
			reader = gr
			defer gr.Close()
		} else {
			log.Printf("[ERROR] Failed to create gzip reader: %v", err)
		}
	case "br":
		log.Printf("[DEBUG] Response is brotli encoded")
		reader = brotli.NewReader(resp.Body)
	case "":
		log.Printf("[DEBUG] Response is not compressed")
	default:
		log.Printf("[DEBUG] Unknown encoding: %s", encoding)
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		log.Printf("[ERROR] Failed to read details response: %v", err)
		return "", fmt.Errorf("failed to read details response: %w", err)
	}

	// Parse category from response
	data := string(body)
	log.Printf("[DEBUG] Details page size: %d bytes", len(data))

	// Log a sample of the response to check if we got the right page
	if len(data) > 500 {
		log.Printf("[DEBUG] Details page sample: %s", data[:500])
	} else if len(data) > 0 {
		log.Printf("[DEBUG] Full details page: %s", data)
	}

	cat := extractCategory(data)
	log.Printf("[DEBUG] Extracted category: %s", cat)

	// Download the actual file using the configured pattern
	downloadURL := fmt.Sprintf(downloadURLPattern, dynamicHost, id, id)
	req, err = http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create download request: %v", err)
		return cat, fmt.Errorf("failed to create download request: %w", err)
	}

	// Extract hostname from upstream URL for Host header
	if u, err := url.Parse(dynamicHost); err == nil {
		req.Header.Set("Host", u.Host)
	}
	req.Header.Set("Referer", dynamicHost)
	req.Header.Set("Cookie", fmt.Sprintf("uid=1105849; pass=%s; hideCats=0; hideTop=0", token))

	resp, err = client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to download file: %v", err)
		return cat, fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] Bad status code: %d", resp.StatusCode)
		return cat, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	fileData, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read file data: %v", err)
		return cat, fmt.Errorf("failed to read file data: %w", err)
	}

	// Save file to disk
	var filePath string

	// Clean up watcherPath to ensure it's properly formatted
	absWatcherPath, err := filepath.Abs(watcherPath)
	if err != nil {
		log.Printf("[WARN] Could not get absolute path for %s: %v", watcherPath, err)
		absWatcherPath = watcherPath
	}

	if cat != "" {
		// Build proper path with category
		catPath := filepath.Join(absWatcherPath, cat)

		// Try to create category directory if it doesn't exist
		if err := os.MkdirAll(catPath, 0755); err != nil {
			log.Printf("[WARN] Failed to create category directory %s: %v", catPath, err)
			filePath = filepath.Join(absWatcherPath, id+downloadFileExtension)
		} else {
			log.Printf("[DEBUG] Created/verified category directory: %s", catPath)
			filePath = filepath.Join(catPath, id+downloadFileExtension)
		}
	} else {
		filePath = filepath.Join(absWatcherPath, id+downloadFileExtension)
	}

	log.Printf("[DEBUG] Will save file to: %s", filePath)

	if err := os.WriteFile(filePath, fileData, 0755); err != nil {
		log.Printf("[ERROR] Failed to save file: %v", err)
		return cat, fmt.Errorf("failed to save file: %w", err)
	}

	// Set proper permissions
	if err := os.Chmod(filePath, 0755); err != nil {
		log.Printf("[ERROR] Failed to chmod file: %v", err)
		// Don't return error here, file was saved successfully
	}

	log.Printf("[SUCCESS] File saved to: %s", filePath)
	return cat, nil
}
func extractCategory(html string) string {
	// Look for the tags div - try different patterns
	var index int
	patterns := []string{
		`<div class="tags sub">`,
		`class="tags sub"`,
		`tags sub`,
	}

	for _, pattern := range patterns {
		index = strings.Index(html, pattern)
		if index != -1 {
			log.Printf("[DEBUG] Found tags div with pattern: %s", pattern)
			break
		}
	}

	if index == -1 {
		log.Printf("[DEBUG] Could not find tags div with any pattern")
		return "other"
	}

	// Find the start of the div tag (if we found it mid-tag)
	divStart := strings.LastIndex(html[:index], `<div`)
	if divStart != -1 && divStart > index-50 {
		index = divStart
	}

	// Find the end of this div - just take a large chunk to see what we get
	divEnd := 2000 // Take 2000 characters to see what's there
	if index+divEnd > len(html) {
		divEnd = len(html) - index
	}

	// Extract the tags section content
	tagsContent := html[index : index+divEnd]
	log.Printf("[DEBUG] Taking %d characters from tags section", divEnd)

	// Find the actual end of the tags div
	realDivEnd := strings.Index(tagsContent, `</div>`)
	if realDivEnd > 0 {
		log.Printf("[DEBUG] Found </div> at position %d", realDivEnd)
		// Check if there are more anchor tags after this div
		remainingContent := tagsContent[realDivEnd:]
		if strings.Contains(remainingContent, `class="v"`) {
			log.Printf("[DEBUG] Found class='v' after first </div>, tags might continue")
		}
	}

	// Log full tags content for debugging
	log.Printf("[DEBUG] Full tags content: %s", strings.ReplaceAll(tagsContent, "\n", " "))

	// Look for the category link - it's the first anchor tag with class="v" that contains a category pattern
	// First, let's see all anchor tags in the content
	anchorCount := strings.Count(tagsContent, "<a ")
	log.Printf("[DEBUG] Found %d anchor tags in tags content", anchorCount)

	start := 0
	for {
		linkIndex := strings.Index(tagsContent[start:], `class="v"`)
		if linkIndex == -1 {
			log.Printf("[DEBUG] No more class='v' found from position %d", start)
			break
		}
		linkIndex += start

		// Find the > after class="v"
		tagEnd := strings.Index(tagsContent[linkIndex:], `>`)
		if tagEnd == -1 {
			start = linkIndex + 1
			continue
		}
		linkIndex += tagEnd + 1

		// Find the end of the anchor text
		endIndex := strings.Index(tagsContent[linkIndex:], `</a>`)
		if endIndex == -1 {
			start = linkIndex
			continue
		}

		// Extract the link text
		linkText := tagsContent[linkIndex : linkIndex+endIndex]
		linkText = strings.TrimSpace(linkText)
		log.Printf("[DEBUG] Found tag: %s", linkText)

		// Check if this is a category (contains /)
		if strings.Contains(linkText, "/") {
			parts := strings.Split(linkText, "/")
			category := parts[0]

			// Normalize category names
			category = strings.TrimSpace(category)
			switch strings.ToLower(category) {
			case "movie", "movies":
				return "movies"
			case "tv":
				return "tv"
			case "apps", "applications", "appz", "mobile":
				return "apps"
			case "games":
				return "games"
			case "music", "podcast":
				return "music"
			case "ebooks", "ebook", "books", "book", "audiobooks", "audiobook":
				return "books"
			default:
				return "other"
			}
		}

		start = linkIndex + endIndex
	}

	log.Printf("[DEBUG] Could not extract category from tags")
	return "other"
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// Get upstream host (rotates every 10 minutes if random subdomain is enabled)
	dynamicHost := getUpstreamHost()

	// Strip query strings from CSS requests
	requestURL := r.URL.String()
	if strings.HasSuffix(strings.ToLower(r.URL.Path), ".css") && r.URL.RawQuery != "" {
		// Remove query string for CSS files
		requestURL = r.URL.Path
		if r.URL.Fragment != "" {
			requestURL += "#" + r.URL.Fragment
		}
		log.Printf("[DEBUG] Stripped query string from CSS request: %s -> %s", r.URL.String(), requestURL)
	}

	targetURL := dynamicHost + requestURL

	// Create proxy request
	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for name, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(name, value)
		}
	}

	setProxyHeaders(proxyReq, dynamicHost)

	// Do request
	resp, err := proxyClient.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Handle redirects
	if resp.StatusCode == 301 || resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		location = strings.Replace(location, dynamicHost, "", 1)
		http.Redirect(w, r, location, resp.StatusCode)
		return
	}

	// Check if we need to inject HTML
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		// Handle compressed responses
		var reader io.Reader = resp.Body
		encoding := resp.Header.Get("Content-Encoding")

		switch encoding {
		case "gzip":
			if gr, err := gzip.NewReader(resp.Body); err == nil {
				reader = gr
				defer gr.Close()
			}
		case "br":
			reader = brotli.NewReader(resp.Body)
		}

		body, err := io.ReadAll(reader)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		html := string(body)

		// Simple injection - add before </body>
		if idx := strings.LastIndex(strings.ToLower(html), "</body>"); idx != -1 {
			html = html[:idx] + injectCode + html[idx:]
			log.Printf("[DEBUG] Injected code before </body>")
		} else {
			html += injectCode
			log.Printf("[DEBUG] Appended code at end of HTML")
		}

		// Write response
		for name, values := range resp.Header {
			if name != "Content-Length" && name != "Content-Encoding" {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
		}
		w.Write([]byte(html))
	} else {
		// Not HTML, just proxy as-is
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func setProxyHeaders(req *http.Request, dynamicHost string) {
	// Extract hostname from upstream URL for Host header
	if u, err := url.Parse(dynamicHost); err == nil {
		req.Header.Set("Host", u.Host)
	} else {
		// Log error if parsing fails
		log.Printf("[ERROR] Failed to parse upstream host: %v", err)
	}
	req.Header.Set("Referer", dynamicHost)
	req.Header.Set("Cookie", fmt.Sprintf("uid=1105849; pass=%s; hideCats=0; hideTop=0", token))
	req.Header.Set("Origin", dynamicHost)
}
