package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// --- Structs for Linguistic Data ---

type WordFreq struct {
	Word    string  `json:"word"`
	Count   int     `json:"count"`
	Percent float64 `json:"percent"`
}

type LinguisticStats struct {
	TotalEmails       int        `json:"total_emails"`
	AvgWordCount      float64    `json:"avg_word_count"`
	AvgSentenceLength float64    `json:"avg_sentence_length"`
	AvgShoutingScore  float64    `json:"avg_shouting_score"`
	TopBodyWords      []WordFreq `json:"top_body_words"`
	TopSubjectWords   []WordFreq `json:"top_subject_words"`
}

type LinguisticReport struct {
	SafeStats LinguisticStats `json:"safe_stats"`
	ScamStats LinguisticStats `json:"scam_stats"`
}

// Global stats
var globalStats LinguisticReport

// In-memory store for uploaded files
var (
	memoryStore = make(map[string]string)
	memoryMutex sync.RWMutex
)

// --- Analysis Result Structs ---

type LinguisticTrigger struct {
	Text        string
	Explanation string // More detailed info
}

type RiskFactors struct {
	// Header Analysis
	SPFStatus          string   `json:"header_spf_status"`
	DKIMStatus         string   `json:"header_dkim_status"`
	DMARCStatus        string   `json:"header_dmarc_status"`
	FromReturnPathDiff bool     `json:"from_return_path_mismatch"`
	ReplyToDiff        bool     `json:"reply_to_mismatch"`
	Suspiciouskeywords []string `json:"suspicious_keywords"`

	// Active Network/API Checks
	Domain           string `json:"domain"`
	HasMXRecords     bool   `json:"network_has_mx_records"`
	LiveSPFRecord    string `json:"network_live_spf_record"`
	LiveDMARCRecord  string `json:"network_live_dmarc_record"`
	DomainTrustScore string `json:"domain_trust_score"` // "Trustworthy", "Neutral", "Suspicious", "Unknown"
	BlacklistStatus  string `json:"blacklist_status"`   // "Clean", "Listed", "Error", "Unknown"
	IsDisposable     bool   `json:"api_is_disposable"`

	// Linguistic Analysis
	LinguisticTriggers []LinguisticTrigger `json:"linguistic_triggers"`
	ShoutingScore      float64             `json:"shouting_score"`
}

type ScoreBreakdown struct {
	BaseScore         float64 `json:"base_score"`
	AuthFailPenalty   float64 `json:"auth_fail_penalty"`
	AuthPassBonus     float64 `json:"auth_pass_bonus"`
	MismatchPenalty   float64 `json:"mismatch_penalty"`
	KeywordPenalty    float64 `json:"keyword_penalty"`
	NoMXPenalty       float64 `json:"no_mx_penalty"`
	DisposablePenalty float64 `json:"disposable_penalty"`
	LinguisticPenalty float64 `json:"linguistic_penalty"`
	TotalScore        float64 `json:"total_score"`
}

type AnalysisResult struct {
	FileName        string              `json:"file_name"`
	ScamProbability float64             `json:"scam_probability_percent"`
	SafeProbability float64             `json:"safe_probability_percent"`
	TechScore       float64             `json:"tech_score"`
	BodyScore       float64             `json:"body_score"`
	SubjectScore    float64             `json:"subject_score"`
	EmailBody       string              `json:"email_body"`
	RiskFactors     RiskFactors         `json:"risk_factors"`
	ScoreBreakdown  ScoreBreakdown      `json:"calculation_details"`
	BodyTriggers    []LinguisticTrigger `json:"body_triggers"`
	SubjectTriggers []LinguisticTrigger `json:"subject_triggers"`
}

// PageData struct for template
type PageData struct {
	TestEmails []string
	OwnEmails  []string
	Analysis   *AnalysisResult
}

// DisposableResponse structure for API
type DisposableResponse struct {
	Disposable bool `json:"disposable"`
}

// --- Main Logic ---

func loadLinguisticStats() {
	path := resolvePath("data/linguistic_stats.json")
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Warning: Could not load linguistic stats from %s: %v", path, err)
		return
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&globalStats); err != nil {
		log.Printf("Error decoding linguistic stats: %v", err)
	} else {
		fmt.Println("Successfully loaded linguistic stats database.")
	}
}

func resolvePath(relativePath string) string {
	// Try direct path (running from root)
	if _, err := os.Stat(relativePath); err == nil {
		return relativePath
	}
	// Try moving up two levels (running from cmd/server)
	upTwo := filepath.Join("../../", relativePath)
	if _, err := os.Stat(upTwo); err == nil {
		return upTwo
	}
	// Default to original relative path and hope for the best (or let it fail later)
	return relativePath
}

func getTestEmails() []string {
	dir := resolvePath("data/test_emails")
	files, err := os.ReadDir(dir)
	if err != nil {
		return []string{}
	}
	var emails []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".eml") {
			emails = append(emails, f.Name())
		}
	}
	return emails
}

func main() {
	loadLinguisticStats()

	// Periodic cleanup of memory store (every 1 hour)
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			memoryMutex.Lock()
			memoryStore = make(map[string]string)
			memoryMutex.Unlock()
		}
	}()

	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseFiles("templates/index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		memoryMutex.RLock()
		ownEmails := make([]string, 0, len(memoryStore))
		for k := range memoryStore {
			ownEmails = append(ownEmails, k)
		}
		memoryMutex.RUnlock()

		data := PageData{
			TestEmails: getTestEmails(),
			OwnEmails:  ownEmails,
			Analysis:   nil,
		}
		t.Execute(w, data)
	})

	http.HandleFunc("/analyze", handleAnalyze)

	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	testFile := r.URL.Query().Get("testFile")
	var msg *mail.Message
	var bodyString string
	var filename string
	var err error

	if strings.HasPrefix(testFile, "memory:") {
		// Load from memory
		key := strings.TrimPrefix(testFile, "memory:")
		memoryMutex.RLock()
		content, ok := memoryStore[key]
		memoryMutex.RUnlock()

		if !ok {
			http.Error(w, "File not found in memory (expired?)", 404)
			return
		}

		filename = key

		// Check for mbox format (starts with "From ") and strip it
		if strings.HasPrefix(content, "From ") {
			fmt.Println("DEBUG: Found mbox prefix in memory content, stripping line.")
			// Find first newline
			if idx := strings.Index(content, "\n"); idx != -1 {
				content = content[idx+1:]
			}
		}

		msg, err = mail.ReadMessage(strings.NewReader(content))
		if err != nil {
			fmt.Printf("DEBUG: Error parsing email in memory: %v\n", err)
			http.Error(w, "Invalid email format in memory", 500)
			return
		}
		fmt.Printf("DEBUG: Successfully parsed email from memory. FromHeader: '%s'\n", msg.Header.Get("From"))
		bodyBytes, _ := io.ReadAll(msg.Body)
		bodyString = string(bodyBytes)

	} else if testFile != "" {
		// Load from test emails
		filename = testFile
		// Load from test emails
		filename = testFile
		dir := resolvePath("data/test_emails")
		path := filepath.Join(dir, testFile)

		// Read file content first to handle mbox stripping
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "File not found", 404)
			return
		}
		contentString := string(contentBytes)

		// Check for mbox format (starts with "From ") and strip it
		if strings.HasPrefix(contentString, "From ") {
			if idx := strings.Index(contentString, "\n"); idx != -1 {
				contentString = contentString[idx+1:]
			}
		}

		msg, err = mail.ReadMessage(strings.NewReader(contentString))
		if err != nil {
			http.Error(w, "Invalid email format", 500)
			return
		}

		// mail.ReadMessage parses headers and leaves body in msg.Body
		bodyBytes, _ := io.ReadAll(msg.Body)
		bodyString = string(bodyBytes)

	} else {
		// Handle Upload
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		file, header, err := r.FormFile("emailFile")
		if err != nil {
			http.Error(w, "Error uploading file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Read entire content to store
		contentBytes, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}
		contentString := string(contentBytes)

		filename = header.Filename

		// Store in memory
		memoryMutex.Lock()
		memoryStore[filename] = contentString
		memoryMutex.Unlock()

		// Redirect to analyze view
		// Use QueryEscape to handle spaces and special chars safely
		safeFilename := url.QueryEscape(filename)
		http.Redirect(w, r, "/analyze?testFile=memory:"+safeFilename, http.StatusSeeOther)
		return
	}

	result := analyzeEmail(filename, msg, bodyString)

	t, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	memoryMutex.RLock()
	ownEmails := make([]string, 0, len(memoryStore))
	for k := range memoryStore {
		ownEmails = append(ownEmails, k)
	}
	memoryMutex.RUnlock()

	data := PageData{
		TestEmails: getTestEmails(),
		OwnEmails:  ownEmails,
		Analysis:   &result,
	}
	if err := t.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

func analyzeEmail(filename string, msg *mail.Message, body string) AnalysisResult {
	riskFactors := RiskFactors{
		SPFStatus:   "unknown",
		DKIMStatus:  "unknown",
		DMARCStatus: "unknown",
	}
	breakdown := ScoreBreakdown{}

	// --- 1. Header Analysis ---

	authResults := msg.Header.Get("Authentication-Results")
	if authResults != "" {
		lowerAuth := strings.ToLower(authResults)
		if strings.Contains(lowerAuth, "spf=fail") || strings.Contains(lowerAuth, "spf=softfail") {
			riskFactors.SPFStatus = "fail"
			breakdown.AuthFailPenalty += 30
		} else if strings.Contains(lowerAuth, "spf=pass") {
			riskFactors.SPFStatus = "pass"
			breakdown.AuthPassBonus += 10
		}
		if strings.Contains(lowerAuth, "dkim=fail") {
			riskFactors.DKIMStatus = "fail"
			breakdown.AuthFailPenalty += 30
		} else if strings.Contains(lowerAuth, "dkim=pass") {
			riskFactors.DKIMStatus = "pass"
			breakdown.AuthPassBonus += 10
		}
		if strings.Contains(lowerAuth, "dmarc=fail") {
			riskFactors.DMARCStatus = "fail"
			breakdown.AuthFailPenalty += 20
		} else if strings.Contains(lowerAuth, "dmarc=pass") {
			riskFactors.DMARCStatus = "pass"
			breakdown.AuthPassBonus += 5
		}
	} else {
		breakdown.BaseScore += 10
	}

	from := msg.Header.Get("From")
	returnPath := msg.Header.Get("Return-Path")
	fromAddr := extractEmail(from)
	returnPathAddr := extractEmail(returnPath)
	fromDomain := getDomain(fromAddr)
	riskFactors.Domain = fromDomain

	if fromAddr != "" && returnPathAddr != "" {
		if fromDomain != getDomain(returnPathAddr) && getDomain(returnPathAddr) != "" {
			riskFactors.FromReturnPathDiff = true
			breakdown.MismatchPenalty += 25
		}
	}

	// Check Reply-To mismatch
	replyTo := msg.Header.Get("Reply-To")
	if replyTo != "" {
		replyToAddr := extractEmail(replyTo)
		replyToDomain := getDomain(replyToAddr)
		if fromDomain != replyToDomain && replyToDomain != "" {
			riskFactors.ReplyToDiff = true
			breakdown.MismatchPenalty += 20
		}
	}

	subject := msg.Header.Get("Subject")
	suspiciousKeywords := []string{"urgent", "verify", "account", "suspended", "winner", "lottery", "password", "profit", "margin"}
	for _, kw := range suspiciousKeywords {
		if strings.Contains(strings.ToLower(subject), kw) {
			riskFactors.Suspiciouskeywords = append(riskFactors.Suspiciouskeywords, kw)
			breakdown.KeywordPenalty += 15
		}
	}

	if fromDomain != "" {
		fmt.Println("DEBUG: Starting Active DNS Checks for:", fromDomain)
		mxRecords, err := net.LookupMX(fromDomain)
		if err == nil && len(mxRecords) > 0 {
			fmt.Printf("DEBUG: Found %d MX records for %s\n", len(mxRecords), fromDomain)
			riskFactors.HasMXRecords = true
		} else {
			fmt.Printf("DEBUG: No MX records found for %s (Err: %v)\n", fromDomain, err)
			breakdown.NoMXPenalty += 50
		}

		// Active DNS Checks
		txtRecords, _ := net.LookupTXT(fromDomain)
		fmt.Printf("DEBUG: Found %d TXT records for %s\n", len(txtRecords), fromDomain)
		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, "v=spf1") {
				fmt.Printf("DEBUG: Found SPF Record: %s\n", txt)
				riskFactors.LiveSPFRecord = txt
				break
			}
		}

		dmarcName := "_dmarc." + fromDomain
		dmarcRecords, _ := net.LookupTXT(dmarcName)
		fmt.Printf("DEBUG: Found %d TXT records for %s\n", len(dmarcRecords), dmarcName)
		for _, txt := range dmarcRecords {
			if strings.HasPrefix(txt, "v=DMARC1") {
				fmt.Printf("DEBUG: Found DMARC Record: %s\n", txt)
				riskFactors.LiveDMARCRecord = txt
			}
		}

		// Domain Trust Check
		riskFactors.DomainTrustScore = checkDomainTrust(fromDomain)
		fmt.Printf("DEBUG: Domain '%s' Trust Score: %s\n", fromDomain, riskFactors.DomainTrustScore)

		// Public API Blacklist Check (spamhaus dbl via google dns)
		riskFactors.BlacklistStatus = checkBlacklist(fromDomain)
		fmt.Printf("DEBUG: Domain '%s' Blacklist Status: %s\n", fromDomain, riskFactors.BlacklistStatus)

	} else {
		fmt.Println("DEBUG: No domain extracted, Trust Score: Unknown")
		riskFactors.DomainTrustScore = "Unknown"
		riskFactors.BlacklistStatus = "Unknown"
	}

	// --- 2. Linguistic Analysis (Body) ---

	cleanBody := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(body, " ")
	lowerBody := strings.ToLower(cleanBody)
	// Use Unicode-aware pattern to match German umlauts and other letters
	words := regexp.MustCompile(`[\p{L}]{3,}`).FindAllString(lowerBody, -1)

	fmt.Printf("DEBUG: Extracted %d words from body\n", len(words))
	if len(words) > 0 && len(words) <= 20 {
		fmt.Printf("DEBUG: First words: %v\n", words[:min(10, len(words))])
	}

	wordSet := make(map[string]bool)
	for _, w := range words {
		wordSet[w] = true
	}

	// Comparison Logic: Scam vs Safe stats
	safeWordMap := make(map[string]float64)
	if len(globalStats.SafeStats.TopBodyWords) > 0 {
		for _, w := range globalStats.SafeStats.TopBodyWords {
			safeWordMap[w.Word] = w.Percent
		}
	}

	// Define Ignored Words (Stop Words)
	ignoredWords := map[string]bool{
		"email":       true,
		"service":     true,
		"customer":    true,
		"access":      true,
		"details":     true,
		"information": true,
		"account":     false,
		"click":       false,
		"security":    false,
		"update":      true,
		"support":     true,
		"team":        true,
		"contact":     true,
		"please":      true,
		"address":     true,
		"view":        true,
		"rights":      true,
		"reserved":    true,
	}

	if len(globalStats.ScamStats.TopBodyWords) > 0 {
		matchCount := 0
		for _, stat := range globalStats.ScamStats.TopBodyWords {
			// Lowered threshold to 7% to catch more relevant words
			if stat.Percent > 7.0 && wordSet[stat.Word] {
				if ignoredWords[stat.Word] {
					continue
				}

				// Check if word appears in scam emails
				matchCount++
				fmt.Printf("DEBUG: Matched word '%s' (%.0f%% in scams)\n", stat.Word, stat.Percent)
				text := fmt.Sprintf("Enthält '%s'", stat.Word)
				explanation := fmt.Sprintf("Kommt in %.0f%% bekannter Phishing-Mails vor.", stat.Percent)

				riskFactors.LinguisticTriggers = append(riskFactors.LinguisticTriggers, LinguisticTrigger{
					Text:        text,
					Explanation: explanation,
				})

				penalty := stat.Percent / 2.0
				if penalty > 15 {
					penalty = 15
				} // Cap per word
				breakdown.LinguisticPenalty += penalty
			}
		}
		fmt.Printf("DEBUG: Found %d linguistic matches in body\n", matchCount)
	}

	// --- 3. Subject Linguistic Analysis ---
	subjectLower := strings.ToLower(subject)
	// Use Unicode-aware pattern to match German umlauts and other letters
	subjectWords := regexp.MustCompile(`[\p{L}]{3,}`).FindAllString(subjectLower, -1)
	subjectWordSet := make(map[string]bool)
	for _, w := range subjectWords {
		subjectWordSet[w] = true
	}

	// Ignored subject words (technical artifacts)
	ignoredSubjectWords := map[string]bool{
		"utf": true, // UTF-8 encoding artifacts
	}

	if len(globalStats.ScamStats.TopSubjectWords) > 0 {
		for _, stat := range globalStats.ScamStats.TopSubjectWords {
			if stat.Percent > 5.0 && subjectWordSet[stat.Word] {
				// Skip ignored technical words
				if ignoredSubjectWords[stat.Word] {
					continue
				}
				text := fmt.Sprintf("Betreff: '%s'", stat.Word)
				explanation := fmt.Sprintf("Kommt in %.0f%% der Phishing-Betreffzeilen vor.", stat.Percent)
				riskFactors.LinguisticTriggers = append(riskFactors.LinguisticTriggers, LinguisticTrigger{
					Text:        text,
					Explanation: explanation,
				})
				breakdown.LinguisticPenalty += stat.Percent / 3.0
			}
		}
	}

	// Shouting Score
	upperCount := 0
	totalChars := 0
	for _, r := range cleanBody {
		if r >= 'A' && r <= 'Z' {
			upperCount++
		}
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			totalChars++
		}
	}
	if totalChars > 0 {
		riskFactors.ShoutingScore = (float64(upperCount) / float64(totalChars)) * 100
		// Threshold increased from 10.0 to 25.0 to avoid flagging headers/acronyms
		if riskFactors.ShoutingScore > 25.0 {
			breakdown.LinguisticPenalty += 15
			riskFactors.LinguisticTriggers = append(riskFactors.LinguisticTriggers, LinguisticTrigger{
				Text:        "Exzessive Großschreibung (Shouting)",
				Explanation: fmt.Sprintf("Ein Anteil von %.0f%% Großbuchstaben ist typisch für aggressive Betrugsversuche.", riskFactors.ShoutingScore),
			})
		}
	}

	// --- Final Score Calculation ---

	// Technical Score (max 40 points -> scale to 100%)
	techRaw := breakdown.BaseScore + breakdown.AuthFailPenalty - breakdown.AuthPassBonus +
		breakdown.MismatchPenalty + breakdown.NoMXPenalty + breakdown.DisposablePenalty
	if techRaw < 0 {
		techRaw = 0
	}
	if techRaw > 40 {
		techRaw = 40
	}
	techScore := (techRaw / 40.0) * 100

	// Body Linguistic Score (max 50 points -> scale to 100%)
	bodyRaw := breakdown.LinguisticPenalty
	if bodyRaw > 50 {
		bodyRaw = 50
	}
	bodyScore := (bodyRaw / 50.0) * 100

	// Subject/Keyword Score (max 30 points -> scale to 100%)
	subjectRaw := breakdown.KeywordPenalty
	if subjectRaw > 30 {
		subjectRaw = 30
	}
	subjectScore := (subjectRaw / 30.0) * 100

	// Weighted total: Tech 40%, Body 35%, Subject 25%
	total := (techScore * 0.40) + (bodyScore * 0.35) + (subjectScore * 0.25)
	if total > 100 {
		total = 100
	}
	breakdown.TotalScore = total

	// Separate triggers
	var bodyTriggers, subjectTriggers []LinguisticTrigger
	for _, t := range riskFactors.LinguisticTriggers {
		if strings.HasPrefix(t.Text, "Betreff:") {
			subjectTriggers = append(subjectTriggers, t)
		} else {
			bodyTriggers = append(bodyTriggers, t)
		}
	}

	return AnalysisResult{
		FileName:        filename,
		ScamProbability: total,
		SafeProbability: 100 - total,
		TechScore:       techScore,
		BodyScore:       bodyScore,
		SubjectScore:    subjectScore,
		EmailBody:       body,
		RiskFactors:     riskFactors,
		ScoreBreakdown:  breakdown,
		BodyTriggers:    bodyTriggers,
		SubjectTriggers: subjectTriggers,
	}
}

// Helpers
func extractEmail(s string) string {
	start := strings.Index(s, "<")
	end := strings.LastIndex(s, ">")
	if start != -1 && end != -1 && end > start {
		return strings.TrimSpace(s[start+1 : end])
	}
	return s
}

func getDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return strings.ToLower(parts[1])
	}
	return ""
}

func checkDomainTrust(domain string) string {
	// Simple allowlist for demonstration
	trusted := []string{
		"google.com", "gmail.com",
		"microsoft.com", "outlook.com", "hotmail.com",
		"apple.com", "icloud.com",
		"amazon.com",
		"linkedin.com",
		"paypal.com",
		"slack.com",
		"acquire.com",
		"reddit.com", "redditmail.com",
	}

	for _, t := range trusted {
		if domain == t || strings.HasSuffix(domain, "."+t) {
			return "Trustworthy"
		}
	}
	return "Neutral"
}

// Google DoH Response Structure (minimal)
type DoHResponse struct {
	Status int `json:"Status"` // 0 = NOERROR, 3 = NXDOMAIN
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func checkBlacklist(domain string) string {
	// 1. Try Google DoH API first (as requested)
	apiURL := fmt.Sprintf("https://dns.google/resolve?name=%s.dbl.spamhaus.org&type=A", domain)
	status := "Unknown"

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(apiURL)
	if err == nil && resp.StatusCode == 200 {
		var doh DoHResponse
		if json.NewDecoder(resp.Body).Decode(&doh) == nil {
			if doh.Status == 3 {
				resp.Body.Close()
				return "Clean" // Specified NXDOMAIN = Clean
			}
			if doh.Status == 0 && len(doh.Answer) > 0 {
				ip := doh.Answer[0].Data
				// Check for Open Resolver Block return code
				if ip == "127.255.255.254" {
					fmt.Println("DEBUG: Google DoH blocked by Spamhaus. Falling back to system DNS.")
					status = "Fallback"
				} else {
					fmt.Printf("DEBUG: API found match: %s\n", ip)
					resp.Body.Close()
					return "Listed"
				}
			}
		}
		resp.Body.Close()
	} else {
		if err != nil {
			fmt.Printf("DEBUG: DoH API Error: %v\n", err)
		} else {
			fmt.Printf("DEBUG: DoH API Status: %d\n", resp.StatusCode)
			resp.Body.Close()
		}
		status = "Fallback"
	}

	// 2. Fallback to System DNS (if API failed or was blocked)
	// This ensures we actually get a result even if Public APIs are rate-limited
	if status == "Fallback" {
		lookupName := domain + ".dbl.spamhaus.org"
		ips, err := net.LookupHost(lookupName)
		if err != nil {
			// lookup error usually means NXDOMAIN -> Clean
			// But strictly check if it is a "no such host" error
			if strings.Contains(err.Error(), "no such host") {
				return "Clean"
			}
			// Other error
			return "Error"
		}
		if len(ips) > 0 {
			// Check again for block codes just in case local is also blocked
			if ips[0] == "127.255.255.254" {
				return "Error (Blocked)"
			}
			return "Listed"
		}
	}

	return "Clean"
}
