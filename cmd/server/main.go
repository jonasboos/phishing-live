package main

import (
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
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

	"github.com/abadojack/whatlanggo"
	"github.com/bregydoc/gtranslate"
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

// Global stats
var globalStats LinguisticStats

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
	BaseScore                float64 `json:"base_score"`
	AuthFailPenalty          float64 `json:"auth_fail_penalty"`
	AuthPassBonus            float64 `json:"auth_pass_bonus"`
	MismatchPenalty          float64 `json:"mismatch_penalty"`
	KeywordPenalty           float64 `json:"keyword_penalty"`
	NoMXPenalty              float64 `json:"no_mx_penalty"`
	DisposablePenalty        float64 `json:"disposable_penalty"`
	LinguisticPenalty        float64 `json:"linguistic_penalty"`
	SubjectLinguisticPenalty float64 `json:"subject_linguistic_penalty"`
	TotalScore               float64 `json:"total_score"`
}

type AnalysisResult struct {
	FileName        string              `json:"file_name"`
	DetectedLang    string              `json:"detected_lang"`
	TranslatedBody  string              `json:"translated_body"`
	ScamProbability float64             `json:"scam_probability_percent"`
	SafeProbability float64             `json:"safe_probability_percent"`
	TechScore       float64             `json:"tech_score"`
	BodyScore       float64             `json:"body_score"`
	SubjectScore    float64             `json:"subject_score"`
	EmailBody       template.HTML       `json:"email_body"` // Highlighted text version (optional/fallback)
	HTMLBody        template.HTML       `json:"html_body"`  // Authentic HTML for iframe
	Headers         map[string]string   `json:"headers"`
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
	IsTestFile bool
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
			IsTestFile: false,
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
	isTestFile := false

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
		fmt.Printf("DEBUG: Successfully parsed email from memory. FromHeader: '%s'\n", msg.Header.Get("From"))
		bodyString = extractEmailBody(msg)

	} else if testFile != "" {
		// Load from test emails
		filename = testFile
		isTestFile = true
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
		// mail.ReadMessage parses headers and leaves body in msg.Body
		bodyString = extractEmailBody(msg)

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
		IsTestFile: isTestFile,
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

	from := decodeHeader(msg.Header.Get("From"))
	returnPath := decodeHeader(msg.Header.Get("Return-Path"))
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
	replyTo := decodeHeader(msg.Header.Get("Reply-To"))
	if replyTo != "" {
		replyToAddr := extractEmail(replyTo)
		replyToDomain := getDomain(replyToAddr)
		if fromDomain != replyToDomain && replyToDomain != "" {
			riskFactors.ReplyToDiff = true
			breakdown.MismatchPenalty += 20
		}
	}

	subjectHeader := msg.Header.Get("Subject")
	subject := decodeHeader(subjectHeader)
	fmt.Printf("DEBUG: Subject Raw: '%s', Decoded: '%s'\n", subjectHeader, subject)
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

	// Language Detection
	info := whatlanggo.Detect(cleanBody)
	detectedLang := info.Lang.String()
	fmt.Printf("DEBUG: Detected Language: %s (Confidence: %.2f)\n", detectedLang, info.Confidence)

	analysisText := cleanBody
	var translatedBody string

	// Automatic Translation if not English (and text is long enough)
	if info.Lang != whatlanggo.Eng && len(cleanBody) > 50 {
		fmt.Println("DEBUG: Non-English email detected. Attempting translation...")
		translated, err := gtranslate.TranslateWithParams(cleanBody, gtranslate.TranslationParams{
			From: info.Lang.Iso6391(),
			To:   "en",
		})
		if err == nil {
			fmt.Println("DEBUG: Translation successful.")
			translatedBody = translated
			analysisText = translated // Use translated text for analysis
		} else {
			fmt.Printf("DEBUG: Translation failed: %v\n", err)
		}
	} else {
		detectedLang = "English" // Normalize
	}

	lowerBody := strings.ToLower(analysisText)
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

	// Comparison Logic: Check against Phishing Stats
	if len(globalStats.TopBodyWords) > 0 {
		for _, stat := range globalStats.TopBodyWords {
			// Lowered threshold to 7% to catch more relevant words
			if stat.Percent > 7.0 && wordSet[stat.Word] {
				if ignoredWords[stat.Word] {
					continue
				}

				// Check if word appears in scam emails
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

	if len(globalStats.TopSubjectWords) > 0 {
		for _, stat := range globalStats.TopSubjectWords {
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
				breakdown.SubjectLinguisticPenalty += stat.Percent / 3.0
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
	subjectRaw := breakdown.KeywordPenalty + breakdown.SubjectLinguisticPenalty
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

	// Highlight keywords in clean text for scoring/debug (and potentially text view)
	// We still calculate this primarily for the scoring logic which uses 'cleanText' derived inside highlightKeywords?
	// Actually highlightKeywords calls stripHTML.
	// We should probably stripHTML once for analysis, and highlight separately?
	// For now, keeping existing flow for 'EmailBody' (text version), but adding HTMLBody.

	// Create authentic HTML preview
	safeHTML := sanitizeHTMLForPreview(body)

	highlightedBody := highlightKeywords(body, riskFactors.Suspiciouskeywords)

	return AnalysisResult{
		FileName:        filename,
		DetectedLang:    detectedLang,
		TranslatedBody:  translatedBody,
		ScamProbability: total,
		SafeProbability: 100 - total,
		TechScore:       techScore,
		BodyScore:       bodyScore,
		SubjectScore:    subjectScore,
		EmailBody:       highlightedBody,
		HTMLBody:        template.HTML(safeHTML),
		Headers: map[string]string{
			"From":    decodeHeader(msg.Header.Get("From")),
			"To":      decodeHeader(msg.Header.Get("To")),
			"Subject": decodeHeader(msg.Header.Get("Subject")),
			"Date":    msg.Header.Get("Date"),
		},
		RiskFactors:     riskFactors,
		ScoreBreakdown:  breakdown,
		BodyTriggers:    bodyTriggers,
		SubjectTriggers: subjectTriggers,
	}
}

func sanitizeHTMLForPreview(input string) string {
	// Remove <script> tags and their content
	reScript := regexp.MustCompile(`(?si)<script[^>]*>.*?</script>`)
	text := reScript.ReplaceAllString(input, "")

	// Remove on* events (simple regex, not perfect but helps)
	reEvents := regexp.MustCompile(`(?i) on\w+="[^"]*"`)
	text = reEvents.ReplaceAllString(text, "")

	return text
}

func extractEmailBody(msg *mail.Message) string {
	contentType := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		b, _ := io.ReadAll(msg.Body)
		return string(b)
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		return parseMultipart(msg.Body, params["boundary"])
	}

	// Not multipart
	b, _ := io.ReadAll(msg.Body)
	return decodeContent(string(b), msg.Header.Get("Content-Transfer-Encoding"))
}

func parseMultipart(r io.Reader, boundary string) string {
	mr := multipart.NewReader(r, boundary)
	var htmlBody, textBody string

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // Skip malformed parts
		}

		// Get types
		contentType := p.Header.Get("Content-Type")
		mediaType, params, _ := mime.ParseMediaType(contentType)
		cte := p.Header.Get("Content-Transfer-Encoding")

		if strings.HasPrefix(mediaType, "multipart/") {
			// RECURSIVE CALL
			subContent := parseMultipart(p, params["boundary"])
			// Heuristic: If we found something in the sub-part, use it.
			// Prefer HTML from sub-parts if it looks like HTML
			if strings.Contains(strings.ToLower(subContent), "<html") ||
				strings.Contains(strings.ToLower(subContent), "<div") ||
				strings.Contains(strings.ToLower(subContent), "<body") {
				htmlBody = subContent
			} else {
				// Keep as text fallback if we don't have text yet, or just overwrite?
				// In multipart/alternative, we usually want the last one.
				if textBody == "" {
					textBody = subContent
				}
			}
		} else if mediaType == "text/html" {
			b, _ := io.ReadAll(p)
			htmlBody = decodeContent(string(b), cte)
		} else if mediaType == "text/plain" {
			b, _ := io.ReadAll(p)
			// Only set text body if we haven't found a text body yet
			// (OR should we prioritize the last one for alternative? Let's keep first for simple text)
			// Actually RFC says last is best for alternative.
			textBody = decodeContent(string(b), cte)
		}
	}

	if htmlBody != "" {
		return htmlBody
	}
	return textBody
}

func decodeContent(content string, transferEncoding string) string {
	switch strings.ToLower(transferEncoding) {
	case "quoted-printable":
		r := quotedprintable.NewReader(strings.NewReader(content))
		b, _ := io.ReadAll(r)
		return string(b)
	// Base64 decoding could be added here if needed
	default:
		return content
	}
}

func highlightKeywords(body string, suspiciousKeywords []string) template.HTML {
	// Strip HTML first to get clean text
	cleanText := stripHTML(body)

	// Simple HTML escaping for safety before highlighting
	safeBody := html.EscapeString(cleanText)

	// Highlight critical phishing keywords (red)
	for _, kw := range suspiciousKeywords {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(kw) + `\b`)
		safeBody = re.ReplaceAllString(safeBody, `<span class="highlight-scam">$0</span>`)
	}

	// Highlight aggressive/urgency words (yellow/orange) - hardcoded list for now or reuse globalStats
	urgencyWords := []string{"immediately", "urgent", "suspend", "limit", "verify", "action"}
	for _, kw := range urgencyWords {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(kw) + `\b`)
		safeBody = re.ReplaceAllString(safeBody, `<span class="highlight-urgent">$0</span>`)
	}

	// Convert newlines to breaks for plain text visualization
	safeBody = strings.ReplaceAll(safeBody, "\n", "<br>")

	return template.HTML(safeBody)
}

func stripHTML(input string) string {
	// 0. Remove script and style blocks entirely (content included)
	// (?s) enables dot matching newlines
	reScriptStyle := regexp.MustCompile(`(?si)<(script|style)[^>]*>.*?</(script|style)>`)
	text := reScriptStyle.ReplaceAllString(input, "")

	// 1. Replace block tags with newlines to preserve structure
	// Replace <br>, <p>, <div>, </div>, </tr> with newlines
	reBlock := regexp.MustCompile(`(?i)<(br|p|div|/div|tr|/tr)[^>]*>`)
	text = reBlock.ReplaceAllString(text, "\n")

	// 2. Remove all other tags
	reTags := regexp.MustCompile(`<[^>]*>`)
	text = reTags.ReplaceAllString(text, "")

	// 3. Unescape HTML entities (&nbsp;, &amp;, etc.)
	text = html.UnescapeString(text)

	// 4. Collapse multiple newlines/spaces
	reSpace := regexp.MustCompile(`\n\s*\n`)
	text = reSpace.ReplaceAllString(text, "\n\n")

	return strings.TrimSpace(text)
}

func decodeHeader(header string) string {
	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(header)
	if err != nil {
		// If decoding fails, return original
		return header
	}
	return decoded
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
