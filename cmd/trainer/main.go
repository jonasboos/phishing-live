package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Document represents a single email's analysis
type Document struct {
	Index              int     `json:"index"`
	Subject            string  `json:"subject"`
	Body               string  `json:"body"`
	WordCount          int     `json:"word_count"`
	UniqueWordCount    int     `json:"unique_word_count"`
	SentenceCount      int     `json:"sentence_count"`
	AvgSentenceLen     float64 `json:"avg_sentence_len"`
	TTR                float64 `json:"ttr"`                  // Type-Token Ratio
	RichnessStore      float64 `json:"richness_score"`       // Custom score for 'meaningfulness'
	SentimentScore     float64 `json:"sentiment_score"`      // Positive/Negative dictionary match
	ReadabilityScore   float64 `json:"readability_score"`    // Automated Readability Index approximation
	ShoutingScore      float64 `json:"shouting_score"`       // Ratio of uppercase chars vs total chars
	SpamTriggerDensity float64 `json:"spam_trigger_density"` // Occurrences of trigger phrases per 100 words
}

// CorpusStats holds aggregated statistics
type CorpusStats struct {
	TotalEmails          int     `json:"total_emails_analyzed"`
	TotalWords           int     `json:"total_words"`
	UniqueWords          int     `json:"unique_words"`
	AvgWordsPerEmail     float64 `json:"avg_words_per_email"`
	AvgSentencesPerEmail float64 `json:"avg_sentences_per_email"`
	AvgSentiment         float64 `json:"avg_sentiment"`
	AvgReadability       float64 `json:"avg_readability"`
	AvgShouting          float64 `json:"avg_shouting"`
	AvgSpamDensity       float64 `json:"avg_spam_density"`
}

// WordFrequency holds a word and its count
type WordFrequency struct {
	Word  string `json:"word"`
	Count int    `json:"count"`
}

// SentenceFrequency holds a sentence and its count
type SentenceFrequency struct {
	Sentence string `json:"sentence"`
	Count    int    `json:"count"`
}

// Metadata holds verbose execution details
type Metadata struct {
	AnalysisTimestamp  string  `json:"analysis_timestamp"`
	EngineVersion      string  `json:"engine_version"`
	HeuristicModel     string  `json:"heuristic_model"`
	DataIntegrityScore float64 `json:"data_integrity_score"`
	ProcessorID        string  `json:"processor_id"`
	ProcessDescription string  `json:"process_description"`
}

// AnalysisResult is the final output structure
type AnalysisResult struct {
	Metadata            Metadata            `json:"metadata"`
	CorpusStats         CorpusStats         `json:"corpus_stats"`
	TopWords            []WordFrequency     `json:"top_words"`
	TopSentences        []SentenceFrequency `json:"top_sentences"`
	MeaningfulDocuments []DocumentSnippet   `json:"meaningful_documents"`
}

type DocumentSnippet struct {
	Criteria string  `json:"criteria"`
	Index    int     `json:"index"`
	Subject  string  `json:"subject"`
	Snippet  string  `json:"snippet"`
	Score    float64 `json:"score"`
}

var (
	wordRegex     = regexp.MustCompile(`[a-zA-Z]+`) // Strict letters only
	sentenceRegex = regexp.MustCompile(`[.!?]+`)
	stopWords     = map[string]bool{
		"the": true, "be": true, "to": true, "of": true, "and": true,
		"a": true, "in": true, "that": true, "have": true, "i": true,
		"it": true, "for": true, "not": true, "on": true, "with": true,
		"he": true, "as": true, "you": true, "do": true, "at": true,
		"this": true, "but": true, "his": true, "by": true, "from": true,
		"they": true, "we": true, "say": true, "her": true, "she": true,
		"or": true, "an": true, "will": true, "my": true, "one": true,
		"all": true, "would": true, "there": true, "their": true, "what": true,
		"so": true, "up": true, "out": true, "if": true, "about": true,
		"who": true, "get": true, "which": true, "go": true, "me": true,
		"when": true, "make": true, "can": true, "like": true, "time": true,
		"no": true, "just": true, "him": true, "know": true, "take": true,
		"people": true, "into": true, "year": true, "your": true, "good": true,
		"some": true, "could": true, "them": true, "see": true, "other": true,
		"than": true, "then": true, "now": true, "look": true, "only": true,
		"come": true, "its": true, "over": true, "think": true, "also": true,
		"back": true, "after": true, "use": true, "two": true, "how": true,
		"our": true, "work": true, "first": true, "well": true, "way": true,
		"even": true, "new": true, "want": true, "because": true, "any": true,
		"these": true, "give": true, "day": true, "most": true, "us": true,
		"is": true, "are": true, "was": true, "were": true, "been": true, "has": true,
		"re": true, "fw": true, "cc": true, "pm": true, "am": true, "subject": true, "forwarded": true,
		"original": true, "message": true, "sent": true, "date": true,
		"mail": true, "mailto": true, "image": true, "attached": true, "file": true,
	}
	// Words that appear in phishing dataset but aren't actual phishing indicators
	phishingIrrelevant = map[string]bool{
		// Common email words
		"dear": true, "please": true, "thank": true, "thanks": true, "regards": true,
		"sincerely": true, "hello": true, "hi": true, "sir": true, "madam": true,
		// Names (from dataset artifacts)
		"jose": true, "monkey": true, "john": true, "james": true, "david": true,
		"michael": true, "robert": true, "william": true, "mary": true, "patricia": true,
		// Domain/tech noise
		"com": true, "org": true, "net": true, "gov": true, "edu": true, "mil": true,
		"www": true, "http": true, "https": true, "html": true, "php": true,
		// Generic words
		"here": true, "below": true, "above": true, "following": true, "attached": true,
		"received": true, "sent": true, "reply": true, "forward": true,
		"today": true, "tomorrow": true, "yesterday": true, "soon": true,
		"may": true, "might": true, "must": true, "should": true, "would": true,
		"contact": true, "questions": true, "help": true, "support": true,
		"best": true, "team": true, "company": true,
		// Numbers as words
		"one": true, "two": true, "three": true, "four": true, "five": true,
	}
	validEnglishWords = make(map[string]bool)
)

const dictionaryURL = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
const dictionaryFile = "../../data/words_alpha.txt"

func loadDictionary() {
	// Check if file exists
	if _, err := os.Stat(dictionaryFile); os.IsNotExist(err) {
		fmt.Println("Dictionary not found. Downloading from", dictionaryURL, "...")
		if err := downloadFile(dictionaryFile, dictionaryURL); err != nil {
			log.Printf("Error downloading dictionary: %v. Filtering disabled.\n", err)
			return
		}
		fmt.Println("Dictionary downloaded successfully.")
	}

	file, err := os.Open(dictionaryFile)
	if err != nil {
		log.Printf("Warning: Could not open dictionary: %v. Dictionary filtering disabled.", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if len(word) > 1 {
			validEnglishWords[word] = true
		}
	}
}

func downloadFile(filepath string, url string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// LinguisticAnalysis holds the descriptive stats for a category (Safe vs Scam)
type LinguisticStats struct {
	TotalEmails       int        `json:"total_emails"`
	AvgWordCount      float64    `json:"avg_word_count"`
	AvgSentenceLength float64    `json:"avg_sentence_length"`
	AvgShoutingScore  float64    `json:"avg_shouting_score"`
	TopBodyWords      []WordFreq `json:"top_body_words"`
	TopSubjectWords   []WordFreq `json:"top_subject_words"`
}

type WordFreq struct {
	Word    string  `json:"word"`
	Count   int     `json:"count"`
	Percent float64 `json:"percent"`
}

type LinguisticReport struct {
	SafeStats LinguisticStats `json:"safe_stats"`
	ScamStats LinguisticStats `json:"scam_stats"`
}

// JSONEntry represents a row in combined_reduced.json
type JSONEntry struct {
	Text  string `json:"text"`
	Label int    `json:"label"` // 0 = Safe, 1 = Scam
}

// WordStats holds statistics for a single word
type WordStats struct {
	SafeCount int     `json:"safe_count"`
	ScamCount int     `json:"scam_count"`
	SpamProb  float64 `json:"spam_prob"`
}

// TrainingOutput represents the generated model/stats
type TrainingOutput struct {
	TotalSafeEmails int                  `json:"total_safe_emails"`
	TotalScamEmails int                  `json:"total_scam_emails"`
	WordStats       map[string]WordStats `json:"word_stats"`
}

func main() {
	loadDictionary()
	filePath := flag.String("file", "", "Path to the input file (.csv or .json)")
	flag.Parse()

	if *filePath == "" {
		// Default to Nazario.csv if present and no flag
		if _, err := os.Stat("../../data/Nazario.csv"); err == nil {
			*filePath = "../../data/Nazario.csv"
			fmt.Println("No file specified, defaulting to ../../data/Nazario.csv")
		} else {
			log.Fatal("Please provide a file path using -file")
		}
	}

	if strings.HasSuffix(*filePath, ".json") {
		analyzeJSON(*filePath)
	} else {
		analyzeCSV(*filePath)
	}
}

func analyzeJSON(filePath string) {
	fmt.Printf("Analyzing JSON file: %s for linguistic features...\n", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Unable to open file: %v", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	_, err = dec.Token() // Open bracket
	if err != nil {
		log.Fatal(err)
	}

	// Accumulators
	safeWordCounts := make(map[string]int)
	scamWordCounts := make(map[string]int)

	var safeWordSum, scamWordSum int
	var safeSentSum, scamSentSum int
	var safeShoutSum, scamShoutSum float64
	var safeCount, scamCount int

	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	// Simple sentence approximation (split by . ! ?)
	sentSplit := regexp.MustCompile(`[.!?]+`)

	count := 0
	for dec.More() {
		var entry JSONEntry
		if err := dec.Decode(&entry); err != nil {
			log.Printf("Error decoding entry: %v", err)
			continue
		}
		count++
		if count%1000 == 0 {
			fmt.Printf("Processed %d emails...\r", count)
		}

		// 1. Preprocessing
		cleanText := htmlTagRegex.ReplaceAllString(entry.Text, " ")
		textLower := strings.ToLower(cleanText)

		// 2. Lingustic Features

		// Words
		words := wordRegex.FindAllString(textLower, -1)
		currWordCount := 0
		uniqueWordsInDoc := make(map[string]bool)

		for _, w := range words {
			if len(w) < 3 || isNumeric(w) {
				continue
			}
			if len(validEnglishWords) > 0 && !validEnglishWords[w] {
				continue
			}
			if stopWords[w] {
				continue
			}

			currWordCount++
			uniqueWordsInDoc[w] = true
		}

		// Update global document frequency counts
		for w := range uniqueWordsInDoc {
			if entry.Label == 1 {
				scamWordCounts[w]++
			} else {
				safeWordCounts[w]++
			}
		}

		// Sentences
		sentences := sentSplit.Split(cleanText, -1)
		currSentCount := 0
		for _, s := range sentences {
			if len(strings.TrimSpace(s)) > 10 {
				currSentCount++
			}
		}
		if currSentCount == 0 {
			currSentCount = 1
		} // avoid div by zero issues later

		// Shouting
		shoutScore := calculateShoutingScore(cleanText)

		// 3. Accumulate
		if entry.Label == 1 {
			scamCount++
			scamWordSum += currWordCount
			scamSentSum += currWordCount / currSentCount // Approx avg sentence length (words/sentence) for this doc
			scamShoutSum += shoutScore
		} else {
			safeCount++
			safeWordSum += currWordCount
			safeSentSum += currWordCount / currSentCount
			safeShoutSum += shoutScore
		}
	}

	_, err = dec.Token() // Close bracket

	fmt.Println("\nGenerating linguistic report...")

	// Helper to get top formatted words
	getTopWords := func(counts map[string]int, total int) []WordFreq {
		if total == 0 {
			return nil
		}
		var wordList []WordFreq
		for w, c := range counts {
			if c > 2 {
				percent := (float64(c) / float64(total)) * 100
				wordList = append(wordList, WordFreq{Word: w, Count: c, Percent: percent})
			}
		}
		sort.Slice(wordList, func(i, j int) bool {
			return wordList[i].Percent > wordList[j].Percent
		})
		topN := 100
		if len(wordList) < topN {
			topN = len(wordList)
		}
		return wordList[:topN]
	}

	report := LinguisticReport{
		SafeStats: LinguisticStats{
			TotalEmails:       safeCount,
			AvgWordCount:      float64(safeWordSum) / float64(safeCount),
			AvgSentenceLength: float64(safeSentSum) / float64(safeCount),
			AvgShoutingScore:  safeShoutSum / float64(safeCount),
			TopBodyWords:      getTopWords(safeWordCounts, safeCount),
			TopSubjectWords:   []WordFreq{}, // No subject in this JSON dataset
		},
		ScamStats: LinguisticStats{
			TotalEmails:       scamCount,
			AvgWordCount:      float64(scamWordSum) / float64(scamCount),
			AvgSentenceLength: float64(scamSentSum) / float64(scamCount),
			AvgShoutingScore:  scamShoutSum / float64(scamCount),
			TopBodyWords:      getTopWords(scamWordCounts, scamCount),
			TopSubjectWords:   []WordFreq{}, // No subject in this JSON dataset
		},
	}

	outFile, err := os.Create("../../data/linguistic_stats.json")
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	enc := json.NewEncoder(outFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Done! Linguistic analysis written to linguistic_stats.json")
}

func analyzeDocument(index int, subject, body string, globalWordCounts, globalSentenceCounts map[string]int) Document {
	text := subject + " " + body
	textLower := strings.ToLower(text)

	// Word Analysis
	rawWords := wordRegex.FindAllString(textLower, -1)
	docWordCounts := make(map[string]int)
	validWordCount := 0

	for _, w := range rawWords {
		if len(w) < 2 { // Skip single letters
			continue
		}
		// Skip purely numeric tokens
		if isNumeric(w) {
			continue
		}
		// Check if it's a valid English word (if dictionary is loaded)
		if len(validEnglishWords) > 0 && !validEnglishWords[w] {
			continue
		}

		if !stopWords[w] {
			docWordCounts[w]++
			globalWordCounts[w]++
			validWordCount++
		}
	}

	// Sentence Analysis
	sentences := sentenceRegex.Split(text, -1)
	sentenceCount := 0
	totalSentenceLen := 0
	for _, s := range sentences {
		trimmed := strings.TrimSpace(s)
		if len(trimmed) > 10 { // Minimum length to be considered a real sentence
			globalSentenceCounts[strings.ToLower(trimmed)]++
			sentenceCount++
			totalSentenceLen += len(strings.Fields(trimmed))
		}
	}

	avgSentenceLen := 0.0
	if sentenceCount > 0 {
		avgSentenceLen = float64(totalSentenceLen) / float64(sentenceCount)
	}

	ttr := 0.0
	if validWordCount > 0 {
		ttr = float64(len(docWordCounts)) / float64(validWordCount)
	}

	// Richness Score: TTR * log(WordCount). Favors diverse vocabulary in longer texts.

	// Richness Score: TTR * log(WordCount). Favors diverse vocabulary in longer texts.
	richnessScore := 0.0
	if validWordCount > 1 {
		richnessScore = ttr * math.Log(float64(validWordCount))
	}

	// Advanced Metrics
	sentiment := calculateSentiment(text)
	readability := calculateReadability(text, validWordCount, sentenceCount)
	shouting := calculateShoutingScore(text)
	spamDensity := calculateSpamTriggerDensity(text)

	return Document{
		Index:              index,
		Subject:            subject,
		Body:               body,
		WordCount:          validWordCount,
		UniqueWordCount:    len(docWordCounts),
		SentenceCount:      sentenceCount,
		AvgSentenceLen:     avgSentenceLen,
		TTR:                ttr,
		RichnessStore:      richnessScore,
		SentimentScore:     sentiment,
		ReadabilityScore:   readability,
		ShoutingScore:      shouting,
		SpamTriggerDensity: spamDensity,
	}
}

func getTopWords(counts map[string]int, n int) []WordFrequency {
	var freqs []WordFrequency
	for w, c := range counts {
		freqs = append(freqs, WordFrequency{Word: w, Count: c})
	}
	sort.Slice(freqs, func(i, j int) bool {
		return freqs[i].Count > freqs[j].Count
	})
	if len(freqs) > n {
		return freqs[:n]
	}
	return freqs
}

func getTopSentences(counts map[string]int, n int) []SentenceFrequency {
	var freqs []SentenceFrequency
	for s, c := range counts {
		freqs = append(freqs, SentenceFrequency{Sentence: s, Count: c})
	}
	sort.Slice(freqs, func(i, j int) bool {
		return freqs[i].Count > freqs[j].Count
	})
	if len(freqs) > n {
		return freqs[:n]
	}
	return freqs
}

func getMeaningfulDocuments(docs []Document) []DocumentSnippet {
	var snippets []DocumentSnippet

	// Top 5 by Richness Score
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].RichnessStore > docs[j].RichnessStore
	})
	for i := 0; i < 5 && i < len(docs); i++ {
		snippets = append(snippets, DocumentSnippet{
			Criteria: "High Lexical Richness",
			Index:    docs[i].Index,
			Subject:  docs[i].Subject,
			Snippet:  getSnippet(docs[i].Body),
			Score:    docs[i].RichnessStore,
		})
	}

	// Top 5 by Word Count
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].WordCount > docs[j].WordCount
	})
	for i := 0; i < 5 && i < len(docs); i++ {
		snippets = append(snippets, DocumentSnippet{
			Criteria: "Highest Word Count",
			Index:    docs[i].Index,
			Subject:  docs[i].Subject,
			Snippet:  getSnippet(docs[i].Body),
			Score:    float64(docs[i].WordCount),
		})
	}

	return snippets
}

func getSnippet(body string) string {
	runes := []rune(body)
	if len(runes) > 100 {
		return string(runes[:100]) + "..."
	}
	return body
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

var (
	spamTriggers = []string{
		"act now", "winner", "free", "urgent", "click here",
		"limited time", "guaranteed", "investment", "security", "account",
		"verify", "suspended", "lottery", "prize", "selected",
	}
	positiveWords = map[string]bool{
		"good": true, "great": true, "excellent": true, "best": true,
		"love": true, "happy": true, "success": true, "profit": true,
		"win": true, "gain": true, "opportunity": true, "freedom": true,
	}
	negativeWords = map[string]bool{
		"bad": true, "loss": true, "failure": true, "scam": true,
		"fraud": true, "urgent": true, "danger": true, "risk": true,
		"fear": true, "lose": true, "limit": true, "cancel": true,
	}
)

func calculateSentiment(text string) float64 {
	words := wordRegex.FindAllString(strings.ToLower(text), -1)
	if len(words) == 0 {
		return 0
	}
	score := 0.0
	for _, w := range words {
		if positiveWords[w] {
			score += 1.0
		} else if negativeWords[w] {
			score -= 1.0
		}
	}
	// Normalize slightly
	return score / float64(len(words)) * 10.0 // Scaled
}

func calculateReadability(text string, wordCount, sentenceCount int) float64 {
	// Approximation of Automated Readability Index (ARI)
	if wordCount == 0 || sentenceCount == 0 {
		return 0
	}

	cleanText := strings.ReplaceAll(text, " ", "")
	charCount := len(cleanText)

	// ARI = 4.71 * (chars/words) + 0.5 * (words/sentences) - 21.43
	avgCharsPerWord := float64(charCount) / float64(wordCount)
	avgWordsPerSentence := float64(wordCount) / float64(sentenceCount)

	return 4.71*avgCharsPerWord + 0.5*avgWordsPerSentence - 21.43
}

func calculateShoutingScore(text string) float64 {
	if len(text) == 0 {
		return 0
	}
	upperCount := 0
	totalChars := 0
	for _, r := range text {
		if unicode.IsLetter(r) {
			totalChars++
			if unicode.IsUpper(r) {
				upperCount++
			}
		}
	}
	if totalChars == 0 {
		return 0
	}
	return float64(upperCount) / float64(totalChars)
}

func calculateSpamTriggerDensity(text string) float64 {
	lowerText := strings.ToLower(text)
	matches := 0
	for _, trigger := range spamTriggers {
		matches += strings.Count(lowerText, trigger)
	}

	wordCount := len(strings.Fields(lowerText))
	if wordCount == 0 {
		return 0
	}

	// Triggers per 100 words
	return (float64(matches) / float64(wordCount)) * 100
}

func analyzeCSV(filePath string) {
	fmt.Printf("Analyzing CSV file: %s for linguistic features...\n", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Unable to read input file %s: %v", filePath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	csvReader.LazyQuotes = true

	// Read header
	header, err := csvReader.Read()
	if err != nil {
		log.Fatal("Unable to read header:", err)
	}

	// Find indices
	labelIdx := -1
	bodyIdx := -1
	subjectIdx := -1

	for i, h := range header {
		cleanH := strings.ToLower(strings.TrimSpace(h))
		if cleanH == "label" || cleanH == "class" {
			labelIdx = i
		}
		if cleanH == "body" || cleanH == "text" {
			bodyIdx = i
		}
		if cleanH == "subject" {
			subjectIdx = i
		}
	}

	// Fallback/Heuristics
	if labelIdx == -1 {
		labelIdx = len(header) - 1 // Assume last
	}
	if bodyIdx == -1 && len(header) > 4 {
		bodyIdx = 4 // Nazario default
	}
	if subjectIdx == -1 && len(header) > 3 {
		subjectIdx = 3 // Nazario default
	}

	fmt.Printf("Columns - Subject: %d, Body: %d, Label: %d\n", subjectIdx, bodyIdx, labelIdx)

	// Accumulators
	safeBodyWordCounts := make(map[string]int)
	scamBodyWordCounts := make(map[string]int)
	safeSubjectWordCounts := make(map[string]int)
	scamSubjectWordCounts := make(map[string]int)

	var safeWordSum, scamWordSum int
	var safeSentSum, scamSentSum int
	var safeShoutSum, scamShoutSum float64
	var safeCount, scamCount int

	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	sentSplit := regexp.MustCompile(`[.!?]+`)

	count := 0
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(record) <= labelIdx || len(record) <= bodyIdx {
			continue
		}

		count++
		if count%1000 == 0 {
			fmt.Printf("Processed %d emails...\r", count)
		}

		// Determine Label
		labelStr := strings.TrimSpace(record[labelIdx])
		isScam := labelStr == "1" || strings.ToLower(labelStr) == "phish" || strings.ToLower(labelStr) == "spam"

		// Get Content
		subjectText := ""
		if subjectIdx != -1 && subjectIdx < len(record) {
			subjectText = record[subjectIdx]
		}
		bodyText := record[bodyIdx]

		// 1. Body Analysis
		cleanBody := htmlTagRegex.ReplaceAllString(bodyText, " ")
		bodyLower := strings.ToLower(cleanBody)
		bodyWords := wordRegex.FindAllString(bodyLower, -1)
		uniqueBodyWords := make(map[string]bool)
		for _, w := range bodyWords {
			if len(w) < 3 || isNumeric(w) {
				continue
			}
			if len(validEnglishWords) > 0 && !validEnglishWords[w] {
				continue
			}
			if stopWords[w] {
				continue
			}
			if phishingIrrelevant[w] {
				continue
			}
			uniqueBodyWords[w] = true
		}

		// 2. Subject Analysis
		subjLower := strings.ToLower(subjectText)
		subjWords := wordRegex.FindAllString(subjLower, -1)
		uniqueSubjWords := make(map[string]bool)
		for _, w := range subjWords {
			if len(w) < 2 || isNumeric(w) {
				continue
			} // Allow 2-letter words in subject (e.g. "re", "fw")
			if stopWords[w] {
				continue
			}
			if phishingIrrelevant[w] {
				continue
			}
			uniqueSubjWords[w] = true
		}

		// 3. Update Global Stats
		if isScam {
			scamCount++
			// Body Stats
			scamWordSum += len(bodyWords) // Rough estimate
			scamShoutSum += calculateShoutingScore(cleanBody)

			// Sentences (Body only)
			sentences := sentSplit.Split(cleanBody, -1)
			currSentCount := 0
			for _, s := range sentences {
				if len(strings.TrimSpace(s)) > 10 {
					currSentCount++
				}
			}
			if currSentCount == 0 {
				currSentCount = 1
			}
			scamSentSum += len(bodyWords) / currSentCount

			// Word Frequencies
			for w := range uniqueBodyWords {
				scamBodyWordCounts[w]++
			}
			for w := range uniqueSubjWords {
				scamSubjectWordCounts[w]++
			}

		} else {
			safeCount++
			// Body Stats
			safeWordSum += len(bodyWords)
			safeShoutSum += calculateShoutingScore(cleanBody)

			// Sentences
			sentences := sentSplit.Split(cleanBody, -1)
			currSentCount := 0
			for _, s := range sentences {
				if len(strings.TrimSpace(s)) > 10 {
					currSentCount++
				}
			}
			if currSentCount == 0 {
				currSentCount = 1
			}
			safeSentSum += len(bodyWords) / currSentCount

			// Word Frequencies
			for w := range uniqueBodyWords {
				safeBodyWordCounts[w]++
			}
			for w := range uniqueSubjWords {
				safeSubjectWordCounts[w]++
			}
		}
	}

	fmt.Printf("\nTotal Emails: %d (Safe: %d, Scam: %d)\n", count, safeCount, scamCount)
	fmt.Println("Generating linguistic report...")

	// Helper to get top formatted words
	getTopWords := func(counts map[string]int, total int) []WordFreq {
		if total == 0 {
			return nil
		}
		var wordList []WordFreq
		for w, c := range counts {
			if c > 2 {
				percent := (float64(c) / float64(total)) * 100
				wordList = append(wordList, WordFreq{Word: w, Count: c, Percent: percent})
			}
		}
		sort.Slice(wordList, func(i, j int) bool {
			return wordList[i].Percent > wordList[j].Percent
		})
		topN := 100
		if len(wordList) < topN {
			topN = len(wordList)
		}
		return wordList[:topN]
	}

	// Helper for safe division
	safeDiv := func(n, d int) float64 {
		if d == 0 {
			return 0.0
		}
		return float64(n) / float64(d)
	}

	report := LinguisticReport{
		SafeStats: LinguisticStats{
			TotalEmails:       safeCount,
			AvgWordCount:      safeDiv(safeWordSum, safeCount),
			AvgSentenceLength: safeDiv(safeSentSum, safeCount),
			AvgShoutingScore:  safeDiv(int(safeShoutSum*100), safeCount) / 100, // Handle float div slightly differently or just use safeDiv for floats
			TopBodyWords:      getTopWords(safeBodyWordCounts, safeCount),
			TopSubjectWords:   getTopWords(safeSubjectWordCounts, safeCount),
		},
		ScamStats: LinguisticStats{
			TotalEmails:       scamCount,
			AvgWordCount:      safeDiv(scamWordSum, scamCount),
			AvgSentenceLength: safeDiv(scamSentSum, scamCount),
			AvgShoutingScore:  safeDiv(int(scamShoutSum*10000), scamCount) / 10000, // Trick to preserve precision or just cast
			TopBodyWords:      getTopWords(scamBodyWordCounts, scamCount),
			TopSubjectWords:   getTopWords(scamSubjectWordCounts, scamCount),
		},
	}

	outFile, err := os.Create("linguistic_stats.json")
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	enc := json.NewEncoder(outFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Done! Linguistic analysis written to linguistic_stats.json")
}
