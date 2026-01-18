package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

// --- Configuration & Regex ---

var (
	// Strict letters only for words
	wordRegex    = regexp.MustCompile(`[a-zA-Z]+`)
	htmlTagRegex = regexp.MustCompile(`<[^>]*>`)

	// Common English stop words to ignore
	stopWords = map[string]bool{
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

	// Words clearly visible in dataset but irrelevant for phishing detection
	phishingIrrelevant = map[string]bool{
		// Common email greetings/closings
		"dear": true, "please": true, "thank": true, "thanks": true, "regards": true,
		"sincerely": true, "hello": true, "hi": true, "sir": true, "madam": true,
		// Names / Artifacts
		"jose": true, "monkey": true, "john": true, "james": true, "david": true,
		"michael": true, "robert": true, "william": true, "mary": true, "patricia": true,
		// Tech terms
		"com": true, "org": true, "net": true, "gov": true, "edu": true, "mil": true,
		"www": true, "http": true, "https": true, "html": true, "php": true,
		// Generic
		"here": true, "below": true, "above": true, "following": true, "attached": true,
		"received": true, "sent": true, "reply": true, "forward": true,
		"today": true, "tomorrow": true, "yesterday": true, "soon": true,
		"may": true, "might": true, "must": true, "should": true, "would": true,
		"contact": true, "questions": true, "help": true, "support": true,
		"best": true, "team": true, "company": true,
		// Numbers
		"one": true, "two": true, "three": true, "four": true, "five": true,
	}

	validEnglishWords = make(map[string]bool)
)

const dictionaryURL = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
const dictionaryFile = "../../data/words_alpha.txt"

// --- Data Structures ---

type WordFreq struct {
	Word    string  `json:"word"`
	Count   int     `json:"count"`
	Percent float64 `json:"percent"`
}

type LinguisticStats struct {
	TotalEmails     int        `json:"total_emails"`
	TopBodyWords    []WordFreq `json:"top_body_words"`
	TopSubjectWords []WordFreq `json:"top_subject_words"`
}

// --- Main ---

func main() {
	loadDictionary()
	filePath := flag.String("file", "", "Path to the input CSV file")
	flag.Parse()

	if *filePath == "" {
		if _, err := os.Stat("../../data/Nazario.csv"); err == nil {
			*filePath = "../../data/Nazario.csv"
			fmt.Println("No file specified, defaulting to ../../data/Nazario.csv")
		} else {
			log.Fatal("Please provide a file path using -file")
		}
	}

	analyzeCSV(*filePath)
}

// --- Dictionary Loading ---

func loadDictionary() {
	if _, err := os.Stat(dictionaryFile); os.IsNotExist(err) {
		fmt.Println("Dictionary not found. Downloading...")
		if err := downloadFile(dictionaryFile, dictionaryURL); err != nil {
			log.Printf("Error downloading dictionary: %v. Filtering disabled.\n", err)
			return
		}
		fmt.Println("Dictionary downloaded successfully.")
	}

	file, err := os.Open(dictionaryFile)
	if err != nil {
		log.Printf("Warning: Could not open dictionary: %v. Filtering disabled.", err)
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
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// --- Analysis Logic ---

func analyzeCSV(filePath string) {
	fmt.Printf("Analyzing CSV file: %s for keywords...\n", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Unable to read input file %s: %v", filePath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	csvReader.LazyQuotes = true

	header, err := csvReader.Read()
	if err != nil {
		log.Fatal("Unable to read header:", err)
	}

	// Identify columns
	labelIdx, bodyIdx, subjectIdx := -1, -1, -1
	for i, h := range header {
		hLower := strings.ToLower(strings.TrimSpace(h))
		if hLower == "label" || hLower == "class" {
			labelIdx = i
		}
		if hLower == "body" || hLower == "text" {
			bodyIdx = i
		}
		if hLower == "subject" {
			subjectIdx = i
		}
	}

	// Defaults for Nazario
	if labelIdx == -1 {
		labelIdx = len(header) - 1
	}
	if bodyIdx == -1 && len(header) > 4 {
		bodyIdx = 4
	}
	if subjectIdx == -1 && len(header) > 3 {
		subjectIdx = 3
	}

	fmt.Printf("Columns detected - Subject: %d, Body: %d (Ignoring Label)\n", subjectIdx, bodyIdx)

	// Counters
	bodyCounts := make(map[string]int)
	subjectCounts := make(map[string]int)

	count := 0

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) <= bodyIdx {
			continue
		}

		count++
		if count%1000 == 0 {
			fmt.Printf("Processed %d emails...\r", count)
		}

		// Extract content
		subject := ""
		if subjectIdx != -1 && subjectIdx < len(record) {
			subject = record[subjectIdx]
		}
		body := record[bodyIdx]

		// Process Body
		bodyWords := extractWords(body)
		for w := range bodyWords {
			bodyCounts[w]++
		}

		// Process Subject
		subjectWords := extractWords(subject)
		for w := range subjectWords {
			subjectCounts[w]++
		}
	}

	fmt.Printf("\nTotal Emails Analyzed: %d\n", count)
	fmt.Println("Generating statistical report...")

	report := LinguisticStats{
		TotalEmails:     count,
		TopBodyWords:    getTopWords(bodyCounts, count),
		TopSubjectWords: getTopWords(subjectCounts, count),
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
	fmt.Println("Success! Stats saved to linguistic_stats.json")
}

// extractWords cleans text and returns unique words for the document freq count
func extractWords(text string) map[string]bool {
	// 1. Remove HTML tags
	clean := htmlTagRegex.ReplaceAllString(text, " ")
	// 2. Lowercase
	lower := strings.ToLower(clean)
	// 3. Find words
	raw := wordRegex.FindAllString(lower, -1)

	unique := make(map[string]bool)
	for _, w := range raw {
		// Filter small words / numeric
		if len(w) < 3 || isNumeric(w) {
			continue
		}
		// Filter stop words and irrelevant words
		if stopWords[w] || phishingIrrelevant[w] {
			continue
		}
		// Dictionary check (if available)
		if len(validEnglishWords) > 0 && !validEnglishWords[w] {
			continue
		}
		unique[w] = true
	}
	return unique
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func getTopWords(counts map[string]int, total int) []WordFreq {
	if total == 0 {
		return []WordFreq{}
	}
	var list []WordFreq
	for w, c := range counts {
		// Minimum occurrence threshold (e.g., must appear in at least 2 emails)
		if c > 2 {
			pct := (float64(c) / float64(total)) * 100
			list = append(list, WordFreq{Word: w, Count: c, Percent: pct})
		}
	}
	// Sort by Percent descending
	sort.Slice(list, func(i, j int) bool {
		return list[i].Percent > list[j].Percent
	})
	// Top 100
	if len(list) > 100 {
		return list[:100]
	}
	return list
}
