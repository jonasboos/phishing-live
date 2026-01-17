# Technische Dokumentation: Linguistic Trainer (`cmd/trainer`)

## Einführung
Der `trainer` ist das analytische Backend des Projekts. Er ist kein Server, sondern ein CLI-Tool (Command Line Interface), das große Mengen an Trainingsdaten verarbeitet. Seine Aufgabe ist es, "Wahrheit" aus Daten zu extrahieren. Er vergleicht Tausende von bekannten gutartigen ("Ham") und bösartigen ("Spam/Phish") E-Mails, um die subtilen Unterschiede in der Sprache und Struktur zu quantifizieren.

Das Ergebnis seiner Arbeit ist die `linguistic_stats.json`, die als Gehirn für den Scanner-Server dient.

---

## 1. Datenverarbeitungspipeline

Der Prozess läuft in strengen Phasen ab:

### Phase 1: Ingestion (Einlesen)
*   **Format**: Der Trainer erwartet CSV-Dateien (Standard: Nazario Dataset Format) oder JSON-Arrays.
*   **Heuristik**: Er versucht intelligent, die Spalten für "Body", "Subject" und "Label" (Ist es Spam?) zu erkennen, auch wenn die CSV-Header variieren.
*   **Filterung**: Leere oder beschädigte Datensätze werden sofort verworfen.

### Phase 2: Preprocessing (Bereinigung)
Bevor Text analysiert werden kann, muss er normalisiert werden:
1.  **HTML Removal**: Entfernt alle Tags (`<br>`, `<div>`, `<a href...>`), da Spam-Mails oft code-lastig sind. Wir wollen aber den *sichtbaren* Text analysieren.
2.  **Tokenisierung**: Zerlegt Text in Wörter.
3.  **Stopwords**: Entfernt Füllwörter ("the", "and", "is"), die keine semantische Bedeutung für die Betrugserkennung haben.
4.  **Dictionary Check**: (Optional) Prüft gegen `words_alpha.txt`, um zufällige Zeichenketten (oft in Spam als Hash genutzt) zu ignorieren und sich auf echte Sprache zu konzentrieren.

### Phase 3: Feature Extraction (Merkmalserkennung)

Für jede E-Mail werden komplexe Metriken berechnet:

*   **Type-Token Ratio (TTR)**:
    *   Formel: `Einzigartige Wörter / Gesamtwörter`
    *   Bedeutung: Ein Maß für den Wortschatzreichtum. Phishing-Mails nutzen oft sehr repetitiven, einfachen Wortschatz (Copy-Paste-Templates).
*   **Sentiment Score**:
    *   Analysiert die Stimmung (Positiv vs. Negativ).
    *   Phishing nutzt oft extrem positive ("Gewinn", "Profit") oder extrem negative ("Verlust", "Gefahr") Wörter. Normale Mails sind oft neutraler.
*   **Readability (Lesbarkeit)**:
    *   Nutzt eine Annäherung an den *Automated Readability Index (ARI)*.
    *   Spam ist oft grammatikalisch schlecht oder künstlich komplex (um Spam-Filter zu verwirren).
*   **Shouting Score**:
    *   Verhältnis von Großbuchstaben. Ein hoher Score korreliert stark mit "Dringlichkeit" in Betrugsmails.

---

## 2. Statistische Aggregation

Nachdem alle Mails einzeln analysiert wurden, bildet der Trainer zwei große Cluster: **SAFE** und **SCAM**.

Er berechnet für jedes Wort im gesamten Wortschatz zwei Wahrscheinlichkeiten:
1.  `P(Wort | Spam)`: Wahrscheinlichkeit, dass das Wort auftritt, WENN es Spam ist.
2.  `P(Wort | Safe)`: Wahrscheinlichkeit, dass das Wort auftritt, WENN es sicher ist.

**Beispiel:**
Das Wort "Update" kommt oft in beiden vor. Relativ nutzlos.
Das Wort "Verifizierung" kommt in Safe-Mails selten, in Spam oft vor. -> **Starker Indikator**.

Der Trainer speichert nur die "Top N" Wörter, die die stärkste Trennschärfe zwischen den beiden Gruppen haben, um die JSON-Datei klein und performant zu halten.

---

---

## 3. Code-Map & Verzeichnisstruktur

### `cmd/trainer/main.go`
Ein eigenständiges CLI-Tool, das die Datenverarbeitung übernimmt.

#### Wichtige Funktionen
*   `func main()`:
    *   Liest Startargumente (`-file`).
    *   Lädt Wörterbücher (`words_alpha.txt`).
    *   Entscheidet ob CSV oder JSON Analyse gestartet wird (`analyzeCSV` vs `analyzeJSON`).
*   `func analyzeCSV(filePath)` / `analyzeJSON(filePath)`:
    *   Iteriert durch die Eingabedatei.
    *   Führt für *jede* E-Mail das Preprocessing durch (HTML entfernen, Stopwords entfernen).
    *   Ruft für *jede* E-Mail `analyzeDocument` auf.
    *   Aggregiert am Ende alle Daten und schreibt die `linguistic_stats.json`.
*   `func analyzeDocument(...) Document`:
    *   Die "Arbeitsbiene". Berechnet alle Metriken für eine einzelne Mail:
    *   **Word Count / Unique Words**: Zählt Wörter.
    *   **Richness Score**: Berechnet die lexikalische Vielfalt.
    *   `calculateSentiment(text)`: Zählt positive/negative Wörter (Gut vs. Böse).
    *   `calculateShoutingScore(text)`: Zählt Großbuchstaben ("URGENT").
    *   `calculateSpamTriggerDensity(text)`: Sucht nach Phrasen wie "act now" oder "winner".

### Externe Daten
*   `data/words_alpha.txt`: Ein englisches Wörterbuch, das automatisch heruntergeladen wird, um "echte" Wörter von "zufälligen Zeichen" zu unterscheiden.
*   `data/Nazario.csv` (oder andere): Die Input-Rohdaten.

---

## 4. Output Format (`linguistic_stats.json`)

Die generierte JSON-Datei enthält:

```json
{
  "safe_stats": {
    "total_emails": 1500,
    "top_body_words": [ ... ],
    "avg_shouting_score": 2.5
  },
  "scam_stats": {
    "total_emails": 1500,
    "top_body_words": [
      { "word": "suspended", "percent": 14.5 },
      { "word": "bank", "percent": 12.1 }
    ],
    "avg_shouting_score": 8.9
  }
}
```

Der Server nutzt diese Datei, um zu prüfen: *"Diese neue E-Mail hat einen Shouting-Score von 9.0. Das liegt sehr nah am Scam-Durchschnitt (8.9) und weit weg vom Safe-Durchschnitt (2.5). Das ist verdächtig."*

---

## 4. Training durchführen

Um den Trainer laufen zu lassen, wird der Befehl im Terminal ausgeführt:

```bash
# Standard (sucht nach data/Nazario.csv)
go run cmd/trainer/main.go

# Mit spezifischer Datei
go run cmd/trainer/main.go -file mein_eigener_datensatz.csv
```

**Wichtig**: Je besser und größer der Datensatz, desto "schlauer" wird das System. Ein Datensatz mit nur Finanz-Spam wird das System sehr gut auf Bank-Betrug trainieren, aber vielleicht schlechter auf "Enkel-Trick"-Betrug. Diversität im Training ist wichtig.
