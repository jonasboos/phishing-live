# Technische Dokumentation: Phishing Scanner Server (`cmd/server`)

## Einführung
Der Server ist das Herzstück des Phishing-Erkennungssystems. Er stellt eine Web-Oberfläche bereit, über die Benutzer E-Mails (im `.eml` oder `.mbox` Format) hochladen können. Diese E-Mails werden in Echtzeit analysiert, indem technische Header-Informationen mit linguistischen Merkmalen des Inhalts kombiniert werden.

Das Ziel ist es, eine **Betrugswahrscheinlichkeit (Scam Probability)** zu berechnen, die nicht nur auf einfachen Listen ("Blacklists") basiert, sondern auf dem Verhalten und der Struktur der E-Mail.

---

## 1. Systemarchitektur

Der Server ist in Go geschrieben und nutzt ausschließlich die Standardbibliothek sowie `html/template` für das Rendering. Er besteht aus drei Hauptkomponenten:

1.  **Handler-Layer**: Nimmt HTTP-Requests entgegen (`/` für Frontend, `/analyze` für Uploads).
2.  **Analyse-Engine**: Zerlegt die E-Mail in Header und Body und führt diverse Checks durch.
3.  **Wissensbasis**: Lädt beim Start eine JSON-Datenbank (`linguistic_stats.json`), die vom `trainer` erstellt wurde und statistische Merkmale von Phishing-Mails enthält.

---

## 2. Analyse-Verfahren

Die Analyse erfolgt in drei gewichteten Kategorien. Die Endpunktzahl (0-100%) setzt sich wie folgt zusammen:

| Kategorie | Gewichtung | Beschreibung |
| :--- | :--- | :--- |
| **Technische Sicherheit** | **40%** | Prüft die Infrastruktur des Absenders (SPF, DKIM, DMARC, DNS). |
| **Inhaltliche Analyse** | **35%** | Untersucht den E-Mail-Text auf typische Phishing-Phrasen und psychologischen Druck. |
| **Betreff-Analyse** | **25%** | Analysiert die Betreffzeile auf Keywords wie "Urgent", "Gewinner", etc. |

### 2.1 Technische Analyse (Technical Score)

Hier wird geprüft, ob der Absender authentisch ist und ob die Mail-Header manipuliert wurden.

*   **Authentication-Results (SPF, DKIM, DMARC)**:
    *   Der Server parst den `Authentication-Results` Header, der von vorgelagerten Mailservern (z.B. Gmail, Outlook) eingefügt wird.
    *   **SPF (Sender Policy Framework)**: Darf die sende IP-Adresse für diese Domain Mails versenden? (`fail` = hohes Risiko).
    *   **DKIM (DomainKeys Identified Mail)**: Ist die digitale Signatur der Mail gültig? Garantiert, dass die Mail unterwegs nicht verändert wurde.
    *   **DMARC**: Eine Policy, die festlegt, was bei SPF/DKIM-Fehlern passieren soll.
    *   *Bewertung*: Ein `Pass` gibt Pluspunkte (Vertrauen), ein `Fail` gibt massive Minuspunkte.

*   **Identitäts-Mismatch (Spoofing-Indikatoren)**:
    *   Wir vergleichen drei Adressen:
        1.  **From**: Das, was der Benutzer sieht (z.B. `support@paypal.com`).
        2.  **Return-Path**: Wohin Fehlermeldungen gehen (technischer Absender).
        3.  **Reply-To**: Wohin eine Antwort geschickt wird.
    *   **Alarm**: Wenn `From` "amazon.com" sagt, aber `Reply-To` "hacker@freemail.ru" ist, handelt es sich mit sehr hoher Wahrscheinlichkeit um Betrug.

*   **MX-Check (Mail Exchanger)**:
    *   Der Server prüft live via DNS, ob die Absender-Domain überhaupt E-Mails empfangen kann.
    *   Viele Spam-Domains sind "Send-Only" und haben keine MX-Records -> **Hoher Risikofaktor**.

### 2.2 Inhaltliche Linguistik (Body Score)

Der Text der E-Mail wird bereinigt (HTML-Tags entfernt) und in Wörter zerlegt. Diese werden gegen die geladene `linguistic_stats.json` geprüft.

*   **Statistische Trigger**:
    *   Für jedes Wort prüfen wir: "Wie oft kommt dieses Wort in Scam-Mails vor vs. in sicheren Mails?"
    *   Beispiel: Das Wort "suspended" kommt in 0.1% aller sicheren Mails vor, aber in 15% aller Scam-Mails.
    *   Wenn ein Wort signifikant häufiger (Faktor 2x) in Scam-Mails auftritt, wird es als Trigger markiert.
    *   Die Strafe (Penalty) berechnet sich dynamisch anhand der Häufigkeit.

*   **Shouting Score (Aggressivität)**:
    *   Berechnet das Verhältnis von Großbuchstaben zur Gesamtlänge.
    *   Ein hoher Anteil (>10%) deutet auf "Shouting" hin (z.B. "URGENT CHECK NOW"), was ein typisches Merkmal von Erpressungs- oder Panik-Mails ist.

### 2.3 Betreff Analyse (Subject Score)

Ähnlich wie die Body-Analyse, aber fokussiert auf die erste Zeile, die das Opfer sieht.

*   **Keyword-Scanning**: Suche nach fest definierten Alarm-Wörtern (`urgent`, `verify`, `lottery`, `profit`).
*   **Statistische Analyse**: Vergleich mit der Datenbank speziell für Betreffzeilen. Phishing-Betreffe sind oft kürzer und nutzen spezifischere Vokabeln ("Account Notification") als normale Mails.

---

## 3. Code-Map & Verzeichnisstruktur

### `cmd/server/main.go`
Dies ist die einzige Go-Datei für den Server. Sie enthält die gesamte Logik für Webserver, Analyse und Datenhaltung.

#### Kern-Komponenten & Variablen
*   `var globalStats LinguisticReport`: Hält die geladenen Trainingsdaten im Arbeitsspeicher.
*   `var memoryStore map[string]string`: **[NEU]** Ein In-Memory Speicher (RAM) für hochgeladene E-Mails. Dateien werden hier kurzzeitig gespeichert, um sie im Frontend anzuzeigen, ohne sie auf die Festplatte zu schreiben (Datenschutz).
*   `type RiskFactors`: Das zentrale Struct, das alle gefundenen Risiken (SPF-Fail, böse Wörter, Domain Trust) sammelt.

#### Wichtige Funktionen
*   `func main()`:
    *   Lädt `linguistic_stats.json`.
    *   Startet eine Hintergrund-Routine (`go func`), die stündlich den `memoryStore` leert.
    *   Startet den HTTP-Server auf Port 8080.
*   `func handleAnalyze()`:
    *   Der zentrale HTTP-Handler.
    *   Unterscheidet zwischen **Upload** (POST) und **Anzeige** (GET).
    *   Priorisiert den Zugriff auf den `memoryStore` (wenn `testFile=memory:...`), sucht sonst im `data/test_emails` Ordner auf der Festplatte.
    *   Ruft `analyzeEmail` auf und rendert das Template.
*   `func analyzeEmail(...) AnalysisResult`:
    *   Führt die eigentliche Bewertung durch.
    *   **Header-Checks**: SPF/DKIM/DMARC Parsing.
    *   **Active DNS**: Führt `net.LookupTXT` aus, um live zu prüfen, ob die Domain E-Mail-Records hat.
    *   **Domain Trust**: Ruft `checkDomainTrust` auf.
    *   **Linguistik**: Vergleicht Wörter mit `globalStats`.
*   `func checkDomainTrust(domain)`: **[NEU]** Prüft Domains gegen eine interne "Allowlist" (Google, Apple, Microsoft...), um Fehlalarme bei großen Anbietern zu minimieren.
*   `func resolvePath(relativePath)`: **[NEU]** Ein intelligenter Helper, der sicherstellt, dass die Datendateien gefunden werden, egal ob der Server aus dem Root-Verzeichnis oder aus `cmd/server` gestartet wird.

### `cmd/server/templates/index.html`
*   Das Frontend-Template.
*   Enthält CSS für das dunkle Theme und das Layout.
*   Beinhaltet jetzt auch **JavaScript** für den neuen Lade-Overlay (`.loading-overlay`), der während der DNS-Checks angezeigt wird.

### Daten-Verzeichnisse
*   `data/test_emails/`: Enthält Beispiel-E-Mails (`.eml`), die immer im Scanner zur Demo verfügbar sind.
*   `data/linguistic_stats.json`: Die "Gehirn"-Datei, die vom Trainer generiert wurde.

---

## 4. Erweiterbarkeit
Um die Erkennung zu verbessern:
1.  **Code**: Neue technische Checks (z.B. IP-Blacklists) in `analyzeEmail` in `main.go`.
2.  **Daten**: Neue Beispiele in den Trainer füttern, um `linguistic_stats.json` zu verbessern. Der Server muss danach neu gestartet werden.
