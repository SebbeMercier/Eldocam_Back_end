package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/go-playground/validator/v10"
)

var (
	validate       = validator.New()
	rateLimitMutex sync.Mutex
	rateLimits     = make(map[string][]time.Time)

	urlRegex      = regexp.MustCompile(`(https?://[^\s]+)|(www\.[^\s]+)|([a-z0-9\-]+\.[a-z]{2,})`)
	cyrillicRegex = regexp.MustCompile("[\u0400-\u04FF]")
)

type ContactForm struct {
	Name     string `json:"name" validate:"required,min=2,max=80"`
	Email    string `json:"email" validate:"required,email"`
	Tel      string `json:"tel" validate:"max=40"`
	Language string `json:"language" validate:"omitempty,oneof=fr nl en"`
	Message  string `json:"message" validate:"required,min=10,max=5000"`
}

// --- RATE LIMIT : 10 requêtes / 15 min / IP ---
func allowRequest(ip string) bool {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	window := 15 * time.Minute
	max := 10

	reqs := rateLimits[ip]
	// Nettoie les anciennes requêtes
	newReqs := []time.Time{}
	for _, t := range reqs {
		if now.Sub(t) < window {
			newReqs = append(newReqs, t)
		}
	}
	if len(newReqs) >= max {
		return false
	}
	newReqs = append(newReqs, now)
	rateLimits[ip] = newReqs
	return true
}

// --- Envoi des mails ---
func sendEmail(form ContactForm, mailUser, mailPass, adminTo string) error {
	auth := smtp.PlainAuth("", mailUser, mailPass, "ssl0.ovh.net")

	escapedMsg := html.EscapeString(form.Message)
	escapedMsg = strings.ReplaceAll(escapedMsg, "\n", "<br>")

	// Mail à l'admin
	adminBody := fmt.Sprintf(
		"To: %s\r\nSubject: Prise de contact de %s\r\nReply-To: %s\r\n\r\nNom: %s\nEmail: %s\nTel: %s\nMessage:\n%s",
		adminTo, form.Name, form.Email, form.Name, form.Email, form.Tel, form.Message,
	)

	err := smtp.SendMail("ssl0.ovh.net:587", auth, mailUser, []string{adminTo}, []byte(adminBody))
	if err != nil {
		return err
	}

	// Auto-réponse
	var subject, htmlBody, successText string
	switch form.Language {
	case "nl":
		subject = "Automatisch antwoord"
		htmlBody = fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; padding: 20px;">
		<h2 style="color: #222;">Hallo %s,</h2>
		<p>Bedankt voor uw contact! We hebben je bericht ontvangen.</p>
		<blockquote style="border-left: 4px solid #e80000ff; margin: 10px 0; padding-left: 10px;">%s</blockquote>
		<p>We nemen zo snel mogelijk contact met je op.</p>
		<p style="font-size: 12px; color: #888;">Dit is een geautomatiseerd bericht. Gelieve niet te antwoorden.</p>
		<p style="font-size: 12px; color: #888;">— Het Eldocam-team</p>
		</div>`, html.EscapeString(form.Name), escapedMsg)
		successText = "Je bericht is aangekomen. Je kunt deze pagina sluiten."
	case "en":
		subject = "Auto reply"
		htmlBody = fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; padding: 20px;">
		<h2 style="color: #222;">Hello %s,</h2>
		<p>Thank you for contacting us! We have received your message.</p>
		<blockquote style="border-left: 4px solid #e80000ff; margin: 10px 0; padding-left: 10px;">%s</blockquote>
		<p>We will get back to you as soon as possible.</p>
		<p style="font-size: 12px; color: #888;">This is an automated message. Please do not reply.</p>
		<p style="font-size: 12px; color: #888;">— The Eldocam team</p>
		</div>`, html.EscapeString(form.Name), escapedMsg)
		successText = "Your message has been received. You can close this page."
	default:
		subject = "Réponse automatique"
		htmlBody = fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; padding: 20px;">
		<h2 style="color: #222;">Bonjour %s,</h2>
		<p>Merci de nous avoir contactés ! Nous avons bien reçu votre message.</p>
		<blockquote style="border-left: 4px solid #e80000ff; margin: 10px 0; padding-left: 10px;">%s</blockquote>
		<p>Nous reviendrons vers vous dans les plus brefs délais.</p>
		<p style="font-size: 12px; color: #888;">Ceci est un message automatique. Merci de ne pas répondre.</p>
		<p style="font-size: 12px; color: #888;">— L’équipe Eldocam</p>
		</div>`, html.EscapeString(form.Name), escapedMsg)
		successText = "Votre message nous est bien parvenu. Vous pouvez fermer cette page."
	}

	clientBody := fmt.Sprintf(
		"To: %s\r\nSubject: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		form.Email, subject, htmlBody,
	)

	err = smtp.SendMail("ssl0.ovh.net:587", auth, mailUser, []string{form.Email}, []byte(clientBody))
	if err != nil {
		return err
	}

	log.Println(successText)
	return nil
}

// --- Handler ---
func contactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	ip := r.RemoteAddr
	if !allowRequest(ip) {
		http.Error(w, "Trop de requêtes. Réessayez plus tard.", http.StatusTooManyRequests)
		return
	}

	var form ContactForm
	err := decodeJSON(r, &form)
	if err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

	if form.Language == "" {
		form.Language = "fr"
	}

	// Validation
	if err := validate.Struct(form); err != nil {
		http.Error(w, "Champs invalides", http.StatusBadRequest)
		return
	}

	// Anti-spam
	cleanName := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(form.Name), " ", ""))
	if cleanName == "robertves" {
		http.Error(w, "Ce nom est interdit.", http.StatusBadRequest)
		return
	}
	if cyrillicRegex.MatchString(form.Message) {
		http.Error(w, "L'alphabet cyrillique n'est pas autorisé.", http.StatusBadRequest)
		return
	}
	if urlRegex.MatchString(form.Message) {
		http.Error(w, "L'envoi de liens n'est pas autorisé.", http.StatusBadRequest)
		return
	}

	mailUser := os.Getenv("MAIL_USER")
	mailPass := os.Getenv("MAIL_PASS")
	adminTo := os.Getenv("ADMIN_TO")

	err = sendEmail(form, mailUser, mailPass, adminTo)
	if err != nil {
		log.Println("Erreur envoi email:", err)
		http.Error(w, "Erreur lors de l'envoi de l'email.", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, "Message bien reçu.")
}

// --- Petit utilitaire JSON ---
func decodeJSON(r *http.Request, v interface{}) error {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return fmt.Errorf("Content-Type invalide")
	}
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 200_000)).Decode(v)
}

func main() {
	// Charger .env
	err := godotenv.Load()
	if err != nil {
		log.Println(".env non trouvé, utilisation des variables d'environnement système")
	}

	// Headers sécurisés basiques (équivalent Helmet léger)
	http.HandleFunc("/contact/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		contactHandler(w, r)
	})

	addr := "127.0.0.1:3000"
	log.Println("Serveur en écoute sur http://" + addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
