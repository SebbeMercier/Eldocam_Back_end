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

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
)

var (
	validate       = validator.New()
	rateLimitMutex sync.Mutex
	rateLimits     = make(map[string][]time.Time)

	urlRegex      = regexp.MustCompile(`(https?://[^\s]+)|(www\.[^\s]+)|([a-z0-9\-]+\.[a-z]{2,})`)
	cyrillicRegex = regexp.MustCompile("[\u0400-\u04FF]")
)

// Structure du formulaire
type ContactForm struct {
	Name     string `validate:"required,min=2,max=80"`
	Email    string `validate:"required,email"`
	Tel      string `validate:"max=40"`
	Language string
	Message  string `validate:"required,min=3,max=5000"`
}

// --- Vérification Turnstile ---
func verifyTurnstile(token string, remoteIP string) bool {
	secret := os.Getenv("TURNSTILE_SECRET")
	if secret == "" {
		log.Println("⚠️ Variable TURNSTILE_SECRET non définie")
		return false
	}

	resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", map[string][]string{
		"secret":   {secret},
		"response": {token},
		"remoteip": {remoteIP},
	})
	if err != nil {
		log.Println("Erreur requête Turnstile:", err)
		return false
	}
	defer resp.Body.Close()

	var data struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Println("Erreur décodage Turnstile:", err)
		return false
	}
	return data.Success
}

// --- Rate limit : 10 requêtes / 15 min / IP ---
func allowRequest(ip string) bool {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	window := 15 * time.Minute
	max := 10

	reqs := rateLimits[ip]
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

// --- Envoi d'email (inchangé sauf simplifié) ---
func sendEmail(form ContactForm, mailUser, mailPass, adminTo string) (string, error) {
	auth := smtp.PlainAuth("", mailUser, mailPass, "ssl0.ovh.net")

	escapedMsg := html.EscapeString(form.Message)
	escapedMsg = strings.ReplaceAll(escapedMsg, "\n", "<br>")

	// --- Mail à l'admin ---
	adminBody := fmt.Sprintf(
		"To: %s\r\nSubject: Prise de contact de %s\r\nReply-To: %s\r\n\r\nNom: %s\nEmail: %s\nTel: %s\nMessage:\n%s",
		adminTo, form.Name, form.Email, form.Name, form.Email, form.Tel, form.Message,
	)

	err := smtp.SendMail("ssl0.ovh.net:587", auth, mailUser, []string{adminTo}, []byte(adminBody))
	if err != nil {
		return "", err
	}

	// --- Auto-réponse selon la langue ---
	var subject, htmlBody, successText string

	switch strings.ToLower(form.Language) {
	case "nl":
		subject = "Automatisch antwoord"
		htmlBody = fmt.Sprintf(`
			<div style="font-family: Arial, sans-serif; padding: 20px;">
				<h2>Hallo %s,</h2>
				<p>Bedankt voor uw bericht! We hebben uw aanvraag ontvangen.</p>
				<blockquote style="border-left: 4px solid #e80000; margin: 10px 0; padding-left: 10px;">%s</blockquote>
				<p>We nemen zo snel mogelijk contact met u op.</p>
				<p style="font-size:12px; color:#888;">— Het Eldocam-team</p>
			</div>`, html.EscapeString(form.Name), escapedMsg)
		successText = "Je bericht is goed ontvangen."

	case "en":
		subject = "Automatic reply"
		htmlBody = fmt.Sprintf(`
			<div style="font-family: Arial, sans-serif; padding: 20px;">
				<h2>Hello %s,</h2>
				<p>Thank you for contacting us! We have received your message.</p>
				<blockquote style="border-left: 4px solid #e80000; margin: 10px 0; padding-left: 10px;">%s</blockquote>
				<p>We will get back to you as soon as possible.</p>
				<p style="font-size:12px; color:#888;">— The Eldocam team</p>
			</div>`, html.EscapeString(form.Name), escapedMsg)
		successText = "Your message has been received."

	default:
		subject = "Réponse automatique"
		htmlBody = fmt.Sprintf(`
			<div style="font-family: Arial, sans-serif; padding: 20px;">
				<h2>Bonjour %s,</h2>
				<p>Merci de nous avoir contactés ! Nous avons bien reçu votre message.</p>
				<blockquote style="border-left: 4px solid #e80000; margin: 10px 0; padding-left: 10px;">%s</blockquote>
				<p>Nous reviendrons vers vous dans les plus brefs délais.</p>
				<p style="font-size:12px; color:#888;">— L’équipe Eldocam</p>
			</div>`, html.EscapeString(form.Name), escapedMsg)
		successText = "Votre message a bien été envoyé."
	}

	// --- Envoi de l'auto-réponse ---
	clientBody := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n"+
			"MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		mailUser, form.Email, subject, htmlBody,
	)

	err = smtp.SendMail("ssl0.ovh.net:587", auth, mailUser, []string{form.Email}, []byte(clientBody))
	if err != nil {
		log.Println("⚠️ Erreur auto-réponse :", err)
	} else {
		log.Println("✅ Auto-réponse envoyée à", form.Email)
	}

	return successText, nil
}

// --- Handler principal ---
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
	log.Printf("DEBUG form: %+v\n", form)
	if err != nil {
		http.Error(w, "Champs invalides", http.StatusBadRequest)
		return
	}

	// 🔒 Vérification Turnstile
	token := r.FormValue("cf-turnstile-response")
	if token == "" || !verifyTurnstile(token, ip) {
		http.Error(w, "Vérification Turnstile échouée.", http.StatusBadRequest)
		return
	}

	// Validation de contenu
	if err := validate.Struct(form); err != nil {
		http.Error(w, "Champs invalides", http.StatusBadRequest)
		return
	}
	if urlRegex.MatchString(form.Message) {
		http.Error(w, "L'envoi de liens n'est pas autorisé.", http.StatusBadRequest)
		return
	}

	mailUser := os.Getenv("MAIL_USER")
	mailPass := os.Getenv("MAIL_PASS")
	adminTo := os.Getenv("ADMIN_TO")

	successText, err := sendEmail(form, mailUser, mailPass, adminTo)
	if err != nil {
		log.Println("Erreur envoi email:", err)
		http.Error(w, "Erreur lors de l'envoi.", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, successText)
}

// --- Utilitaire decodeJSON ---
func decodeJSON(r *http.Request, v interface{}) error {
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "application/json") {
		return json.NewDecoder(r.Body).Decode(v)
	}
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		err := r.ParseForm()
		if err != nil {
			return err
		}
		form := v.(*ContactForm)
		form.Name = r.FormValue("name")
		form.Email = r.FormValue("email")
		form.Tel = r.FormValue("tel")
		form.Language = r.FormValue("language")
		form.Message = r.FormValue("message")
		return nil
	}
	return fmt.Errorf("Content-Type invalide")
}

func main() {
	_ = godotenv.Load()

	http.HandleFunc("/api/contact", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		contactHandler(w, r)
	})

	addr := "127.0.0.1:3000"
	log.Println("🚀 Serveur en écoute sur http://" + addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
