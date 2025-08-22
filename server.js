require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const helmet = require('helmet');

const app = express();
const PORT = 3000;

// --- Sécurité HTTP ---
app.use(helmet({
  contentSecurityPolicy: false, // inutile pour une API pure
}));
app.set('trust proxy', 1);

// --- Body parsers (limites) ---
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));

// --- Rate limit API /contact ---
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // 10 req / 15 min / IP
  standardHeaders: true,
  legacyHeaders: false,
});

const transporter = nodemailer.createTransport({
  host: 'ssl0.ovh.net',
  port: 587,
  secure: false,           // STARTTLS
  requireTLS: true,
  auth: {
    user: process.env.MAIL_USER, // noreply@eldocam.com
    pass: process.env.MAIL_PASS
  },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 20000,
});

// Vérifie la connexion SMTP au boot (log seulement)
transporter.verify()
  .then(() => console.log('SMTP OK (OVH 587 STARTTLS)'))
  .catch(err => console.error('SMTP verify error:', err));

// --- Helpers ---
function escapeHtml(str = '') {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

const urlRegex = /(https?:\/\/[^\s]+)|(www\.[^\s]+)|([a-z0-9\-]+\.[a-z]{2,})/i;
const cyrillicRegex = /[\u0400-\u04FF]/;

async function sendEmail(contactInfo) {
  const { name, email, tel, language = 'fr', message } = contactInfo;
  const escapedMsg = escapeHtml(message).replace(/\n/g, '<br>');

  // 1) Mail admin
  const adminMail = {
    from: `Eldocam <${process.env.MAIL_USER}>`,
    to: process.env.ADMIN_TO,
    subject: `Prise de contact de ${name}`,
    text: `Nom: ${name}\nEmail: ${email}\nTel: ${tel}\nMessage:\n${message}`,
    replyTo: email, 
  };

  // 2) Auto-réponse
  let subjectClient, htmlClient, successText;
  if (language === 'nl') {
    subjectClient = 'Automatisch antwoord';
    htmlClient = `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #222;">Hallo ${escapeHtml(name)},</h2>
        <p>Bedankt voor uw contact! We hebben je bericht ontvangen.</p>
        <h4 style="color: #555;">Uw bericht:</h4>
        <blockquote style="border-left: 4px solid #e80000ff; margin: 10px 0; padding-left: 10px; color: #333;">${escapedMsg}</blockquote>
        <p>We nemen zo snel mogelijk contact met je op.</p>
        <br>
        <p style="font-size: 12px; color: #888;">Dit is een geautomatiseerd bericht. Gelieve niet te antwoorden.</p>
        <p style="font-size: 12px; color: #888;">— Het Eldocam-team</p>
      </div>`;
    successText = 'Je bericht is aangekomen. Je kunt deze pagina sluiten.';
  } else if (language === 'en') {
    subjectClient = 'Auto reply';
    htmlClient = `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #222;">Hello ${escapeHtml(name)},</h2>
        <p>Thank you for contacting us! We have received your message.</p>
        <h4 style="color: #555;">Your message:</h4>
        <blockquote style="border-left: 4px solid #e80000ff; margin: 10px 0; padding-left: 10px; color: #333;">${escapedMsg}</blockquote>
        <p>We will get back to you as soon as possible.</p>
        <br>
        <p style="font-size: 12px; color: #888;">This is an automated message. Please do not reply.</p>
        <p style="font-size: 12px; color: #888;">— The Eldocam team</p>
      </div>`;
    successText = 'Your message has been received. You can close this page.';
  } else {
    subjectClient = 'Réponse automatique';
    htmlClient = `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #222;">Bonjour ${escapeHtml(name)},</h2>
        <p>Merci de nous avoir contactés ! Nous avons bien reçu votre message.</p>
        <h4 style="color: #555;">Votre message :</h4>
        <blockquote style="border-left: 4px solid #e80000ff; margin: 10px 0; padding-left: 10px; color: #333;">${escapedMsg}</blockquote>
        <p>Nous reviendrons vers vous dans les plus brefs délais.</p>
        <br>
        <p style="font-size: 12px; color: #888;">Ceci est un message automatique. Merci de ne pas répondre.</p>
        <p style="font-size: 12px; color: #888;">— L’équipe Eldocam</p>
      </div>`;
    successText = 'Votre message nous est bien parvenu. Vous pouvez fermer cette page.';
  }

  const autoReply = {
    from: `Eldocam <${process.env.MAIL_USER}>`,
    to: email,
    subject: subjectClient,
    html: htmlClient,
  };

  // Envoi (admin → si succès → auto-réponse)
  await transporter.sendMail(adminMail);
  await transporter.sendMail(autoReply);

  return successText;
}

// --- Route ---
app.post(
  '/contact/',
  contactLimiter,
  // Validations
  body('name').trim().isLength({ min: 2, max: 80 }),
  body('email').isEmail().normalizeEmail(),
  body('tel').optional().isLength({ max: 40 }),
  body('language').optional().isIn(['fr', 'nl', 'en']),
  body('message').isLength({ min: 10, max: 5000 }),
  async (req, res) => {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).send('Champs invalides.');
    }

    const { name, email, tel = '', language = 'fr', message } = req.body;

    // Règles anti-spam (simples)
    const cleanName = name.trim().replace(/\s+/g, '').toLowerCase();
    if (cleanName === 'robertves') {
      return res.status(400).send('Ce nom est interdit.');
    }
    if (cyrillicRegex.test(message)) {
      return res.status(400).send("L'alphabet cyrillique n'est pas autorisé.");
    }
    if (urlRegex.test(message)) {
      return res.status(400).send("L'envoi de liens n'est pas autorisé dans le message.");
    }

    try {
      const okText = await sendEmail({ name, email, tel, language, message });
      return res.status(200).send(okText);
    } catch (err) {
      console.error('Erreur envoi email:', err);
      return res.status(500).send("Erreur lors de l'envoi de l'email.");
    }
  }
);

app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server is running on http://127.0.0.1:${PORT}`);
});
