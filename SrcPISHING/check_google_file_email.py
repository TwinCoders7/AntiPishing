import os
import re
import requests
import imaplib
import email
from email.header import decode_header
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import logging
import time
import pickle
import base64

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler("phishing_detector.log", mode="a", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Credenciales (use environment variables or secure storage in production)
os.environ["EMAIL_ADDRESS"] = "xxxxxxxx"
os.environ["EMAIL_PASSWORD"] = "xxxxxxxxx"
os.environ["GOOGLE_API_KEY"] = "xxxxxxxxxxx"
os.environ["PHISHTANK_API_KEY"] = ""

email_address = os.getenv("EMAIL_ADDRESS")
email_password = os.getenv("EMAIL_PASSWORD")
google_api_key = os.getenv("GOOGLE_API_KEY")
phishtank_api_key = os.getenv("PHISHTANK_API_KEY")

# Configuración
SCORE_THRESHOLD = 30

# Listas para detección
phishing_keywords = [
    "verifica tu cuenta", "haz clic aquí", "actualiza tu información",
    "inicie sesión", "confirma tu identidad", "urgente", "su cuenta será suspendida",
    "contraseña comprometida", "pago rechazado", "responde y gana", "actividad inusual",
    "estimado cliente", "tu opinión nos importa", "bloqueo temporal", "restaurar el acceso",
    "has sido seleccionado", "gana ahora", "no dejes pasar", "oportunidad exclusiva",
    "cuenta limitada", "verificación obligatoria", "acceso restringido", "sigue el enlace",
    "por seguridad", "cuenta bloqueada", "autenticación requerida", "actualización necesaria",
    "promoción especial", "felicidades", "has ganado", "lidl", "departamento lidl",
    "malware detectado", "herramienta de seguridad", "información personal en riesgo",
    "no ignore", "dispositivo infectado", "ganador", "recompensa", "premio", "oferta limitada",
    "verificación de seguridad", "suspensión de cuenta", "acceso no autorizado",
    "actualización de datos", "enlace seguro", "protege tu cuenta"
]
blacklisted_domains = [
    "bit.ly", "tinyurl.com", "freeshop-now.com", "login-alert.com", "phishing-winner.com",
    "security-paypal-alert.com", "security-google-alerts.com", "malware-fix-now.com",
    "weebly.com", "apple-id.com", "exteriorpersonas-juridico-vz.click", "facebookseguro.com"
]
suspicious_domain_patterns = [
    r".*-winner.*", r".*claim.*", r".*phishing.*", r".*promo.*",
    r".*paypal.*", r".*security.*", r".*verify.*", r".*alert.*",
    r".*convertkit.*", r".*malware.*", r".*apple-.*", r".*juridico.*",
    r".*\.click$", r".*\.top$", r".*\.info$", r".*\.biz$", r".*\.online$",
    r".*\.xyz$", r".*\.win$", r".*\.site$", r".*\.club$"
]
generic_greetings = [
    "estimado cliente", "dear customer", "querido usuario", "promociones exclusivas",
    "equipo de promociones", "suerte", "gracias por elegir", "estimado usuario",
    "equipo de seguridad", "departamento de", "departamento lidl", "hola [nombre]"
]
urgent_words = [
    "urgente", "inmediato", "expira", "acción requerida", "alerta", "ahora mismo",
    "obligatoria", "inmediata", "limitada", "no ignore", "riesgo", "infectado",
    "pronto", "rápido", "de inmediato", "crítico"
]
trusted_senders = [
    "google.com", "game.es", "paypal.com", "amazon.com", "ebay.com", "microsoft.com",
    "convertkit.com", "x.ai"
]
legit_domains = ["paypal.com", "google.com", "microsoft.com", "amazon.com", "ebay.com", "apple.com"]
third_party_domains = ["convertkit-mail2.com", "weebly.com"]

def extract_links(text):
    return re.findall(r'(https?://\S+)', text, re.IGNORECASE)

def get_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except:
        return ""

def check_base64_links(links):
    suspicious_links = []
    for link in links:
        if "base64" in link.lower() or any(c in link for c in ['#', 'aHR0c']):
            try:
                decoded = base64.b64decode(link.split('#')[-1]).decode('utf-8', errors='ignore')
                if 'http' in decoded:
                    suspicious_links.append(f"Enlace codificado en base64: {decoded}")
            except:
                continue
    if suspicious_links:
        return True, ", ".join(suspicious_links)
    return False, ""

def check_safe_browsing(urls):
    if not urls:
        return []
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_api_key}"
    body = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls]
        }
    }
    try:
        response = requests.post(endpoint, json=body, timeout=10)
        response.raise_for_status()
        matches = response.json().get("matches", [])
        return [match["threat"]["url"] for match in matches]
    except Exception as e:
        logging.info(f"⚠️ Error al consultar Google Safe Browsing: {e}")
        return []

def check_openphish(urls, cache_file="openphish_cache.pkl"):
    try:
        with open(cache_file, "rb") as f:
            cache = pickle.load(f)
        if time.time() - cache["timestamp"] < 3600:
            phishing_urls = cache["urls"]
        else:
            raise FileNotFoundError
    except:
        try:
            response = requests.get("https://openphish.com/feed.txt", timeout=10)
            response.raise_for_status()
            phishing_urls = response.text.splitlines()
            with open(cache_file, "wb") as f:
                pickle.dump({"urls": phishing_urls, "timestamp": time.time()}, f)
        except Exception as e:
            logging.info(f"⚠️ Error al consultar OpenPhish: {e}")
            return []
    return [url for url in urls if url in phishing_urls]

def check_phishtank(urls):
    if not phishtank_api_key:
        logging.info("⚠️ PhishTank desactivado: clave API no configurada.")
        return []
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    phishing_urls = []
    headers = {"User-Agent": "phishing-detector/1.0 (wolfcuentaprueba@gmail.com)"}
    for url in urls:
        try:
            response = requests.post(endpoint, data={"url": url, "app_key": phishtank_api_key, "format": "xml"}, headers=headers, timeout=10)
            response.raise_for_status()
            if '<in_database>true</in_database>' in response.text:
                phishing_urls.append(url)
        except Exception as e:
            logging.info(f"⚠️ Error al consultar PhishTank para {url}: {e}")
    return phishing_urls

def check_sender(sender):
    suspicious_patterns = [
        r"noreply@.*", r"support@.*\.info", r"admin@.*\.top",
        r".*@.*\.ru", r".*@.*\.cn", r".*@gmail\.com$"
    ]
    sender = sender.lower()
    for pattern in suspicious_patterns:
        if re.match(pattern, sender):
            return True, f"Remitente sospechoso: {sender}"
    return False, ""

def check_suspicious_domain(domain):
    if not domain:
        return False, ""
    for legit_domain in legit_domains:
        if legit_domain in domain and domain != legit_domain:
            return True, f"Dominio imita servicio legítimo: {domain} (parece {legit_domain})"
        if domain.startswith(legit_domain.split('.')[0]) or domain.endswith(legit_domain.split('.')[0]):
            return True, f"Dominio sospechoso que imita: {domain} (parece {legit_domain})"
    for pattern in suspicious_domain_patterns:
        if re.search(pattern, domain, re.IGNORECASE):
            return True, f"Dominio sospechoso: {domain} (coincide con patrón {pattern})"
    if domain in third_party_domains:
        return True, f"Dominio de terceros que requiere verificación: {domain}"
    return False, ""

def connect_to_mail():
    try:
        logging.info("🔗 Conectando con Gmail...")
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_address, email_password)
        logging.info("✅ Conexión exitosa")
        return mail
    except Exception as e:
        logging.info(f"❌ Error al conectar: {e}")
        return None

def read_emails(mail, max_emails=100):
    phishing_count = 0
    logging.info("📬 Nota: Verifica la carpeta de Spam si no ves correos esperados.")

    try:
        status, messages = mail.select("inbox")
        if status != 'OK':
            logging.info("⚠️ No se pudo seleccionar la bandeja de entrada")
            return phishing_count
        status, messages = mail.search(None, 'UNSEEN')
        if status != 'OK':
            logging.info("⚠️ No se pudieron buscar correos no leídos")
            return phishing_count
        messages = messages[0].split()
        logging.info(f"📧 Total de correos no leídos: {len(messages)}")

        messages_to_process = messages[-max_emails:] if len(messages) > max_emails else messages
        logging.info(f"📧 Procesando {len(messages_to_process)} correos...")

        for msg_id in messages_to_process:
            if isinstance(msg_id, int):
                msg_id = str(msg_id).encode('utf-8')
            for attempt in range(3):
                try:
                    status, msg_data = mail.fetch(msg_id, "(RFC822)")
                    if status != 'OK' or not msg_data or not isinstance(msg_data[0], tuple):
                        logging.info(f"⚠️ Error al obtener correo {msg_id}: {status}, {msg_data}")
                        if attempt == 2:
                            break
                        time.sleep(2)
                        continue
                    msg = email.message_from_bytes(msg_data[0][1])
                    subject = "Asunto no disponible"
                    try:
                        if msg["Subject"]:
                            subject_parts = decode_header(msg["Subject"])[0]
                            subject_text, encoding = subject_parts
                            if isinstance(subject_text, bytes):
                                subject = subject_text.decode(encoding if encoding else "utf-8", errors="ignore")
                            else:
                                subject = subject_text
                    except Exception as e:
                        logging.info(f"⚠️ Error al decodificar asunto: {e}")

                    logging.info(f"\n📌 Asunto: {subject}")
                    sender = msg.get("From", "").lower()
                    logging.info(f"📩 Remitente: {sender}")
                    if any(domain in sender for domain in trusted_senders):
                        logging.info(f"🛡️ Remitente confiable: {sender}")
                        mail.store(msg_id, '-FLAGS', '\\Seen')
                        break

                    sender_suspicious, sender_reason = check_sender(sender)
                    body = ""
                    has_attachment = False
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            try:
                                if content_type == "text/plain":
                                    payload = part.get_payload(decode=True)
                                    if payload:
                                        body += payload.decode(errors="ignore")
                                elif content_type == "text/html":
                                    payload = part.get_payload(decode=True)
                                    if payload:
                                        html = payload.decode(errors="ignore")
                                        soup = BeautifulSoup(html, "html.parser")
                                        body += soup.get_text(separator=" ", strip=True)
                                elif part.get_filename():
                                    suspicious_extensions = ['.exe', '.zip', '.js', '.bat', '.scr', '.pif']
                                    if any(part.get_filename().lower().endswith(ext) for ext in suspicious_extensions):
                                        logging.info(f"📎 Adjunto sospechoso: {part.get_filename()}")
                                        has_attachment = True
                            except Exception as e:
                                logging.info(f"⚠️ Error procesando parte del correo: {e}")
                                continue
                    else:
                        try:
                            payload = msg.get_payload(decode=True)
                            if payload:
                                body = payload.decode(errors="ignore")
                        except Exception as e:
                            logging.info(f"⚠️ Error decodificando payload: {e}")
                            continue

                    score = 0
                    reasons = []
                    keyword_matches = [p for p in phishing_keywords if p.lower() in body.lower()]
                    if keyword_matches:
                        score += len(keyword_matches) * 20
                        reasons.append(f"Frases sospechosas: {', '.join(keyword_matches)}")

                    links = extract_links(body)
                    logging.info(f"🔗 Enlaces: {', '.join(links) if links else 'Ninguno'}")
                    dominios = list(set([get_domain(link) for link in links if get_domain(link)]))
                    dominios_sospechosos = [d for d in dominios if d in blacklisted_domains]
                    if dominios_sospechosos:
                        score += len(dominios_sospechosos) * 50
                        reasons.append(f"Dominios en lista negra: {', '.join(dominios_sospechosos)}")

                    for domain in dominios:
                        is_suspicious, reason = check_suspicious_domain(domain)
                        if is_suspicious:
                            score += 40
                            reasons.append(reason)

                    is_base64, base64_reason = check_base64_links(links)
                    if is_base64:
                        score += 40
                        reasons.append(base64_reason)

                    links_peligrosos = list(set(check_safe_browsing(links) + check_openphish(links)))
                    if links_peligrosos:
                        score += 70
                        reasons.append(f"Enlaces peligrosos: {', '.join(links_peligrosos)}")

                    if sender_suspicious:
                        score += 40
                        reasons.append(sender_reason)

                    if any(w.lower() in subject.lower() or w.lower() in body.lower() for w in urgent_words):
                        score += 30
                        reasons.append("Lenguaje urgente detectado")

                    if has_attachment:
                        score += 30
                        reasons.append("Adjunto sospechoso detectado")

                    if any(g.lower() in body.lower() for g in generic_greetings):
                        score += 30
                        reasons.append("Saludo genérico detectado")

                    if links and any(g.lower() in body.lower() for g in generic_greetings):
                        score += 20
                        reasons.append("Enlace + saludo genérico")
                    if links and any(w.lower() in body.lower() for w in urgent_words):
                        score += 20
                        reasons.append("Enlace + lenguaje urgente")
                    if dominios_sospechosos and keyword_matches:
                        score += 20
                        reasons.append("Dominio sospechoso + frases sospechosas")

                    logging.info(f"📝 Cuerpo (truncado):\n{body[:300]}...")
                    if score >= SCORE_THRESHOLD:
                        phishing_count += 1
                        logging.info(f"⚠️ ¡POSIBLE PHISHING! Puntuación: {score}")
                        for reason in reasons:
                            logging.info(f"   - {reason}")
                        try:
                            mail.store(msg_id, '+X-GM-LABELS', 'posible-phishing')
                            logging.info("📩 Etiquetado como 'posible-phishing'")
                        except Exception as e:
                            logging.info(f"⚠️ Error al etiquetar correo: {e}")
                    else:
                        logging.info(f"🛡️ No phishing. Puntuación: {score}")
                        for reason in reasons:
                            logging.info(f"   - {reason}")
                        try:
                            mail.store(msg_id, '-FLAGS', '\\Seen')
                            logging.info(f"📩 Correo mantenido como no leído")
                        except Exception as e:
                            logging.info(f"⚠️ Error al mantener correo no leído: {e}")
                    logging.info("=" * 60)
                    break
                except Exception as e:
                    logging.info(f"⚠️ Error al procesar correo {msg_id} (intento {attempt + 1}): {str(e)}")
                    if attempt == 2:
                        break
                    time.sleep(2)
    except Exception as e:
        logging.info(f"⚠️ Error general en read_emails: {str(e)}")
        return phishing_count

    return phishing_count

if __name__ == "__main__":
    mail = connect_to_mail()
    if mail:
        read_emails(mail)
        mail.logout()