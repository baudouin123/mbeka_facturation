"""
APPLICATION WEB DE FACTURATION MBEKA - AVEC GESTION DES AMENDES
Pour entreprises sous-traitantes avec gestion des amendes par employé
"""

from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import cm
from io import BytesIO
from datetime import datetime, date, timedelta
import os
import json
import shutil
import glob
from flask import send_file
from pathlib import Path
import csv
from io import StringIO, BytesIO
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
import zipfile
from PyPDF2 import PdfMerger, PdfReader, PdfWriter
#from weasyprint import HTML
from flask import render_template
#html = render_template("facture.html", facture=facture)
#HTML(string=html, base_url=app.root_path).write_pdf(pdf_path)
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
# Création automatique des dossiers nécessaires
os.makedirs('factures', exist_ok=True)
os.makedirs('static/images', exist_ok=True)
def parse_date(value):
    """Essaye plusieurs formats de date automatiquement."""
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(value, fmt).date()
        except:
            pass
    raise ValueError(f"Format date non supporté : {value}")

from PIL import Image
Image.MAX_IMAGE_PIXELS = None


app = Flask(__name__)
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

# ✅ AJOUT : Clé secrète pour la sécurité
app.config['SECRET_KEY'] = 'mbeka-facturation-secure-key-2024-december-14'

# ✅ AJOUT : Configuration Email (Gmail)
# Pour utiliser Gmail : https://myaccount.google.com/apppasswords
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'billjunior126@gmail.com'  # À CONFIGURER
app.config['MAIL_PASSWORD'] = 'rqgmzqnirjlxjouk'  # À CONFIGURER
app.config['MAIL_DEFAULT_SENDER'] = 'billjunior126@gmail.com'  # À CONFIGURER

# ✅ AJOUT : Configuration des sessions
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Session expire après 24h
app.config['SESSION_COOKIE_SECURE'] = False  # True en production avec HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Protection XSS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protection CSRF
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)  # "Remember me" 7 jours

# ✅ Configuration Base de Données - Support PostgreSQL (Production) et SQLite (Développement)
if os.environ.get('DATABASE_URL'):
    # En production sur Render (PostgreSQL)
    database_url = os.environ.get('DATABASE_URL')
    # Render utilise postgres://, mais SQLAlchemy veut postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print("🔵 Mode PRODUCTION - PostgreSQL activé")
else:
    # En développement local (SQLite)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///factures.db'
    print("🟢 Mode DÉVELOPPEMENT - SQLite activé")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ✅ AJOUT : Activer la protection CSRF
csrf = CSRFProtect(app)

# ✅ AJOUT : Configuration Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.session_protection = 'strong'  # Protection forte contre le vol de session

# ============================================================================
# MODÈLES DE BASE DE DONNÉES
# ============================================================================

class Utilisateur(UserMixin, db.Model):
    """Modèle pour les utilisateurs de l'application"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    nom = db.Column(db.String(100))
    prenom = db.Column(db.String(100))
    role = db.Column(db.String(20), nullable=False, default='employe')  # admin, comptable, employe
    actif = db.Column(db.Boolean, default=True)
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    derniere_connexion = db.Column(db.DateTime)
    
    # Champs pour la réinitialisation de mot de passe
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    telephone = db.Column(db.String(20))  # Pour envoi SMS
    
    # Relation avec les permissions
    permissions = db.relationship('Permission', backref='utilisateur', cascade='all, delete-orphan', lazy=True)
    
    def set_password(self, password):
        """Hasher le mot de passe"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Vérifier le mot de passe"""
        return check_password_hash(self.password_hash, password)
    
    def generate_reset_token(self):
        """Générer un token de réinitialisation unique"""
        import secrets
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=24)  # Valide 24h
        return self.reset_token
    
    def verify_reset_token(self, token):
        """Vérifier si le token est valide et non expiré"""
        if self.reset_token != token:
            return False
        if not self.reset_token_expiry:
            return False
        if datetime.utcnow() > self.reset_token_expiry:
            return False
        return True
    
    def clear_reset_token(self):
        """Supprimer le token après utilisation"""
        self.reset_token = None
        self.reset_token_expiry = None
    
    def has_permission(self, page):
        """Vérifier si l'utilisateur a la permission d'accéder à une page"""
        # Admin a accès à tout
        if self.role == 'admin':
            return True
        
        # Chercher la permission spécifique
        perm = Permission.query.filter_by(utilisateur_id=self.id, page=page).first()
        if perm:
            return perm.actif
        
        # Si pas de permission définie, utiliser les permissions par défaut du rôle
        return self._default_permissions().get(page, False)
    
    def _default_permissions(self):
        """Permissions par défaut selon le rôle"""
        if self.role == 'admin':
            return {page: True for page in PAGES_DISPONIBLES}
        elif self.role == 'comptable':
            return {
                'dashboard': True,
                'calendrier': True,
                'factures': True,
                'nouvelle_facture_client': True,
                'nouvelle_facture_employe': True,
                'clients': True,
                'employes': True,
                'recherche': True,
                'sauvegardes': True,
                'historique': True,
                'utilisateurs': False  # Comptable ne peut pas gérer les utilisateurs
            }
        else:  # employe
            return {
                'dashboard': True,
                'calendrier': True,
                'factures': True,  # Consultation uniquement
                'historique': True,
                'nouvelle_facture_client': False,
                'nouvelle_facture_employe': False,
                'clients': False,
                'employes': False,
                'recherche': False,
                'sauvegardes': False,
                'utilisateurs': False
            }
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'nom': self.nom,
            'prenom': self.prenom,
            'role': self.role,
            'actif': self.actif,
            'telephone': self.telephone,
            'date_creation': self.date_creation.strftime('%Y-%m-%d %H:%M') if self.date_creation else None,
            'derniere_connexion': self.derniere_connexion.strftime('%Y-%m-%d %H:%M') if self.derniere_connexion else None
        }

# ============================================================================
# MODÈLE PERMISSIONS
# ============================================================================

# Liste de toutes les pages disponibles dans l'application
PAGES_DISPONIBLES = {
    'dashboard': 'Dashboard & Graphiques',
    'calendrier': 'Calendrier',
    'factures': 'Liste des factures',
    'nouvelle_facture_client': 'Créer facture client',
    'nouvelle_facture_employe': 'Créer facture employé',
    'clients': 'Gestion clients',
    'employes': 'Gestion employés',
    'recherche': 'Recherche avancée',
    'sauvegardes': 'Sauvegardes',
    'historique': 'Historique',
    'utilisateurs': 'Gestion utilisateurs (Admin)'
}

class Permission(db.Model):
    """Modèle pour les permissions personnalisées par utilisateur"""
    id = db.Column(db.Integer, primary_key=True)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=False)
    page = db.Column(db.String(50), nullable=False)  # Clé de PAGES_DISPONIBLES
    actif = db.Column(db.Boolean, default=True)
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Contrainte unique : un utilisateur ne peut avoir qu'une permission par page
    __table_args__ = (db.UniqueConstraint('utilisateur_id', 'page', name='_user_page_uc'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'utilisateur_id': self.utilisateur_id,
            'page': self.page,
            'actif': self.actif,
            'page_label': PAGES_DISPONIBLES.get(self.page, self.page)
        }

# ============================================================================
# MODÈLE LOGS D'ACTIVITÉ
# ============================================================================

class Log(db.Model):
    """Modèle pour tracer toutes les activités des utilisateurs"""
    id = db.Column(db.Integer, primary_key=True)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=True)  # Peut être NULL si système
    utilisateur_nom = db.Column(db.String(100))  # Nom au moment de l'action (au cas où l'utilisateur est supprimé)
    action = db.Column(db.String(100), nullable=False)  # Type d'action (connexion, création facture, etc.)
    details = db.Column(db.Text)  # Détails de l'action en JSON
    ip_address = db.Column(db.String(50))  # Adresse IP de l'utilisateur
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Index pour recherches rapides
    __table_args__ = (
        db.Index('idx_log_date', 'date'),
        db.Index('idx_log_user', 'utilisateur_id'),
        db.Index('idx_log_action', 'action'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'utilisateur_id': self.utilisateur_id,
            'utilisateur_nom': self.utilisateur_nom,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'date': self.date.strftime('%Y-%m-%d %H:%M:%S') if self.date else None
        }

# Fonction utilitaire pour créer des logs
def creer_log(action, details=None, user=None):
    """
    Créer un log d'activité
    
    Args:
        action (str): Type d'action (ex: "connexion", "creation_facture")
        details (dict ou str): Détails de l'action
        user (Utilisateur): Utilisateur qui fait l'action (None = système)
    """
    try:
        # Convertir details en JSON si c'est un dict
        if isinstance(details, dict):
            details = json.dumps(details, ensure_ascii=False)
        
        # Récupérer l'IP de l'utilisateur
        ip = request.remote_addr if request else None
        
        # Créer le log
        log = Log(
            utilisateur_id=user.id if user else None,
            utilisateur_nom=f"{user.prenom or ''} {user.nom or ''} ({user.username})".strip() if user else "Système",
            action=action,
            details=details,
            ip_address=ip
        )
        
        db.session.add(log)
        db.session.commit()
        
    except Exception as e:
        # Ne pas faire échouer l'action si le log échoue
        print(f"Erreur création log: {e}")
        db.session.rollback()

@login_manager.user_loader
def load_user(user_id):
    return Utilisateur.query.get(int(user_id))

# ============================================================================
# MIDDLEWARE DE SÉCURITÉ - VÉRIFICATION GLOBALE
# ============================================================================

@app.before_request
def check_authentication():
    """
    Middleware exécuté AVANT chaque requête
    Force la redirection vers login si l'utilisateur n'est pas authentifié
    Vérifie aussi les permissions personnalisées
    """
    # Liste des routes publiques (accessible sans connexion)
    public_routes = [
        'login',
        'forgot_password',
        'reset_password',
        'static'
    ]
    
    # Routes API et system (ne pas vérifier les permissions)
    skip_permission_check = [
        'logout',
        'api_utilisateurs',
        'api_creer_utilisateur',
        'api_modifier_utilisateur',
        'api_supprimer_utilisateur',
        'generer_lien_reset'
    ]
    
    # Vérifier si la route demandée est publique
    endpoint = request.endpoint
    
    # Si c'est une route publique, laisser passer
    if endpoint in public_routes:
        return None
    
    # Si l'utilisateur n'est pas authentifié
    if not current_user.is_authenticated:
        # Sauvegarder l'URL demandée pour rediriger après login
        session['next_url'] = request.url
        flash('Veuillez vous connecter pour accéder à cette page.', 'warning')
        return redirect(url_for('login'))
    
    # Si l'utilisateur est authentifié mais inactif
    if not current_user.actif:
        logout_user()
        flash('Votre compte a été désactivé. Contactez un administrateur.', 'danger')
        return redirect(url_for('login'))
    
    # Vérifier les permissions personnalisées (sauf pour les routes API)
    if endpoint and endpoint not in skip_permission_check and not endpoint.startswith('api_'):
        # Mapper les endpoints aux pages
        endpoint_to_page = {
            'index': 'dashboard',
            'dashboard': 'dashboard',
            'calendrier': 'calendrier',
            'factures': 'factures',
            'nouvelle_facture_client': 'nouvelle_facture_client',
            'nouvelle_facture_employe': 'nouvelle_facture_employe',
            'clients': 'clients',
            'employes': 'employes',
            'recherche': 'recherche',
            'sauvegardes': 'sauvegardes',
            'historique': 'historique',
            'utilisateurs': 'utilisateurs'
        }
        
        page = endpoint_to_page.get(endpoint)
        
        # Si la page nécessite une permission
        if page and not current_user.has_permission(page):
            flash('Vous n\'avez pas l\'autorisation d\'accéder à cette page.', 'danger')
            return redirect(url_for('index'))
    
    return None

# ============================================================================
# DÉCORATEURS POUR LES PERMISSIONS
# ============================================================================

def admin_required(f):
    """Décorateur pour restreindre l'accès aux administrateurs"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Accès refusé. Vous devez être administrateur.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def comptable_ou_admin_required(f):
    """Décorateur pour restreindre l'accès aux comptables et administrateurs"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'comptable']:
            flash('Accès refusé. Vous devez être comptable ou administrateur.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# FONCTION D'ENVOI D'EMAIL
# ============================================================================

def send_email(to_email, subject, body):
    """
    Envoie un email via Gmail SMTP
    
    Args:
        to_email (str): Adresse email du destinataire
        subject (str): Sujet de l'email
        body (str): Corps de l'email (HTML supporté)
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Vérifier que la configuration email est faite
        if app.config['MAIL_USERNAME'] == 'votre.email@gmail.com':
            return False, "Configuration email non faite. Voir app.py ligne 48-51"
        
        # Créer le message
        msg = MIMEMultipart('alternative')
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Ajouter le corps (HTML)
        html_part = MIMEText(body, 'html')
        msg.attach(html_part)
        
        # Connexion au serveur SMTP
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        
        # Envoyer l'email
        server.send_message(msg)
        server.quit()
        
        return True, "Email envoyé avec succès"
        
    except smtplib.SMTPAuthenticationError:
        return False, "Erreur d'authentification email. Vérifiez username/password."
    except smtplib.SMTPException as e:
        return False, f"Erreur SMTP: {str(e)}"
    except Exception as e:
        return False, f"Erreur: {str(e)}"

def send_facture_email(facture, pdf_path):
    """
    Envoie une facture par email avec le PDF en pièce jointe
    
    Args:
        facture: Objet Facture de la BDD
        pdf_path (str): Chemin vers le fichier PDF de la facture
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Vérifier que la configuration email est faite
        if app.config['MAIL_USERNAME'] == 'votre.email@gmail.com':
            return False, "Configuration email non faite. Voir app.py ligne 48-51"
        
        # Déterminer le destinataire
        if facture.type_facture == 'client':
            if not facture.client or not facture.client.email:
                return False, "Le client n'a pas d'adresse email configurée"
            to_email = facture.client.email
            destinataire_nom = facture.client.nom
        else:  # employe
            if not facture.employe or not facture.employe.email:
                return False, "L'employé n'a pas d'adresse email configurée"
            to_email = facture.employe.email
            destinataire_nom = f"{facture.employe.prenom} {facture.employe.nom}"
        
        # Créer le message
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to_email
        msg['Subject'] = f"Facture {facture.numero} - {VOTRE_ENTREPRISE['nom']}"
        
        # Corps de l'email en HTML
        email_body = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    padding: 30px;
                    background: #f8f9fa;
                }}
                .facture-details {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    margin: 20px 0;
                    border-left: 4px solid #667eea;
                }}
                .facture-details h3 {{
                    color: #667eea;
                    margin-top: 0;
                }}
                .info-row {{
                    display: flex;
                    justify-content: space-between;
                    padding: 10px 0;
                    border-bottom: 1px solid #e9ecef;
                }}
                .info-label {{
                    font-weight: 600;
                    color: #6c757d;
                }}
                .info-value {{
                    color: #2C3E50;
                }}
                .montant-total {{
                    font-size: 24px;
                    font-weight: 700;
                    color: #28a745;
                    text-align: center;
                    padding: 20px;
                    background: #d4edda;
                    border-radius: 8px;
                    margin: 20px 0;
                }}
                .footer {{
                    background: #2C3E50;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 0 0 10px 10px;
                }}
                .footer p {{
                    margin: 5px 0;
                }}
                .btn-download {{
                    display: inline-block;
                    background: #667eea;
                    color: white;
                    padding: 12px 30px;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📄 Nouvelle Facture</h1>
                <p>{VOTRE_ENTREPRISE['nom']}</p>
            </div>
            
            <div class="content">
                <p>Bonjour <strong>{destinataire_nom}</strong>,</p>
                
                <p>Veuillez trouver ci-joint votre facture en pièce jointe.</p>
                
                <div class="facture-details">
                    <h3>📋 Détails de la facture</h3>
                    
                    <div class="info-row">
                        <span class="info-label">Numéro de facture :</span>
                        <span class="info-value">{facture.numero}</span>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Date :</span>
                        <span class="info-value">{facture.date_facture.strftime('%d/%m/%Y')}</span>
                    </div>
                    
                    <div class="info-row">
                        <span class="info-label">Date d'échéance :</span>
                        <span class="info-value">{facture.date_fin.strftime('%d/%m/%Y') if facture.date_fin else 'Non définie'}</span>
                    </div>
                </div>
                
                <div class="montant-total">
                    💰 Montant Total : {facture.total_net:.2f} €
                </div>
                
                <p><strong>Modalités de paiement :</strong></p>
                <div class="facture-details">
                    <p><strong>Nom de la banque :</strong> {VOTRE_ENTREPRISE.get('banque', 'Non renseigné')}</p>
                    <p><strong>IBAN :</strong> {VOTRE_ENTREPRISE.get('iban', 'Non renseigné')}</p>
                    <p><strong>BIC/SWIFT :</strong> {VOTRE_ENTREPRISE.get('bic', 'Non renseigné')}</p>
                </div>
                
                <p style="margin-top: 30px;">Pour toute question concernant cette facture, n'hésitez pas à nous contacter.</p>
                
                <p>Cordialement,<br>
                <strong>{VOTRE_ENTREPRISE['nom']}</strong></p>
            </div>
            
            <div class="footer">
                <p><strong>{VOTRE_ENTREPRISE['nom']}</strong></p>
                <p>{VOTRE_ENTREPRISE.get('adresse', '')}</p>
                <p>📞 {VOTRE_ENTREPRISE.get('telephone', '')} | 📧 {VOTRE_ENTREPRISE.get('email', '')}</p>
                <p>RCCM: {VOTRE_ENTREPRISE.get('rccm', '')} | ID NAT: {VOTRE_ENTREPRISE.get('id_nat', '')}</p>
            </div>
        </body>
        </html>
        """
        
        # Ajouter le corps HTML
        msg.attach(MIMEText(email_body, 'html'))
        
        # Ajouter le PDF en pièce jointe
        try:
            # ✅ DEBUG : Vérifier que le fichier existe et sa taille
            import os
            if not os.path.exists(pdf_path):
                return False, f"Le fichier PDF n'existe pas : {pdf_path}"
            
            file_size = os.path.getsize(pdf_path)
            print(f"📄 PDF trouvé : {pdf_path}")
            print(f"📏 Taille : {file_size} octets")
            
            if file_size == 0:
                return False, f"Le fichier PDF est vide (0 octets) : {pdf_path}"
            
            with open(pdf_path, 'rb') as pdf_file:
                pdf_content = pdf_file.read()
                
                # ✅ DEBUG : Vérifier le contenu
                print(f"📦 Contenu lu : {len(pdf_content)} octets")
                
                if len(pdf_content) == 0:
                    return False, "Le contenu du PDF est vide après lecture"
                
                pdf_attachment = MIMEBase('application', 'pdf')
                pdf_attachment.set_payload(pdf_content)
                encoders.encode_base64(pdf_attachment)
                
                # Nom du fichier
                filename = f"Facture_{facture.numero}.pdf"
                pdf_attachment.add_header('Content-Disposition', f'attachment; filename="{filename}"')
                
                msg.attach(pdf_attachment)
                
                print(f"✅ PDF attaché avec succès : {filename}")
                
        except FileNotFoundError:
            return False, f"Fichier PDF introuvable: {pdf_path}"
        except Exception as e:
            return False, f"Erreur lors de la lecture du PDF: {str(e)}"
        
        # Connexion au serveur SMTP et envoi
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        
        return True, f"Facture envoyée avec succès à {to_email}"
        
    except smtplib.SMTPAuthenticationError:
        return False, "Erreur d'authentification email. Vérifiez username/password."
    except smtplib.SMTPException as e:
        return False, f"Erreur SMTP: {str(e)}"
    except Exception as e:
        return False, f"Erreur: {str(e)}"

# ============================================================================
# MODÈLES DE BASE DE DONNÉES
# ============================================================================

class Client(db.Model):
    """Modèle pour les clients (grandes entreprises)"""
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    adresse = db.Column(db.String(200))
    ville = db.Column(db.String(100))
    email = db.Column(db.String(100))
    telephone = db.Column(db.String(20))
    siret = db.Column(db.String(20))
    date_creation = db.Column(db.DateTime, default=datetime.now)
    factures = db.relationship('Facture', backref='client', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'nom': self.nom,
            'adresse': self.adresse,
            'ville': self.ville,
            'email': self.email,
            'telephone': self.telephone,
            'siret': self.siret
        }

class Employe(db.Model):
    """Modèle pour les employés (sous-traitants)"""
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    matricule = db.Column(db.String(50), unique=True)
    poste = db.Column(db.String(100))
    taux_horaire = db.Column(db.Float, default=0.0)
    telephone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    date_embauche = db.Column(db.Date)
    actif = db.Column(db.Boolean, default=True)
    date_creation = db.Column(db.DateTime, default=datetime.now)
    amendes = db.relationship('Amende', backref='employe', lazy=True)
    livraisons = db.relationship('Livraison', backref='employe', lazy=True)
    factures = db.relationship('Facture', backref='employe', lazy=True, foreign_keys='Facture.employe_id')
    
    def nom_complet(self):
        return f"{self.prenom} {self.nom}"
    
    def to_dict(self):
        return {
            'id': self.id,
            'nom': self.nom,
            'prenom': self.prenom,
            'nom_complet': self.nom_complet(),
            'matricule': self.matricule,
            'poste': self.poste,
            'taux_horaire': self.taux_horaire,
            'telephone': self.telephone,
            'email': self.email,
            'actif': self.actif
        }

class Amende(db.Model):
    """Modèle pour les amendes des employés"""
    id = db.Column(db.Integer, primary_key=True)
    employe_id = db.Column(db.Integer, db.ForeignKey('employe.id'), nullable=False)
    facture_id = db.Column(db.Integer, db.ForeignKey('facture.id'), nullable=True)
    montant = db.Column(db.Float, nullable=False)
    raison = db.Column(db.String(200), nullable=False)
    date_amende = db.Column(db.Date, nullable=False)
    statut = db.Column(db.String(20), default='en_attente') # en_attente, appliquée, annulée
    date_creation = db.Column(db.DateTime, default=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'employe_id': self.employe_id,
            'employe_nom': self.employe.nom_complet() if self.employe else '',
            'facture_id': self.facture_id,
            'montant': self.montant,
            'raison': self.raison,
            'date_amende': self.date_amende.strftime('%d/%m/%Y'),
            'statut': self.statut
        }

class Livraison(db.Model):
    """Modèle pour les livraisons journalières des employés"""
    id = db.Column(db.Integer, primary_key=True)
    employe_id = db.Column(db.Integer, db.ForeignKey('employe.id'), nullable=False)
    date_livraison = db.Column(db.Date, nullable=False)
    nombre_journaux = db.Column(db.Integer, default=0)
    montant_jour = db.Column(db.Float, default=0.0)
    notes = db.Column(db.String(200))
    date_creation = db.Column(db.DateTime, default=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'employe_id': self.employe_id,
            'employe_nom': self.employe.nom_complet() if self.employe else '',
            'date_livraison': self.date_livraison.strftime('%d/%m/%Y'),
            'nombre_journaux': self.nombre_journaux,
            'montant_jour': self.montant_jour,
            'notes': self.notes or ''
        }
class Facture(db.Model):
    """Modèle pour les factures"""
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(50), unique=True, nullable=False)
    type_facture = db.Column(db.String(20), default='client') # client ou employe
    date_facture = db.Column(db.Date, nullable=False)
    date_debut = db.Column(db.Date)
    date_fin = db.Column(db.Date)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    employe_id = db.Column(db.Integer, db.ForeignKey('employe.id'), nullable=True)
    total_brut = db.Column(db.Float, default=0.0)
    total_amendes = db.Column(db.Float, default=0.0)
    total_net = db.Column(db.Float, nullable=False)
    fichier_pdf = db.Column(db.String(200))
    details_json = db.Column(db.Text)
    statut = db.Column(db.String(20), default='en_attente')
    notes = db.Column(db.Text)
    date_creation = db.Column(db.DateTime, default=datetime.now)
    
    # ✅ NOUVEAUX CHAMPS POUR GESTION DES PAIEMENTS
    statut_paiement = db.Column(db.String(20), default='impayee')  # impayee, payee, en_retard, partielle
    date_paiement = db.Column(db.Date, nullable=True)
    methode_paiement = db.Column(db.String(50), nullable=True)  # virement, cheque, especes, carte
    montant_paye = db.Column(db.Float, default=0.0)
    
    amendes = db.relationship('Amende', backref='facture', lazy=True)
    
    def to_dict(self):
        # Récupérer les emails de façon sécurisée
        client_email = ''
        if self.client:
            client_email = getattr(self.client, 'email', '') or ''
        
        employe_email = ''
        if self.employe:
            employe_email = getattr(self.employe, 'email', '') or ''
        
        return {
            'id': self.id,
            'numero': self.numero,
            'type_facture': self.type_facture,
            'date_facture': self.date_facture.strftime('%d/%m/%Y'),
            'date_debut': self.date_debut.strftime('%d/%m/%Y') if self.date_debut else '',
            'date_fin': self.date_fin.strftime('%d/%m/%Y') if self.date_fin else '',
            'client_nom': self.client.nom if self.client else '',
            'client_email': client_email,  # ✅ SÉCURISÉ
            'employe_nom': self.employe.nom_complet() if self.employe else '',
            'employe_email': employe_email,  # ✅ SÉCURISÉ
            'total_brut': self.total_brut,
            'total_amendes': self.total_amendes,
            'total_net': self.total_net,
            'statut': self.statut,
            'fichier_pdf': self.fichier_pdf,
            # ✅ Nouveaux champs de paiement
            'statut_paiement': self.statut_paiement,
            'date_paiement': self.date_paiement.strftime('%d/%m/%Y') if self.date_paiement else None,
            'methode_paiement': self.methode_paiement,
            'montant_paye': self.montant_paye,
            'reste_a_payer': self.total_net - self.montant_paye
        }

# ============================================================================
# FONCTION DE NUMÉROTATION UNIQUE
# ============================================================================

def generer_numero_facture(type_facture):
    """
    Génère un nouveau numéro de facture basé sur le type (client ou employe)
    en incrémentant le dernier numéro existant.
    """
    prefix = 'F' if type_facture == 'client' else 'S'
    
    # Trouver la dernière facture du même type
    derniere_facture = Facture.query.filter_by(
        type_facture=type_facture
    ).order_by(Facture.id.desc()).first()
    
    if derniere_facture:
        # Extraire le numéro et l'incrémenter (Ex: F-0001 -> 0001)
        try:
            dernier_numero = int(derniere_facture.numero.split('-')[-1])
            nouveau_numero = dernier_numero + 1
        except:
            # En cas de format invalide, recommencer à 1
            nouveau_numero = 1
    else:
        # Premier numéro de facture
        nouveau_numero = 1
        
    # Formater avec des zéros de tête (ex: 0001)
    numero_formate = f"{nouveau_numero:04d}"
    
    return f"{prefix}-{numero_formate}"

def generer_matricule_employe(nom, prenom, date_embauche=None):
    """
    Génère un matricule professionnel unique basé sur les informations de l'employé.
    Format: XXX-YYY-NNNN
    - XXX = 3 premières lettres du NOM (en majuscules)
    - YYY = 3 premières lettres du PRÉNOM (en majuscules)
    - NNNN = Année d'embauche + numéro séquentiel sur 2 chiffres
    
    Exemples:
    - Lutula Yannick embauché en 2024 (1er) → LUT-YAN-2401
    - Dupont Marie embauchée en 2024 (2ème) → DUP-MAR-2402
    - Ka Li embauché en 2025 (1er) → KAX-LIX-2501
    """
    import unicodedata
    
    # Fonction pour nettoyer les accents et caractères spéciaux
    def nettoyer_texte(texte):
        # Supprimer les accents
        texte_sans_accent = ''.join(
            c for c in unicodedata.normalize('NFD', texte)
            if unicodedata.category(c) != 'Mn'
        )
        # Garder seulement les lettres
        return ''.join(c for c in texte_sans_accent if c.isalpha()).upper()
    
    # Nettoyer et extraire les premières lettres
    nom_clean = nettoyer_texte(nom)
    prenom_clean = nettoyer_texte(prenom)
    
    # Prendre les 3 premières lettres (ou compléter avec X si trop court)
    part_nom = (nom_clean[:3] + 'XXX')[:3]
    part_prenom = (prenom_clean[:3] + 'XXX')[:3]
    
    # Année d'embauche (ou année actuelle si non fournie)
    if date_embauche:
        if isinstance(date_embauche, str):
            annee = datetime.strptime(date_embauche, "%Y-%m-%d").year
        else:
            annee = date_embauche.year
    else:
        annee = datetime.now().year
    
    # Deux derniers chiffres de l'année
    annee_court = str(annee)[-2:]
    
    # Trouver le numéro séquentiel pour cette année
    # Chercher tous les employés embauchés la même année
    prefix_recherche = f"{part_nom}-{part_prenom}-{annee_court}"
    
    employés_meme_pattern = Employe.query.filter(
        Employe.matricule.like(f'{prefix_recherche}%')
    ).all()
    
    # Trouver le numéro le plus élevé
    max_numero = 0
    for emp in employés_meme_pattern:
        try:
            # Extraire les 2 derniers chiffres du matricule
            numero = int(emp.matricule.split('-')[-1][-2:])
            if numero > max_numero:
                max_numero = numero
        except:
            pass
    
    # Nouveau numéro = max + 1
    nouveau_numero = max_numero + 1
    
    # Formater le numéro sur 2 chiffres
    numero_formate = f"{nouveau_numero:02d}"
    
    # Construire le matricule final
    matricule = f"{part_nom}-{part_prenom}-{annee_court}{numero_formate}"
    
    return matricule


# ============================================================================
# CONFIGURATION ENTREPRISE
# ============================================================================

VOTRE_ENTREPRISE = {
    "nom": "Mbeka",
    "adresse": "boulevard de smet de naeyer 506",
    "ville": "1020 Bruxelles",
    "telephone": "+32 466106509",
    "email": "yannicklutula4@gmail.com",
    "siret": "0652842068",
    "iban": "BE37002012946828",
    "logo": "static/images/logo.png"
}

TAUX_TVA = 21.0

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def generer_pdf_facture(data, type_facture='client'):
    """VERSION CORRIGÉE : Gère Clients ET Employés + Adresses + Colonnes"""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    
    # --- COULEURS ---
    BLEU_FONCE = colors.HexColor("#1e3a8a")
    BLEU_CLAIR = colors.HexColor("#3b82f6")
    GRIS_CLAIR = colors.HexColor("#f3f4f6")
    VERT = colors.HexColor("#10b981")
    
    # --- BANDEAU BLEU ---
    c.setFillColor(BLEU_FONCE)
    c.rect(0, height - 4*cm, width, 4*cm, fill=1, stroke=0)
    
    y = height - 1.5*cm

    # --- LOGO (Correction Import) ---
    try:
        # Utilisation de 'app' directement car défini globalement
        logo_path = os.path.join(app.root_path, 'static', 'images', 'logo.png')
        if os.path.exists(logo_path):
            c.drawImage(logo_path, 1.5*cm, y - 1.5*cm, width=5*cm, height=2.5*cm, preserveAspectRatio=True, mask='auto')
    except Exception as e:
        print(f"Logo warning: {e}") 

    # --- INFOS ENTREPRISE (Haut Droit) ---
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(width - 1.5*cm, y, "MBEKA LOGISTIQUE")
    
    c.setFont("Helvetica", 9)
    y -= 0.5*cm
    c.drawRightString(width - 1.5*cm, y, "Transport & Services")
    y -= 0.4*cm
    c.drawRightString(width - 1.5*cm, y, "contact@mbeka-logistique.com")
    
    # --- TITRE PRINCIPAL ---
    y = height - 5*cm
    c.setFillColor(BLEU_CLAIR)
    c.roundRect(1.5*cm, y - 1.2*cm, 8*cm, 1*cm, 0.3*cm, fill=1, stroke=0)
    
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 20)
    titre_doc = "FACTURE" if type_facture == 'client' else "BULLETIN DE PAIE"
    c.drawString(2*cm, y - 0.9*cm, titre_doc)
    
    # --- CADRES INFOS & DESTINATAIRE ---
    y -= 2*cm
    
    # Infos (Gauche)
    c.setFillColor(GRIS_CLAIR)
    c.roundRect(1.5*cm, y - 2.5*cm, 8*cm, 2.2*cm, 0.3*cm, fill=1, stroke=0)
    c.setFillColor(BLEU_FONCE)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(2*cm, y - 0.6*cm, "DÉTAILS")
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 9)
    c.drawString(2*cm, y - 1.2*cm, f"N° : {data.get('numero_facture', '')}")
    c.drawString(2*cm, y - 1.7*cm, f"Date : {data.get('date_facture', '')}")
    
    # Destinataire (Droite)
    c.setFillColor(GRIS_CLAIR)
    c.roundRect(width/2, y - 2.5*cm, width/2 - 1.5*cm, 2.2*cm, 0.3*cm, fill=1, stroke=0)
    c.setFillColor(BLEU_FONCE)
    c.setFont("Helvetica-Bold", 10)
    
    # Label dynamique (CLIENT ou EMPLOYÉ)
    label_dest = "CLIENT" if type_facture == 'client' else "EMPLOYÉ"
    c.drawString(width/2 + 0.5*cm, y - 0.6*cm, label_dest)
    
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 11)
    # Nom du destinataire
    nom_dest = str(data.get('destinataire_nom', ''))
    c.drawString(width/2 + 0.5*cm, y - 1.2*cm, nom_dest)
    
    # Adresse (Seulement si présente, ex: pour les clients)
    c.setFont("Helvetica", 9)
    adresse = data.get('destinataire_adresse')
    ville = data.get('destinataire_ville')
    
    offset_y = 1.7
    if adresse:
        c.drawString(width/2 + 0.5*cm, y - offset_y*cm, str(adresse))
        offset_y += 0.4
    if ville:
        c.drawString(width/2 + 0.5*cm, y - offset_y*cm, str(ville))
    
    # Pour les employés, on peut afficher le matricule si pas d'adresse
    if type_facture == 'employe' and data.get('matricule'):
        c.drawString(width/2 + 0.5*cm, y - 1.7*cm, f"Matricule: {data.get('matricule')}")
    
    # --- TABLEAU DES ARTICLES ---
    y -= 3.5*cm
    
    # En-tête bleu
    c.setFillColor(BLEU_FONCE)
    c.roundRect(1.5*cm, y - 0.8*cm, width - 3*cm, 0.8*cm, 0.2*cm, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 9)
    
    # Colonnes
    c.drawString(2*cm, y - 0.55*cm, "DESCRIPTION")
    c.drawRightString(width - 8*cm, y - 0.55*cm, "QTÉ")
    c.drawRightString(width - 5*cm, y - 0.55*cm, "PRIX UNIT.")
    c.drawRightString(width - 2*cm, y - 0.55*cm, "TOTAL")
    
    y -= 1.1*cm
    c.setFont("Helvetica", 9)
    c.setFillColor(colors.black)
    
    total_brut = float(data.get('total_brut', 0))
    ligne_index = 0
    
    for detail in data.get('details', []):
        # Fond alterné
        if ligne_index % 2 == 0:
            c.setFillColor(colors.HexColor("#f9fafb"))
            c.rect(1.5*cm, y - 0.5*cm, width - 3*cm, 0.65*cm, fill=1, stroke=0)
        
        c.setFillColor(colors.black)
        
        desc = detail.get('description', '')
        qte = detail.get('quantite', 0)
        
        # Astuce: On cherche 'prix_ht' (Client) OU 'prix_unitaire' (Employé)
        # Si aucun des deux, on met 0
        prix = detail.get('prix_ht')
        if prix is None:
            prix = detail.get('prix_unitaire', 0)
        
        try: montant = float(detail.get('total', 0))
        except: montant = 0.0
            
        # Affichage
        c.drawString(2*cm, y, desc[:45])
        c.drawRightString(width - 8*cm, y, f"{float(qte):.2f}")
        c.drawRightString(width - 5*cm, y, f"{float(prix):.2f} €")
        c.drawRightString(width - 2*cm, y, f"{montant:.2f} €")
        
        y -= 0.7*cm
        ligne_index += 1
        
        # Nouvelle page si on arrive en bas
        if y < 4*cm:
            c.showPage()
            # Redessiner le bandeau en cas de nouvelle page ? (Optionnel, ici on simplifie)
            y = height - 2*cm

    # --- TOTAUX ---
    y -= 0.5*cm
    appliquer_tva = data.get('appliquer_tva', False)
    
    # Calculs finaux
    if appliquer_tva:
        tva = total_brut * 0.20 # TVA 20%
        ttc = total_brut + tva
        label_final = "NET À PAYER:"
        val_final = ttc
    else:
        # Cas Employé (pas de TVA, mais peut avoir des amendes)
        total_amendes = float(data.get('total_amendes', 0))
        if total_amendes > 0:
            # Afficher les amendes
            c.setFillColor(colors.red)
            c.drawRightString(width - 4*cm, y - 0.7*cm, "AMENDES:")
            c.drawRightString(width - 1.5*cm, y - 0.7*cm, f"- {total_amendes:.2f} €")
            y -= 0.7*cm
            
        val_final = total_brut - total_amendes if type_facture == 'employe' else total_brut
        label_final = "NET À PAYER:"

    # Cadre Vert du Total
    c.setFillColor(VERT)
    c.roundRect(width - 9*cm, y - 1.5*cm, 7.5*cm, 1*cm, 0.3*cm, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(width - 4*cm, y - 0.9*cm, label_final)
    c.drawRightString(width - 1.5*cm, y - 0.9*cm, f"{val_final:.2f} €")

    c.save()
    buffer.seek(0)
    
    # Retourne 4 valeurs comme attendu par le reste du code
    return buffer, total_brut, (val_final - total_brut if appliquer_tva else 0), val_final
# ============================================================================
# FILTRES JINJA PERSONNALISÉS
# ============================================================================

@app.template_filter('fromjson')
def fromjson_filter(value):
    try:
        return json.loads(value) if value else []
    except:
        return []

@app.template_filter('date')
def date_filter(value):
    if hasattr(value, 'date'):
        return value.date()
    return value

@app.context_processor
def inject_datetime():
    return {
        'now': datetime.now(),
        'datetime': datetime
    }

# ============================================================================
# ROUTES D'AUTHENTIFICATION
# ============================================================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Page mot de passe oublié (publique)"""
    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip()
        
        if not username_or_email:
            flash('Veuillez entrer votre nom d\'utilisateur ou email.', 'danger')
            return render_template('forgot_password.html', entreprise=VOTRE_ENTREPRISE)
        
        # Chercher l'utilisateur par username OU email
        user = Utilisateur.query.filter(
            (Utilisateur.username == username_or_email) | 
            (Utilisateur.email == username_or_email)
        ).first()
        
        if not user:
            # Pour la sécurité, on ne dit pas si l'utilisateur existe ou non
            flash('Si cet utilisateur existe, un email de réinitialisation a été envoyé.', 'info')
            return render_template('forgot_password.html', entreprise=VOTRE_ENTREPRISE)
        
        if not user.actif:
            flash('Ce compte est désactivé. Contactez un administrateur.', 'danger')
            return render_template('forgot_password.html', entreprise=VOTRE_ENTREPRISE)
        
        # Générer le token
        token = user.generate_reset_token()
        db.session.commit()
        
        # Générer le lien
        reset_link = f"http://localhost:5000/reset-password/{token}"
        
        # Essayer d'envoyer l'email (si configuré)
        if user.email:
            # Préparer l'email HTML
            email_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: #2C3E50;">Réinitialisation de mot de passe</h2>
                <p>Bonjour <strong>{user.prenom or user.username}</strong>,</p>
                <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
                <p>Cliquez sur le lien ci-dessous pour définir un nouveau mot de passe :</p>
                <p style="margin: 30px 0;">
                    <a href="{reset_link}" 
                       style="background: #3498DB; color: white; padding: 12px 30px; 
                              text-decoration: none; border-radius: 5px; display: inline-block;">
                        Réinitialiser mon mot de passe
                    </a>
                </p>
                <p><strong>Ce lien est valide pendant 24 heures.</strong></p>
                <p style="color: #7f8c8d; font-size: 14px;">
                    Si vous n'avez pas demandé cette réinitialisation, ignorez ce message.
                </p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ecf0f1;">
                <p style="color: #95a5a6; font-size: 12px;">
                    L'équipe Mbeka Facturation
                </p>
            </body>
            </html>
            """
            
            # Envoyer l'email
            success, message = send_email(
                to_email=user.email,
                subject="Réinitialisation de votre mot de passe - Mbeka",
                body=email_body
            )
            
            if success:
                flash(f'✅ Un email de réinitialisation a été envoyé à {user.email}', 'success')
            else:
                # SÉCURITÉ : Ne pas afficher le lien, juste l'erreur
                flash(f'❌ Impossible d\'envoyer l\'email. Contactez l\'administrateur système.', 'danger')
                flash(f'Détails techniques : {message}', 'danger')
        else:
            flash('Aucun email associé à ce compte. Contactez un administrateur.', 'danger')
        
        return render_template('forgot_password.html', entreprise=VOTRE_ENTREPRISE)
    
    return render_template('forgot_password.html', entreprise=VOTRE_ENTREPRISE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = Utilisateur.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.actif:
                # Log tentative de connexion compte désactivé
                creer_log('tentative_connexion_compte_desactive', 
                         f"Tentative de connexion avec le compte désactivé : {username}",
                         user)
                flash('Votre compte est désactivé. Contactez un administrateur.', 'danger')
                return redirect(url_for('login'))
            
            # Connexion avec session persistante
            remember = request.form.get('remember', False)
            login_user(user, remember=remember)
            
            # Marquer la session comme permanente si "se souvenir de moi"
            if remember:
                session.permanent = True
            
            user.derniere_connexion = datetime.utcnow()
            db.session.commit()
            
            # Log connexion réussie
            creer_log('connexion', 
                     {'remember': remember, 'ip': request.remote_addr},
                     user)
            
            flash(f'Bienvenue {user.prenom or user.username} !', 'success')
            
            # Rediriger vers la page demandée ou l'accueil
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            # Log tentative de connexion échouée
            creer_log('tentative_connexion_echouee', 
                     f"Tentative avec username : {username}",
                     None)
            flash('Identifiant ou mot de passe incorrect.', 'danger')
    
    return render_template('login.html',
                           entreprise=VOTRE_ENTREPRISE)

@app.route('/logout')
@login_required
def logout():
    """Déconnexion"""
    # Log déconnexion avant de déconnecter
    creer_log('deconnexion', None, current_user)
    
    logout_user()
    flash('Vous avez été déconnecté avec succès.', 'info')
    return redirect(url_for('login'))

@app.route('/utilisateurs')
@admin_required
def utilisateurs():
    """Page de gestion des utilisateurs (admin only)"""
    users = Utilisateur.query.all()
    return render_template('utilisateurs.html',
                           entreprise=VOTRE_ENTREPRISE,
                           utilisateurs=users)

@app.route('/api/utilisateurs', methods=['GET'])
@admin_required
def api_liste_utilisateurs():
    """API: Liste des utilisateurs"""
    users = Utilisateur.query.all()
    return jsonify([u.to_dict() for u in users])

@app.route('/api/utilisateurs/creer', methods=['POST'])
@admin_required
def api_creer_utilisateur():
    """API: Créer un nouvel utilisateur"""
    try:
        data = request.json
        
        # Vérifier si l'username existe déjà
        if Utilisateur.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Nom d\'utilisateur déjà utilisé'}), 400
        
        # Vérifier si l'email existe déjà
        if Utilisateur.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email déjà utilisé'}), 400
        
        # Créer le nouvel utilisateur
        user = Utilisateur(
            username=data['username'],
            email=data['email'],
            telephone=data.get('telephone'),
            nom=data.get('nom'),
            prenom=data.get('prenom'),
            role=data.get('role', 'employe'),
            actif=True
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Utilisateur créé avec succès',
            'utilisateur': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/utilisateurs/<int:user_id>/modifier', methods=['PUT'])
@admin_required
def api_modifier_utilisateur(user_id):
    """API: Modifier un utilisateur"""
    try:
        user = Utilisateur.query.get(user_id)
        if not user:
            return jsonify({'error': 'Utilisateur introuvable'}), 404
        
        data = request.json
        
        # Ne pas permettre de modifier le dernier admin
        if user.role == 'admin' and data.get('role') != 'admin':
            nb_admins = Utilisateur.query.filter_by(role='admin', actif=True).count()
            if nb_admins <= 1:
                return jsonify({'error': 'Impossible de retirer le rôle admin au dernier administrateur'}), 400
        
        # Mettre à jour les champs
        if 'nom' in data:
            user.nom = data['nom']
        if 'prenom' in data:
            user.prenom = data['prenom']
        if 'email' in data:
            user.email = data['email']
        if 'telephone' in data:
            user.telephone = data['telephone']
        if 'role' in data:
            user.role = data['role']
        if 'actif' in data:
            user.actif = data['actif']
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Utilisateur modifié avec succès',
            'utilisateur': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/utilisateurs/<int:user_id>/supprimer', methods=['DELETE'])
@admin_required
def api_supprimer_utilisateur(user_id):
    """API: Supprimer un utilisateur"""
    try:
        user = Utilisateur.query.get(user_id)
        if not user:
            return jsonify({'error': 'Utilisateur introuvable'}), 404
        
        # Ne pas permettre de supprimer le dernier admin
        if user.role == 'admin':
            nb_admins = Utilisateur.query.filter_by(role='admin', actif=True).count()
            if nb_admins <= 1:
                return jsonify({'error': 'Impossible de supprimer le dernier administrateur'}), 400
        
        # Ne pas permettre de se supprimer soi-même
        if user.id == current_user.id:
            return jsonify({'error': 'Vous ne pouvez pas supprimer votre propre compte'}), 400
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Utilisateur supprimé avec succès'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/utilisateurs/<int:user_id>/permissions', methods=['GET'])
@admin_required
def api_get_permissions(user_id):
    """API: Récupérer les permissions d'un utilisateur"""
    try:
        user = Utilisateur.query.get(user_id)
        if not user:
            return jsonify({'error': 'Utilisateur introuvable'}), 404
        
        # Récupérer toutes les permissions
        permissions_dict = {}
        for page_key in PAGES_DISPONIBLES.keys():
            permissions_dict[page_key] = user.has_permission(page_key)
        
        return jsonify({
            'success': True,
            'permissions': permissions_dict,
            'pages_disponibles': PAGES_DISPONIBLES
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/utilisateurs/<int:user_id>/permissions', methods=['PUT'])
@admin_required
def api_update_permissions(user_id):
    """API: Mettre à jour les permissions d'un utilisateur"""
    try:
        user = Utilisateur.query.get(user_id)
        if not user:
            return jsonify({'error': 'Utilisateur introuvable'}), 404
        
        data = request.get_json()
        permissions_data = data.get('permissions', {})
        
        # Supprimer toutes les permissions existantes
        Permission.query.filter_by(utilisateur_id=user_id).delete()
        
        # Créer les nouvelles permissions
        for page, actif in permissions_data.items():
            if page in PAGES_DISPONIBLES:
                perm = Permission(
                    utilisateur_id=user_id,
                    page=page,
                    actif=actif
                )
                db.session.add(perm)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Permissions mises à jour avec succès'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/utilisateurs/<int:user_id>/generer-lien-reset', methods=['POST'])
@admin_required
def generer_lien_reset(user_id):
    """Générer un lien de réinitialisation de mot de passe (admin uniquement)"""
    try:
        user = Utilisateur.query.get(user_id)
        if not user:
            return jsonify({'error': 'Utilisateur introuvable'}), 404
        
        # Générer le token
        token = user.generate_reset_token()
        db.session.commit()
        
        # Générer le lien (à adapter selon votre domaine)
        reset_link = f"http://localhost:5000/reset-password/{token}"
        
        # Vérifier si on doit envoyer l'email automatiquement
        send_email_auto = request.json.get('send_email', False) if request.is_json else False
        
        email_sent = False
        email_message = ""
        
        if send_email_auto and user.email:
            # Préparer l'email HTML
            email_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: #2C3E50;">Réinitialisation de mot de passe</h2>
                <p>Bonjour <strong>{user.prenom or user.username}</strong>,</p>
                <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
                <p>Cliquez sur le lien ci-dessous pour définir un nouveau mot de passe :</p>
                <p style="margin: 30px 0;">
                    <a href="{reset_link}" 
                       style="background: #3498DB; color: white; padding: 12px 30px; 
                              text-decoration: none; border-radius: 5px; display: inline-block;">
                        Réinitialiser mon mot de passe
                    </a>
                </p>
                <p><strong>Ce lien est valide pendant 24 heures.</strong></p>
                <p style="color: #7f8c8d; font-size: 14px;">
                    Si vous n'avez pas demandé cette réinitialisation, ignorez ce message.
                </p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ecf0f1;">
                <p style="color: #95a5a6; font-size: 12px;">
                    L'équipe Mbeka Facturation
                </p>
            </body>
            </html>
            """
            
            # Envoyer l'email
            success, message = send_email(
                to_email=user.email,
                subject="Réinitialisation de votre mot de passe - Mbeka",
                body=email_body
            )
            
            email_sent = success
            email_message = message
        
        # Préparer les messages pour copie manuelle
        message_sms = f"Votre lien de réinitialisation Mbeka : {reset_link} (valide 24h)"
        message_email_text = f"""
Bonjour {user.prenom or user.username},

Voici votre lien de réinitialisation de mot de passe :
{reset_link}

Ce lien est valide pendant 24 heures.

Si vous n'avez pas demandé cette réinitialisation, ignorez ce message.

Cordialement,
L'équipe Mbeka
"""
        
        return jsonify({
            'success': True,
            'message': 'Lien de réinitialisation généré',
            'reset_link': reset_link,
            'message_sms': message_sms,
            'message_email': message_email_text,
            'user_email': user.email,
            'user_telephone': user.telephone,
            'expiry': user.reset_token_expiry.strftime('%d/%m/%Y %H:%M') if user.reset_token_expiry else None,
            'email_sent': email_sent,
            'email_message': email_message
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Page de réinitialisation de mot de passe"""
    # Vérifier que l'utilisateur n'est pas déjà connecté
    if current_user.is_authenticated:
        flash('Vous êtes déjà connecté.', 'info')
        return redirect(url_for('index'))
    
    # Trouver l'utilisateur avec ce token
    user = Utilisateur.query.filter_by(reset_token=token).first()
    
    if not user or not user.verify_reset_token(token):
        flash('Ce lien de réinitialisation est invalide ou a expiré.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or not confirm_password:
            flash('Veuillez remplir tous les champs.', 'danger')
        elif new_password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'danger')
        elif len(new_password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères.', 'danger')
        else:
            # Changer le mot de passe
            user.set_password(new_password)
            user.clear_reset_token()
            db.session.commit()
            
            flash(f'✅ Mot de passe changé avec succès ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html',
                           entreprise=VOTRE_ENTREPRISE,
                           token=token,
                           user=user)

# ============================================================================
# ROUTES PRINCIPALES
# ============================================================================

@app.route('/')
@login_required
def index():
    """Page d'accueil"""
    employes = Employe.query.all()
    
    return render_template('index.html',
                           entreprise=VOTRE_ENTREPRISE,
                           employes=employes,
                           stats={
                               'total_clients': Client.query.count(),
                               'total_employes': Employe.query.count(),
                               'total_factures': Facture.query.count(),
                               'factures_en_attente': Facture.query.filter_by(statut='en_attente').count()
                           })

@app.route('/dashboard')
@login_required
def dashboard():
    """Page du tableau de bord avec graphiques"""
    return render_template('dashboard.html',
                           entreprise=VOTRE_ENTREPRISE)

@app.route('/calendrier')
@login_required
def calendrier():
    """Page du calendrier/planning"""
    return render_template('calendrier.html',
                           entreprise=VOTRE_ENTREPRISE)

@app.route('/nouvelle-facture-client')
@comptable_ou_admin_required
def nouvelle_facture_client():
    """Page pour créer une facture client"""
    numero_auto = generer_numero_facture('client')
    clients = Client.query.order_by(Client.nom).all()
    employes = Employe.query.filter_by(actif=True).order_by(Employe.nom).all()
    
    return render_template('nouvelle_facture_client.html',
                           entreprise=VOTRE_ENTREPRISE,
                           tva=TAUX_TVA,
                           numero_auto=numero_auto,
                           clients=clients,
                           employes=employes)

@app.route('/nouvelle-facture-employe')
@comptable_ou_admin_required
def nouvelle_facture_employe():
    """Page pour créer une facture employé"""
    numero_auto = generer_numero_facture('employe')
    employes = Employe.query.filter_by(actif=True).order_by(Employe.nom).all()
    
    # Récupérer les amendes en attente pour chaque employé
    employes_avec_amendes = []
    for emp in employes:
        amendes_en_attente = Amende.query.filter_by(
            employe_id=emp.id,
            statut='en_attente'
        ).all()
        
        total_amendes = sum(a.montant for a in amendes_en_attente)
        
        employes_avec_amendes.append({
            'employe': emp,
            'amendes': amendes_en_attente,
            'total_amendes': total_amendes
        })
    
    return render_template('nouvelle_facture_employe.html',
                           entreprise=VOTRE_ENTREPRISE,
                           numero_auto=numero_auto,
                           employes_avec_amendes=employes_avec_amendes)

# ============================================================================
# ROUTES POUR GÉNÉRER LES FACTURES
# ============================================================================

@app.route('/generer-facture-client', methods=['POST'])
def generer_facture_client():
    try:
        # 1. Récupération des données
        data = request.form
        client_id = data.get('client_id')
        
        # Vérification ID valide
        if not client_id:
            return jsonify({'error': "ID Client manquant"}), 400
            
        client = Client.query.get(int(client_id))
        if not client: return jsonify({'error': "Client introuvable"}), 404

        # 2. Construction de la liste des articles
        details = []
        total_brut = 0
        index = 1
        while index < 50:
            if f'details[{index}][description]' not in data: break
            try:
                # Utilisation sécurisée de get avec valeur par défaut 0
                qte = float(data.get(f'details[{index}][quantite]') or 0)
                prix = float(data.get(f'details[{index}][prix_ht]') or 0)
                total = qte * prix
                
                details.append({
                    'description': data[f'details[{index}][description]'],
                    'quantite': qte, 
                    'prix_ht': prix,  # Important: clé utilisée par le PDF
                    'total': total
                })
                total_brut += total
            except ValueError: 
                pass # Ignore les lignes mal formées
            index += 1
            
        if not details: return jsonify({'error': "Ajoutez au moins un article"}), 400

        # 3. Préparation données PDF (AVEC ADRESSE)
        numero = data.get('numero_facture', 'TEMP')
        if numero == 'new': numero = generer_numero_facture('client')
        
        pdf_data = {
            'numero_facture': numero,
            'date_facture': datetime.now().strftime('%d/%m/%Y'),
            'destinataire_nom': client.nom,
            # --- ICI L'AJOUT IMPORTANT ---
            'destinataire_adresse': client.adresse,
            'destinataire_ville': client.ville,
            # -----------------------------
            'details': details,
            'total_brut': total_brut,
            'appliquer_tva': data.get('appliquer_tva') == 'on'
        }

        # 4. Génération PDF
        pdf_buffer, brut, tva, net = generer_pdf_facture(pdf_data, 'client')

        # 5. Sauvegarde BDD
        nom_fichier = f"Facture_{numero}.pdf"
        facture = Facture(
            numero=numero, 
            type_facture='client', 
            client_id=client.id,
            date_facture=datetime.now(), 
            total_brut=brut, 
            total_net=net,
            fichier_pdf=nom_fichier, 
            details_json=json.dumps(details), 
            statut='en_attente'
        )
        db.session.add(facture)
        db.session.commit()

        return send_file(pdf_buffer, as_attachment=True, download_name=nom_fichier, mimetype='application/pdf')

    except Exception as e:
        print(f"ERREUR GENERATION FACTURE: {e}") 
        return jsonify({'error': f"Erreur serveur: {str(e)}"}), 500
# ============================================================================
# ROUTES POUR LES FICHIERS
# ============================================================================

@app.route('/telecharger_facture/<int:facture_id>')
def telecharger_facture(facture_id):
    """Télécharger une facture"""
    facture = Facture.query.get_or_404(facture_id)
    
    if not facture.fichier_pdf or not os.path.exists(facture.fichier_pdf):
        return "Fichier non trouvé", 404
    
    nom_fichier = f"{facture.numero}.pdf"
    return send_file(facture.fichier_pdf, as_attachment=True, download_name=nom_fichier)

@app.route('/voir_facture/<int:facture_id>')
def voir_facture(facture_id):
    """Voir une facture dans le navigateur"""
    facture = Facture.query.get_or_404(facture_id)
    
    if not facture.fichier_pdf or not os.path.exists(facture.fichier_pdf):
        return "Fichier non trouvé", 404
    
    return send_file(facture.fichier_pdf, mimetype='application/pdf')

# ============================================================================
# ROUTE POUR GÉNÉRER LE BULLETIN DE PAIE BASÉ SUR LES LIVRAISONS
# ============================================================================

@app.route('/generer-facture-employe', methods=['POST'])
def generer_facture_employe():
    """Génère un bulletin de paie pour un employé basé sur ses livraisons"""
    try:
        data = request.json
        
        app.logger.info(f"Génération bulletin employé: {data}")
        
        # Validation des données
        if not data.get('employe_id'):
            return jsonify({'error': 'Employé obligatoire'}), 400
        
        employe = Employe.query.get(data['employe_id'])
        if not employe:
            return jsonify({'error': 'Employé introuvable'}), 404
        
        # Générer le numéro de facture
        numero_facture = generer_numero_facture('employe')
        
        # Récupérer les données
        total_brut = float(data.get('total_brut', 0))
        amendes_ids = data.get('amendes_ids', [])
        livraisons = data.get('livraisons', [])
        
        # Calculer le total des amendes
        total_amendes = 0
        amendes_a_marquer = []
        if amendes_ids:
            for amende_id in amendes_ids:
                amende = Amende.query.get(amende_id)
                if amende and amende.statut == 'en_attente':
                    total_amendes += amende.montant
                    amendes_a_marquer.append(amende)
        
        # Calculer le net à payer
        total_net = total_brut - total_amendes
        
        # Préparer les détails pour le PDF
        details = []
        
        # Ajouter les livraisons comme détails
        for livraison in livraisons:
            details.append({
                'description': f"Livraison du {livraison['date_livraison']} - {livraison['nombre_journaux']} journaux",
                'quantite': 1,
                'prix_unitaire': livraison['montant_jour'],
                'total': livraison['montant_jour']
            })
        
        # Préparer les données pour le PDF
        pdf_data = {
            'numero_facture': numero_facture,
            'date_facture': data.get('date_facture', datetime.now().strftime('%d/%m/%Y')),
            'date_debut': data.get('date_debut'),
            'date_fin': data.get('date_fin'),
            'destinataire_nom': employe.nom_complet(),
            'matricule': employe.matricule or 'N/A',
            'details': details,
            'total_brut': total_brut,
            'total_amendes': total_amendes,
            'notes': data.get('notes', '')
        }
        
        # Générer le nom du fichier PDF
        nom_fichier = f"Bulletin_{numero_facture.replace('/', '_')}_{employe.nom}.pdf"
        chemin_pdf = os.path.join('factures', nom_fichier)
        
        # Créer le dossier si nécessaire
        os.makedirs('factures', exist_ok=True)
        
        # Générer le PDF
        generer_pdf_facture(pdf_data, chemin_pdf, 'employe')
        
        # Sauvegarder la facture en base de données
        facture = Facture(
            numero=numero_facture,
            type_facture='employe',
            date_facture=datetime.now().date(),
            date_debut=datetime.strptime(data['date_debut'], "%Y-%m-%d").date() if data.get('date_debut') else None,
            date_fin=datetime.strptime(data['date_fin'], "%Y-%m-%d").date() if data.get('date_fin') else None,
            client_id=Client.query.first().id,  # Utilise le premier client (requis par la BDD)
            employe_id=employe.id,
            total_brut=total_brut,
            total_amendes=total_amendes,
            total_net=total_net,
            fichier_pdf=chemin_pdf,
            details_json=json.dumps(livraisons, ensure_ascii=False),
            notes=data.get('notes', ''),
            statut='en_attente'
        )
        
        db.session.add(facture)
        
        # Marquer les amendes comme appliquées et les lier à cette facture
        for amende in amendes_a_marquer:
            amende.statut = 'appliquée'
            amende.facture_id = facture.id
        
        db.session.commit()
        
        app.logger.info(f"✅ Bulletin {numero_facture} généré avec succès")
        
        return jsonify({
            'success': True,
            'message': f'Bulletin {numero_facture} généré avec succès',
            'download_url': f'/telecharger_facture/{facture.id}'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur génération bulletin: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES POUR LES EMPLOYÉS
# ============================================================================

@app.route('/employes')
@comptable_ou_admin_required
def employes():
    """Page de gestion des employés"""
    employes_list = Employe.query.order_by(Employe.nom, Employe.prenom).all()
    
    # Statistiques
    for emp in employes_list:
        emp.amendes_en_attente = Amende.query.filter_by(
            employe_id=emp.id,
            statut='en_attente'
        ).count()
        emp.total_amendes = db.session.query(db.func.sum(Amende.montant)).filter_by(
            employe_id=emp.id,
            statut='en_attente'
        ).scalar() or 0
    
    return render_template('employes.html',
                           employes=employes_list,
                           entreprise=VOTRE_ENTREPRISE)

@app.route('/api/employes', methods=['GET', 'POST'])
def api_employes():
    """API pour gérer les employés"""
    if request.method == 'POST':
        data = request.json
        
        # Générer automatiquement le matricule si non fourni
        matricule = data.get('matricule')
        if not matricule or matricule.strip() == '':
            matricule = generer_matricule_employe(
                data['nom'], 
                data['prenom'],
                data.get('date_embauche')
            )
            app.logger.info(f"✅ Matricule généré automatiquement: {matricule}")
        else:
            # Vérifier si le matricule existe déjà
            existing = Employe.query.filter_by(matricule=matricule).first()
            if existing:
                return jsonify({'error': 'Un employé avec ce matricule existe déjà'}), 400
        
        employe = Employe(
            nom=data['nom'],
            prenom=data['prenom'],
            matricule=matricule,
            poste=data.get('poste'),
            taux_horaire=float(data.get('taux_horaire', 0)),
            telephone=data.get('telephone'),
            email=data.get('email'),
            date_embauche=datetime.strptime(data['date_embauche'], "%Y-%m-%d").date() if data.get('date_embauche') else None
        )
        
        db.session.add(employe)
        db.session.commit()
        
        app.logger.info(f"✅ Employé créé: {employe.nom_complet()} - Matricule: {employe.matricule}")
        
        return jsonify(employe.to_dict()), 201
    
    # GET
    employes_list = Employe.query.order_by(Employe.nom).all()
    return jsonify([e.to_dict() for e in employes_list])

@app.route('/api/employes/<int:employe_id>', methods=['PUT', 'DELETE'])
def api_employe_detail(employe_id):
    """API pour un employé spécifique"""
    employe = Employe.query.get_or_404(employe_id)
    
    if request.method == 'PUT':
        data = request.json
        
        employe.nom = data.get('nom', employe.nom)
        employe.prenom = data.get('prenom', employe.prenom)
        employe.matricule = data.get('matricule', employe.matricule)
        employe.poste = data.get('poste', employe.poste)
        employe.taux_horaire = float(data.get('taux_horaire', employe.taux_horaire))
        employe.telephone = data.get('telephone', employe.telephone)
        employe.email = data.get('email', employe.email)
        employe.actif = data.get('actif', employe.actif)
        
        if data.get('date_embauche'):
            employe.date_embauche = datetime.strptime(data['date_embauche'], "%Y-%m-%d").date()
        
        db.session.commit()
        return jsonify(employe.to_dict())
    
    elif request.method == 'DELETE':
        # Récupérer les informations sur les données associées
        factures = Facture.query.filter_by(employe_id=employe.id).all()
        amendes = Amende.query.filter_by(employe_id=employe.id).all()
        livraisons = Livraison.query.filter_by(employe_id=employe.id).all()
        
        nb_factures = len(factures)
        nb_amendes = len(amendes)
        nb_livraisons = len(livraisons)
        
        # ✅ SUPPRIMER TOUTES LES DONNÉES ASSOCIÉES
        # Supprimer les livraisons
        for livraison in livraisons:
            db.session.delete(livraison)
        
        # Supprimer les amendes
        for amende in amendes:
            db.session.delete(amende)
        
        # Supprimer les factures
        for facture in factures:
            # Supprimer le fichier PDF si il existe
            if facture.fichier_pdf and os.path.exists(facture.fichier_pdf):
                try:
                    os.remove(facture.fichier_pdf)
                except:
                    pass
            db.session.delete(facture)
        
        # Supprimer l'employé
        db.session.delete(employe)
        db.session.commit()
        
        app.logger.info(f"✅ Employé {employe.nom_complet()} supprimé avec {nb_factures} factures, {nb_amendes} amendes, {nb_livraisons} livraisons")
        
        return jsonify({
            'success': True, 
            'message': f'Employé supprimé avec succès (avec {nb_factures} factures, {nb_amendes} amendes, {nb_livraisons} livraisons)'
        })

@app.route('/api/employes/<int:employe_id>/infos-suppression', methods=['GET'])
def api_employe_infos_suppression(employe_id):
    """Obtenir les informations détaillées avant suppression d'un employé"""
    employe = Employe.query.get_or_404(employe_id)
    
    # Compter les données associées
    nb_factures = Facture.query.filter_by(employe_id=employe.id).count()
    nb_amendes = Amende.query.filter_by(employe_id=employe.id).count()
    nb_livraisons = Livraison.query.filter_by(employe_id=employe.id).count()
    
    # Calculer les totaux financiers
    factures = Facture.query.filter_by(employe_id=employe.id).all()
    total_factures = sum(f.total_net for f in factures)
    
    return jsonify({
        'employe': employe.to_dict(),
        'nb_factures': nb_factures,
        'nb_amendes': nb_amendes,
        'nb_livraisons': nb_livraisons,
        'total_factures': total_factures,
        'has_data': nb_factures > 0 or nb_amendes > 0 or nb_livraisons > 0
    })

# ============================================================================
# ROUTES POUR LES AMENDES
# ============================================================================

@app.route('/api/amendes', methods=['POST'])
def api_amendes():
    """Créer une nouvelle amende"""
    data = request.json
    
    amende = Amende(
        employe_id=int(data['employe_id']),
        montant=float(data['montant']),
        raison=data['raison'],
        date_amende=datetime.strptime(data['date_amende'], "%Y-%m-%d").date(),
        statut='en_attente'
    )
    
    db.session.add(amende)
    db.session.commit()
    
    return jsonify(amende.to_dict()), 201

@app.route('/api/employes/<int:employe_id>/amendes')
def api_employe_amendes(employe_id):
    """Récupérer les amendes d'un employé"""
    amendes = Amende.query.filter_by(employe_id=employe_id, statut='en_attente').all()
    return jsonify([a.to_dict() for a in amendes])

@app.route('/api/amendes/<int:amende_id>', methods=['DELETE'])
def api_delete_amende(amende_id):
    """Supprimer une amende"""
    amende = Amende.query.get_or_404(amende_id)
    
    if amende.statut == 'appliquée':
        return jsonify({'error': 'Impossible de supprimer une amende déjà appliquée'}), 400
    
    db.session.delete(amende)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Amende supprimée'})

# ============================================================================
# ROUTES POUR LES CLIENTS ET FACTURES (EXISTANTES)
# ============================================================================

@app.route('/clients')
@comptable_ou_admin_required
def clients():
    """Page de gestion des clients"""
    clients_list = Client.query.order_by(Client.nom).all()
    
    # Calculer les statistiques
    total_clients = len(clients_list)
    total_factures = sum(len(client.factures) for client in clients_list)
    total_ca = sum(sum(f.total_net for f in client.factures) for client in clients_list)
    
    return render_template('clients.html',
                           clients=clients_list,
                           entreprise=VOTRE_ENTREPRISE,
                           stats={
                               'total_clients': total_clients,
                               'total_factures': total_factures,
                               'total_ca': total_ca
                           })

@app.route('/factures')
@login_required
def factures():
    """Page de gestion des factures"""
    factures_list = Facture.query.order_by(Facture.date_facture.desc()).all()
    
    # Séparer factures clients et employés
    factures_clients = [f for f in factures_list if f.type_facture == 'client']
    factures_employes = [f for f in factures_list if f.type_facture == 'employe']
    
    return render_template('factures.html',
                           factures_clients=factures_clients,
                           factures_employes=factures_employes,
                           entreprise=VOTRE_ENTREPRISE)

@app.route('/historique')
@login_required
def historique():
    """Page d'historique"""
    factures_list = Facture.query.order_by(Facture.date_facture.desc()).all()
    return render_template('historique.html',
                           factures=factures_list,
                           entreprise=VOTRE_ENTREPRISE)

@app.route('/logs')
@admin_required
def logs():
    """Page des logs d'activité (Admin uniquement)"""
    # Filtres
    user_filter = request.args.get('user')
    action_filter = request.args.get('action')
    date_debut = request.args.get('date_debut')
    date_fin = request.args.get('date_fin')
    
    # Query de base
    query = Log.query
    
    # Appliquer les filtres
    if user_filter:
        query = query.filter(Log.utilisateur_id == user_filter)
    
    if action_filter:
        query = query.filter(Log.action.like(f'%{action_filter}%'))
    
    if date_debut:
        try:
            date_debut_obj = datetime.strptime(date_debut, '%Y-%m-%d')
            query = query.filter(Log.date >= date_debut_obj)
        except:
            pass
    
    if date_fin:
        try:
            date_fin_obj = datetime.strptime(date_fin, '%Y-%m-%d')
            # Ajouter 1 jour pour inclure toute la journée
            date_fin_obj = date_fin_obj + timedelta(days=1)
            query = query.filter(Log.date < date_fin_obj)
        except:
            pass
    
    # Trier par date décroissante et limiter à 1000 derniers
    logs_list = query.order_by(Log.date.desc()).limit(1000).all()
    
    # Liste des utilisateurs pour le filtre
    utilisateurs = Utilisateur.query.order_by(Utilisateur.username).all()
    
    # Types d'actions uniques
    actions_types = db.session.query(Log.action).distinct().all()
    actions_types = [a[0] for a in actions_types]
    
    return render_template('logs.html',
                           logs=logs_list,
                           utilisateurs=utilisateurs,
                           actions_types=actions_types,
                           user_filter=user_filter,
                           action_filter=action_filter,
                           date_debut=date_debut,
                           date_fin=date_fin,
                           entreprise=VOTRE_ENTREPRISE)

# ============================================================================
# ROUTES API EXISTANTES
# ============================================================================

@app.route('/api/factures/<int:facture_id>/envoyer-email', methods=['POST'])
@login_required
def api_envoyer_facture_email(facture_id):
    """API: Envoyer une facture par email au client/employé"""
    try:
        facture = Facture.query.get(facture_id)
        if not facture:
            return jsonify({'error': 'Facture introuvable'}), 404
        
        # Vérifier que le PDF existe
        pdf_path = facture.fichier_pdf  # ✅ CORRECTION: fichier_pdf au lieu de chemin_pdf
        if not pdf_path or not os.path.exists(pdf_path):
            return jsonify({'error': 'Le fichier PDF de la facture est introuvable. Veuillez régénérer la facture.'}), 404
        
        # Envoyer l'email
        success, message = send_facture_email(facture, pdf_path)
        
        if success:
            # Créer un log
            destinataire = facture.client.email if facture.type_facture == 'client' else facture.employe.email
            creer_log('envoi_facture_email',
                     {'numero_facture': facture.numero, 'destinataire': destinataire},  # ✅ CORRECTION: numero au lieu de numero_facture
                     current_user)
            
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400
            
    except Exception as e:
        app.logger.error(f"Erreur envoi email facture: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================

@app.route('/api/calculer-totals', methods=['POST'])
def calculer_totals():
    """Calcule les totaux en temps réel"""
    try:
        articles = request.json.get('articles', [])
        
        total_ht = 0
        for article in articles:
            if article.get('description', '').strip():
                quantite = float(article.get('quantite', 0)) if article.get('quantite') else 0
                prix_ht = float(article.get('prix_ht', 0)) if article.get('prix_ht') else 0
                total_ht += quantite * prix_ht
        
        total_tva = total_ht * (TAUX_TVA / 100)
        total_ttc = total_ht + total_tva
        
        return jsonify({
            'total_ht': f"{total_ht:.2f}",
            'total_tva': f"{total_tva:.2f}",
            'total_ttc': f"{total_ttc:.2f}",
            'taux_tva': TAUX_TVA
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/numero-auto/<type_facture>')
def get_numero_auto(type_facture):
    """Retourne un nouveau numéro de facture automatique"""
    return jsonify({'numero_facture': generer_numero_facture(type_facture)})

@app.route('/api/factures', methods=['GET'])
def api_get_factures():
    """Récupérer toutes les factures avec filtres optionnels"""
    try:
        type_facture = request.args.get('type')  # client ou employe
        statut_paiement = request.args.get('statut_paiement')  # payee, impayee, etc.
        
        query = Facture.query
        
        if type_facture:
            query = query.filter_by(type_facture=type_facture)
        
        if statut_paiement:
            query = query.filter_by(statut_paiement=statut_paiement)
        
        factures = query.order_by(Facture.date_facture.desc()).all()
        
        # ✅ AJOUT DEBUG : Tester la conversion
        result = []
        for f in factures:
            try:
                result.append(f.to_dict())
            except Exception as e:
                app.logger.error(f"Erreur conversion facture {f.id}: {e}")
                print(f"❌ ERREUR FACTURE {f.id}: {e}")
                # Continuer avec les autres factures
                continue
        
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Erreur API factures: {e}")
        print(f"❌ ERREUR API: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES API POUR LES CLIENTS
# ============================================================================

@app.route('/api/clients', methods=['GET', 'POST'])
def api_clients():
    """API pour gérer les clients"""
    if request.method == 'POST':
        try:
            data = request.json
            
            # Vérifier si le nom est fourni
            if not data.get('nom'):
                return jsonify({'error': 'Le nom du client est obligatoire'}), 400
            
            # Vérifier si un client avec le même SIRET existe déjà
            if data.get('siret'):
                existing = Client.query.filter_by(siret=data['siret']).first()
                if existing:
                    return jsonify({'error': 'Un client avec ce SIRET existe déjà'}), 400
            
            # Créer le client
            client = Client(
                nom=data['nom'],
                adresse=data.get('adresse', ''),
                ville=data.get('ville', ''),
                email=data.get('email', ''),
                telephone=data.get('telephone', ''),
                siret=data.get('siret', '')
            )
            
            db.session.add(client)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Client créé avec succès',
                'client': client.to_dict()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    # GET - Retourner tous les clients
    clients_list = Client.query.order_by(Client.nom).all()
    return jsonify([c.to_dict() for c in clients_list])

@app.route('/api/clients/<int:client_id>', methods=['GET', 'PUT', 'DELETE'])
def api_client_detail(client_id):
    """API pour un client spécifique"""
    client = Client.query.get_or_404(client_id)
    
    if request.method == 'GET':
        return jsonify(client.to_dict())
    
    elif request.method == 'PUT':
        try:
            data = request.json
            
            if not data.get('nom'):
                return jsonify({'error': 'Le nom du client est obligatoire'}), 400
            
            # Vérifier si le SIRET est unique (sauf pour ce client)
            if data.get('siret') and data['siret'] != client.siret:
                existing = Client.query.filter_by(siret=data['siret']).first()
                if existing:
                    return jsonify({'error': 'Un client avec ce SIRET existe déjà'}), 400
            
            # Mettre à jour le client
            client.nom = data.get('nom', client.nom)
            client.adresse = data.get('adresse', client.adresse)
            client.ville = data.get('ville', client.ville)
            client.email = data.get('email', client.email)
            client.telephone = data.get('telephone', client.telephone)
            client.siret = data.get('siret', client.siret)
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Client mis à jour avec succès',
                'client': client.to_dict()
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            # Récupérer les factures associées
            factures = Facture.query.filter_by(client_id=client.id).all()
            nb_factures = len(factures)
            
            # ✅ SUPPRIMER TOUTES LES FACTURES ASSOCIÉES
            for facture in factures:
                # Supprimer le fichier PDF si il existe
                if facture.fichier_pdf and os.path.exists(facture.fichier_pdf):
                    try:
                        os.remove(facture.fichier_pdf)
                    except:
                        pass
                
                # Supprimer les amendes liées à cette facture
                Amende.query.filter_by(facture_id=facture.id).delete()
                
                # Supprimer la facture
                db.session.delete(facture)
            
            nom_client = client.nom
            db.session.delete(client)
            db.session.commit()
            
            app.logger.info(f"✅ Client {nom_client} supprimé avec {nb_factures} factures")
            
            return jsonify({
                'success': True,
                'message': f'Client supprimé avec succès (avec {nb_factures} facture(s))'
            })
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur suppression client: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/clients/<int:client_id>/infos-suppression', methods=['GET'])
def api_client_infos_suppression(client_id):
    """Obtenir les informations détaillées avant suppression d'un client"""
    client = Client.query.get_or_404(client_id)
    
    # Compter les factures associées
    factures = Facture.query.filter_by(client_id=client.id).all()
    nb_factures = len(factures)
    
    # Calculer le total des factures
    total_factures = sum(f.total_net for f in factures)
    
    return jsonify({
        'client': client.to_dict(),
        'nb_factures': nb_factures,
        'total_factures': total_factures,
        'has_data': nb_factures > 0
    })
        
@app.route('/api/clients/<int:client_id>/factures-count', methods=['GET'])
def compter_factures_client(client_id):
    """Compter le nombre de factures d'un client"""
    try:
        count = Facture.query.filter_by(client_id=client_id).count()
        return jsonify({'count': count, 'client_id': client_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES POUR LA GESTION DES PAIEMENTS
# ============================================================================

@app.route('/api/factures/<int:facture_id>/paiement', methods=['PUT'])
def marquer_facture_payee(facture_id):
    """Marquer une facture comme payée ou mettre à jour son statut de paiement"""
    try:
        facture = Facture.query.get_or_404(facture_id)
        data = request.json
        
        # Mettre à jour le statut de paiement
        statut = data.get('statut_paiement', 'payee')
        facture.statut_paiement = statut
        
        # Si marquée comme payée
        if statut == 'payee':
            facture.date_paiement = datetime.now().date()
            facture.methode_paiement = data.get('methode_paiement', 'virement')
            facture.montant_paye = facture.total_net
        
        # Si paiement partiel
        elif statut == 'partielle':
            facture.montant_paye = float(data.get('montant_paye', 0))
            facture.date_paiement = datetime.now().date()
            facture.methode_paiement = data.get('methode_paiement', 'virement')
        
        # Si impayée ou en retard
        else:
            facture.montant_paye = 0
            facture.date_paiement = None
            facture.methode_paiement = None
        
        db.session.commit()
        
        app.logger.info(f"✅ Facture {facture.numero} marquée comme {statut}")
        
        return jsonify({
            'success': True,
            'message': f'Facture {facture.numero} mise à jour',
            'facture': facture.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur mise à jour paiement: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/factures/statistiques-paiements', methods=['GET'])
def statistiques_paiements():
    """Obtenir les statistiques de paiement"""
    try:
        # Toutes les factures
        toutes_factures = Facture.query.all()
        
        # Compter par statut
        nb_payees = sum(1 for f in toutes_factures if f.statut_paiement == 'payee')
        nb_impayees = sum(1 for f in toutes_factures if f.statut_paiement == 'impayee')
        nb_en_retard = sum(1 for f in toutes_factures if f.statut_paiement == 'en_retard')
        nb_partielles = sum(1 for f in toutes_factures if f.statut_paiement == 'partielle')
        
        # Montants
        total_paye = sum(f.montant_paye for f in toutes_factures)
        total_a_payer = sum(f.total_net - f.montant_paye for f in toutes_factures)
        total_factures = sum(f.total_net for f in toutes_factures)
        
        return jsonify({
            'nb_factures': len(toutes_factures),
            'nb_payees': nb_payees,
            'nb_impayees': nb_impayees,
            'nb_en_retard': nb_en_retard,
            'nb_partielles': nb_partielles,
            'total_paye': total_paye,
            'total_a_payer': total_a_payer,
            'total_factures': total_factures,
            'taux_paiement': (total_paye / total_factures * 100) if total_factures > 0 else 0
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/factures/en-retard', methods=['GET'])
def factures_en_retard():
    """Obtenir les factures en retard (impayées + plus de 30 jours)"""
    try:
        date_limite = datetime.now().date() - timedelta(days=30)
        
        factures = Facture.query.filter(
            Facture.statut_paiement.in_(['impayee', 'partielle']),
            Facture.date_facture <= date_limite
        ).order_by(Facture.date_facture.asc()).all()
        
        # Marquer automatiquement comme en retard
        for facture in factures:
            if facture.statut_paiement != 'en_retard':
                facture.statut_paiement = 'en_retard'
        
        db.session.commit()
        
        return jsonify([f.to_dict() for f in factures])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# INITIALISATION
# ============================================================================
 
with app.app_context():
    db.create_all()
    
    # Créer les dossiers nécessaires
    os.makedirs('factures', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Créer votre entreprise comme client si elle n'existe pas
    votre_entreprise_client = Client.query.filter_by(nom=VOTRE_ENTREPRISE['nom']).first()
    if not votre_entreprise_client:
        votre_entreprise_client = Client(
            nom=VOTRE_ENTREPRISE['nom'],
            adresse=VOTRE_ENTREPRISE['adresse'],
            ville=VOTRE_ENTREPRISE['ville'],
            email=VOTRE_ENTREPRISE['email'],
            telephone=VOTRE_ENTREPRISE['telephone'],
            siret=VOTRE_ENTREPRISE['siret']
        )
        db.session.add(votre_entreprise_client)
        db.session.commit()

        # ============================================================================
# ROUTES DE SUPPRESSION - À AJOUTER DANS app.py
# ============================================================================

@app.route('/api/factures/<int:facture_id>', methods=['DELETE'])
def supprimer_facture(facture_id):
    """Supprimer une facture"""
    try:
        facture = Facture.query.get_or_404(facture_id)
        
        # Supprimer le fichier PDF si il existe
        if facture.fichier_pdf and os.path.exists(facture.fichier_pdf):
            try:
                os.remove(facture.fichier_pdf)
                app.logger.info(f"Fichier PDF supprimé: {facture.fichier_pdf}")
            except Exception as e:
                app.logger.warning(f"Impossible de supprimer le PDF: {e}")
        
        # Si c'est une facture employé, remettre les amendes en attente
        if facture.type_facture == 'employe':
            amendes = Amende.query.filter_by(facture_id=facture.id).all()
            for amende in amendes:
                amende.facture_id = None
                amende.statut = 'en_attente'
        
        # Supprimer la facture
        db.session.delete(facture)
        db.session.commit()
        
        app.logger.info(f"✅ Facture {facture.numero} supprimée")
        
        return jsonify({
            'success': True,
            'message': f'Facture {facture.numero} supprimée avec succès'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur suppression facture: {e}")
        return jsonify({'error': str(e)}), 500
    
    # ============================================================================
# ROUTES POUR LA GESTION DES LIVRAISONS
# ============================================================================

@app.route('/saisie-journaliere')
def saisie_journaliere():
    """Page de saisie des livraisons journalières"""
    employes = Employe.query.filter_by(actif=True).order_by(Employe.nom).all()
    return render_template('saisie_journaliere.html',
                         entreprise=VOTRE_ENTREPRISE,
                         employes=employes)

@app.route('/api/livraisons', methods=['GET', 'POST'])
def api_livraisons():
    """API pour gérer les livraisons"""
    if request.method == 'POST':
        try:
            data = request.json
            
            # Validation
            if not data.get('employe_id'):
                return jsonify({'error': 'Employé obligatoire'}), 400
            
            if not data.get('date_livraison'):
                return jsonify({'error': 'Date obligatoire'}), 400
            
            # Créer la livraison
            livraison = Livraison(
                employe_id=int(data['employe_id']),
                date_livraison=datetime.strptime(data['date_livraison'], "%Y-%m-%d").date(),
                nombre_journaux=int(data.get('nombre_journaux', 0)),
                montant_jour=float(data.get('montant_jour', 0)),
                notes=data.get('notes', '')
            )
            
            db.session.add(livraison)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Livraison enregistrée',
                'livraison': livraison.to_dict()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    # GET - Récupérer les livraisons
    employe_id = request.args.get('employe_id')
    mois = request.args.get('mois')  # Format: YYYY-MM
    
    query = Livraison.query
    
    if employe_id:
        query = query.filter_by(employe_id=int(employe_id))
    
    if mois:
        annee, mois_num = mois.split('-')
        debut_mois = date(int(annee), int(mois_num), 1)
        if int(mois_num) == 12:
            fin_mois = date(int(annee) + 1, 1, 1) - timedelta(days=1)
        else:
            fin_mois = date(int(annee), int(mois_num) + 1, 1) - timedelta(days=1)
        
        query = query.filter(
            Livraison.date_livraison >= debut_mois,
            Livraison.date_livraison <= fin_mois
        )
    
    livraisons = query.order_by(Livraison.date_livraison.desc()).all()
    return jsonify([l.to_dict() for l in livraisons])

@app.route('/api/livraisons/<int:livraison_id>', methods=['PUT', 'DELETE'])
def api_livraison_detail(livraison_id):
    """Modifier ou supprimer une livraison"""
    livraison = Livraison.query.get_or_404(livraison_id)
    
    if request.method == 'PUT':
        try:
            data = request.json
            
            livraison.nombre_journaux = int(data.get('nombre_journaux', livraison.nombre_journaux))
            livraison.montant_jour = float(data.get('montant_jour', livraison.montant_jour))
            livraison.notes = data.get('notes', livraison.notes)
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Livraison mise à jour',
                'livraison': livraison.to_dict()
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            db.session.delete(livraison)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Livraison supprimée'
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

@app.route('/api/inventaire-mensuel/<int:employe_id>/<mois>')
def api_inventaire_mensuel(employe_id, mois):
    """Calculer l'inventaire mensuel d'un employé"""
    try:
        employe = Employe.query.get_or_404(employe_id)
        
        # Récupérer les livraisons du mois
        annee, mois_num = mois.split('-')
        debut_mois = date(int(annee), int(mois_num), 1)
        if int(mois_num) == 12:
            fin_mois = date(int(annee) + 1, 1, 1) - timedelta(days=1)
        else:
            fin_mois = date(int(annee), int(mois_num) + 1, 1) - timedelta(days=1)
        
        livraisons = Livraison.query.filter(
            Livraison.employe_id == employe_id,
            Livraison.date_livraison >= debut_mois,
            Livraison.date_livraison <= fin_mois
        ).order_by(Livraison.date_livraison).all()
        
        # Calculer les totaux
        total_journaux = sum(l.nombre_journaux for l in livraisons)
        total_montant = sum(l.montant_jour for l in livraisons)
        
        # Récupérer les amendes du mois
        amendes = Amende.query.filter(
            Amende.employe_id == employe_id,
            Amende.date_amende >= debut_mois,
            Amende.date_amende <= fin_mois,
            Amende.statut == 'en_attente'
        ).all()
        
        total_amendes = sum(a.montant for a in amendes)
        
        return jsonify({
            'employe': employe.to_dict(),
            'periode': {
                'debut': debut_mois.strftime('%d/%m/%Y'),
                'fin': fin_mois.strftime('%d/%m/%Y'),
                'mois': mois
            },
            'livraisons': [l.to_dict() for l in livraisons],
            'jours_travailles': len(livraisons),
            'total_journaux': total_journaux,
            'total_brut': total_montant,
            'amendes': [a.to_dict() for a in amendes],
            'total_amendes': total_amendes,
            'net_a_payer': total_montant - total_amendes
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES POUR LE TABLEAU DE BORD / DASHBOARD
# ============================================================================

@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """Obtenir toutes les statistiques pour le tableau de bord"""
    try:
        # Statistiques générales
        total_factures = Facture.query.count()
        total_clients = Client.query.count()
        total_employes = Employe.query.count()
        
        # Statistiques de paiement
        factures = Facture.query.all()
        total_ca = sum(f.total_net for f in factures)
        total_paye = sum(f.montant_paye for f in factures)
        total_impaye = total_ca - total_paye
        
        nb_payees = sum(1 for f in factures if f.statut_paiement == 'payee')
        nb_impayees = sum(1 for f in factures if f.statut_paiement in ['impayee', 'en_retard'])
        nb_partielles = sum(1 for f in factures if f.statut_paiement == 'partielle')
        
        taux_paiement = (total_paye / total_ca * 100) if total_ca > 0 else 0
        
        # Évolution des revenus par mois (12 derniers mois)
        revenus_par_mois = {}
        today = datetime.now()
        
        for i in range(12):
            mois = (today.month - i - 1) % 12 + 1
            annee = today.year if today.month - i > 0 else today.year - 1
            
            debut_mois = date(annee, mois, 1)
            if mois == 12:
                fin_mois = date(annee + 1, 1, 1)
            else:
                fin_mois = date(annee, mois + 1, 1)
            
            factures_mois = Facture.query.filter(
                Facture.date_facture >= debut_mois,
                Facture.date_facture < fin_mois
            ).all()
            
            total_mois = sum(f.total_net for f in factures_mois)
            mois_nom = debut_mois.strftime('%b %Y')
            
            revenus_par_mois[mois_nom] = total_mois
        
        # Inverser pour avoir du plus ancien au plus récent
        revenus_par_mois = dict(reversed(list(revenus_par_mois.items())))
        
        # Top 5 clients par CA
        clients_stats = {}
        for client in Client.query.all():
            factures_client = Facture.query.filter_by(client_id=client.id).all()
            total_client = sum(f.total_net for f in factures_client)
            if total_client > 0:
                clients_stats[client.nom] = total_client
        
        top_clients = dict(sorted(clients_stats.items(), key=lambda x: x[1], reverse=True)[:5])
        
        # Performance des employés
        employes_stats = []
        for employe in Employe.query.all():
            factures_emp = Facture.query.filter_by(employe_id=employe.id).all()
            nb_factures = len(factures_emp)
            total_factures = sum(f.total_net for f in factures_emp)
            
            amendes = Amende.query.filter_by(employe_id=employe.id).all()
            nb_amendes = len(amendes)
            total_amendes = sum(a.montant for a in amendes)
            
            if nb_factures > 0 or nb_amendes > 0:
                employes_stats.append({
                    'nom': employe.nom_complet(),
                    'factures': nb_factures,
                    'total_factures': total_factures,
                    'amendes': nb_amendes,
                    'total_amendes': total_amendes
                })
        
        # Trier par nombre de factures
        employes_stats = sorted(employes_stats, key=lambda x: x['factures'], reverse=True)[:5]
        
        return jsonify({
            'general': {
                'total_factures': total_factures,
                'total_clients': total_clients,
                'total_employes': total_employes,
                'total_ca': total_ca,
                'total_paye': total_paye,
                'total_impaye': total_impaye,
                'taux_paiement': taux_paiement
            },
            'paiements': {
                'payees': nb_payees,
                'impayees': nb_impayees,
                'partielles': nb_partielles
            },
            'revenus_par_mois': revenus_par_mois,
            'top_clients': top_clients,
            'employes_stats': employes_stats
        })
        
    except Exception as e:
        app.logger.error(f"Erreur stats dashboard: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES POUR LES EXPORTS EXCEL/CSV
# ============================================================================

@app.route('/api/export/factures/excel', methods=['GET'])
def export_factures_excel():
    """Exporter toutes les factures en Excel"""
    try:
        # Récupérer les paramètres de période optionnels
        date_debut = request.args.get('date_debut')
        date_fin = request.args.get('date_fin')
        
        query = Facture.query
        
        if date_debut:
            query = query.filter(Facture.date_facture >= datetime.strptime(date_debut, '%Y-%m-%d').date())
        if date_fin:
            query = query.filter(Facture.date_facture <= datetime.strptime(date_fin, '%Y-%m-%d').date())
        
        factures = query.order_by(Facture.date_facture.desc()).all()
        
        # Créer un classeur Excel
        wb = Workbook()
        ws = wb.active
        ws.title = "Factures"
        
        # Style pour l'en-tête
        header_fill = PatternFill(start_color="3498DB", end_color="3498DB", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True, size=12)
        header_alignment = Alignment(horizontal="center", vertical="center")
        
        # En-têtes
        headers = [
            'N° Facture', 'Type', 'Date', 'Client/Employé', 
            'Total Brut', 'Amendes', 'Total Net', 
            'Statut Paiement', 'Date Paiement', 'Méthode Paiement',
            'Montant Payé', 'Reste à Payer'
        ]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = header_alignment
        
        # Données
        for row, facture in enumerate(factures, 2):
            destinataire = facture.client.nom if facture.type_facture == 'client' else facture.employe.nom_complet()
            
            statut_labels = {
                'payee': '✅ Payée',
                'impayee': '❌ Impayée',
                'en_retard': '⚠️ En retard',
                'partielle': '🟡 Partielle'
            }
            statut = statut_labels.get(facture.statut_paiement, facture.statut_paiement)
            
            ws.cell(row=row, column=1, value=facture.numero)
            ws.cell(row=row, column=2, value=facture.type_facture.capitalize())
            ws.cell(row=row, column=3, value=facture.date_facture.strftime('%d/%m/%Y'))
            ws.cell(row=row, column=4, value=destinataire)
            ws.cell(row=row, column=5, value=facture.total_brut)
            ws.cell(row=row, column=6, value=facture.total_amendes)
            ws.cell(row=row, column=7, value=facture.total_net)
            ws.cell(row=row, column=8, value=statut)
            ws.cell(row=row, column=9, value=facture.date_paiement.strftime('%d/%m/%Y') if facture.date_paiement else '')
            ws.cell(row=row, column=10, value=facture.methode_paiement or '')
            ws.cell(row=row, column=11, value=facture.montant_paye)
            ws.cell(row=row, column=12, value=facture.total_net - facture.montant_paye)
        
        # Ajuster la largeur des colonnes
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[chr(64 + col)].width = 15
        
        # Ajouter une ligne de totaux
        total_row = len(factures) + 2
        ws.cell(row=total_row, column=4, value="TOTAL").font = Font(bold=True)
        ws.cell(row=total_row, column=5, value=sum(f.total_brut for f in factures)).font = Font(bold=True)
        ws.cell(row=total_row, column=6, value=sum(f.total_amendes for f in factures)).font = Font(bold=True)
        ws.cell(row=total_row, column=7, value=sum(f.total_net for f in factures)).font = Font(bold=True)
        ws.cell(row=total_row, column=11, value=sum(f.montant_paye for f in factures)).font = Font(bold=True)
        ws.cell(row=total_row, column=12, value=sum(f.total_net - f.montant_paye for f in factures)).font = Font(bold=True)
        
        # Sauvegarder dans un buffer
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        filename = f"factures_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Erreur export Excel: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/factures/csv', methods=['GET'])
def export_factures_csv():
    """Exporter toutes les factures en CSV"""
    try:
        date_debut = request.args.get('date_debut')
        date_fin = request.args.get('date_fin')
        
        query = Facture.query
        
        if date_debut:
            query = query.filter(Facture.date_facture >= datetime.strptime(date_debut, '%Y-%m-%d').date())
        if date_fin:
            query = query.filter(Facture.date_facture <= datetime.strptime(date_fin, '%Y-%m-%d').date())
        
        factures = query.order_by(Facture.date_facture.desc()).all()
        
        # Créer le CSV
        output = StringIO()
        writer = csv.writer(output, delimiter=';')
        
        # En-têtes
        writer.writerow([
            'Numero', 'Type', 'Date', 'Client_Employe',
            'Total_Brut', 'Amendes', 'Total_Net',
            'Statut_Paiement', 'Date_Paiement', 'Methode_Paiement',
            'Montant_Paye', 'Reste_A_Payer'
        ])
        
        # Données
        for facture in factures:
            destinataire = facture.client.nom if facture.type_facture == 'client' else facture.employe.nom_complet()
            
            writer.writerow([
                facture.numero,
                facture.type_facture,
                facture.date_facture.strftime('%d/%m/%Y'),
                destinataire,
                facture.total_brut,
                facture.total_amendes,
                facture.total_net,
                facture.statut_paiement,
                facture.date_paiement.strftime('%d/%m/%Y') if facture.date_paiement else '',
                facture.methode_paiement or '',
                facture.montant_paye,
                facture.total_net - facture.montant_paye
            ])
        
        output.seek(0)
        filename = f"factures_{datetime.now().strftime('%Y-%m-%d')}.csv"
        
        return send_file(
            BytesIO(output.getvalue().encode('utf-8-sig')),  # UTF-8 with BOM pour Excel
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Erreur export CSV: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/clients/excel', methods=['GET'])
def export_clients_excel():
    """Exporter tous les clients avec statistiques"""
    try:
        clients = Client.query.order_by(Client.nom).all()
        
        wb = Workbook()
        ws = wb.active
        ws.title = "Clients"
        
        # Style en-tête
        header_fill = PatternFill(start_color="2ecc71", end_color="2ecc71", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        
        # En-têtes
        headers = ['Nom', 'Adresse', 'Ville', 'Email', 'Téléphone', 'SIRET', 'Nb Factures', 'CA Total', 'CA Payé', 'CA Impayé']
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.fill = header_fill
            cell.font = header_font
        
        # Données
        for row, client in enumerate(clients, 2):
            factures_client = Facture.query.filter_by(client_id=client.id).all()
            nb_factures = len(factures_client)
            ca_total = sum(f.total_net for f in factures_client)
            ca_paye = sum(f.montant_paye for f in factures_client)
            ca_impaye = ca_total - ca_paye
            
            ws.cell(row=row, column=1, value=client.nom)
            ws.cell(row=row, column=2, value=client.adresse)
            ws.cell(row=row, column=3, value=client.ville)
            ws.cell(row=row, column=4, value=client.email)
            ws.cell(row=row, column=5, value=client.telephone)
            ws.cell(row=row, column=6, value=client.siret)
            ws.cell(row=row, column=7, value=nb_factures)
            ws.cell(row=row, column=8, value=ca_total)
            ws.cell(row=row, column=9, value=ca_paye)
            ws.cell(row=row, column=10, value=ca_impaye)
        
        # Ajuster colonnes
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[chr(64 + col)].width = 18
        
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        filename = f"clients_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/employes/excel', methods=['GET'])
def export_employes_excel():
    """Exporter tous les employés avec amendes"""
    try:
        employes = Employe.query.order_by(Employe.nom).all()
        
        wb = Workbook()
        ws = wb.active
        ws.title = "Employés"
        
        # Style en-tête
        header_fill = PatternFill(start_color="9b59b6", end_color="9b59b6", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        
        # En-têtes
        headers = ['Matricule', 'Nom', 'Prénom', 'Téléphone', 'Email', 'Actif', 'Nb Bulletins', 'Total Brut', 'Nb Amendes', 'Total Amendes']
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.fill = header_fill
            cell.font = header_font
        
        # Données
        for row, employe in enumerate(employes, 2):
            factures_emp = Facture.query.filter_by(employe_id=employe.id).all()
            amendes_emp = Amende.query.filter_by(employe_id=employe.id).all()
            
            nb_bulletins = len(factures_emp)
            total_brut = sum(f.total_brut for f in factures_emp)
            nb_amendes = len(amendes_emp)
            total_amendes = sum(a.montant for a in amendes_emp)
            
            ws.cell(row=row, column=1, value=employe.matricule)
            ws.cell(row=row, column=2, value=employe.nom)
            ws.cell(row=row, column=3, value=employe.prenom)
            ws.cell(row=row, column=4, value=employe.telephone)
            ws.cell(row=row, column=5, value=employe.email)
            ws.cell(row=row, column=6, value='Oui' if employe.actif else 'Non')
            ws.cell(row=row, column=7, value=nb_bulletins)
            ws.cell(row=row, column=8, value=total_brut)
            ws.cell(row=row, column=9, value=nb_amendes)
            ws.cell(row=row, column=10, value=total_amendes)
        
        # Ajuster colonnes
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[chr(64 + col)].width = 16
        
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        
        filename = f"employes_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES POUR LE CALENDRIER / PLANNING
# ============================================================================

@app.route('/api/calendrier/mois', methods=['GET'])
def calendrier_mois():
    """Obtenir tous les événements d'un mois pour le calendrier"""
    try:
        annee = int(request.args.get('annee', datetime.now().year))
        mois = int(request.args.get('mois', datetime.now().month))
        
        # Dates du mois
        premier_jour = date(annee, mois, 1)
        if mois == 12:
            dernier_jour = date(annee + 1, 1, 1) - timedelta(days=1)
        else:
            dernier_jour = date(annee, mois + 1, 1) - timedelta(days=1)
        
        evenements = []
        
        # Livraisons du mois
        livraisons = Livraison.query.filter(
            Livraison.date_livraison >= premier_jour,
            Livraison.date_livraison <= dernier_jour
        ).all()
        
        for livraison in livraisons:
            evenements.append({
                'type': 'livraison',
                'date': livraison.date_livraison.strftime('%Y-%m-%d'),
                'employe': livraison.employe.nom_complet(),
                'employe_id': livraison.employe_id,
                'journaux': livraison.nombre_journaux,
                'montant': livraison.montant,
                'titre': f"{livraison.employe.nom_complet()} - {livraison.nombre_journaux} journaux"
            })
        
        # Factures du mois (dates d'échéance)
        factures = Facture.query.filter(
            Facture.date_facture >= premier_jour,
            Facture.date_facture <= dernier_jour
        ).all()
        
        for facture in factures:
            evenements.append({
                'type': 'facture',
                'date': facture.date_facture.strftime('%Y-%m-%d'),
                'numero': facture.numero,
                'destinataire': facture.client.nom if facture.type_facture == 'client' else facture.employe.nom_complet(),
                'montant': facture.total_net,
                'statut': facture.statut_paiement,
                'titre': f"{facture.numero} - {facture.total_net:.0f}€"
            })
        
        # Amendes du mois
        amendes = Amende.query.filter(
            Amende.date_amende >= premier_jour,
            Amende.date_amende <= dernier_jour
        ).all()
        
        for amende in amendes:
            evenements.append({
                'type': 'amende',
                'date': amende.date_amende.strftime('%Y-%m-%d'),
                'employe': amende.employe.nom_complet(),
                'employe_id': amende.employe_id,
                'motif': amende.motif,
                'montant': amende.montant,
                'titre': f"Amende - {amende.employe.nom_complet()}"
            })
        
        # Statistiques du mois
        stats = {
            'total_livraisons': len(livraisons),
            'total_journaux': sum(l.nombre_journaux for l in livraisons),
            'total_factures': len(factures),
            'total_ca': sum(f.total_net for f in factures),
            'total_amendes': sum(a.montant for a in amendes)
        }
        
        return jsonify({
            'evenements': evenements,
            'stats': stats,
            'mois': mois,
            'annee': annee
        })
        
    except Exception as e:
        app.logger.error(f"Erreur calendrier: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/calendrier/jour', methods=['GET'])
def calendrier_jour():
    """Obtenir les détails d'un jour spécifique"""
    try:
        date_str = request.args.get('date')  # Format: YYYY-MM-DD
        jour = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        # Livraisons du jour
        livraisons = Livraison.query.filter_by(date_livraison=jour).all()
        
        # Factures du jour
        factures = Facture.query.filter_by(date_facture=jour).all()
        
        # Amendes du jour
        amendes = Amende.query.filter_by(date_amende=jour).all()
        
        details = {
            'date': date_str,
            'livraisons': [{
                'employe': l.employe.nom_complet(),
                'journaux': l.nombre_journaux,
                'montant': l.montant
            } for l in livraisons],
            'factures': [{
                'numero': f.numero,
                'type': f.type_facture,
                'destinataire': f.client.nom if f.type_facture == 'client' else f.employe.nom_complet(),
                'montant': f.total_net,
                'statut': f.statut_paiement
            } for f in factures],
            'amendes': [{
                'employe': a.employe.nom_complet(),
                'motif': a.motif,
                'montant': a.montant
            } for a in amendes],
            'totaux': {
                'livraisons': len(livraisons),
                'journaux': sum(l.nombre_journaux for l in livraisons),
                'factures': len(factures),
                'ca': sum(f.total_net for f in factures),
                'amendes': sum(a.montant for a in amendes)
            }
        }
        
        return jsonify(details)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/calendrier/employe', methods=['GET'])
def calendrier_employe():
    """Planning d'un employé pour un mois"""
    try:
        employe_id = int(request.args.get('employe_id'))
        annee = int(request.args.get('annee', datetime.now().year))
        mois = int(request.args.get('mois', datetime.now().month))
        
        # Dates du mois
        premier_jour = date(annee, mois, 1)
        if mois == 12:
            dernier_jour = date(annee + 1, 1, 1) - timedelta(days=1)
        else:
            dernier_jour = date(annee, mois + 1, 1) - timedelta(days=1)
        
        employe = Employe.query.get(employe_id)
        if not employe:
            return jsonify({'error': 'Employé introuvable'}), 404
        
        # Livraisons
        livraisons = Livraison.query.filter(
            Livraison.employe_id == employe_id,
            Livraison.date_livraison >= premier_jour,
            Livraison.date_livraison <= dernier_jour
        ).all()
        
        # Amendes
        amendes = Amende.query.filter(
            Amende.employe_id == employe_id,
            Amende.date_amende >= premier_jour,
            Amende.date_amende <= dernier_jour
        ).all()
        
        # Jours travaillés
        jours_travailles = sorted(list(set([l.date_livraison for l in livraisons])))
        
        planning = {
            'employe': {
                'id': employe.id,
                'nom': employe.nom_complet(),
                'matricule': employe.matricule
            },
            'mois': mois,
            'annee': annee,
            'jours_travailles': [j.strftime('%Y-%m-%d') for j in jours_travailles],
            'nb_jours': len(jours_travailles),
            'livraisons': [{
                'date': l.date_livraison.strftime('%Y-%m-%d'),
                'journaux': l.nombre_journaux,
                'montant': l.montant
            } for l in livraisons],
            'amendes': [{
                'date': a.date_amende.strftime('%Y-%m-%d'),
                'motif': a.motif,
                'montant': a.montant
            } for a in amendes],
            'totaux': {
                'livraisons': len(livraisons),
                'journaux': sum(l.nombre_journaux for l in livraisons),
                'brut': sum(l.montant for l in livraisons),
                'amendes': sum(a.montant for a in amendes),
                'net': sum(l.montant for l in livraisons) - sum(a.montant for a in amendes)
            }
        }
        
        return jsonify(planning)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES POUR LA RECHERCHE AVANCÉE
# ============================================================================

@app.route('/recherche')
@comptable_ou_admin_required
def recherche():
    """Page de recherche avancée"""
    return render_template('recherche.html',
                           entreprise=VOTRE_ENTREPRISE)

@app.route('/api/recherche/globale', methods=['GET'])
def recherche_globale():
    """Recherche globale dans toutes les entités"""
    try:
        query = request.args.get('q', '').lower()
        
        if not query or len(query) < 2:
            return jsonify({'error': 'Requête trop courte (minimum 2 caractères)'}), 400
        
        resultats = {
            'factures': [],
            'clients': [],
            'employes': []
        }
        
        # Recherche dans les factures
        factures = Facture.query.all()
        for facture in factures:
            if (query in facture.numero.lower() or 
                query in facture.client.nom.lower() or
                (facture.employe and query in facture.employe.nom_complet().lower())):
                resultats['factures'].append({
                    'id': facture.id,
                    'numero': facture.numero,
                    'type': facture.type_facture,
                    'date': facture.date_facture.strftime('%d/%m/%Y'),
                    'destinataire': facture.client.nom if facture.type_facture == 'client' else facture.employe.nom_complet(),
                    'montant': facture.total_net,
                    'statut_paiement': facture.statut_paiement
                })
        
        # Recherche dans les clients
        clients = Client.query.all()
        for client in clients:
            if (query in client.nom.lower() or
                query in client.ville.lower() or
                (client.email and query in client.email.lower()) or
                (client.siret and query in client.siret)):
                
                factures_client = Facture.query.filter_by(client_id=client.id).all()
                resultats['clients'].append({
                    'id': client.id,
                    'nom': client.nom,
                    'ville': client.ville,
                    'email': client.email,
                    'telephone': client.telephone,
                    'nb_factures': len(factures_client),
                    'ca_total': sum(f.total_net for f in factures_client)
                })
        
        # Recherche dans les employés
        employes = Employe.query.all()
        for employe in employes:
            if (query in employe.nom.lower() or
                query in employe.prenom.lower() or
                query in employe.matricule.lower() or
                (employe.email and query in employe.email.lower())):
                
                factures_emp = Facture.query.filter_by(employe_id=employe.id).all()
                amendes_emp = Amende.query.filter_by(employe_id=employe.id).all()
                
                resultats['employes'].append({
                    'id': employe.id,
                    'matricule': employe.matricule,
                    'nom_complet': employe.nom_complet(),
                    'email': employe.email,
                    'telephone': employe.telephone,
                    'actif': employe.actif,
                    'nb_factures': len(factures_emp),
                    'nb_amendes': len(amendes_emp)
                })
        
        # Limiter les résultats
        resultats['factures'] = resultats['factures'][:20]
        resultats['clients'] = resultats['clients'][:20]
        resultats['employes'] = resultats['employes'][:20]
        
        total = len(resultats['factures']) + len(resultats['clients']) + len(resultats['employes'])
        
        return jsonify({
            'query': query,
            'total': total,
            'resultats': resultats
        })
        
    except Exception as e:
        app.logger.error(f"Erreur recherche: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recherche/factures', methods=['GET'])
def recherche_factures_avancee():
    """Recherche avancée dans les factures avec filtres multiples"""
    try:
        # Récupérer les paramètres
        query_text = request.args.get('q', '').lower()
        type_facture = request.args.get('type')
        statut_paiement = request.args.get('statut')
        date_debut = request.args.get('date_debut')
        date_fin = request.args.get('date_fin')
        montant_min = request.args.get('montant_min')
        montant_max = request.args.get('montant_max')
        
        query = Facture.query
        
        # Filtrer par type
        if type_facture and type_facture != 'all':
            query = query.filter_by(type_facture=type_facture)
        
        # Filtrer par statut paiement
        if statut_paiement and statut_paiement != 'all':
            query = query.filter_by(statut_paiement=statut_paiement)
        
        # Filtrer par période
        if date_debut:
            query = query.filter(Facture.date_facture >= datetime.strptime(date_debut, '%Y-%m-%d').date())
        if date_fin:
            query = query.filter(Facture.date_facture <= datetime.strptime(date_fin, '%Y-%m-%d').date())
        
        # Filtrer par montant
        if montant_min:
            query = query.filter(Facture.total_net >= float(montant_min))
        if montant_max:
            query = query.filter(Facture.total_net <= float(montant_max))
        
        factures = query.order_by(Facture.date_facture.desc()).all()
        
        # Filtrer par texte si présent
        if query_text:
            factures = [f for f in factures if 
                       query_text in f.numero.lower() or
                       query_text in f.client.nom.lower() or
                       (f.employe and query_text in f.employe.nom_complet().lower())]
        
        resultats = []
        for facture in factures[:50]:  # Limiter à 50 résultats
            resultats.append({
                'id': facture.id,
                'numero': facture.numero,
                'type': facture.type_facture,
                'date': facture.date_facture.strftime('%d/%m/%Y'),
                'destinataire': facture.client.nom if facture.type_facture == 'client' else facture.employe.nom_complet(),
                'montant': facture.total_net,
                'statut_paiement': facture.statut_paiement,
                'montant_paye': facture.montant_paye,
                'reste_a_payer': facture.total_net - facture.montant_paye
            })
        
        return jsonify({
            'total': len(resultats),
            'resultats': resultats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES POUR L'IMPRESSION GROUPÉE
# ============================================================================

@app.route('/api/impression/factures-zip', methods=['POST'])
def impression_factures_zip():
    """Télécharger plusieurs factures en ZIP"""
    try:
        data = request.json
        facture_ids = data.get('facture_ids', [])
        
        if not facture_ids:
            return jsonify({'error': 'Aucune facture sélectionnée'}), 400
        
        # Créer un fichier ZIP en mémoire
        zip_buffer = BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for facture_id in facture_ids:
                facture = Facture.query.get(facture_id)
                if facture and facture.fichier_pdf:
                    pdf_path = facture.fichier_pdf
                    if os.path.exists(pdf_path):
                        # Ajouter le PDF au ZIP
                        zip_file.write(pdf_path, os.path.basename(pdf_path))
        
        zip_buffer.seek(0)
        
        filename = f"factures_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.zip"
        
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Erreur création ZIP: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/impression/factures-fusion', methods=['POST'])
def impression_factures_fusion():
    """Fusionner plusieurs factures en un seul PDF"""
    try:
        data = request.json
        facture_ids = data.get('facture_ids', [])
        
        if not facture_ids:
            return jsonify({'error': 'Aucune facture sélectionnée'}), 400
        
        # Créer un merger PDF
        merger = PdfMerger()
        
        for facture_id in facture_ids:
            facture = Facture.query.get(facture_id)
            if facture and facture.fichier_pdf:
                pdf_path = facture.fichier_pdf
                if os.path.exists(pdf_path):
                    merger.append(pdf_path)
        
        # Sauvegarder dans un buffer
        output_buffer = BytesIO()
        merger.write(output_buffer)
        merger.close()
        output_buffer.seek(0)
        
        filename = f"factures_fusionnees_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.pdf"
        
        return send_file(
            output_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Erreur fusion PDF: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/impression/periode-zip', methods=['GET'])
def impression_periode_zip():
    """Télécharger toutes les factures d'une période en ZIP"""
    try:
        date_debut = request.args.get('date_debut')
        date_fin = request.args.get('date_fin')
        type_facture = request.args.get('type', 'all')
        
        if not date_debut or not date_fin:
            return jsonify({'error': 'Dates requises'}), 400
        
        query = Facture.query.filter(
            Facture.date_facture >= datetime.strptime(date_debut, '%Y-%m-%d').date(),
            Facture.date_facture <= datetime.strptime(date_fin, '%Y-%m-%d').date()
        )
        
        if type_facture != 'all':
            query = query.filter_by(type_facture=type_facture)
        
        factures = query.all()
        
        if not factures:
            return jsonify({'error': 'Aucune facture trouvée pour cette période'}), 404
        
        # Créer le ZIP
        zip_buffer = BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for facture in factures:
                if facture.fichier_pdf and os.path.exists(facture.fichier_pdf):
                    zip_file.write(facture.fichier_pdf, os.path.basename(facture.fichier_pdf))
        
        zip_buffer.seek(0)
        
        filename = f"factures_{date_debut}_au_{date_fin}.zip"
        
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/impression/bulletins-mois', methods=['POST'])
def generer_bulletins_mois():
    """Générer tous les bulletins d'un mois pour tous les employés actifs"""
    try:
        data = request.json
        mois = data.get('mois')  # Format: YYYY-MM
        
        if not mois:
            return jsonify({'error': 'Mois requis (format YYYY-MM)'}), 400
        
        annee, mois_num = map(int, mois.split('-'))
        
        # Dates du mois
        date_debut = date(annee, mois_num, 1)
        if mois_num == 12:
            date_fin = date(annee + 1, 1, 1) - timedelta(days=1)
        else:
            date_fin = date(annee, mois_num + 1, 1) - timedelta(days=1)
        
        # Récupérer les employés actifs
        employes = Employe.query.filter_by(actif=True).all()
        
        if not employes:
            return jsonify({'error': 'Aucun employé actif'}), 404
        
        bulletins_crees = []
        erreurs = []
        
        for employe in employes:
            try:
                # Vérifier si un bulletin existe déjà pour ce mois
                bulletin_existe = Facture.query.filter(
                    Facture.employe_id == employe.id,
                    Facture.date_debut >= date_debut,
                    Facture.date_debut <= date_fin
                ).first()
                
                if bulletin_existe:
                    erreurs.append(f"{employe.nom_complet()}: Bulletin déjà existant")
                    continue
                
                # Récupérer les livraisons du mois
                livraisons = Livraison.query.filter(
                    Livraison.employe_id == employe.id,
                    Livraison.date_livraison >= date_debut,
                    Livraison.date_livraison <= date_fin
                ).all()
                
                if not livraisons:
                    erreurs.append(f"{employe.nom_complet()}: Aucune livraison ce mois")
                    continue
                
                # Calculer totaux
                total_journaux = sum(l.nombre_journaux for l in livraisons)
                total_brut = sum(l.montant for l in livraisons)
                
                # Récupérer amendes du mois
                amendes = Amende.query.filter(
                    Amende.employe_id == employe.id,
                    Amende.date_amende >= date_debut,
                    Amende.date_amende <= date_fin
                ).all()
                
                total_amendes = sum(a.montant for a in amendes)
                total_net = total_brut - total_amendes
                
                # Créer la facture
                numero = generer_numero_facture('employe')
                
                nouvelle_facture = Facture(
                    numero=numero,
                    type_facture='employe',
                    date_facture=date_fin,
                    date_debut=date_debut,
                    date_fin=date_fin,
                    client_id=Client.query.filter_by(nom=VOTRE_ENTREPRISE['nom']).first().id,
                    employe_id=employe.id,
                    total_brut=total_brut,
                    total_amendes=total_amendes,
                    total_net=total_net,
                    statut='en_attente',
                    statut_paiement='impayee',
                    montant_paye=0.0
                )
                
                db.session.add(nouvelle_facture)
                db.session.flush()
                
                # Générer le PDF (réutiliser votre fonction existante)
                # Pour simplifier, on va juste marquer comme créé
                
                bulletins_crees.append({
                    'employe': employe.nom_complet(),
                    'numero': numero,
                    'montant': total_net
                })
                
            except Exception as e:
                erreurs.append(f"{employe.nom_complet()}: {str(e)}")
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'bulletins_crees': len(bulletins_crees),
            'details': bulletins_crees,
            'erreurs': erreurs
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES POUR LA SAUVEGARDE ET RESTAURATION
# ============================================================================

# Dossier pour stocker les sauvegardes
BACKUP_DIR = 'backups'
DB_PATH = 'instance/factures.db'

# Créer le dossier de sauvegarde si il n'existe pas
os.makedirs(BACKUP_DIR, exist_ok=True)

@app.route('/sauvegardes')
@comptable_ou_admin_required
def sauvegardes():
    """Page de gestion des sauvegardes"""
    # Lister toutes les sauvegardes disponibles
    backups = []
    
    if os.path.exists(BACKUP_DIR):
        for backup_file in sorted(glob.glob(os.path.join(BACKUP_DIR, 'backup_*.db')), reverse=True):
            file_stat = os.stat(backup_file)
            backups.append({
                'filename': os.path.basename(backup_file),
                'path': backup_file,
                'size': file_stat.st_size / (1024 * 1024),  # Taille en MB
                'date': datetime.fromtimestamp(file_stat.st_mtime)
            })
    
    return render_template('sauvegardes.html',
                           entreprise=VOTRE_ENTREPRISE,
                           backups=backups,
                           nb_backups=len(backups))

@app.route('/api/backup/create', methods=['POST'])
def create_backup():
    """Créer une sauvegarde manuelle de la base de données"""
    try:
        # Vérifier que la base de données existe
        if not os.path.exists(DB_PATH):
            return jsonify({'error': 'Base de données introuvable'}), 404
        
        # Créer le nom du fichier de sauvegarde
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        backup_filename = f'backup_{timestamp}.db'
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Copier la base de données
        shutil.copy2(DB_PATH, backup_path)
        
        # Nettoyer les anciennes sauvegardes (garder seulement les 30 dernières)
        cleanup_old_backups()
        
        file_size = os.path.getsize(backup_path) / (1024 * 1024)  # MB
        
        app.logger.info(f"✅ Sauvegarde créée : {backup_filename}")
        
        return jsonify({
            'success': True,
            'message': f'Sauvegarde créée avec succès',
            'filename': backup_filename,
            'size': f'{file_size:.2f} MB',
            'date': timestamp
        })
        
    except Exception as e:
        app.logger.error(f"❌ Erreur lors de la sauvegarde : {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/download/<filename>')
def download_backup(filename):
    """Télécharger une sauvegarde"""
    try:
        backup_path = os.path.join(BACKUP_DIR, filename)
        
        if not os.path.exists(backup_path):
            return jsonify({'error': 'Sauvegarde introuvable'}), 404
        
        return send_file(backup_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/restore/<filename>', methods=['POST'])
def restore_backup(filename):
    """Restaurer une sauvegarde"""
    try:
        backup_path = os.path.join(BACKUP_DIR, filename)
        
        if not os.path.exists(backup_path):
            return jsonify({'error': 'Sauvegarde introuvable'}), 404
        
        # Créer une sauvegarde de sécurité avant restauration
        safety_backup = f'backup_before_restore_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.db'
        safety_path = os.path.join(BACKUP_DIR, safety_backup)
        shutil.copy2(DB_PATH, safety_path)
        
        # Restaurer la sauvegarde
        shutil.copy2(backup_path, DB_PATH)
        
        app.logger.info(f"✅ Base de données restaurée depuis : {filename}")
        
        return jsonify({
            'success': True,
            'message': f'Base de données restaurée avec succès depuis {filename}',
            'safety_backup': safety_backup
        })
        
    except Exception as e:
        app.logger.error(f"❌ Erreur lors de la restauration : {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/delete/<filename>', methods=['DELETE'])
def delete_backup(filename):
    """Supprimer une sauvegarde"""
    try:
        backup_path = os.path.join(BACKUP_DIR, filename)
        
        if not os.path.exists(backup_path):
            return jsonify({'error': 'Sauvegarde introuvable'}), 404
        
        os.remove(backup_path)
        
        app.logger.info(f"🗑️ Sauvegarde supprimée : {filename}")
        
        return jsonify({
            'success': True,
            'message': f'Sauvegarde {filename} supprimée'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def cleanup_old_backups(max_backups=30):
    """Nettoyer les anciennes sauvegardes (garder les 30 dernières)"""
    try:
        backups = sorted(glob.glob(os.path.join(BACKUP_DIR, 'backup_*.db')))
        
        # Si on a plus de max_backups, supprimer les plus anciennes
        if len(backups) > max_backups:
            for old_backup in backups[:-max_backups]:
                os.remove(old_backup)
                app.logger.info(f"🗑️ Ancienne sauvegarde supprimée : {os.path.basename(old_backup)}")
    
    except Exception as e:
        app.logger.error(f"❌ Erreur nettoyage sauvegardes : {e}")

def auto_backup():
    """Fonction pour créer une sauvegarde automatique"""
    try:
        if os.path.exists(DB_PATH):
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            backup_filename = f'backup_auto_{timestamp}.db'
            backup_path = os.path.join(BACKUP_DIR, backup_filename)
            
            shutil.copy2(DB_PATH, backup_path)
            cleanup_old_backups()
            
            app.logger.info(f"✅ Sauvegarde automatique créée : {backup_filename}")
    except Exception as e:
        app.logger.error(f"❌ Erreur sauvegarde automatique : {e}")

if __name__ == '__main__':
    # ============================================================================
    # SÉCURITÉ : Invalider toutes les sessions au démarrage
    # ============================================================================
    # Changer la clé secrète au démarrage invalide TOUS les cookies/sessions existants
    # Ceci force une reconnexion obligatoire de tous les utilisateurs
    import secrets
    import hashlib
    
    # Générer une nouvelle SECRET_KEY basée sur le timestamp
    timestamp = datetime.now().isoformat()
    new_secret = hashlib.sha256(f"mbeka-{timestamp}-{secrets.token_hex(16)}".encode()).hexdigest()
    app.config['SECRET_KEY'] = new_secret
    
    print("🔒 Nouvelle clé de session générée - toutes les sessions précédentes invalidées")
    
    # Nettoyer aussi le dossier flask_session s'il existe
    try:
        flask_session_dir = os.path.join(os.path.dirname(__file__), 'flask_session')
        if os.path.exists(flask_session_dir):
            shutil.rmtree(flask_session_dir)
            print("🔒 Dossier de sessions nettoyé")
    except Exception as e:
        pass
    
    # ============================================================================
    
    with app.app_context():
        # Créer les tables si elles n'existent pas
        db.create_all()
        
        # Créer un utilisateur admin par défaut s'il n'existe pas
        if not Utilisateur.query.filter_by(username='admin').first():
            admin = Utilisateur(
                username='admin',
                email='admin@mbeka.com',
                nom='Administrateur',
                prenom='Système',
                role='admin',
                actif=True
            )
            admin.set_password('admin123')  # ⚠️ À CHANGER EN PRODUCTION !
            db.session.add(admin)
            db.session.commit()
            print("✅ Utilisateur admin créé (username: admin, password: admin123)")
            print("⚠️  IMPORTANT: Changez ce mot de passe en production !")
    
    print("\n" + "="*60)
    print("🚀 APPLICATION DE FACTURATION MBEKA - SÉCURISÉE")
    print("="*60)
    print(f"Entreprise: {VOTRE_ENTREPRISE['nom']}")
    print(f"TVA: {TAUX_TVA}%")
    print("\n🔐 SÉCURITÉ:")
    print("   ✅ Authentification obligatoire")
    print("   ✅ Sessions sécurisées")
    print("   ✅ Reconnexion requise au démarrage")
    print("\n🔐 CONNEXION:")
    print("   Username: admin")
    print("   Password: admin123")
    print("\n👉 Ouvrez votre navigateur et allez à :")
    print("   http://localhost:5000")
    print("\n📁 Routes principales:")
    print("   /login                   - Connexion")
    print("   /                        - Tableau de bord")
    print("   /utilisateurs            - Gestion utilisateurs (admin)")
    print("   /factures                - Toutes les factures")
    print("="*60)
    
    
# ============================================================================
# INITIALISATION AUTOMATIQUE DE LA BASE DE DONNÉES
# ============================================================================

def init_database():
    """Initialise la base de données et crée un admin par défaut si nécessaire"""
    with app.app_context():
        try:
            # Créer toutes les tables
            db.create_all()
            print("✅ Tables de base de données créées")
            
            # Vérifier si un admin existe déjà
            admin_exists = Utilisateur.query.filter_by(role='admin').first()
            
            if not admin_exists:
                # Créer l'utilisateur admin par défaut
                admin = Utilisateur(
                    username='admin',
                    email='admin@mbeka.com',
                    role='admin',
                    actif=True
                )
                admin.set_password('Admin2024!')
                
                db.session.add(admin)
                db.session.commit()
                
                print("=" * 60)
                print("✅ UTILISATEUR ADMIN CRÉÉ AUTOMATIQUEMENT !")
                print("=" * 60)
                print("🔑 Username: admin")
                print("🔑 Password: Admin2024!")
                print("=" * 60)
                print("⚠️  IMPORTANT: Changez ce mot de passe après la première connexion !")
                print("=" * 60)
            else:
                print("ℹ️  Un administrateur existe déjà - Connexion disponible")
        except Exception as e:
            print(f"❌ Erreur lors de l'initialisation de la base de données: {e}")

# Initialiser la base de données au démarrage (important pour Render)
init_database()

# ✅ CORRECTION ICI : Le serveur ne se lance que si on exécute "python app.py" manuellement
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=5000)
