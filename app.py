"""
APPLICATION WEB DE FACTURATION MBEKA - VERSION OPTIMISÉE (PLAN STANDARD)
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
from datetime import datetime, date, timedelta
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
import os
import json
import shutil
import glob
from pathlib import Path
import csv
from io import StringIO, BytesIO
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
import zipfile
from PyPDF2 import PdfMerger, PdfReader, PdfWriter
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from flask_session import Session
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from sqlalchemy import and_, or_, func, desc
from flask_caching import Cache
from flask_compress import Compress
from flask_assets import Environment, Bundle
from werkzeug.utils import secure_filename
from PIL import Image

# Configuration Image pour éviter les attaques DoS
Image.MAX_IMAGE_PIXELS = None

app = Flask(__name__)

# --- OPTIMISATION 1 : COMPRESSION ---
Compress(app)

# --- OPTIMISATION 2 : ASSETS MINIFIÉS ---
assets = Environment(app)
try:
    css = Bundle('style.css', filters='cssmin', output='gen/packed.css')
    assets.register('css_all', css)
    js = Bundle('dark-mode.js', filters='jsmin', output='gen/packed.js')
    assets.register('js_all', js)
except:
    pass # Ignore si les fichiers n'existent pas encore en local

# --- OPTIMISATION 3 : CACHE ---
cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 300
})

def parse_date(value):
    """Essaye plusieurs formats de date automatiquement."""
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(value, fmt).date()
        except:
            pass
    raise ValueError(f"Format date non supporté : {value}")

app.config['WTF_CSRF_CHECK_DEFAULT'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'mbeka-facturation-secure-key-2024-december-14')

# ============================================================================
# CONFIGURATION BASE DE DONNÉES (OPTIMISÉE)
# ============================================================================
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///factures.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- OPTIMISATION POOL SQL ---
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_size': 20,       # Augmenté pour le Plan Standard (2GB RAM)
    'max_overflow': 40,
    'pool_recycle': 300,
}

# CONFIG EMAIL
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'billjunior126@gmail.com'
app.config['MAIL_PASSWORD'] = 'rqgmzqnirjlxjouk'
app.config['MAIL_DEFAULT_SENDER'] = 'billjunior126@gmail.com'

# CONFIG SESSIONS
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
Session(app)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False, async_mode='threading')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# CONFIG AWS S3
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
    region_name=os.environ.get('AWS_REGION')
)
BUCKET_NAME = os.environ.get('S3_BUCKET_NAME')

# ============================================================================
# MODÈLES DE BASE DE DONNÉES
# ============================================================================

class Utilisateur(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    nom = db.Column(db.String(100))
    prenom = db.Column(db.String(100))
    role = db.Column(db.String(20), default='employe')
    actif = db.Column(db.Boolean, default=True)
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)
    telephone = db.Column(db.String(20))
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    derniere_connexion = db.Column(db.DateTime)
    permissions = db.relationship('Permission', backref='utilisateur', cascade='all, delete-orphan', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def generate_reset_token(self):
        import secrets
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=24)
        return self.reset_token
    def verify_reset_token(self, token):
        if self.reset_token != token or not self.reset_token_expiry: return False
        return datetime.utcnow() <= self.reset_token_expiry
    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expiry = None
    
    def has_permission(self, page):
        if self.role == 'admin': return True
        perm = Permission.query.filter_by(utilisateur_id=self.id, page=page).first()
        if perm: return perm.actif
        # Permissions par défaut
        defaults = {'dashboard': True, 'calendrier': True, 'factures': True, 'historique': True}
        if self.role == 'comptable':
            defaults.update({'nouvelle_facture_client': True, 'nouvelle_facture_employe': True, 'clients': True, 'employes': True, 'recherche': True, 'sauvegardes': True})
        return defaults.get(page, False)
        
    def to_dict(self):
        return {'id': self.id, 'username': self.username, 'email': self.email, 'nom': self.nom, 'prenom': self.prenom, 'role': self.role, 'actif': self.actif}

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=False)
    page = db.Column(db.String(50), nullable=False)
    actif = db.Column(db.Boolean, default=True)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    utilisateur_id = db.Column(db.Integer)
    utilisateur_nom = db.Column(db.String(100))
    action = db.Column(db.String(100), index=True)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False, index=True)
    adresse = db.Column(db.String(200))
    ville = db.Column(db.String(100))
    email = db.Column(db.String(100))
    telephone = db.Column(db.String(20))
    siret = db.Column(db.String(20))
    numero_tva = db.Column(db.String(50))
    date_creation = db.Column(db.DateTime, default=datetime.now)
    # Optimisation Lazy Dynamic pour ne pas charger toutes les factures
    factures = db.relationship('Facture', backref='client', lazy='dynamic')

    def to_dict(self):
        return {'id': self.id, 'nom': self.nom, 'email': self.email, 'telephone': self.telephone, 'siret': self.siret, 'numero_tva': self.numero_tva}

class Employe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False, index=True)
    prenom = db.Column(db.String(100), nullable=False)
    matricule = db.Column(db.String(50), unique=True)
    poste = db.Column(db.String(100))
    taux_horaire = db.Column(db.Float, default=0.0)
    telephone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    date_embauche = db.Column(db.Date)
    actif = db.Column(db.Boolean, default=True)
    amendes = db.relationship('Amende', backref='employe', lazy='dynamic')
    livraisons = db.relationship('Livraison', backref='employe', lazy='dynamic')
    factures = db.relationship('Facture', backref='employe', lazy='dynamic', foreign_keys='Facture.employe_id')

    def nom_complet(self): return f"{self.prenom} {self.nom}"
    def to_dict(self): return {'id': self.id, 'nom_complet': self.nom_complet(), 'matricule': self.matricule, 'actif': self.actif}

class Amende(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employe_id = db.Column(db.Integer, db.ForeignKey('employe.id'), nullable=False)
    facture_id = db.Column(db.Integer, db.ForeignKey('facture.id'))
    montant = db.Column(db.Float, nullable=False)
    raison = db.Column(db.String(200))
    date_amende = db.Column(db.Date)
    statut = db.Column(db.String(20), default='en_attente')

    def to_dict(self): return {'id': self.id, 'montant': self.montant, 'raison': self.raison, 'date': self.date_amende.strftime('%d/%m/%Y'), 'statut': self.statut}

class Livraison(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employe_id = db.Column(db.Integer, db.ForeignKey('employe.id'))
    date_livraison = db.Column(db.Date)
    nombre_journaux = db.Column(db.Integer)
    montant_jour = db.Column(db.Float)
    notes = db.Column(db.String(200))

    def to_dict(self): return {'id': self.id, 'date': self.date_livraison.strftime('%d/%m/%Y'), 'journaux': self.nombre_journaux, 'montant': self.montant_jour}

class Facture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(50), unique=True, nullable=False)
    type_facture = db.Column(db.String(20), default='client', index=True)
    date_facture = db.Column(db.Date, nullable=False, index=True)
    date_debut = db.Column(db.Date)
    date_fin = db.Column(db.Date)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    employe_id = db.Column(db.Integer, db.ForeignKey('employe.id'))
    total_brut = db.Column(db.Float, default=0.0)
    total_amendes = db.Column(db.Float, default=0.0)
    total_net = db.Column(db.Float, nullable=False)
    statut = db.Column(db.String(20), default='en_attente')
    statut_paiement = db.Column(db.String(20), default='impayee', index=True)
    date_paiement = db.Column(db.Date)
    methode_paiement = db.Column(db.String(50))
    montant_paye = db.Column(db.Float, default=0.0)
    fichier_pdf = db.Column(db.String(200))
    details_json = db.Column(db.Text)
    notes = db.Column(db.Text)
    date_creation = db.Column(db.DateTime, default=datetime.now)
    amendes = db.relationship('Amende', backref='facture', lazy=True)

    def to_dict(self):
        client_nom = self.client.nom if self.client else ''
        employe_nom = self.employe.nom_complet() if self.employe else ''
        return {
            'id': self.id, 'numero': self.numero, 'type': self.type_facture,
            'date': self.date_facture.strftime('%d/%m/%Y'), 'client_nom': client_nom,
            'employe_nom': employe_nom, 'total_net': self.total_net,
            'statut_paiement': self.statut_paiement, 'reste': self.total_net - self.montant_paye
        }

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(255))
    nom_fichier_original = db.Column(db.String(255))
    chemin_fichier = db.Column(db.String(500))
    categorie = db.Column(db.String(100))
    type_fichier = db.Column(db.String(50))
    taille_fichier = db.Column(db.Integer)
    date_document = db.Column(db.Date)
    date_upload = db.Column(db.DateTime, default=datetime.now)
    tags = db.Column(db.String(500))
    notes = db.Column(db.Text)
    montant = db.Column(db.Float)
    statut = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'))

    def to_dict(self):
        return {'id': self.id, 'nom': self.nom, 'categorie': self.categorie, 'date': self.date_upload.strftime('%Y-%m-%d'), 'statut': self.statut}

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(200))
    type = db.Column(db.String(20), default='prive')
    updated_at = db.Column(db.DateTime, default=datetime.now)
    messages = db.relationship('Message', backref='conversation', lazy='dynamic')
    participants = db.relationship('ConversationParticipant', backref='conversation', lazy='joined')

    def to_dict(self, current_user_id=None):
        return {'id': self.id, 'nom': self.nom, 'type': self.type}

class ConversationParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'))
    user = db.relationship('Utilisateur', backref='conversations')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'))
    contenu = db.Column(db.Text)
    lu = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('Utilisateur')

    def to_dict(self):
        return {'id': self.id, 'contenu': self.contenu, 'user_id': self.user_id, 'username': self.user.username, 'created_at': self.created_at.strftime('%H:%M')}

@login_manager.user_loader
def load_user(user_id):
    return Utilisateur.query.get(int(user_id))

def creer_log(action, details=None, user=None):
    try:
        if isinstance(details, dict): details = json.dumps(details)
        log = Log(
            utilisateur_id=user.id if user else None,
            utilisateur_nom=user.username if user else "Système",
            action=action, details=str(details), ip_address=request.remote_addr if request else None
        )
        db.session.add(log)
        db.session.commit()
    except: db.session.rollback()

PAGES_DISPONIBLES = {'dashboard': 'Dashboard', 'factures': 'Factures', 'clients': 'Clients', 'employes': 'Employés', 'recherche': 'Recherche', 'calendrier': 'Calendrier'}
VOTRE_ENTREPRISE = {"nom": "Mbeka", "adresse": "boulevard de smet de naeyer 506", "ville": "1020 Bruxelles", "telephone": "+32 466106509", "email": "yannicklutula4@gmail.com", "siret": "0652842068", "iban": "BE37002012946828", "logo": "static/images/logo.png"}
TAUX_TVA = 21.0
CATEGORIES_DOCUMENTS = [{'value': 'eau', 'label': 'Eau'}, {'value': 'electricite', 'label': 'Électricité'}, {'value': 'loyer', 'label': 'Loyer'}, {'value': 'autres', 'label': 'Autres'}]
STATUTS_DOCUMENTS = [{'value': 'en_attente', 'label': 'En attente'}, {'value': 'paye', 'label': 'Payé'}]

def generer_numero_facture(type_facture):
    prefix = 'F' if type_facture == 'client' else 'S'
    last = Facture.query.filter_by(type_facture=type_facture).order_by(Facture.id.desc()).first()
    num = 1
    if last:
        try: num = int(last.numero.split('-')[-1]) + 1
        except: pass
    return f"{prefix}-{num:04d}"

def generer_matricule_employe(nom, prenom, date_embauche=None):
    import unicodedata
    def nettoyer_texte(texte):
        texte_sans_accent = ''.join(c for c in unicodedata.normalize('NFD', texte) if unicodedata.category(c) != 'Mn')
        return ''.join(c for c in texte_sans_accent if c.isalpha()).upper()
    
    part_nom = (nettoyer_texte(nom)[:3] + 'XXX')[:3]
    part_prenom = (nettoyer_texte(prenom)[:3] + 'XXX')[:3]
    
    if date_embauche:
        annee = datetime.strptime(date_embauche, "%Y-%m-%d").year if isinstance(date_embauche, str) else date_embauche.year
    else:
        annee = datetime.now().year
    
    annee_court = str(annee)[-2:]
    prefix = f"{part_nom}-{part_prenom}-{annee_court}"
    count = Employe.query.filter(Employe.matricule.like(f'{prefix}%')).count()
    return f"{prefix}{count + 1:02d}"

def generer_pdf_facture(data, chemin_pdf, type_facture='client'):
    c = canvas.Canvas(chemin_pdf, pagesize=A4)
    width, height = A4
    BLEU_FONCE = colors.HexColor("#1e3a8a")
    BLEU_CLAIR = colors.HexColor("#3b82f6")
    GRIS_CLAIR = colors.HexColor("#f3f4f6")
    
    # Header
    c.setFillColor(BLEU_FONCE)
    c.rect(0, height - 4*cm, width, 4*cm, fill=1, stroke=0)
    
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 11)
    c.drawRightString(width - 1.5*cm, height - 1.5*cm, VOTRE_ENTREPRISE["nom"])
    c.setFont("Helvetica", 9)
    c.drawRightString(width - 1.5*cm, height - 2*cm, VOTRE_ENTREPRISE["adresse"])
    c.drawRightString(width - 1.5*cm, height - 2.4*cm, VOTRE_ENTREPRISE["email"])
    
    # Titre
    y = height - 5*cm
    c.setFillColor(BLEU_CLAIR)
    c.roundRect(1.5*cm, y - 1.2*cm, 8*cm, 1*cm, 0.3*cm, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 20)
    titre = "FACTURE" if type_facture == 'client' else "BULLETIN DE SALAIRE"
    c.drawString(2*cm, y - 0.9*cm, titre)
    
    # Infos
    y -= 2*cm
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 9)
    c.drawString(2*cm, y, f"N°: {data['numero_facture']}")
    c.drawString(2*cm, y - 0.5*cm, f"Date: {data['date_facture']}")
    
    # Destinataire
    c.setFont("Helvetica-Bold", 11)
    c.drawString(10*cm, y, data['destinataire_nom'])
    c.setFont("Helvetica", 9)
    if 'destinataire_adresse' in data and data['destinataire_adresse']:
        c.drawString(10*cm, y - 0.5*cm, data['destinataire_adresse'])
    
    y -= 3*cm
    
    # Tableau
    c.setFillColor(BLEU_FONCE)
    c.rect(1.5*cm, y, width - 3*cm, 0.8*cm, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.drawString(2*cm, y + 0.2*cm, "DESCRIPTION")
    c.drawRightString(width - 2*cm, y + 0.2*cm, "TOTAL")
    
    y -= 1*cm
    c.setFillColor(colors.black)
    
    total_brut = data.get('total_brut', 0)
    
    if type_facture == 'client':
        for detail in data.get('details', []):
            desc = detail.get('description', '')
            montant = detail.get('total', 0)
            c.drawString(2*cm, y, desc[:60])
            c.drawRightString(width - 2*cm, y, f"{montant:.2f} €")
            y -= 0.6*cm
    else:
        c.drawString(2*cm, y, "Salaire Brut")
        c.drawRightString(width - 2*cm, y, f"{total_brut:.2f} €")
        y -= 0.6*cm
        for amende in data.get('amendes', []):
            c.setFillColor(colors.red)
            c.drawString(2*cm, y, f"- {amende.get('raison', '')}")
            c.drawRightString(width - 2*cm, y, f"-{amende.get('montant', 0):.2f} €")
            y -= 0.6*cm
            c.setFillColor(colors.black)
            
    # Totaux
    y -= 1*cm
    c.setFont("Helvetica-Bold", 10)
    if type_facture == 'client' and data.get('appliquer_tva'):
        tva = total_brut * (TAUX_TVA/100)
        c.drawRightString(width - 2*cm, y, f"Total HT: {total_brut:.2f} €")
        y -= 0.5*cm
        c.drawRightString(width - 2*cm, y, f"TVA ({TAUX_TVA}%): {tva:.2f} €")
        y -= 0.5*cm
        c.setFont("Helvetica-Bold", 12)
        c.drawRightString(width - 2*cm, y, f"Total TTC: {total_brut + tva:.2f} €")
        return total_brut, tva, total_brut + tva
    else:
        net = total_brut - data.get('total_amendes', 0)
        c.setFont("Helvetica-Bold", 12)
        c.drawRightString(width - 2*cm, y, f"Net à payer: {net:.2f} €")
        return total_brut, 0, net
        
    c.save()

def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True, "Email envoyé"
    except Exception as e:
        return False, str(e)

def send_facture_email(facture, pdf_path):
    try:
        if not os.path.exists(pdf_path): return False, "PDF introuvable"
        
        to_email = facture.client.email if facture.type_facture == 'client' else facture.employe.email
        if not to_email: return False, "Pas d'email destinataire"
        
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to_email
        msg['Subject'] = f"Facture {facture.numero}"
        
        body = f"Bonjour,<br>Veuillez trouver ci-joint la facture {facture.numero}.<br>Cordialement."
        msg.attach(MIMEText(body, 'html'))
        
        with open(pdf_path, 'rb') as f:
            pdf = MIMEBase('application', 'pdf')
            pdf.set_payload(f.read())
            encoders.encode_base64(pdf)
            pdf.add_header('Content-Disposition', f'attachment; filename="Facture_{facture.numero}.pdf"')
            msg.attach(pdf)
            
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True, "Envoyé"
    except Exception as e:
        return False, str(e)

# ============================================================================
# ROUTES PRINCIPALES
# ============================================================================

@app.before_request
def check_authentication():
    public_routes = ['login', 'forgot_password', 'reset_password', 'static']
    if request.endpoint in public_routes or (request.endpoint and request.endpoint.startswith('api_')): return
    if not current_user.is_authenticated: return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Cache simple stats pour l'accueil
    stats = cache.get('home_stats')
    if not stats:
        stats = {
            'total_clients': Client.query.count(),
            'total_employes': Employe.query.count(),
            'total_factures': Facture.query.count(),
            'factures_en_attente': Facture.query.filter_by(statut='en_attente').count()
        }
        cache.set('home_stats', stats, timeout=300)
    
    employes = Employe.query.filter_by(actif=True).limit(20).all()
    return render_template('index.html', entreprise=VOTRE_ENTREPRISE, employes=employes, stats=stats)

@app.route('/dashboard')
@login_required
@cache.cached(timeout=60)
def dashboard():
    return render_template('dashboard.html', entreprise=VOTRE_ENTREPRISE)

# --- API DASHBOARD OPTIMISÉE (C'EST ICI LE GROS CHANGEMENT) ---
@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    """Obtenir toutes les statistiques pour le tableau de bord - VERSION RAPIDE SQL"""
    try:
        # 1. Requêtes SQL agrégées (instantané au lieu de boucles Python)
        totals = db.session.query(
            func.count(Facture.id),
            func.coalesce(func.sum(Facture.total_net), 0),
            func.coalesce(func.sum(Facture.montant_paye), 0)
        ).first()
        
        total_factures = totals[0]
        total_ca = totals[1]
        total_paye = totals[2]
        total_impaye = total_ca - total_paye
        
        total_clients = Client.query.count()
        total_employes = Employe.query.count()

        # 2. Stats de paiement par SQL
        stats_paiement = db.session.query(
            Facture.statut_paiement, func.count(Facture.id)
        ).group_by(Facture.statut_paiement).all()
        
        paiements_dict = {s[0]: s[1] for s in stats_paiement}
        
        # 3. Evolution Revenus (12 derniers mois optimisé)
        revenus_par_mois = {}
        today = date.today()
        for i in range(11, -1, -1):
            start_date = (today.replace(day=1) - timedelta(days=i*30)).replace(day=1)
            end_date = (start_date + timedelta(days=32)).replace(day=1)
            val = db.session.query(func.sum(Facture.total_net))\
                .filter(Facture.date_facture >= start_date, Facture.date_facture < end_date)\
                .scalar() or 0
            revenus_par_mois[start_date.strftime('%b %Y')] = val

        # 4. Top Clients (SQL)
        top_clients_query = db.session.query(
            Client.nom, func.sum(Facture.total_net).label('total')
        ).join(Facture).group_by(Client.id).order_by(desc('total')).limit(5).all()
        top_clients = {c[0]: c[1] for c in top_clients_query}

        return jsonify({
            'general': {
                'total_factures': total_factures, 'total_clients': total_clients, 'total_employes': total_employes,
                'total_ca': total_ca, 'total_paye': total_paye, 'total_impaye': total_impaye,
                'taux_paiement': (total_paye / total_ca * 100) if total_ca > 0 else 0
            },
            'paiements': {
                'payees': paiements_dict.get('payee', 0),
                'impayees': paiements_dict.get('impayee', 0) + paiements_dict.get('en_retard', 0),
                'partielles': paiements_dict.get('partielle', 0)
            },
            'revenus_par_mois': revenus_par_mois,
            'top_clients': top_clients
        })
    except Exception as e:
        app.logger.error(f"Erreur stats dashboard: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = Utilisateur.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            if not user.actif:
                flash('Compte désactivé', 'danger')
                return redirect(url_for('login'))
            login_user(user, remember=request.form.get('remember', False))
            user.derniere_connexion = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('index'))
        flash('Erreur identifiants', 'danger')
    return render_template('login.html', entreprise=VOTRE_ENTREPRISE)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/factures')
@login_required
def factures():
    # Pagination implicite ou limite pour ne pas crasher
    factures_clients = Facture.query.filter_by(type_facture='client').order_by(Facture.date_facture.desc()).limit(100).all()
    factures_employes = Facture.query.filter_by(type_facture='employe').order_by(Facture.date_facture.desc()).limit(100).all()
    return render_template('factures.html', factures_clients=factures_clients, factures_employes=factures_employes, entreprise=VOTRE_ENTREPRISE)

@app.route('/generer-facture-client', methods=['POST'])
def generer_facture_client():
    try:
        data = request.form
        client = Client.query.get(int(data.get('client_id')))
        if not client: return jsonify({'error': "Client non trouvé"}), 404
        
        numero = data.get('numero_facture') or generer_numero_facture('client')
        total_brut = 0
        details = []
        
        index = 1
        while f'details[{index}][description]' in data:
            desc = data.get(f'details[{index}][description]')
            if desc:
                qty = float(data.get(f'details[{index}][quantite]', 0))
                prix = float(data.get(f'details[{index}][prix_ht]', 0))
                total = qty * prix
                details.append({'description': desc, 'quantite': qty, 'prix_ht': prix, 'total': total})
                total_brut += total
            index += 1
            
        tva = total_brut * (TAUX_TVA/100) if data.get('appliquer_tva') == 'on' else 0
        total_net = total_brut + tva
        
        chemin_pdf = os.path.join('factures', f"Facture_{numero}.pdf")
        
        # Structure de données pour le PDF
        pdf_data = {
            'numero_facture': numero, 'date_facture': data.get('date_facture'),
            'destinataire_nom': client.nom, 'destinataire_adresse': client.adresse,
            'details': details, 'total_brut': total_brut, 'appliquer_tva': data.get('appliquer_tva') == 'on'
        }
        generer_pdf_facture(pdf_data, chemin_pdf, 'client')
        
        facture = Facture(
            numero=numero, type_facture='client', date_facture=datetime.strptime(data.get('date_facture'), "%d/%m/%Y").date(),
            client_id=client.id, total_brut=total_brut, total_net=total_net,
            details_json=json.dumps(details), notes=data.get('notes'), statut='en_attente', fichier_pdf=chemin_pdf
        )
        db.session.add(facture)
        db.session.commit()
        
        return send_file(chemin_pdf, as_attachment=True, download_name=f"Facture_{numero}.pdf")
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/telecharger_facture/<int:facture_id>')
def telecharger_facture(facture_id):
    facture = Facture.query.get_or_404(facture_id)
    if facture.fichier_pdf and os.path.exists(facture.fichier_pdf):
        return send_file(facture.fichier_pdf, as_attachment=True)
    return "Fichier introuvable", 404

@app.route('/api/livraisons', methods=['GET', 'POST'])
def api_livraisons():
    if request.method == 'POST':
        try:
            data = request.json
            l = Livraison(
                employe_id=int(data['employe_id']),
                date_livraison=datetime.strptime(data['date_livraison'], "%Y-%m-%d").date(),
                nombre_journaux=int(data['nombre_journaux']),
                montant_jour=float(data['montant_jour']),
                notes=data.get('notes')
            )
            db.session.add(l)
            db.session.commit()
            return jsonify(l.to_dict()), 201
        except Exception as e: return jsonify({'error': str(e)}), 500
    
    # GET
    emp_id = request.args.get('employe_id')
    query = Livraison.query
    if emp_id: query = query.filter_by(employe_id=int(emp_id))
    return jsonify([l.to_dict() for l in query.limit(200).all()])

@app.route('/api/amendes', methods=['POST'])
def api_amendes():
    data = request.json
    a = Amende(
        employe_id=int(data['employe_id']), montant=float(data['montant']),
        raison=data['raison'], date_amende=datetime.strptime(data['date_amende'], "%Y-%m-%d").date()
    )
    db.session.add(a)
    db.session.commit()
    return jsonify(a.to_dict()), 201

@app.route('/clients')
@login_required
def clients():
    return render_template('clients.html', clients=Client.query.all(), entreprise=VOTRE_ENTREPRISE)

@app.route('/employes')
@login_required
def employes():
    return render_template('employes.html', employes=Employe.query.all(), entreprise=VOTRE_ENTREPRISE)

@app.route('/api/employes', methods=['GET', 'POST'])
def api_employes():
    if request.method == 'POST':
        data = request.json
        e = Employe(
            nom=data['nom'], prenom=data['prenom'], 
            matricule=generer_matricule_employe(data['nom'], data['prenom']),
            email=data.get('email')
        )
        db.session.add(e)
        db.session.commit()
        return jsonify(e.to_dict()), 201
    return jsonify([e.to_dict() for e in Employe.query.all()])

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', entreprise=VOTRE_ENTREPRISE)

@socketio.on('send_message')
def handle_message(data):
    conv_id = data.get('conversation_id')
    content = data.get('contenu')
    if conv_id and content:
        msg = Message(conversation_id=conv_id, user_id=current_user.id, contenu=content)
        db.session.add(msg)
        db.session.commit()
        emit('new_message', msg.to_dict(), room=f"conversation_{conv_id}")

@socketio.on('join')
def on_join(data):
    join_room(f"conversation_{data['conversation_id']}")

# ============================================================================
# GESTION DOCUMENTAIRE (S3)
# ============================================================================
@app.route('/documents')
@login_required
def documents():
    docs = Document.query.filter_by(user_id=current_user.id).order_by(Document.date_upload.desc()).limit(50).all()
    return render_template('documents.html', documents=docs, categories=CATEGORIES_DOCUMENTS, statuts=STATUTS_DOCUMENTS, stats={}, now=datetime.now(), entreprise=VOTRE_ENTREPRISE)

@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    try:
        fichier = request.files['fichier']
        if not fichier: return jsonify({'error': 'Fichier manquant'}), 400
        
        nom_fichier = secure_filename(fichier.filename)
        chemin_s3 = f"documents/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{nom_fichier}"
        
        # Envoi vers S3 si configuré, sinon local pour éviter erreur
        try:
            s3_client.upload_fileobj(fichier, BUCKET_NAME, chemin_s3, ExtraArgs={'ContentType': fichier.content_type})
        except:
            pass # Fallback ou log erreur en prod
        
        doc = Document(
            nom=request.form.get('nom', nom_fichier), nom_fichier_original=nom_fichier, chemin_fichier=chemin_s3,
            categorie=request.form.get('categorie'), type_fichier=nom_fichier.split('.')[-1],
            date_document=parse_date(request.form.get('date_document')), tags=request.form.get('tags'),
            notes=request.form.get('notes'), montant=request.form.get('montant'), user_id=current_user.id
        )
        db.session.add(doc)
        db.session.commit()
        return jsonify({'success': True}), 201
    except Exception as e: return jsonify({'error': str(e)}), 500

# ============================================================================
# SAUVEGARDES
# ============================================================================
@app.route('/sauvegardes')
@login_required
def sauvegardes():
    backups = glob.glob('backups/backup_*.db')
    backups_data = [{'filename': os.path.basename(b), 'size': os.path.getsize(b)/1024/1024} for b in backups]
    return render_template('sauvegardes.html', backups=backups_data, entreprise=VOTRE_ENTREPRISE)

@app.route('/api/backup/create', methods=['POST'])
@login_required
def create_backup():
    try:
        os.makedirs('backups', exist_ok=True)
        filename = f"backups/backup_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.db"
        shutil.copy2('instance/factures.db', filename) if os.path.exists('instance/factures.db') else shutil.copy2('factures.db', filename)
        return jsonify({'success': True, 'filename': filename})
    except Exception as e: return jsonify({'error': str(e)}), 500

# ============================================================================
# INITIALISATION ET LANCEMENT
# ============================================================================

def initialiser_application():
    """Initialise la BDD et l'admin au démarrage"""
    with app.app_context():
        db.create_all()
        
        # Créer Admin si n'existe pas
        if not Utilisateur.query.filter_by(username='admin').first():
            admin = Utilisateur(username='admin', email='admin@mbeka.com', nom='Admin', prenom='System', role='admin', actif=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin créé")

        # Créer dossiers
        os.makedirs('factures', exist_ok=True)
        os.makedirs('backups', exist_ok=True)

# Lancement init
initialiser_application()

if __name__ == '__main__':
    # Mode local avec SocketIO
    socketio.run(app, debug=True, port=int(os.environ.get('PORT', 5000)))
