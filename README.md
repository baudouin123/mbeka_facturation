# 📊 Mbeka Facturation

Application web professionnelle de gestion de facturation développée avec Flask.

## 🎯 Fonctionnalités

### 📄 Facturation
- ✅ Factures clients
- ✅ Bulletins de paie employés
- ✅ Génération PDF automatique
- ✅ Envoi automatique par email
- ✅ Gestion des paiements
- ✅ Suivi des impayés

### 👥 Gestion
- ✅ Gestion clients
- ✅ Gestion employés
- ✅ Système d'amendes
- ✅ Livraisons et tracking

### 🔐 Sécurité
- ✅ Multi-utilisateurs (Admin, Comptable, Employé)
- ✅ Permissions personnalisables par page
- ✅ Authentification sécurisée
- ✅ Sessions persistantes
- ✅ Protection CSRF

### 📊 Reporting
- ✅ Dashboard avec statistiques
- ✅ Calendrier des factures
- ✅ Exports Excel/CSV
- ✅ Historique complet
- ✅ Logs d'activité

### 💾 Backup
- ✅ Sauvegardes automatiques
- ✅ Restauration simple
- ✅ Export ZIP

## 🚀 Installation locale

### Prérequis

- Python 3.11+
- pip

### Installation

```bash
# Cloner le projet
git clone https://github.com/VOTRE_USERNAME/mbeka-facturation.git
cd mbeka-facturation

# Installer les dépendances
pip install -r requirements.txt

# Créer la base de données
python
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
>>> exit()

# Lancer l'application
python app.py
```

L'application sera accessible sur `http://localhost:5000`

### Créer un utilisateur admin

```python
python
>>> from app import app, db, Utilisateur
>>> with app.app_context():
...     admin = Utilisateur(username='admin', email='admin@example.com', role='admin', actif=True)
...     admin.set_password('votre_mot_de_passe')
...     db.session.add(admin)
...     db.session.commit()
>>> exit()
```

## 🌐 Déploiement en production

Consultez le guide complet : [GUIDE_DEPLOIEMENT_RENDER.md](GUIDE_DEPLOIEMENT_RENDER.md)

### Déploiement rapide sur Render

1. Créer compte sur https://render.com
2. Connecter ce repo GitHub
3. Créer PostgreSQL database
4. Créer Web Service
5. Configurer variables d'environnement
6. ✅ En ligne !

## ⚙️ Configuration

### Variables d'environnement

Créez un fichier `.env` (copie de `.env.example`) :

```env
SECRET_KEY=votre_cle_secrete_longue
DATABASE_URL=sqlite:///factures.db
MAIL_USERNAME=votre.email@gmail.com
MAIL_PASSWORD=mot_de_passe_app_gmail
FLASK_DEBUG=False
```

### Configuration Gmail

Pour l'envoi automatique d'emails :

1. Activer validation 2 étapes sur Gmail
2. Créer mot de passe d'application : https://myaccount.google.com/apppasswords
3. Utiliser ce mot de passe dans `MAIL_PASSWORD`

## 📚 Documentation

- [Guide de déploiement](GUIDE_DEPLOIEMENT_RENDER.md)
- [Guide logs d'activité](GUIDE_LOGS_COMPLET.md)
- [Guide permissions](GUIDE_PERMISSIONS_PERSONNALISEES.md)
- [Guide envoi emails](GUIDE_ENVOI_FACTURES_EMAIL.md)

## 🛠️ Technologies utilisées

- **Backend:** Flask 3.0
- **Database:** SQLite (dev) / PostgreSQL (prod)
- **Auth:** Flask-Login
- **Forms:** Flask-WTF
- **PDF:** ReportLab
- **Excel:** openpyxl
- **Word:** python-docx

## 📋 Structure du projet

```
mbeka-facturation/
├── app.py                  # Application principale
├── requirements.txt        # Dépendances
├── Procfile               # Config Render
├── runtime.txt            # Version Python
├── .env.example           # Exemple variables env
├── templates/             # Templates HTML
│   ├── index.html
│   ├── factures.html
│   ├── login.html
│   └── ...
├── static/               # CSS, JS, Images
│   ├── style.css
│   └── images/
└── factures/            # PDFs générés (gitignored)
```

## 🔒 Sécurité

- ✅ Mots de passe hashés (Werkzeug)
- ✅ Protection CSRF
- ✅ Sessions sécurisées
- ✅ Permissions granulaires
- ✅ Logs d'activité
- ✅ Variables d'environnement pour secrets

## 📈 Roadmap

- [ ] Application mobile
- [ ] API REST
- [ ] Notifications push
- [ ] Multi-devises
- [ ] Multi-langues
- [ ] Rapports automatiques

## 🤝 Contribution

Ce projet est privé. Contactez l'équipe Mbeka pour contribuer.

## 📄 Licence

Propriétaire - Mbeka © 2025

## 👨‍💻 Auteur

**Mbeka Team**

---

**⭐ Si ce projet vous aide, mettez une étoile ! ⭐**
