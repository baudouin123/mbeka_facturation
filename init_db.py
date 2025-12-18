#!/usr/bin/env python3
import os
import sys

# Forcer l'URL de la base de données
os.environ['DATABASE_URL'] = 'postgresql://mbeka_user:5G2MXzg6BMstri5qB0pTclTHrUSVm9Ok@dpg-d4vj7jnpm1nc73bprt3g-a.frankfurt-postgres.render.com/mbeka_db'

from app import app, db

with app.app_context():
    print("🔥 RÉINITIALISATION COMPLÈTE DE LA BASE...")

    # Force drop de TOUTES les tables
    db.session.execute('DROP TABLE IF EXISTS permission CASCADE')
    db.session.execute('DROP TABLE IF EXISTS log CASCADE')
    db.session.execute('DROP TABLE IF EXISTS amende CASCADE')
    db.session.execute('DROP TABLE IF EXISTS livraison CASCADE')
    db.session.execute('DROP TABLE IF EXISTS facture CASCADE')
    db.session.execute('DROP TABLE IF EXISTS employe CASCADE')
    db.session.execute('DROP TABLE IF EXISTS client CASCADE')
    db.session.execute('DROP TABLE IF EXISTS utilisateur CASCADE')
    db.session.commit()
    print("✅ Tables supprimées")

    # Recréer les tables
    db.create_all()
    print("✅ Tables recréées")

    # Créer l'admin directement
    from app import Utilisateur, Client, VOTRE_ENTREPRISE

    admin = Utilisateur(
        username='admin',
        email='admin@mbeka.com',
        nom='Administrateur',
        prenom='Système',
        role='admin',
        actif=True
    )
    admin.set_password('admin123')
    db.session.add(admin)

    # Créer aussi le client par défaut
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
    print("✅✅✅ ADMIN CRÉÉ AVEC SUCCÈS !")
    print("Username: admin")
    print("Password: admin123")

    # Vérification
    test = Utilisateur.query.filter_by(username='admin').first()
    if test:
        print(f"✓ Vérification: L'admin existe bien dans la base")
    else:
        print("❌ ERREUR: Admin non trouvé après création")
