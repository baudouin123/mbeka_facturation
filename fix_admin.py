#!/usr/bin/env python3
"""
Script pour créer l'utilisateur admin dans la base PostgreSQL
À exécuter une seule fois après le déploiement
"""

import os
import sys

# Forcer la configuration PostgreSQL
os.environ['DATABASE_URL'] = 'postgresql://mbeka_user:5G2MXzg6BMstri5qB0pTclTHrUSVm9Ok@dpg-d4vj7jnpm1nc73bprt3g-a.frankfurt-postgres.render.com/mbeka_db'

print("🔧 Configuration de la base de données...")

from app import app, db, Utilisateur, Client, VOTRE_ENTREPRISE
from sqlalchemy import text

def init_database():
    """Initialise la base de données avec l'admin"""
    with app.app_context():
        print("📊 Connexion à la base de données...")

        # Créer toutes les tables
        try:
            db.create_all()
            print("✅ Tables créées/vérifiées")
        except Exception as e:
            print(f"⚠️ Erreur création tables: {e}")

        # Vérifier si l'admin existe déjà
        try:
            admin = Utilisateur.query.filter_by(username='admin').first()
            if admin:
                print(f"⚠️ L'utilisateur admin existe déjà (ID: {admin.id})")
                # Le supprimer pour le recréer
                try:
                    # D'abord, supprimer les dépendances
                    db.session.execute(text("DELETE FROM permission WHERE utilisateur_id = :id"), {'id': admin.id})
                    db.session.execute(text("DELETE FROM log WHERE utilisateur_id = :id"), {'id': admin.id})
                    db.session.commit()
                    print("✅ Dépendances supprimées")

                    # Maintenant supprimer l'admin
                    db.session.delete(admin)
                    db.session.commit()
                    print("✅ Ancien admin supprimé")
                except Exception as e:
                    print(f"⚠️ Erreur suppression admin: {e}")
                    db.session.rollback()
        except Exception as e:
            print(f"ℹ️ Pas d'admin existant: {e}")

        # Créer le nouvel admin
        try:
            print("🔨 Création du nouvel admin...")
            nouvel_admin = Utilisateur(
                username='admin',
                email='admin@mbeka.com',
                nom='Administrateur',
                prenom='Système',
                role='admin',
                actif=True
            )
            nouvel_admin.set_password('admin123')
            db.session.add(nouvel_admin)
            db.session.commit()
            print("✅ Admin créé avec succès !")

            # Vérifier que l'admin a bien été créé
            verif = Utilisateur.query.filter_by(username='admin').first()
            if verif:
                print(f"✅ Vérification OK - Admin ID: {verif.id}")
                print(f"   Username: {verif.username}")
                print(f"   Email: {verif.email}")
                print(f"   Role: {verif.role}")
            else:
                print("❌ ERREUR: Admin non trouvé après création !")

        except Exception as e:
            print(f"❌ Erreur création admin: {e}")
            db.session.rollback()
            return False

        # Créer le client par défaut (votre entreprise) si nécessaire
        try:
            client_defaut = Client.query.filter_by(nom=VOTRE_ENTREPRISE['nom']).first()
            if not client_defaut:
                client_defaut = Client(
                    nom=VOTRE_ENTREPRISE['nom'],
                    adresse=VOTRE_ENTREPRISE['adresse'],
                    ville=VOTRE_ENTREPRISE['ville'],
                    email=VOTRE_ENTREPRISE['email'],
                    telephone=VOTRE_ENTREPRISE['telephone'],
                    siret=VOTRE_ENTREPRISE['siret']
                )
                db.session.add(client_defaut)
                db.session.commit()
                print(f"✅ Client par défaut créé: {VOTRE_ENTREPRISE['nom']}")
        except Exception as e:
            print(f"⚠️ Client par défaut: {e}")

    return True

if __name__ == "__main__":
    print("="*60)
    print("🚀 SCRIPT D'INITIALISATION MBEKA FACTURATION")
    print("="*60)

    success = init_database()

    if success:
        print("\n" + "="*60)
        print("✅ INITIALISATION TERMINÉE AVEC SUCCÈS !")
        print("="*60)
        print("\n📝 INFORMATIONS DE CONNEXION:")
        print("   URL: https://mbeka-facturation.onrender.com/login")
        print("   Username: admin")
        print("   Password: admin123")
        print("\n⚠️ IMPORTANT: Changez ce mot de passe après la première connexion !")
        print("="*60)
    else:
        print("\n❌ Échec de l'initialisation")
        sys.exit(1)
