import os
import sys

# Configurer la base de données PostgreSQL directement
os.environ['DATABASE_URL'] = 'postgresql://mbeka_user:5G2MXzg6BMstri5qB0pTclTHrUSVm9Ok@dpg-d4vj7jnpm1nc73bprt3g-a.frankfurt-postgres.render.com/mbeka_db'

from app import app, db, Utilisateur

def create_admin():
    with app.app_context():
        # Créer les tables
        db.create_all()
        print("✅ Tables créées")

        # Supprimer l'ancien admin si existe
        old_admin = Utilisateur.query.filter_by(username='admin').first()
        if old_admin:
            db.session.delete(old_admin)
            db.session.commit()
            print("🗑️ Ancien admin supprimé")

        # Créer le nouvel admin
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
        db.session.commit()

        print("✅ ADMIN CRÉÉ AVEC SUCCÈS!")
        print("Username: admin")
        print("Password: admin123")

        # Vérifier
        test = Utilisateur.query.filter_by(username='admin').first()
        if test:
            print(f"✅ Vérification OK - Admin ID: {test.id}")
        else:
            print("❌ ERREUR - Admin non trouvé!")

if __name__ == '__main__':
    create_admin()
