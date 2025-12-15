"""
Script d'initialisation de la base de données
Crée automatiquement un utilisateur admin si aucun n'existe
"""
from app import app, db, Utilisateur

def init_database():
    """Initialise la base de données et crée un admin par défaut"""
    with app.app_context():
        # Créer toutes les tables si elles n'existent pas
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
            
            print("=" * 50)
            print("✅ UTILISATEUR ADMIN CRÉÉ !")
            print("=" * 50)
            print("Username: admin")
            print("Password: Admin2024!")
            print("=" * 50)
            print("⚠️  CHANGEZ CE MOT DE PASSE après la première connexion !")
            print("=" * 50)
        else:
            print("ℹ️  Un administrateur existe déjà")

if __name__ == '__main__':
    init_database()
