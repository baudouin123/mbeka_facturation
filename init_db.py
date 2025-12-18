from app import app, db, Utilisateur, Client, VOTRE_ENTREPRISE

def init_database():
    with app.app_context():
        # Créer les tables
        db.create_all()

        # Créer l'utilisateur admin s'il n'existe pas
        admin = Utilisateur.query.filter_by(username='admin').first()
        if not admin:
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
            print("✅ Admin créé")

        # Créer votre entreprise comme client
        entreprise = Client.query.filter_by(nom=VOTRE_ENTREPRISE['nom']).first()
        if not entreprise:
            entreprise = Client(
                nom=VOTRE_ENTREPRISE['nom'],
                adresse=VOTRE_ENTREPRISE['adresse'],
                ville=VOTRE_ENTREPRISE['ville'],
                email=VOTRE_ENTREPRISE['email'],
                telephone=VOTRE_ENTREPRISE['telephone'],
                siret=VOTRE_ENTREPRISE['siret']
            )
            db.session.add(entreprise)
            db.session.commit()
            print("✅ Entreprise créée")

if __name__ == '__main__':
    init_database()
