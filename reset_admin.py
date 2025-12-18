from app import app, db, Utilisateur

with app.app_context():
    # Supprimer l'ancien admin si existe
    old_admin = Utilisateur.query.filter_by(username='admin').first()
    if old_admin:
        db.session.delete(old_admin)
        db.session.commit()
        print("❌ Ancien admin supprimé")

    # Créer un nouvel admin
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

    print("✅ Nouvel admin créé avec succès!")
    print("Username: admin")
    print("Password: admin123")
