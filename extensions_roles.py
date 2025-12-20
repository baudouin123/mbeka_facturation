"""
============================================================================
EXTENSIONS ROLES - SYSTÈME DE GESTION DES RÔLES PERSONNALISABLES
============================================================================
Ce fichier étend app.py avec la gestion des rôles personnalisables.
Ne PAS modifier app.py, juste importer ce fichier !
============================================================================
"""

from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime
import json


# ============================================================================
# FONCTION D'INITIALISATION
# ============================================================================

def init_roles(app, db):
    """
    Initialise le système de rôles personnalisables
    Appelée depuis app.py
    """
    
    # ========================================================================
    # MODÈLES DE DONNÉES
    # ========================================================================
    
    class Role(db.Model):
        """Modèle pour les rôles personnalisables"""
        __tablename__ = 'role'
        
        id = db.Column(db.Integer, primary_key=True)
        nom = db.Column(db.String(50), unique=True, nullable=False)
        code = db.Column(db.String(30), unique=True, nullable=False)
        description = db.Column(db.Text)
        couleur = db.Column(db.String(7), default='#3498db')
        est_systeme = db.Column(db.Boolean, default=False)
        actif = db.Column(db.Boolean, default=True)
        date_creation = db.Column(db.DateTime, default=datetime.utcnow)
        created_by = db.Column(db.Integer, db.ForeignKey('utilisateur.id'))
        
        permissions_role = db.relationship('RolePermission', backref='role', cascade='all, delete-orphan', lazy=True)
        
        def to_dict(self):
            return {
                'id': self.id,
                'nom': self.nom,
                'code': self.code,
                'description': self.description,
                'couleur': self.couleur,
                'est_systeme': self.est_systeme,
                'actif': self.actif,
                'nb_utilisateurs': db.session.query(db.func.count(db.text('utilisateur.id'))).filter(
                    db.text('utilisateur.role = :code')).params(code=self.code).scalar() or 0,
                'permissions': {p.page: p.actif for p in self.permissions_role},
                'date_creation': self.date_creation.strftime('%Y-%m-%d %H:%M') if self.date_creation else None
            }
    
    
    class RolePermission(db.Model):
        """Permissions attachées à un rôle"""
        __tablename__ = 'role_permission'
        
        id = db.Column(db.Integer, primary_key=True)
        role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
        page = db.Column(db.String(50), nullable=False)
        actif = db.Column(db.Boolean, default=True)
        
        __table_args__ = (
            db.UniqueConstraint('role_id', 'page', name='unique_role_page'),
        )
    
    
    # ========================================================================
    # FONCTION D'INITIALISATION DES RÔLES PAR DÉFAUT
    # ========================================================================
    
    def initialiser_roles_systeme():
        """Crée les 3 rôles système par défaut"""
        
        # Import PAGES_DISPONIBLES depuis app.py
        from app import PAGES_DISPONIBLES
        
        roles_systeme = [
            {
                'nom': 'Administrateur',
                'code': 'admin',
                'description': 'Accès complet à toutes les fonctionnalités',
                'couleur': '#e74c3c',
                'est_systeme': True,
                'permissions': {page: True for page in PAGES_DISPONIBLES}
            },
            {
                'nom': 'Comptable',
                'code': 'comptable',
                'description': 'Gestion des factures, clients et employés',
                'couleur': '#3498db',
                'est_systeme': True,
                'permissions': {
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
                    'utilisateurs': False,
                    'saisie_journaliere': True
                }
            },
            {
                'nom': 'Employé',
                'code': 'employe',
                'description': 'Consultation des données uniquement',
                'couleur': '#95a5a6',
                'est_systeme': True,
                'permissions': {
                    'dashboard': True,
                    'calendrier': True,
                    'factures': True,
                    'historique': True,
                    'nouvelle_facture_client': False,
                    'nouvelle_facture_employe': False,
                    'clients': False,
                    'employes': False,
                    'recherche': False,
                    'sauvegardes': False,
                    'utilisateurs': False,
                    'saisie_journaliere': False
                }
            }
        ]
        
        for role_data in roles_systeme:
            role_existant = Role.query.filter_by(code=role_data['code']).first()
            
            if not role_existant:
                nouveau_role = Role(
                    nom=role_data['nom'],
                    code=role_data['code'],
                    description=role_data['description'],
                    couleur=role_data['couleur'],
                    est_systeme=role_data['est_systeme'],
                    actif=True
                )
                db.session.add(nouveau_role)
                db.session.flush()
                
                for page, actif in role_data['permissions'].items():
                    perm = RolePermission(
                        role_id=nouveau_role.id,
                        page=page,
                        actif=actif
                    )
                    db.session.add(perm)
                
                print(f"✅ Rôle système créé: {role_data['nom']}")
        
        try:
            db.session.commit()
            print("✅ Initialisation des rôles système terminée")
        except Exception as e:
            db.session.rollback()
            print(f"⚠️ Erreur initialisation rôles: {e}")
    
    
    # ========================================================================
    # DÉCORATEUR ADMIN
    # ========================================================================
    
    def admin_required(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role != 'admin':
                flash('Accès refusé. Vous devez être administrateur.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    
    
    # ========================================================================
    # FONCTION LOG
    # ========================================================================
    
    def log_action(action, details):
        """Log simplifié"""
        try:
            from app import Log
            log = Log(
                utilisateur_id=current_user.id if current_user.is_authenticated else None,
                utilisateur_nom=current_user.username if current_user.is_authenticated else 'Système',
                action=action,
                details=details
            )
            db.session.add(log)
            db.session.commit()
        except:
            pass
    
    
    # ========================================================================
    # ROUTES
    # ========================================================================
    
    @app.route('/roles')
    @login_required
    @admin_required
    def roles():
        """Page de gestion des rôles"""
        from app import VOTRE_ENTREPRISE, PAGES_DISPONIBLES
        return render_template('roles.html',
                             entreprise=VOTRE_ENTREPRISE,
                             user=current_user,
                             pages_disponibles=PAGES_DISPONIBLES)
    
    
    @app.route('/api/roles', methods=['GET'])
    @login_required
    @admin_required
    def api_liste_roles():
        """API: Liste de tous les rôles"""
        try:
            roles_list = Role.query.order_by(
                Role.est_systeme.desc(),
                Role.nom
            ).all()
            
            return jsonify([r.to_dict() for r in roles_list])
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/roles/creer', methods=['POST'])
    @login_required
    @admin_required
    def api_creer_role():
        """API: Créer un nouveau rôle"""
        try:
            from app import PAGES_DISPONIBLES
            data = request.json
            
            if not data.get('nom'):
                return jsonify({'error': 'Nom du rôle requis'}), 400
            
            code = data['nom'].lower().replace(' ', '_').replace('é', 'e').replace('è', 'e')
            code = ''.join(c for c in code if c.isalnum() or c == '_')
            
            if Role.query.filter_by(code=code).first():
                return jsonify({'error': f'Un rôle avec le code "{code}" existe déjà'}), 400
            
            nouveau_role = Role(
                nom=data['nom'],
                code=code,
                description=data.get('description', ''),
                couleur=data.get('couleur', '#3498db'),
                est_systeme=False,
                actif=True,
                created_by=current_user.id
            )
            
            db.session.add(nouveau_role)
            db.session.flush()
            
            permissions_data = data.get('permissions', {})
            for page in PAGES_DISPONIBLES.keys():
                perm = RolePermission(
                    role_id=nouveau_role.id,
                    page=page,
                    actif=permissions_data.get(page, False)
                )
                db.session.add(perm)
            
            db.session.commit()
            
            log_action('ROLE_CREATION', f'Rôle "{nouveau_role.nom}" créé')
            
            return jsonify({
                'success': True,
                'message': 'Rôle créé avec succès',
                'role': nouveau_role.to_dict()
            })
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/roles/<int:role_id>', methods=['GET'])
    @login_required
    @admin_required
    def api_get_role(role_id):
        """API: Récupérer un rôle"""
        try:
            role = Role.query.get(role_id)
            if not role:
                return jsonify({'error': 'Rôle introuvable'}), 404
            
            return jsonify(role.to_dict())
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/roles/<int:role_id>/modifier', methods=['PUT'])
    @login_required
    @admin_required
    def api_modifier_role(role_id):
        """API: Modifier un rôle"""
        try:
            role = Role.query.get(role_id)
            if not role:
                return jsonify({'error': 'Rôle introuvable'}), 404
            
            data = request.json
            
            if role.est_systeme:
                # Rôles système : modifier seulement les permissions
                if 'permissions' in data:
                    for page, actif in data['permissions'].items():
                        perm = RolePermission.query.filter_by(
                            role_id=role.id,
                            page=page
                        ).first()
                        
                        if perm:
                            perm.actif = actif
                        else:
                            nouvelle_perm = RolePermission(
                                role_id=role.id,
                                page=page,
                                actif=actif
                            )
                            db.session.add(nouvelle_perm)
                    
                    db.session.commit()
                    log_action('ROLE_MODIFICATION', f'Permissions du rôle "{role.nom}" modifiées')
                    
                    return jsonify({
                        'success': True,
                        'message': 'Permissions mises à jour',
                        'role': role.to_dict()
                    })
                else:
                    return jsonify({'error': 'Les rôles système ne peuvent être modifiés (sauf permissions)'}), 400
            
            # Rôles personnalisés : tout modifier
            if 'nom' in data:
                role.nom = data['nom']
            if 'description' in data:
                role.description = data['description']
            if 'couleur' in data:
                role.couleur = data['couleur']
            if 'actif' in data:
                role.actif = data['actif']
            
            if 'permissions' in data:
                for page, actif in data['permissions'].items():
                    perm = RolePermission.query.filter_by(
                        role_id=role.id,
                        page=page
                    ).first()
                    
                    if perm:
                        perm.actif = actif
                    else:
                        nouvelle_perm = RolePermission(
                            role_id=role.id,
                            page=page,
                            actif=actif
                        )
                        db.session.add(nouvelle_perm)
            
            db.session.commit()
            
            log_action('ROLE_MODIFICATION', f'Rôle "{role.nom}" modifié')
            
            return jsonify({
                'success': True,
                'message': 'Rôle mis à jour',
                'role': role.to_dict()
            })
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/roles/<int:role_id>/supprimer', methods=['DELETE'])
    @login_required
    @admin_required
    def api_supprimer_role(role_id):
        """API: Supprimer un rôle"""
        try:
            from app import Utilisateur
            
            role = Role.query.get(role_id)
            if not role:
                return jsonify({'error': 'Rôle introuvable'}), 404
            
            if role.est_systeme:
                return jsonify({'error': 'Les rôles système ne peuvent être supprimés'}), 400
            
            nb_users = Utilisateur.query.filter_by(role=role.code).count()
            if nb_users > 0:
                return jsonify({
                    'error': f'{nb_users} utilisateur(s) ont ce rôle. Réassignez-les avant de supprimer.'
                }), 400
            
            nom = role.nom
            db.session.delete(role)
            db.session.commit()
            
            log_action('ROLE_SUPPRESSION', f'Rôle "{nom}" supprimé')
            
            return jsonify({
                'success': True,
                'message': 'Rôle supprimé'
            })
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    
    @app.route('/api/roles/<int:role_id>/dupliquer', methods=['POST'])
    @login_required
    @admin_required
    def api_dupliquer_role(role_id):
        """API: Dupliquer un rôle"""
        try:
            role_original = Role.query.get(role_id)
            if not role_original:
                return jsonify({'error': 'Rôle introuvable'}), 404
            
            nouveau_nom = f"{role_original.nom} (copie)"
            nouveau_code = f"{role_original.code}_copie"
            
            compteur = 1
            while Role.query.filter_by(code=nouveau_code).first():
                nouveau_code = f"{role_original.code}_copie{compteur}"
                nouveau_nom = f"{role_original.nom} (copie {compteur})"
                compteur += 1
            
            nouveau_role = Role(
                nom=nouveau_nom,
                code=nouveau_code,
                description=f"Copie de {role_original.nom}",
                couleur=role_original.couleur,
                est_systeme=False,
                actif=True,
                created_by=current_user.id
            )
            
            db.session.add(nouveau_role)
            db.session.flush()
            
            for perm_original in role_original.permissions_role:
                nouvelle_perm = RolePermission(
                    role_id=nouveau_role.id,
                    page=perm_original.page,
                    actif=perm_original.actif
                )
                db.session.add(nouvelle_perm)
            
            db.session.commit()
            
            log_action('ROLE_DUPLICATION', f'Rôle "{role_original.nom}" dupliqué')
            
            return jsonify({
                'success': True,
                'message': 'Rôle dupliqué',
                'role': nouveau_role.to_dict()
            })
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    
    # ========================================================================
    # INITIALISER LES RÔLES AU DÉMARRAGE
    # ========================================================================
    
    with app.app_context():
        try:
            db.create_all()
            initialiser_roles_systeme()
        except Exception as e:
            print(f"⚠️ Erreur initialisation rôles: {e}")
    
    
    print("✅ Extension ROLES chargée avec succès")
