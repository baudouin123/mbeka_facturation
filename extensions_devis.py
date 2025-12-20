"""
============================================================================
EXTENSIONS DEVIS - SYSTÈME DE GESTION DES DEVIS
============================================================================
Ce fichier étend app.py avec la gestion des devis.
Ne PAS modifier app.py, juste importer ce fichier !
============================================================================
"""

from flask import render_template, request, jsonify, send_file, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime, date, timedelta
import json
import os


def init_devis(app, db):
    """Initialise le système de devis"""
    
    # Import des générateurs PDF et email
    try:
        from devis_pdf_generator import generer_pdf_devis
    except:
        def generer_pdf_devis(devis):
            print("⚠️ devis_pdf_generator non trouvé")
            return None
    
    try:
        from email_service_devis import envoyer_email_devis
    except:
        def envoyer_email_devis(devis):
            return {'success': False, 'error': 'Module email non trouvé'}
    
    # ========================================================================
    # MODÈLE DEVIS
    # ========================================================================
    
    class Devis(db.Model):
        __tablename__ = 'devis'
        
        id = db.Column(db.Integer, primary_key=True)
        numero = db.Column(db.String(50), unique=True, nullable=False)
        date_devis = db.Column(db.Date, nullable=False)
        date_validite = db.Column(db.Date, nullable=False)
        
        client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
        client = db.relationship('Client', backref='devis')
        
        total_ht = db.Column(db.Float, default=0.0)
        tva_montant = db.Column(db.Float, default=0.0)
        tva_taux = db.Column(db.Float, default=16.0)
        total_ttc = db.Column(db.Float, nullable=False)
        
        items_json = db.Column(db.Text)
        statut = db.Column(db.String(20), default='brouillon')
        notes = db.Column(db.Text)
        conditions = db.Column(db.Text)
        fichier_pdf = db.Column(db.String(200))
        
        facture_id = db.Column(db.Integer, db.ForeignKey('facture.id'), nullable=True)
        date_conversion = db.Column(db.DateTime, nullable=True)
        
        date_creation = db.Column(db.DateTime, default=datetime.now)
        date_modification = db.Column(db.DateTime, default=datetime.now)
        date_envoi = db.Column(db.DateTime, nullable=True)
        date_acceptation = db.Column(db.DateTime, nullable=True)
        date_refus = db.Column(db.DateTime, nullable=True)
        
        created_by = db.Column(db.Integer, db.ForeignKey('utilisateur.id'))
        
        def to_dict(self):
            est_expire = self.date_validite < date.today() if self.date_validite else False
            
            return {
                'id': self.id,
                'numero': self.numero,
                'date_devis': self.date_devis.strftime('%d/%m/%Y'),
                'date_validite': self.date_validite.strftime('%d/%m/%Y'),
                'jours_restants': (self.date_validite - date.today()).days if self.date_validite >= date.today() else 0,
                'est_expire': est_expire,
                'client_id': self.client_id,
                'client_nom': self.client.nom if self.client else '',
                'client_email': self.client.email if self.client else '',
                'total_ht': round(self.total_ht, 2),
                'tva_taux': self.tva_taux,
                'tva_montant': round(self.tva_montant, 2),
                'total_ttc': round(self.total_ttc, 2),
                'items': json.loads(self.items_json) if self.items_json else [],
                'statut': self.statut,
                'notes': self.notes or '',
                'conditions': self.conditions or '',
                'fichier_pdf': self.fichier_pdf,
                'facture_id': self.facture_id,
                'date_creation': self.date_creation.strftime('%d/%m/%Y %H:%M'),
                'date_envoi': self.date_envoi.strftime('%d/%m/%Y %H:%M') if self.date_envoi else None
            }
    
    # ========================================================================
    # FONCTION GÉNÉRATION NUMÉRO
    # ========================================================================
    
    def generer_numero_devis():
        annee = datetime.now().year
        prefix = f'DEVIS-{annee}-'
        
        dernier = Devis.query.filter(Devis.numero.like(f'{prefix}%')).order_by(Devis.id.desc()).first()
        
        if dernier:
            try:
                num = int(dernier.numero.split('-')[-1])
                nouveau = num + 1
            except:
                nouveau = 1
        else:
            nouveau = 1
        
        return f'{prefix}{nouveau:03d}'
    
    # ========================================================================
    # CONSTANTES
    # ========================================================================
    
    CONDITIONS_DEVIS_DEFAUT = """Conditions générales:
- Devis valable 30 jours
- Paiement à réception de facture
- TVA de 16% applicable"""
    
    # ========================================================================
    # FONCTION LOG
    # ========================================================================
    
    def log_action(action, details):
        try:
            from app import Log
            log = Log(
                utilisateur_id=current_user.id,
                utilisateur_nom=current_user.username,
                action=action,
                details=details
            )
            db.session.add(log)
            db.session.commit()
        except:
            pass
    
    def parse_date(value):
        for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
            try:
                return datetime.strptime(value, fmt).date()
            except:
                pass
        return date.today()
    
    # ========================================================================
    # ROUTES
    # ========================================================================
    
    @app.route('/devis')
    @login_required
    def devis():
        from app import VOTRE_ENTREPRISE
        return render_template('devis.html', entreprise=VOTRE_ENTREPRISE, user=current_user)
    
    @app.route('/nouveau-devis')
    @login_required
    def nouveau_devis():
        from app import VOTRE_ENTREPRISE
        return render_template('nouveau_devis.html', entreprise=VOTRE_ENTREPRISE, user=current_user)
    
    @app.route('/api/devis', methods=['GET'])
    @login_required
    def api_liste_devis():
        try:
            statut = request.args.get('statut')
            client_id = request.args.get('client_id', type=int)
            
            query = Devis.query
            
            if statut and statut != 'tous':
                query = query.filter_by(statut=statut)
            if client_id:
                query = query.filter_by(client_id=client_id)
            
            # Mettre à jour expirés
            expires = query.filter(Devis.date_validite < date.today(), 
                                 Devis.statut.in_(['brouillon', 'envoye'])).all()
            for d in expires:
                d.statut = 'expire'
            db.session.commit()
            
            devis_list = query.order_by(Devis.date_creation.desc()).all()
            
            return jsonify([d.to_dict() for d in devis_list])
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/devis/creer', methods=['POST'])
    @login_required
    def api_creer_devis():
        try:
            data = request.json
            
            if not data.get('client_id'):
                return jsonify({'error': 'Client requis'}), 400
            
            nouveau_devis = Devis(
                numero=generer_numero_devis(),
                date_devis=parse_date(data.get('date_devis', date.today().strftime('%Y-%m-%d'))),
                date_validite=parse_date(data.get('date_validite')) if data.get('date_validite') else 
                             (date.today() + timedelta(days=30)),
                client_id=data['client_id'],
                total_ht=float(data.get('total_ht', 0)),
                tva_taux=float(data.get('tva_taux', 16)),
                tva_montant=float(data.get('tva_montant', 0)),
                total_ttc=float(data.get('total_ttc', 0)),
                items_json=json.dumps(data['items']),
                notes=data.get('notes', ''),
                conditions=data.get('conditions', CONDITIONS_DEVIS_DEFAUT),
                statut=data.get('statut', 'brouillon'),
                created_by=current_user.id
            )
            
            db.session.add(nouveau_devis)
            db.session.commit()
            
            fichier_pdf = generer_pdf_devis(nouveau_devis)
            if fichier_pdf:
                nouveau_devis.fichier_pdf = fichier_pdf
                db.session.commit()
            
            log_action('DEVIS_CREATION', f'Devis {nouveau_devis.numero} créé')
            
            return jsonify({
                'success': True,
                'message': 'Devis créé',
                'devis': nouveau_devis.to_dict()
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/devis/<int:devis_id>', methods=['GET'])
    @login_required
    def api_get_devis(devis_id):
        try:
            d = Devis.query.get(devis_id)
            if not d:
                return jsonify({'error': 'Devis introuvable'}), 404
            return jsonify(d.to_dict())
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/devis/<int:devis_id>/modifier', methods=['PUT'])
    @login_required
    def api_modifier_devis(devis_id):
        try:
            d = Devis.query.get(devis_id)
            if not d:
                return jsonify({'error': 'Devis introuvable'}), 404
            
            if d.statut not in ['brouillon', 'envoye']:
                return jsonify({'error': 'Ce devis ne peut plus être modifié'}), 400
            
            data = request.json
            
            if 'client_id' in data:
                d.client_id = data['client_id']
            if 'date_devis' in data:
                d.date_devis = parse_date(data['date_devis'])
            if 'date_validite' in data:
                d.date_validite = parse_date(data['date_validite'])
            if 'items' in data:
                d.items_json = json.dumps(data['items'])
            if 'total_ht' in data:
                d.total_ht = float(data['total_ht'])
            if 'tva_montant' in data:
                d.tva_montant = float(data['tva_montant'])
            if 'total_ttc' in data:
                d.total_ttc = float(data['total_ttc'])
            if 'notes' in data:
                d.notes = data['notes']
            
            d.date_modification = datetime.now()
            db.session.commit()
            
            fichier_pdf = generer_pdf_devis(d)
            if fichier_pdf:
                d.fichier_pdf = fichier_pdf
                db.session.commit()
            
            log_action('DEVIS_MODIFICATION', f'Devis {d.numero} modifié')
            
            return jsonify({'success': True, 'devis': d.to_dict()})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/devis/<int:devis_id>/supprimer', methods=['DELETE'])
    @login_required
    def api_supprimer_devis(devis_id):
        try:
            d = Devis.query.get(devis_id)
            if not d:
                return jsonify({'error': 'Devis introuvable'}), 404
            
            if d.statut != 'brouillon':
                return jsonify({'error': 'Seuls les brouillons peuvent être supprimés'}), 400
            
            if d.fichier_pdf and os.path.exists(d.fichier_pdf):
                os.remove(d.fichier_pdf)
            
            db.session.delete(d)
            db.session.commit()
            
            log_action('DEVIS_SUPPRESSION', f'Devis supprimé')
            
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/devis/<int:devis_id>/convertir-facture', methods=['POST'])
    @login_required
    def api_convertir_devis_facture(devis_id):
        try:
            from app import Facture, generer_numero_facture
            
            d = Devis.query.get(devis_id)
            if not d:
                return jsonify({'error': 'Devis introuvable'}), 404
            
            if d.statut == 'converti':
                return jsonify({'error': 'Déjà converti'}), 400
            if d.statut != 'accepte':
                return jsonify({'error': 'Seuls les devis acceptés peuvent être convertis'}), 400
            
            facture = Facture(
                numero=generer_numero_facture('client'),
                type_facture='client',
                date_facture=date.today(),
                client_id=d.client_id,
                total_net=d.total_ttc,
                details_json=d.items_json,
                notes=f"Facture depuis devis {d.numero}\n{d.notes or ''}",
                statut='validee',
                statut_paiement='impayee'
            )
            
            db.session.add(facture)
            db.session.commit()
            
            d.facture_id = facture.id
            d.statut = 'converti'
            d.date_conversion = datetime.now()
            db.session.commit()
            
            log_action('DEVIS_CONVERSION', f'Devis {d.numero} → Facture {facture.numero}')
            
            return jsonify({
                'success': True,
                'message': f'Converti en facture {facture.numero}',
                'facture_id': facture.id,
                'facture_numero': facture.numero
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/telecharger_devis/<int:devis_id>')
    @login_required
    def telecharger_devis(devis_id):
        d = Devis.query.get(devis_id)
        if not d:
            return redirect(url_for('devis'))
        
        if not d.fichier_pdf or not os.path.exists(d.fichier_pdf):
            fichier_pdf = generer_pdf_devis(d)
            if fichier_pdf:
                d.fichier_pdf = fichier_pdf
                db.session.commit()
        
        return send_file(d.fichier_pdf, as_attachment=True, download_name=f'{d.numero}.pdf')
    
    @app.route('/voir_devis/<int:devis_id>')
    @login_required
    def voir_devis(devis_id):
        d = Devis.query.get(devis_id)
        if not d:
            return redirect(url_for('devis'))
        
        if not d.fichier_pdf or not os.path.exists(d.fichier_pdf):
            fichier_pdf = generer_pdf_devis(d)
            if fichier_pdf:
                d.fichier_pdf = fichier_pdf
                db.session.commit()
        
        return send_file(d.fichier_pdf, mimetype='application/pdf')
    
    @app.route('/api/devis/<int:devis_id>/envoyer-email', methods=['POST'])
    @login_required
    def api_envoyer_email_devis(devis_id):
        try:
            d = Devis.query.get(devis_id)
            if not d:
                return jsonify({'error': 'Devis introuvable'}), 404
            
            if not d.client or not d.client.email:
                return jsonify({'error': 'Le client n\'a pas d\'email'}), 400
            
            resultat = envoyer_email_devis(d)
            
            if resultat['success']:
                if d.statut == 'brouillon':
                    d.statut = 'envoye'
                    d.date_envoi = datetime.now()
                    db.session.commit()
                
                log_action('DEVIS_EMAIL', f'Devis {d.numero} envoyé')
                
                return jsonify({'success': True, 'message': f'Envoyé à {d.client.email}'})
            else:
                return jsonify({'error': resultat['error']}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/devis/statistiques', methods=['GET'])
    @login_required
    def api_statistiques_devis():
        try:
            total = Devis.query.count()
            acceptes = Devis.query.filter_by(statut='accepte').count()
            refuses = Devis.query.filter_by(statut='refuse').count()
            convertis = Devis.query.filter_by(statut='converti').count()
            
            avec_reponse = acceptes + refuses
            taux = (acceptes / avec_reponse * 100) if avec_reponse > 0 else 0
            
            return jsonify({
                'total_devis': total,
                'par_statut': {
                    'brouillon': Devis.query.filter_by(statut='brouillon').count(),
                    'envoye': Devis.query.filter_by(statut='envoye').count(),
                    'accepte': acceptes,
                    'refuse': refuses,
                    'converti': convertis,
                    'expire': Devis.query.filter_by(statut='expire').count()
                },
                'taux_acceptation': round(taux, 1)
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # ========================================================================
    # INITIALISER AU DÉMARRAGE
    # ========================================================================
    
    with app.app_context():
        try:
            db.create_all()
        except:
            pass
    
    print("✅ Extension DEVIS chargée avec succès")
