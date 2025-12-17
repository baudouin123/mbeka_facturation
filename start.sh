#!/bin/bash
echo "🔄 Démarrage de l'application MBeka Facturation..."
python -c "from app import init_database; init_database()"
gunicorn app:app
