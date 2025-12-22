# ============================================================================
# CONFIGURATION GUNICORN OPTIMISÉE - MBEKA
# ============================================================================
# Ce fichier configure Gunicorn pour des performances maximales sur Render
# 
# UTILISATION :
# Sur Render Dashboard → Settings → Start Command :
# gunicorn -c gunicorn_config.py app:app
# ============================================================================

import os
import multiprocessing

# ============================================================================
# WORKERS & THREADS
# ============================================================================
# Nombre de workers (processus)
# Formule recommandée : (2 x CPU) + 1
# Render gratuit a 0.5 CPU, donc on met 2 workers
workers = int(os.environ.get('GUNICORN_WORKERS', '2'))

# Nombre de threads par worker
# 4 threads = bon équilibre pour des requêtes mixtes (DB + I/O)
threads = int(os.environ.get('GUNICORN_THREADS', '4'))

# Type de worker
# 'sync' = standard, 'gevent' = asynchrone (meilleur pour I/O)
# Pour Flask avec SocketIO, on utilise 'gevent'
worker_class = 'gevent'

# ============================================================================
# TIMEOUTS
# ============================================================================
# Timeout des requêtes (en secondes)
# 120 sec = suffisant pour les requêtes lentes (génération PDF)
timeout = 120

# Timeout gracieux avant de tuer un worker
graceful_timeout = 30

# Keep-alive pour les connexions HTTP persistantes
keepalive = 5

# ============================================================================
# PERFORMANCE
# ============================================================================
# Redémarrer un worker après N requêtes (évite les fuites mémoire)
max_requests = 1000
max_requests_jitter = 50  # Aléatoire pour éviter les redémarrages simultanés

# Limite de la taille des requêtes (en octets)
# 16 MB = suffisant pour upload de fichiers
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# ============================================================================
# BINDING
# ============================================================================
# Port depuis la variable d'environnement (Render fournit $PORT)
port = int(os.environ.get('PORT', '10000'))
bind = f"0.0.0.0:{port}"

# ============================================================================
# LOGS
# ============================================================================
# Niveau de log ('debug', 'info', 'warning', 'error', 'critical')
loglevel = 'info'

# Logs d'accès (désactiver en production pour performance)
accesslog = '-'  # '-' = stdout
errorlog = '-'   # '-' = stderr

# Format des logs d'accès
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# ============================================================================
# SÉCURITÉ
# ============================================================================
# Forwarded headers (important pour Render)
forwarded_allow_ips = '*'

# ============================================================================
# PRELOAD (OPTIONNEL)
# ============================================================================
# Précharger l'app avant de fork les workers
# Économise de la mémoire mais peut causer des problèmes avec certaines libs
preload_app = True

# ============================================================================
# CALLBACKS (OPTIONNEL)
# ============================================================================
def on_starting(server):
    """Appelé au démarrage du serveur"""
    print("=" * 80)
    print("🚀 MBEKA FACTURATION - DÉMARRAGE EN PRODUCTION")
    print("=" * 80)
    print(f"📍 Workers: {workers}")
    print(f"📍 Threads par worker: {threads}")
    print(f"📍 Type de worker: {worker_class}")
    print(f"📍 Port: {port}")
    print(f"📍 Timeout: {timeout}s")
    print("=" * 80)

def on_exit(server):
    """Appelé à l'arrêt du serveur"""
    print("=" * 80)
    print("🛑 MBEKA FACTURATION - ARRÊT")
    print("=" * 80)

# ============================================================================
# FIN DE LA CONFIGURATION
# ============================================================================
