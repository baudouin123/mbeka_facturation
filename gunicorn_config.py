# ============================================================================
# CONFIGURATION GUNICORN OPTIMISÉE - RENDER STANDARD (1 CPU + 2 GB RAM)
# ============================================================================
# Configuration optimale pour le plan Standard de Render
# ============================================================================

import os
import multiprocessing

# ============================================================================
# WORKERS & THREADS - OPTIMISÉ POUR 1 CPU + 2 GB RAM
# ============================================================================
# Avec 1 CPU complet, on peut utiliser 3-4 workers
workers = int(os.environ.get('GUNICORN_WORKERS', '3'))

# 4 threads par worker = bon équilibre
threads = int(os.environ.get('GUNICORN_THREADS', '4'))

# Type de worker : gevent pour SocketIO et I/O asynchrone
# CRITIQUE pour le chat en temps réel !
worker_class = 'gevent'

# ============================================================================
# TIMEOUTS
# ============================================================================
# Timeout des requêtes (120 sec = génération PDF, exports)
timeout = 120

# Timeout gracieux avant de tuer un worker
graceful_timeout = 30

# Keep-alive pour les connexions HTTP persistantes
keepalive = 5

# ============================================================================
# PERFORMANCE & STABILITÉ
# ============================================================================
# Redémarrer un worker après N requêtes (évite les fuites mémoire)
max_requests = 1000
max_requests_jitter = 50

# Limite de la taille des requêtes
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# ============================================================================
# WORKER CONNECTIONS - IMPORTANT POUR SOCKETIO
# ============================================================================
# Avec gevent, on peut gérer beaucoup plus de connexions simultanées
worker_connections = 1000

# ============================================================================
# BINDING
# ============================================================================
# Port depuis la variable d'environnement
port = int(os.environ.get('PORT', '10000'))
bind = f"0.0.0.0:{port}"

# ============================================================================
# LOGS
# ============================================================================
# Niveau de log
loglevel = 'info'

# Logs d'accès et d'erreur
accesslog = '-'  # stdout
errorlog = '-'   # stderr

# Format des logs
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# ============================================================================
# SÉCURITÉ
# ============================================================================
# Forwarded headers (important pour Render)
forwarded_allow_ips = '*'

# ============================================================================
# PRELOAD
# ============================================================================
# Précharger l'app avant de fork les workers
# Économise de la mémoire (~30% moins de RAM utilisée)
preload_app = True

# ============================================================================
# WORKER LIFECYCLE
# ============================================================================
def on_starting(server):
    """Appelé au démarrage du serveur"""
    print("=" * 80)
    print("🚀 MBEKA FACTURATION - DÉMARRAGE EN PRODUCTION")
    print("=" * 80)
    print(f"📍 Plan: Render Standard (1 CPU + 2 GB RAM)")
    print(f"📍 Workers: {workers}")
    print(f"📍 Threads par worker: {threads}")
    print(f"📍 Type de worker: {worker_class}")
    print(f"📍 Connexions par worker: {worker_connections}")
    print(f"📍 Port: {port}")
    print(f"📍 Timeout: {timeout}s")
    print("=" * 80)
    print("✅ Chat en temps réel: ACTIVÉ (gevent)")
    print("✅ Support 100+ utilisateurs simultanés")
    print("=" * 80)

def on_exit(server):
    """Appelé à l'arrêt du serveur"""
    print("=" * 80)
    print("🛑 MBEKA FACTURATION - ARRÊT PROPRE")
    print("=" * 80)

def worker_int(worker):
    """Appelé quand un worker reçoit SIGINT ou SIGTERM"""
    print(f"⚠️  Worker {worker.pid} terminé proprement")

def post_worker_init(worker):
    """Appelé après l'initialisation d'un worker"""
    print(f"✅ Worker {worker.pid} initialisé et prêt")

# ============================================================================
# FIN DE LA CONFIGURATION
# ============================================================================
