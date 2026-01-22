"""
King'immob - Backend API
Système de gestion immobilière multi-tenant pour la Côte d'Ivoire
Créé par: DIABATE MADARA ABOUBAKAR - King Services
"""

from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import os
from datetime import datetime, timedelta
from functools import wraps
import json
import csv
import io
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.pdfgen import canvas

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configuration
DATABASE = 'kingimmob.db'
UPLOAD_FOLDER = 'uploads/logos'
QUITTANCES_FOLDER = 'quittances'
SECRET_KEY = secrets.token_hex(32)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUITTANCES_FOLDER, exist_ok=True)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max

# ==================== DATABASE ====================

def get_db():
    """Connexion à la base de données"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialiser la base de données"""
    import os
    
    # Vérifier si le fichier SQL existe
    if not os.path.exists('kingimmob_schema.sql'):
        print("⚠️ Fichier kingimmob_schema.sql non trouvé !")
        print("🔧 Création de la base avec SQL inline...")
        
        # SQL inline de secours
        sql_script = """
-- Table Super Admins (Administrateurs King Services)
CREATE TABLE IF NOT EXISTS super_admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nom_complet TEXT NOT NULL,
    email TEXT NOT NULL,
    telephone TEXT,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table Propriétaires (Clients de King Services)
CREATE TABLE IF NOT EXISTS proprietaires (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nom_entreprise TEXT NOT NULL,
    nom_complet TEXT NOT NULL,
    email TEXT NOT NULL,
    telephone TEXT NOT NULL,
    ville TEXT,
    quartier TEXT,
    adresse TEXT,
    abonnement TEXT DEFAULT 'gratuit',
    statut TEXT DEFAULT 'actif',
    date_inscription TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_expiration DATE,
    logo_path TEXT
);

-- Table Propriétés
CREATE TABLE IF NOT EXISTS proprietes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proprietaire_id INTEGER NOT NULL,
    nom TEXT NOT NULL,
    type TEXT NOT NULL,
    ville TEXT NOT NULL,
    quartier TEXT NOT NULL,
    adresse TEXT NOT NULL,
    loyer_mensuel REAL NOT NULL,
    caution REAL,
    statut TEXT DEFAULT 'disponible',
    date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (proprietaire_id) REFERENCES proprietaires(id)
);

-- Table Locataires
CREATE TABLE IF NOT EXISTS locataires (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proprietaire_id INTEGER NOT NULL,
    propriete_id INTEGER,
    nom_complet TEXT NOT NULL,
    telephone TEXT NOT NULL,
    email TEXT,
    date_entree DATE,
    loyer_mensuel REAL NOT NULL,
    caution_versee REAL,
    statut TEXT DEFAULT 'actif',
    date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (proprietaire_id) REFERENCES proprietaires(id),
    FOREIGN KEY (propriete_id) REFERENCES proprietes(id)
);

-- Table Paiements
CREATE TABLE IF NOT EXISTS paiements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proprietaire_id INTEGER NOT NULL,
    locataire_id INTEGER NOT NULL,
    montant REAL NOT NULL,
    mode_paiement TEXT NOT NULL,
    date_paiement DATE NOT NULL,
    periode_debut DATE,
    periode_fin DATE,
    reference_transaction TEXT,
    statut TEXT DEFAULT 'paye',
    date_enregistrement TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (proprietaire_id) REFERENCES proprietaires(id),
    FOREIGN KEY (locataire_id) REFERENCES locataires(id)
);

-- Table Terrains/Lots
CREATE TABLE IF NOT EXISTS terrains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proprietaire_id INTEGER NOT NULL,
    nom TEXT NOT NULL,
    superficie REAL NOT NULL,
    unite_superficie TEXT DEFAULT 'm²',
    ville TEXT NOT NULL,
    quartier TEXT NOT NULL,
    adresse TEXT,
    prix_vente REAL NOT NULL,
    statut TEXT DEFAULT 'disponible',
    description TEXT,
    titre_foncier TEXT,
    date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_vente DATE,
    FOREIGN KEY (proprietaire_id) REFERENCES proprietaires(id)
);

-- Insérer le super admin par défaut
INSERT OR IGNORE INTO super_admins (id, username, password_hash, nom_complet, email, telephone)
VALUES (1, 'admin', 'placeholder', 'Administrateur King Services', 'admin@kingservices.ci', '+225 07 58 80 00 39');
"""
    else:
        with open('kingimmob_schema.sql', 'r', encoding='utf-8') as f:
            sql_script = f.read()
    
    conn = get_db()
    conn.executescript(sql_script)
    
    # Hasher le mot de passe admin
    admin_password = hash_password('admin123')
    conn.execute(
        "UPDATE super_admins SET password_hash = ? WHERE username = 'admin'",
        (admin_password,)
    )
    conn.commit()
    conn.close()
    print("✅ Base de données initialisée avec succès!")


def hash_password(password):
    """Hasher un mot de passe"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    """Vérifier un mot de passe"""
    return hash_password(password) == hashed

# ==================== AUTHENTICATION ====================

def create_session_token():
    """Créer un token de session"""
    return secrets.token_urlsafe(32)

def require_auth(f):
    """Décorateur pour protéger les routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token manquant'}), 401
        
        # Vérifier le token (à implémenter avec une vraie gestion de sessions)
        # Pour l'instant, on vérifie juste que le token existe
        
        return f(*args, **kwargs)
    return decorated

# ==================== ROUTES AUTHENTICATION ====================

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    """Connexion (Super Admin ou Propriétaire)"""
    if request.method == 'OPTIONS':
        return '', 204
    
    print("🔍 LOGIN: Requête reçue")
    data = request.json
    print(f"🔍 LOGIN: Data = {data}")
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        print("❌ LOGIN: Username ou password manquant")
        return jsonify({'error': 'Username et password requis'}), 400
    
    conn = get_db()
    
    # Chercher dans super_admins
    admin = conn.execute(
        'SELECT * FROM super_admins WHERE username = ?',
        (username,)
    ).fetchone()
    
    if admin and verify_password(password, admin['password_hash']):
        print(f"✅ LOGIN: Super Admin trouvé - {username}")
        token = create_session_token()
        conn.close()
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': admin['id'],
                'username': admin['username'],
                'nom_complet': admin['nom_complet'],
                'email': admin['email'],
                'role': 'super_admin'
            }
        })
    
    # Chercher dans propriétaires
    proprietaire = conn.execute(
        'SELECT * FROM proprietaires WHERE username = ?',
        (username,)
    ).fetchone()
    
    if proprietaire and verify_password(password, proprietaire['password_hash']):
        print(f"✅ LOGIN: Propriétaire trouvé - {username}")
        # Vérifier le statut de l'abonnement
        if proprietaire['statut'] == 'bloque':
            conn.close()
            return jsonify({'error': 'Compte bloqué. Contactez King Services.'}), 403
        
        if proprietaire['statut'] == 'expire':
            conn.close()
            return jsonify({'error': 'Abonnement expiré. Veuillez renouveler.'}), 403
        
        token = create_session_token()
        conn.close()
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': proprietaire['id'],
                'username': proprietaire['username'],
                'nom_complet': proprietaire['nom_complet'],
                'nom_entreprise': proprietaire['nom_entreprise'],
                'email': proprietaire['email'],
                'abonnement': proprietaire['abonnement'],
                'statut': proprietaire['statut'],
                'date_expiration': proprietaire['date_expiration'],
                'logo_path': proprietaire['logo_path'],
                'role': 'proprietaire'
            }
        })
    
    print(f"❌ LOGIN: Identifiants incorrects pour {username}")
    conn.close()
    return jsonify({'error': 'Identifiants incorrects'}), 401

# ==================== ROUTES SUPER ADMIN ====================

@app.route('/api/admin/proprietaires', methods=['GET'])
def get_proprietaires():
    """Liste tous les propriétaires (Super Admin)"""
    conn = get_db()
    proprietaires = conn.execute('''
        SELECT p.*,
               COUNT(DISTINCT pr.id) as nb_proprietes,
               COUNT(DISTINCT l.id) as nb_locataires
        FROM proprietaires p
        LEFT JOIN proprietes pr ON pr.proprietaire_id = p.id
        LEFT JOIN locataires l ON l.proprietaire_id = p.id
        GROUP BY p.id
        ORDER BY p.created_at DESC
    ''').fetchall()
    
    conn.close()
    return jsonify([dict(p) for p in proprietaires])

@app.route('/api/admin/proprietaires', methods=['POST'])
def create_proprietaire():
    """Créer un nouveau propriétaire (Super Admin)"""
    data = request.json
    
    # Validation
    required = ['username', 'password', 'nom_entreprise', 'nom_complet', 'email', 'telephone']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} requis'}), 400
    
    conn = get_db()
    
    # Vérifier si username existe
    existing = conn.execute(
        'SELECT id FROM proprietaires WHERE username = ?',
        (data['username'],)
    ).fetchone()
    
    if existing:
        conn.close()
        return jsonify({'error': 'Username déjà utilisé'}), 400
    
    # Calculer date d'expiration (14 jours d'essai gratuit)
    date_expiration = (datetime.now() + timedelta(days=14)).isoformat()
    
    # Créer le propriétaire
    cursor = conn.execute('''
        INSERT INTO proprietaires (
            username, password_hash, nom_entreprise, nom_complet,
            email, telephone, whatsapp, ville, quartier, adresse,
            abonnement, statut, date_expiration, limite_proprietes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['username'],
        hash_password(data['password']),
        data['nom_entreprise'],
        data['nom_complet'],
        data['email'],
        data['telephone'],
        data.get('whatsapp', data['telephone']),
        data.get('ville', 'Bouaké'),
        data.get('quartier', ''),
        data.get('adresse', ''),
        'gratuit',
        'actif',
        date_expiration,
        3  # Gratuit: 3 propriétés max
    ))
    
    conn.commit()
    proprietaire_id = cursor.lastrowid
    conn.close()
    
    return jsonify({
        'success': True,
        'proprietaire_id': proprietaire_id,
        'message': 'Propriétaire créé avec succès'
    }), 201

@app.route('/api/admin/proprietaires/<int:id>', methods=['PUT'])
def update_proprietaire(id):
    """Mettre à jour un propriétaire (Super Admin)"""
    data = request.json
    conn = get_db()
    
    # Construire la requête UPDATE dynamiquement
    fields = []
    values = []
    
    allowed_fields = ['nom_entreprise', 'nom_complet', 'email', 'telephone', 
                      'whatsapp', 'ville', 'quartier', 'adresse', 'abonnement', 
                      'statut', 'date_expiration', 'limite_proprietes']
    
    for field in allowed_fields:
        if field in data:
            fields.append(f'{field} = ?')
            values.append(data[field])
    
    if not fields:
        return jsonify({'error': 'Aucun champ à mettre à jour'}), 400
    
    values.append(id)
    query = f"UPDATE proprietaires SET {', '.join(fields)} WHERE id = ?"
    
    conn.execute(query, values)
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Propriétaire mis à jour'})

@app.route('/api/admin/proprietaires/<int:id>', methods=['DELETE'])
def delete_proprietaire(id):
    """Supprimer un propriétaire (Super Admin)"""
    conn = get_db()
    conn.execute('DELETE FROM proprietaires WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Propriétaire supprimé'})

# ==================== NOUVELLES ROUTES - CHANGEMENT MOT DE PASSE ====================

@app.route('/api/admin/proprietaires/<int:id>/reset-password', methods=['POST'])
def reset_proprietaire_password(id):
    """Réinitialiser le mot de passe d'un propriétaire (Super Admin)"""
    data = request.json
    new_password = data.get('new_password')
    
    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Mot de passe trop court (min 6 caractères)'}), 400
    
    conn = get_db()
    password_hash = hash_password(new_password)
    
    conn.execute(
        'UPDATE proprietaires SET password_hash = ? WHERE id = ?',
        (password_hash, id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Mot de passe réinitialisé'})

@app.route('/api/admin/change-password', methods=['POST'])
def admin_change_password():
    """Changer son propre mot de passe (Super Admin)"""
    data = request.json
    username = data.get('username')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not all([username, current_password, new_password]):
        return jsonify({'error': 'Tous les champs sont requis'}), 400
    
    if len(new_password) < 6:
        return jsonify({'error': 'Nouveau mot de passe trop court (min 6 caractères)'}), 400
    
    conn = get_db()
    admin = conn.execute(
        'SELECT * FROM super_admins WHERE username = ?',
        (username,)
    ).fetchone()
    
    if not admin or not verify_password(current_password, admin['password_hash']):
        conn.close()
        return jsonify({'error': 'Mot de passe actuel incorrect'}), 401
    
    password_hash = hash_password(new_password)
    conn.execute(
        'UPDATE super_admins SET password_hash = ? WHERE username = ?',
        (password_hash, username)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Mot de passe changé avec succès'})

@app.route('/api/proprietaire/change-password', methods=['POST'])
def proprietaire_change_password():
    """Changer son propre mot de passe (Propriétaire)"""
    data = request.json
    username = data.get('username')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not all([username, current_password, new_password]):
        return jsonify({'error': 'Tous les champs sont requis'}), 400
    
    if len(new_password) < 6:
        return jsonify({'error': 'Nouveau mot de passe trop court (min 6 caractères)'}), 400
    
    conn = get_db()
    proprietaire = conn.execute(
        'SELECT * FROM proprietaires WHERE username = ?',
        (username,)
    ).fetchone()
    
    if not proprietaire or not verify_password(current_password, proprietaire['password_hash']):
        conn.close()
        return jsonify({'error': 'Mot de passe actuel incorrect'}), 401
    
    password_hash = hash_password(new_password)
    conn.execute(
        'UPDATE proprietaires SET password_hash = ? WHERE username = ?',
        (password_hash, username)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Mot de passe changé avec succès'})

# ==================== EXPORT CSV ====================

@app.route('/api/admin/export/clients', methods=['GET'])
def export_clients():
    """Exporter la liste des clients en CSV"""
    import io
    import csv
    
    conn = get_db()
    clients = conn.execute('''
        SELECT id, nom_entreprise, nom_complet, username, email, telephone, 
               ville, quartier, abonnement, statut, date_inscription, date_expiration
        FROM proprietaires
        ORDER BY date_inscription DESC
    ''').fetchall()
    conn.close()
    
    # Créer le CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # En-têtes
    writer.writerow(['ID', 'Entreprise', 'Nom Complet', 'Username', 'Email', 'Téléphone', 
                    'Ville', 'Quartier', 'Abonnement', 'Statut', 'Date Inscription', 'Date Expiration'])
    
    # Données
    for client in clients:
        writer.writerow([
            client['id'], client['nom_entreprise'], client['nom_complet'], 
            client['username'], client['email'], client['telephone'],
            client['ville'], client['quartier'], client['abonnement'], 
            client['statut'], client['date_inscription'], client['date_expiration']
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=clients_kingimmob.csv'}
    )

@app.route('/api/proprietaire/<int:proprietaire_id>/export/proprietes', methods=['GET'])
def export_proprietes(proprietaire_id):
    """Exporter les propriétés d'un propriétaire en CSV"""
    import io
    import csv
    
    conn = get_db()
    proprietes = conn.execute('''
        SELECT id, nom, type, ville, quartier, adresse, loyer_mensuel, caution, statut, date_ajout
        FROM proprietes
        WHERE proprietaire_id = ?
        ORDER BY date_ajout DESC
    ''', (proprietaire_id,)).fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['ID', 'Nom', 'Type', 'Ville', 'Quartier', 'Adresse', 
                    'Loyer Mensuel', 'Caution', 'Statut', 'Date Ajout'])
    
    for prop in proprietes:
        writer.writerow([
            prop['id'], prop['nom'], prop['type'], prop['ville'], 
            prop['quartier'], prop['adresse'], prop['loyer_mensuel'], 
            prop['caution'], prop['statut'], prop['date_ajout']
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=proprietes_kingimmob.csv'}
    )

@app.route('/api/proprietaire/<int:proprietaire_id>/export/paiements', methods=['GET'])
def export_paiements(proprietaire_id):
    """Exporter les paiements d'un propriétaire en CSV"""
    import io
    import csv
    
    conn = get_db()
    paiements = conn.execute('''
        SELECT p.id, l.nom_complet as locataire, p.montant, p.mode_paiement, 
               p.date_paiement, p.periode_debut, p.periode_fin, p.statut
        FROM paiements p
        JOIN locataires l ON p.locataire_id = l.id
        WHERE p.proprietaire_id = ?
        ORDER BY p.date_paiement DESC
    ''', (proprietaire_id,)).fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['ID', 'Locataire', 'Montant', 'Mode de Paiement', 
                    'Date Paiement', 'Période Début', 'Période Fin', 'Statut'])
    
    for pmt in paiements:
        writer.writerow([
            pmt['id'], pmt['locataire'], pmt['montant'], pmt['mode_paiement'],
            pmt['date_paiement'], pmt['periode_debut'], pmt['periode_fin'], pmt['statut']
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=paiements_kingimmob.csv'}
    )

# ==================== NOTIFICATIONS ====================

@app.route('/api/admin/notifications/expirations', methods=['GET'])
def get_expirations():
    """Obtenir les clients avec abonnement expiré ou proche de l'expiration"""
    from datetime import datetime, timedelta
    
    today = datetime.now().date()
    week_later = today + timedelta(days=7)
    
    conn = get_db()
    
    # Clients expirés
    expired = conn.execute('''
        SELECT id, nom_entreprise, nom_complet, telephone, abonnement, date_expiration
        FROM proprietaires
        WHERE date_expiration < ? AND statut = 'actif'
        ORDER BY date_expiration
    ''', (today.isoformat(),)).fetchall()
    
    # Clients expirant dans 7 jours
    expiring_soon = conn.execute('''
        SELECT id, nom_entreprise, nom_complet, telephone, abonnement, date_expiration
        FROM proprietaires
        WHERE date_expiration BETWEEN ? AND ? AND statut = 'actif'
        ORDER BY date_expiration
    ''', (today.isoformat(), week_later.isoformat())).fetchall()
    
    conn.close()
    
    return jsonify({
        'success': True,
        'expired': [dict(c) for c in expired],
        'expiring_soon': [dict(c) for c in expiring_soon],
        'counts': {
            'expired': len(expired),
            'expiring_soon': len(expiring_soon)
        }
    })

@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats():
    """Statistiques globales (Super Admin)"""
    conn = get_db()
    
    # Nombre de clients
    nb_clients = conn.execute('SELECT COUNT(*) as count FROM proprietaires').fetchone()['count']
    nb_actifs = conn.execute('SELECT COUNT(*) as count FROM proprietaires WHERE statut = "actif"').fetchone()['count']
    
    # Revenus mensuels estimés
    revenus = conn.execute('''
        SELECT 
            SUM(CASE WHEN abonnement = 'starter' THEN 3000 ELSE 0 END) +
            SUM(CASE WHEN abonnement = 'pro' THEN 8000 ELSE 0 END) +
            SUM(CASE WHEN abonnement = 'agence' THEN 20000 ELSE 0 END) as total
        FROM proprietaires
        WHERE statut = 'actif' AND abonnement != 'gratuit'
    ''').fetchone()['total'] or 0
    
    # Statistiques par abonnement
    abonnements = conn.execute('''
        SELECT abonnement, COUNT(*) as count
        FROM proprietaires
        WHERE statut = 'actif'
        GROUP BY abonnement
    ''').fetchall()
    
    # Total propriétés gérées
    nb_proprietes = conn.execute('SELECT COUNT(*) as count FROM proprietes').fetchone()['count']
    nb_locataires = conn.execute('SELECT COUNT(*) as count FROM locataires WHERE statut = "actif"').fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'clients': {
            'total': nb_clients,
            'actifs': nb_actifs,
            'suspendus': nb_clients - nb_actifs
        },
        'revenus_mensuels': revenus,
        'abonnements': {row['abonnement']: row['count'] for row in abonnements},
        'proprietes_total': nb_proprietes,
        'locataires_total': nb_locataires
    })

# ==================== ROUTES PROPRIÉTÉS ====================

@app.route('/api/proprietes', methods=['GET'])
def get_proprietes():
    """Liste des propriétés du propriétaire connecté"""
    proprietaire_id = request.args.get('proprietaire_id', type=int)
    
    if not proprietaire_id:
        return jsonify({'error': 'proprietaire_id requis'}), 400
    
    conn = get_db()
    proprietes = conn.execute('''
        SELECT p.*,
               COUNT(DISTINCT l.id) as nb_locataires
        FROM proprietes p
        LEFT JOIN locataires l ON l.propriete_id = p.id AND l.statut = 'actif'
        WHERE p.proprietaire_id = ?
        GROUP BY p.id
        ORDER BY p.created_at DESC
    ''', (proprietaire_id,)).fetchall()
    
    conn.close()
    return jsonify([dict(p) for p in proprietes])

@app.route('/api/proprietes', methods=['POST'])
def create_propriete():
    """Créer une nouvelle propriété"""
    data = request.json
    proprietaire_id = data.get('proprietaire_id')
    
    # Vérifier la limite selon l'abonnement
    conn = get_db()
    proprietaire = conn.execute(
        'SELECT abonnement, limite_proprietes FROM proprietaires WHERE id = ?',
        (proprietaire_id,)
    ).fetchone()
    
    nb_proprietes = conn.execute(
        'SELECT COUNT(*) as count FROM proprietes WHERE proprietaire_id = ?',
        (proprietaire_id,)
    ).fetchone()['count']
    
    if nb_proprietes >= proprietaire['limite_proprietes']:
        conn.close()
        return jsonify({
            'error': f'Limite atteinte ({proprietaire["limite_proprietes"]} propriétés). Upgradez votre abonnement.'
        }), 403
    
    # Créer la propriété
    cursor = conn.execute('''
        INSERT INTO proprietes (
            proprietaire_id, nom, type, ville, quartier, adresse,
            nombre_pieces, superficie, loyer_mensuel, caution,
            charges_incluses, montant_charges, equipements, description, statut
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        proprietaire_id,
        data['nom'],
        data['type'],
        data.get('ville', 'Bouaké'),
        data['quartier'],
        data['adresse'],
        data.get('nombre_pieces'),
        data.get('superficie'),
        data['loyer_mensuel'],
        data.get('caution', data['loyer_mensuel'] * 2),
        data.get('charges_incluses', 0),
        data.get('montant_charges', 0),
        json.dumps(data.get('equipements', {})),
        data.get('description', ''),
        'disponible'
    ))
    
    conn.commit()
    propriete_id = cursor.lastrowid
    conn.close()
    
    return jsonify({
        'success': True,
        'propriete_id': propriete_id,
        'message': 'Propriété créée avec succès'
    }), 201

@app.route('/api/proprietes/<int:id>', methods=['PUT'])
def update_propriete(id):
    """Mettre à jour une propriété"""
    data = request.json
    conn = get_db()
    
    # Construire UPDATE dynamiquement
    fields = []
    values = []
    
    allowed_fields = ['nom', 'type', 'ville', 'quartier', 'adresse', 'nombre_pieces',
                      'superficie', 'loyer_mensuel', 'caution', 'charges_incluses',
                      'montant_charges', 'equipements', 'description', 'statut']
    
    for field in allowed_fields:
        if field in data:
            fields.append(f'{field} = ?')
            if field == 'equipements':
                values.append(json.dumps(data[field]))
            else:
                values.append(data[field])
    
    fields.append('updated_at = ?')
    values.append(datetime.now().isoformat())
    values.append(id)
    
    query = f"UPDATE proprietes SET {', '.join(fields)} WHERE id = ?"
    conn.execute(query, values)
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Propriété mise à jour'})

@app.route('/api/proprietes/<int:id>', methods=['DELETE'])
def delete_propriete(id):
    """Supprimer une propriété"""
    conn = get_db()
    conn.execute('DELETE FROM proprietes WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Propriété supprimée'})

# ==================== ROUTES LOCATAIRES ====================

@app.route('/api/locataires', methods=['GET'])
def get_locataires():
    """Liste des locataires"""
    proprietaire_id = request.args.get('proprietaire_id', type=int)
    
    conn = get_db()
    locataires = conn.execute('''
        SELECT l.*, p.nom as propriete_nom, p.quartier, p.ville
        FROM locataires l
        LEFT JOIN proprietes p ON p.id = l.propriete_id
        WHERE l.proprietaire_id = ?
        ORDER BY l.created_at DESC
    ''', (proprietaire_id,)).fetchall()
    
    conn.close()
    return jsonify([dict(l) for l in locataires])

@app.route('/api/locataires', methods=['POST'])
def create_locataire():
    """Créer un nouveau locataire"""
    data = request.json
    conn = get_db()
    
    # Marquer la propriété comme louée
    conn.execute(
        'UPDATE proprietes SET statut = ? WHERE id = ?',
        ('loue', data['propriete_id'])
    )
    
    # Créer le locataire
    cursor = conn.execute('''
        INSERT INTO locataires (
            proprietaire_id, propriete_id, nom_complet, telephone, whatsapp,
            email, profession, employeur, piece_identite, numero_piece,
            date_naissance, personne_contact, telephone_contact,
            date_entree, loyer_mensuel, caution_versee, statut, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['proprietaire_id'],
        data['propriete_id'],
        data['nom_complet'],
        data['telephone'],
        data.get('whatsapp', data['telephone']),
        data.get('email', ''),
        data.get('profession', ''),
        data.get('employeur', ''),
        data.get('piece_identite', 'CNI'),
        data.get('numero_piece', ''),
        data.get('date_naissance', ''),
        data.get('personne_contact', ''),
        data.get('telephone_contact', ''),
        data['date_entree'],
        data['loyer_mensuel'],
        data.get('caution_versee', 0),
        'actif',
        data.get('notes', '')
    ))
    
    conn.commit()
    locataire_id = cursor.lastrowid
    conn.close()
    
    return jsonify({
        'success': True,
        'locataire_id': locataire_id,
        'message': 'Locataire créé avec succès'
    }), 201

@app.route('/api/locataires/<int:id>', methods=['PUT'])
def update_locataire(id):
    """Mettre à jour un locataire"""
    data = request.json
    conn = get_db()
    
    fields = []
    values = []
    
    allowed_fields = ['nom_complet', 'telephone', 'whatsapp', 'email', 'profession',
                      'employeur', 'piece_identite', 'numero_piece', 'date_naissance',
                      'personne_contact', 'telephone_contact', 'loyer_mensuel',
                      'date_sortie', 'statut', 'notes']
    
    for field in allowed_fields:
        if field in data:
            fields.append(f'{field} = ?')
            values.append(data[field])
    
    fields.append('updated_at = ?')
    values.append(datetime.now().isoformat())
    values.append(id)
    
    query = f"UPDATE locataires SET {', '.join(fields)} WHERE id = ?"
    conn.execute(query, values)
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Locataire mis à jour'})

@app.route('/api/locataires/<int:id>', methods=['DELETE'])
def delete_locataire(id):
    """Supprimer un locataire"""
    conn = get_db()
    
    # Récupérer la propriété pour la marquer comme disponible
    locataire = conn.execute('SELECT propriete_id FROM locataires WHERE id = ?', (id,)).fetchone()
    
    if locataire:
        conn.execute('UPDATE proprietes SET statut = ? WHERE id = ?', ('disponible', locataire['propriete_id']))
    
    conn.execute('DELETE FROM locataires WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Locataire supprimé'})

# ==================== ROUTES TERRAINS ====================

@app.route('/api/terrains', methods=['GET'])
def get_terrains():
    """Liste des terrains d'un propriétaire"""
    proprietaire_id = request.args.get('proprietaire_id', type=int)
    
    if not proprietaire_id:
        return jsonify({'error': 'proprietaire_id requis'}), 400
    
    conn = get_db()
    terrains = conn.execute('''
        SELECT * FROM terrains
        WHERE proprietaire_id = ?
        ORDER BY date_ajout DESC
    ''', (proprietaire_id,)).fetchall()
    
    conn.close()
    return jsonify([dict(t) for t in terrains])

@app.route('/api/terrains', methods=['POST'])
def create_terrain():
    """Créer un nouveau terrain"""
    data = request.json
    conn = get_db()
    
    cursor = conn.execute('''
        INSERT INTO terrains (
            proprietaire_id, nom, superficie, unite_superficie, ville, quartier,
            adresse, prix_vente, statut, description, titre_foncier
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['proprietaire_id'],
        data['nom'],
        data['superficie'],
        data.get('unite_superficie', 'm²'),
        data['ville'],
        data['quartier'],
        data.get('adresse', ''),
        data['prix_vente'],
        data.get('statut', 'disponible'),
        data.get('description', ''),
        data.get('titre_foncier', '')
    ))
    
    conn.commit()
    terrain_id = cursor.lastrowid
    conn.close()
    
    return jsonify({
        'success': True,
        'terrain_id': terrain_id,
        'message': 'Terrain créé avec succès'
    }), 201

@app.route('/api/terrains/<int:id>', methods=['PUT'])
def update_terrain(id):
    """Modifier un terrain"""
    data = request.json
    conn = get_db()
    
    fields = []
    values = []
    
    allowed_fields = ['nom', 'superficie', 'unite_superficie', 'ville', 'quartier',
                      'adresse', 'prix_vente', 'statut', 'description', 'titre_foncier', 'date_vente']
    
    for field in allowed_fields:
        if field in data:
            fields.append(f'{field} = ?')
            values.append(data[field])
    
    if not fields:
        return jsonify({'error': 'Aucun champ à mettre à jour'}), 400
    
    values.append(id)
    query = f"UPDATE terrains SET {', '.join(fields)} WHERE id = ?"
    
    conn.execute(query, values)
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Terrain mis à jour'})

@app.route('/api/terrains/<int:id>', methods=['DELETE'])
def delete_terrain(id):
    """Supprimer un terrain"""
    conn = get_db()
    conn.execute('DELETE FROM terrains WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Terrain supprimé'})

# ==================== ROUTES PAIEMENTS ====================

@app.route('/api/paiements', methods=['GET'])
def get_paiements():
    """Liste des paiements"""
    proprietaire_id = request.args.get('proprietaire_id', type=int)
    mois = request.args.get('mois')  # Format: YYYY-MM
    
    conn = get_db()
    query = '''
        SELECT pa.*, 
               l.nom_complet as locataire_nom,
               l.telephone as locataire_telephone,
               pr.nom as propriete_nom,
               pr.adresse as propriete_adresse
        FROM paiements pa
        LEFT JOIN locataires l ON l.id = pa.locataire_id
        LEFT JOIN proprietes pr ON pr.id = pa.propriete_id
        WHERE pa.proprietaire_id = ?
    '''
    
    params = [proprietaire_id]
    
    if mois:
        query += ' AND strftime("%Y-%m", pa.periode_debut) = ?'
        params.append(mois)
    
    query += ' ORDER BY pa.created_at DESC'
    
    paiements = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(p) for p in paiements])

@app.route('/api/paiements', methods=['POST'])
def create_paiement():
    """Enregistrer un paiement"""
    data = request.json
    conn = get_db()
    
    cursor = conn.execute('''
        INSERT INTO paiements (
            proprietaire_id, locataire_id, propriete_id, montant,
            type_paiement, mode_paiement, reference_paiement,
            periode_debut, periode_fin, date_paiement, date_echeance,
            statut, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['proprietaire_id'],
        data['locataire_id'],
        data['propriete_id'],
        data['montant'],
        data.get('type_paiement', 'loyer'),
        data['mode_paiement'],
        data.get('reference_paiement', ''),
        data['periode_debut'],
        data['periode_fin'],
        data.get('date_paiement', datetime.now().date().isoformat()),
        data.get('date_echeance', ''),
        data.get('statut', 'paye'),
        data.get('notes', '')
    ))
    
    conn.commit()
    paiement_id = cursor.lastrowid
    conn.close()
    
    return jsonify({
        'success': True,
        'paiement_id': paiement_id,
        'message': 'Paiement enregistré avec succès'
    }), 201

@app.route('/api/paiements/<int:id>', methods=['PUT'])
def update_paiement(id):
    """Mettre à jour un paiement"""
    data = request.json
    conn = get_db()
    
    fields = []
    values = []
    
    allowed_fields = ['montant', 'type_paiement', 'mode_paiement', 'reference_paiement',
                      'date_paiement', 'statut', 'notes']
    
    for field in allowed_fields:
        if field in data:
            fields.append(f'{field} = ?')
            values.append(data[field])
    
    fields.append('updated_at = ?')
    values.append(datetime.now().isoformat())
    values.append(id)
    
    query = f"UPDATE paiements SET {', '.join(fields)} WHERE id = ?"
    conn.execute(query, values)
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Paiement mis à jour'})

# ==================== GÉNÉRATION QUITTANCES ====================

@app.route('/api/quittance/generate', methods=['POST'])
def generate_quittance():
    """Générer une quittance PDF"""
    data = request.json
    
    # Récupérer les infos du propriétaire
    conn = get_db()
    proprietaire = conn.execute(
        'SELECT * FROM proprietaires WHERE id = ?',
        (data['proprietaire_id'],)
    ).fetchone()
    
    # Créer le PDF
    filename = f"quittance_{data['paiement_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(QUITTANCES_FOLDER, filename)
    
    # Génération avec ReportLab
    doc = SimpleDocTemplate(filepath, pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    
    # Style personnalisé
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a3c5a'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    # Titre
    story.append(Paragraph("QUITTANCE DE LOYER", title_style))
    story.append(Spacer(1, 0.5*cm))
    
    # Numéro
    story.append(Paragraph(f"N° {data['paiement_id']}-{datetime.now().year}", styles['Normal']))
    story.append(Spacer(1, 1*cm))
    
    # Bailleur
    story.append(Paragraph("<b>BAILLEUR</b>", styles['Heading3']))
    story.append(Paragraph(f"<b>{proprietaire['nom_entreprise']}</b>", styles['Normal']))
    story.append(Paragraph(f"{proprietaire['nom_complet']}", styles['Normal']))
    story.append(Paragraph(f"Tél: {proprietaire['telephone']}", styles['Normal']))
    story.append(Paragraph(f"Email: {proprietaire['email']}", styles['Normal']))
    story.append(Spacer(1, 0.5*cm))
    
    # Locataire
    story.append(Paragraph("<b>LOCATAIRE</b>", styles['Heading3']))
    story.append(Paragraph(f"<b>{data['locataire_nom']}</b>", styles['Normal']))
    story.append(Paragraph(f"{data['locataire_telephone']}", styles['Normal']))
    story.append(Spacer(1, 0.5*cm))
    
    # Logement
    story.append(Paragraph("<b>LOGEMENT</b>", styles['Heading3']))
    story.append(Paragraph(f"<b>{data['propriete_nom']}</b>", styles['Normal']))
    story.append(Paragraph(f"{data['propriete_adresse']}", styles['Normal']))
    story.append(Spacer(1, 1*cm))
    
    # Détails paiement
    story.append(Paragraph("<b>DÉTAILS DU PAIEMENT</b>", styles['Heading3']))
    
    paiement_data = [
        ['Période', data['periode']],
        ['Date de paiement', data['date_paiement']],
        ['Mode de paiement', data['mode_paiement']],
        ['Montant', f"{int(data['montant']):,} FCFA".replace(',', ' ')],
    ]
    
    table = Table(paiement_data, colWidths=[8*cm, 8*cm])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f6f1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d4a574'))
    ]))
    
    story.append(table)
    story.append(Spacer(1, 1*cm))
    
    # Confirmation
    confirmation_style = ParagraphStyle(
        'Confirmation',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor('#2d7a5a'),
        alignment=TA_CENTER,
        spaceAfter=20
    )
    story.append(Paragraph("✓ Paiement reçu et enregistré", confirmation_style))
    
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(f"Document généré le {datetime.now().strftime('%d/%m/%Y')}", styles['Normal']))
    
    # Construire le PDF
    doc.build(story)
    
    # Marquer comme générée
    conn.execute(
        'UPDATE paiements SET quittance_generee = 1 WHERE id = ?',
        (data['paiement_id'],)
    )
    conn.commit()
    conn.close()
    
    return send_file(filepath, as_attachment=True, download_name=filename)

# ==================== UPLOAD LOGO ====================

@app.route('/api/upload-logo', methods=['POST'])
def upload_logo():
    """Upload du logo du propriétaire"""
    if 'logo' not in request.files:
        return jsonify({'error': 'Aucun fichier'}), 400
    
    file = request.files['logo']
    proprietaire_id = request.form.get('proprietaire_id')
    
    if not file or not proprietaire_id:
        return jsonify({'error': 'Fichier et proprietaire_id requis'}), 400
    
    # Vérifier l'extension
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    filename = file.filename
    if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({'error': 'Format non supporté'}), 400
    
    # Sauvegarder
    filename = f"logo_{proprietaire_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{filename.rsplit('.', 1)[1]}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    # Mettre à jour dans la DB
    conn = get_db()
    conn.execute(
        'UPDATE proprietaires SET logo_path = ? WHERE id = ?',
        (filepath, proprietaire_id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'logo_path': filepath,
        'message': 'Logo uploadé avec succès'
    })

# ==================== STATISTIQUES ====================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Statistiques pour le propriétaire"""
    proprietaire_id = request.args.get('proprietaire_id', type=int)
    mois = request.args.get('mois')  # YYYY-MM
    
    conn = get_db()
    
    # Total propriétés
    nb_proprietes = conn.execute(
        'SELECT COUNT(*) as count FROM proprietes WHERE proprietaire_id = ?',
        (proprietaire_id,)
    ).fetchone()['count']
    
    # Total locataires actifs
    nb_locataires = conn.execute(
        'SELECT COUNT(*) as count FROM locataires WHERE proprietaire_id = ? AND statut = "actif"',
        (proprietaire_id,)
    ).fetchone()['count']
    
    # Revenus
    revenus_query = '''
        SELECT SUM(montant) as total
        FROM paiements
        WHERE proprietaire_id = ? AND statut = 'paye'
    '''
    params = [proprietaire_id]
    
    if mois:
        revenus_query += ' AND strftime("%Y-%m", periode_debut) = ?'
        params.append(mois)
    
    revenus = conn.execute(revenus_query, params).fetchone()['total'] or 0
    
    # Paiements en attente
    paiements_attente = conn.execute(
        'SELECT COUNT(*) as count FROM paiements WHERE proprietaire_id = ? AND statut = "en_attente"',
        (proprietaire_id,)
    ).fetchone()['count']
    
    # Taux d'occupation
    taux_occupation = (nb_locataires / nb_proprietes * 100) if nb_proprietes > 0 else 0
    
    conn.close()
    
    return jsonify({
        'nb_proprietes': nb_proprietes,
        'nb_locataires': nb_locataires,
        'revenus_total': revenus,
        'paiements_attente': paiements_attente,
        'taux_occupation': round(taux_occupation, 1)
    })

# ==================== ROUTE PRINCIPALE ====================

@app.route('/')
def index():
    """Page d'accueil de l'API"""
    return '''
    <html>
    <head>
        <title>King'immob API</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 900px;
                margin: 50px auto;
                padding: 20px;
                background: #f5f7fa;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 { color: #1a3c5a; }
            .logo { text-align: center; margin-bottom: 20px; }
            .endpoint {
                background: #e8f5e9;
                padding: 10px;
                margin: 10px 0;
                border-left: 4px solid #2d7a5a;
                border-radius: 4px;
            }
            code {
                background: #f5f7fa;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: monospace;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>🦁 King'immob - API Backend</h1>
                <p><strong>Système de gestion immobilière multi-tenant</strong></p>
                <p>Par: DIABATE MADARA ABOUBAKAR - King Services</p>
                <p>📱 +225 07 58 80 00 39 | 📧 coucoudiabate@gmail.com</p>
            </div>
            
            <h2>📡 Endpoints Disponibles</h2>
            
            <h3>🔐 Authentication</h3>
            <div class="endpoint">POST /api/login - Connexion</div>
            
            <h3>👑 Super Admin</h3>
            <div class="endpoint">GET /api/admin/proprietaires - Liste des clients</div>
            <div class="endpoint">POST /api/admin/proprietaires - Créer un client</div>
            <div class="endpoint">PUT /api/admin/proprietaires/:id - Modifier un client</div>
            <div class="endpoint">DELETE /api/admin/proprietaires/:id - Supprimer un client</div>
            <div class="endpoint">GET /api/admin/stats - Statistiques globales</div>
            
            <h3>🏠 Propriétés</h3>
            <div class="endpoint">GET /api/proprietes - Liste des propriétés</div>
            <div class="endpoint">POST /api/proprietes - Créer une propriété</div>
            <div class="endpoint">PUT /api/proprietes/:id - Modifier une propriété</div>
            <div class="endpoint">DELETE /api/proprietes/:id - Supprimer une propriété</div>
            
            <h3>👥 Locataires</h3>
            <div class="endpoint">GET /api/locataires - Liste des locataires</div>
            <div class="endpoint">POST /api/locataires - Créer un locataire</div>
            <div class="endpoint">PUT /api/locataires/:id - Modifier un locataire</div>
            <div class="endpoint">DELETE /api/locataires/:id - Supprimer un locataire</div>
            
            <h3>💰 Paiements</h3>
            <div class="endpoint">GET /api/paiements - Liste des paiements</div>
            <div class="endpoint">POST /api/paiements - Enregistrer un paiement</div>
            <div class="endpoint">PUT /api/paiements/:id - Modifier un paiement</div>
            
            <h3>📄 Quittances</h3>
            <div class="endpoint">POST /api/quittance/generate - Générer une quittance PDF</div>
            
            <h3>📊 Statistiques</h3>
            <div class="endpoint">GET /api/stats - Statistiques du propriétaire</div>
            
            <h3>🖼️ Upload</h3>
            <div class="endpoint">POST /api/upload-logo - Upload du logo</div>
            
            <hr>
            <p style="text-align: center; color: #666; margin-top: 30px;">
                ✅ Serveur opérationnel | 🇨🇮 Made in Côte d'Ivoire
            </p>
        </div>
    </body>
    </html>
    '''

# ==================== LANCEMENT ====================

if __name__ == '__main__':
    # Initialiser la DB si elle n'existe pas
    if not os.path.exists(DATABASE):
        print("🔧 Initialisation de la base de données...")
        init_db()
    
    print("=" * 60)
    print("🦁 King'immob - API Backend")
    print("=" * 60)
    print("✅ Serveur démarré sur http://localhost:5000")
    print("✅ API prête à recevoir des requêtes")
    print("\n📱 Contact: DIABATE MADARA ABOUBAKAR")
    print("   Tel: +225 07 58 80 00 39")
    print("   Email: coucoudiabate@gmail.com")
    print("\nAppuyez sur Ctrl+C pour arrêter")
    print("=" * 60)
    
    # Configuration pour déploiement (PythonAnywhere, Railway, etc.)
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
