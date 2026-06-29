import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse
from datetime import date, datetime
from decimal import Decimal

try:
    import pymysql
    import pymysql.cursors
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

RELOAD_TOKEN      = os.environ.get('RELOAD_TOKEN', '')
OAUTH_CLIENT_ID   = os.environ.get('OAUTH_CLIENT_ID', '')
OAUTH_CLIENT_SECRET = os.environ.get('OAUTH_CLIENT_SECRET', '')
SERVER_NAME       = 'corp-mcp-py'
SERVER_VERSION    = '3.0.0'
MCP_VERSION       = '2024-11-05'
BASE_URL          = 'https://corp.pintuandes.com'

# ---------------------------------------------------------------------------
# OAuth 2.0 — in-memory storage (persiste entre requests en mismo proceso)
# ---------------------------------------------------------------------------

_auth_codes    = {}   # code  -> {client_id, redirect_uri, code_challenge, exp}
_access_tokens = {}   # token -> {client_id, exp}
_oauth_lock    = threading.Lock()


def _clean_expired():
    now = time.time()
    with _oauth_lock:
        for store in (_auth_codes, _access_tokens):
            for k in [k for k, v in store.items() if v['exp'] < now]:
                del store[k]


def _new_auth_code(client_id, redirect_uri, code_challenge):
    code = secrets.token_urlsafe(32)
    with _oauth_lock:
        _auth_codes[code] = {
            'client_id': client_id, 'redirect_uri': redirect_uri,
            'code_challenge': code_challenge, 'exp': time.time() + 600,
        }
    return code


def _new_access_token(client_id):
    _clean_expired()
    token = secrets.token_urlsafe(40)
    with _oauth_lock:
        _access_tokens[token] = {'client_id': client_id, 'exp': time.time() + 3600}
    return token


def _valid_token(token):
    entry = _access_tokens.get(token)
    return bool(entry and time.time() < entry['exp'])


def _verify_pkce(verifier, challenge):
    digest = hashlib.sha256(verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return secrets.compare_digest(computed, challenge)


def _bearer(environ):
    auth = environ.get('HTTP_AUTHORIZATION', '')
    return auth[7:] if auth.startswith('Bearer ') else None


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------

def _get_db():
    return pymysql.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        port=int(os.environ.get('DB_PORT', 3306)),
        user=os.environ.get('DB_USER', ''),
        password=os.environ.get('DB_PASSWORD', ''),
        database=os.environ.get('DB_NAME', ''),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        connect_timeout=10,
    )


def _query(sql, params=None):
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()
    finally:
        conn.close()


class _Enc(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (date, datetime)):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def _dumps(obj):
    return json.dumps(obj, cls=_Enc, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Herramientas MCP
# ---------------------------------------------------------------------------

TIPO_LABEL = {
    'FACT': 'Factura', 'N/CR': 'Nota de Crédito', 'N/DB': 'Nota de Débito',
    'RIVA': 'Retención de IVA', 'ISLR': 'Impuesto Sobre la Renta',
    'ADEL': 'Adelanto / Pago', 'AJPA': 'Ajuste Positivo Automático',
    'AJPM': 'Ajuste Positivo Manual', 'AJNA': 'Ajuste Negativo Automático',
    'AJNM': 'Ajuste Negativo Manual',
}

TOOLS = [
    {
        'name': 'Corporativo_compras_ayer',
        'description': 'Retorna el total de compras realizadas ayer en Corporativo C.A. Muestra monto total y cantidad de documentos por moneda.',
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'Corporativo_compras_mes',
        'description': 'Retorna el total de compras del mes en curso en Corporativo C.A. Incluye monto acumulado y cantidad de documentos por moneda.',
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'Corporativo_tasas_hoy',
        'description': 'Retorna las tasas de cambio vigentes registradas en Corporativo C.A. Incluye todas las monedas configuradas con su última tasa.',
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'Corporativo_saldos_pendientes',
        'description': 'Retorna los documentos de compra con saldo pendiente de pago en Corporativo C.A. Ordenados por fecha de vencimiento.',
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'consultar_compras',
        'description': (
            'Consulta el listado de compras con filtros opcionales. '
            'Tipos: FACT (Factura), N/CR (Nota de Crédito), N/DB (Nota de Débito), '
            'RIVA (Retención de IVA), ISLR (Impuesto Sobre la Renta).'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'tipo': {'type': 'string', 'description': 'Tipo: FACT, N/CR, N/DB, RIVA, ISLR'},
                'desde': {'type': 'string', 'description': 'Fecha inicial YYYY-MM-DD'},
                'hasta': {'type': 'string', 'description': 'Fecha final YYYY-MM-DD'},
                'con_saldo': {'type': 'boolean', 'description': 'Solo con saldo pendiente'},
                'limite': {'type': 'integer', 'description': 'Máximo de registros (default 20)'},
            },
            'required': [],
        },
    },
    {
        'name': 'buscar_compra',
        'description': 'Busca un documento de compra por tipo y número. Ejemplo: tipo=FACT, numero=1',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'tipo': {'type': 'string', 'description': 'Tipo: FACT, N/CR, N/DB, RIVA, ISLR'},
                'numero': {'type': 'integer', 'description': 'Número del documento'},
            },
            'required': ['tipo', 'numero'],
        },
    },
    {
        'name': 'resumen_compras',
        'description': 'Resumen de compras agrupado por tipo de documento con totales y cantidades. Útil para reportes gerenciales.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'desde': {'type': 'string', 'description': 'Fecha inicial YYYY-MM-DD'},
                'hasta': {'type': 'string', 'description': 'Fecha final YYYY-MM-DD'},
            },
            'required': [],
        },
    },
    {
        'name': 'consultar_socios',
        'description': 'Consulta socios comerciales: proveedores, suplidores, acreedores. Búsqueda por nombre o RIF.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'buscar': {'type': 'string', 'description': 'Nombre o RIF a buscar'},
                'limite': {'type': 'integer', 'description': 'Máximo de registros (default 20)'},
            },
            'required': [],
        },
    },
]


def _tool_compras_ayer():
    rows = _query("""
        SELECT TRIM(mndCdg) AS moneda, COUNT(*) AS cantidad,
               ROUND(SUM(docTtl),2) AS total, ROUND(SUM(docSld),2) AS saldo_pendiente
        FROM cmpDoc WHERE docRgt = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
        GROUP BY mndCdg ORDER BY mndCdg
    """)
    if not rows:
        return 'No se registraron compras ayer.'
    lines = ['Compras de ayer:']
    for r in rows:
        lines.append(f"  {r['moneda']}: {r['cantidad']} docs | Total: {r['total']} | Saldo: {r['saldo_pendiente']}")
    return '\n'.join(lines)


def _tool_compras_mes():
    rows = _query("""
        SELECT TRIM(mndCdg) AS moneda, COUNT(*) AS cantidad,
               ROUND(SUM(docTtl),2) AS total, ROUND(SUM(docSld),2) AS saldo_pendiente
        FROM cmpDoc
        WHERE MONTH(docRgt)=MONTH(CURDATE()) AND YEAR(docRgt)=YEAR(CURDATE())
        GROUP BY mndCdg ORDER BY mndCdg
    """)
    if not rows:
        return 'No se registraron compras en el mes actual.'
    lines = ['Compras del mes en curso:']
    for r in rows:
        lines.append(f"  {r['moneda']}: {r['cantidad']} docs | Total: {r['total']} | Saldo: {r['saldo_pendiente']}")
    return '\n'.join(lines)


def _tool_tasas_hoy():
    rows = _query("""
        SELECT t.mndCdg AS moneda, t.tasFch AS fecha, t.tasCmb AS tasa
        FROM tas t
        INNER JOIN (SELECT mndCdg, MAX(tasFch) AS ultima FROM tas GROUP BY mndCdg) u
          ON t.mndCdg=u.mndCdg AND t.tasFch=u.ultima
        ORDER BY t.mndCdg
    """)
    if not rows:
        return 'No hay tasas de cambio registradas.'
    lines = ['Tasas de cambio vigentes:']
    for r in rows:
        fecha = r['fecha'].isoformat() if hasattr(r['fecha'], 'isoformat') else r['fecha']
        lines.append(f"  {r['moneda']}: {r['tasa']} (al {fecha})")
    return '\n'.join(lines)


def _tool_saldos_pendientes():
    rows = _query("""
        SELECT c.docTip, c.docNmr, c.docRgt, c.docVnc,
               TRIM(c.socCdg) AS socCdg, TRIM(p.socDsc) AS socDsc, p.socRif,
               TRIM(c.mndCdg) AS mndCdg,
               ROUND(c.docTtl,2) AS docTtl, ROUND(c.docSld,2) AS docSld
        FROM cmpDoc c LEFT JOIN prv p ON p.socCdg=c.socCdg
        WHERE c.docSld > 0
        ORDER BY c.docVnc ASC, c.docSld DESC LIMIT 50
    """)
    if not rows:
        return 'No hay documentos con saldo pendiente.'
    lines = [f'Documentos con saldo pendiente ({len(rows)} registros):']
    for r in rows:
        tipo = TIPO_LABEL.get(r['docTip'], r['docTip'])
        vnc = r['docVnc'].isoformat() if hasattr(r.get('docVnc'), 'isoformat') else r.get('docVnc', '')
        lines.append(f"  {tipo} #{r['docNmr']} | {(r.get('socDsc') or '').strip()} | Vence: {vnc} | Saldo: {r['docSld']} {r['mndCdg']}")
    return '\n'.join(lines)


def _tool_consultar_compras(args):
    conditions, params = [], []
    if args.get('tipo'):
        conditions.append('c.docTip = %s'); params.append(args['tipo'])
    if args.get('desde'):
        conditions.append('c.docRgt >= %s'); params.append(args['desde'])
    if args.get('hasta'):
        conditions.append('c.docRgt <= %s'); params.append(args['hasta'])
    if args.get('con_saldo'):
        conditions.append('c.docSld > 0')
    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    limit = min(int(args.get('limite', 20)), 100)
    params.append(limit)
    rows = _query(f"""
        SELECT c.docTip, c.docNmr, c.docRgt, c.docVnc,
               TRIM(c.socCdg) AS socCdg, TRIM(p.socDsc) AS socDsc, p.socRif,
               TRIM(c.mndCdg) AS mndCdg,
               ROUND(c.docTtl,2) AS docTtl, ROUND(c.docSld,2) AS docSld, c.docAnl
        FROM cmpDoc c LEFT JOIN prv p ON p.socCdg=c.socCdg
        {where} ORDER BY c.docRgt DESC, c.docNmr DESC LIMIT %s
    """, params)
    if not rows:
        return 'No se encontraron documentos con los filtros indicados.'
    lines = [f'Compras encontradas ({len(rows)} registros):']
    for r in rows:
        tipo = TIPO_LABEL.get(r['docTip'], r['docTip'])
        rgt = r['docRgt'].isoformat() if hasattr(r.get('docRgt'), 'isoformat') else r.get('docRgt', '')
        lines.append(f"  {tipo} #{r['docNmr']} | {(r.get('socDsc') or '').strip()} | {rgt} | {r['docTtl']} {r['mndCdg']} | Saldo: {r['docSld']}")
    return '\n'.join(lines)


def _tool_buscar_compra(args):
    rows = _query("""
        SELECT c.*, TRIM(p.socDsc) AS prvNmb, p.socRif AS prvRif
        FROM cmpDoc c LEFT JOIN prv p ON p.socCdg=c.socCdg
        WHERE c.docTip=%s AND c.docNmr=%s
    """, [args.get('tipo'), args.get('numero')])
    if not rows:
        return f"Documento {args.get('tipo')} #{args.get('numero')} no encontrado."
    return _dumps(rows[0])


def _tool_resumen_compras(args):
    conditions, params = [], []
    if args.get('desde'):
        conditions.append('docRgt >= %s'); params.append(args['desde'])
    if args.get('hasta'):
        conditions.append('docRgt <= %s'); params.append(args['hasta'])
    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    rows = _query(f"""
        SELECT docTip AS tipo,
               CASE docTip WHEN 'FACT' THEN 'Factura' WHEN 'N/CR' THEN 'Nota de Crédito'
                 WHEN 'N/DB' THEN 'Nota de Débito' WHEN 'RIVA' THEN 'Retención de IVA'
                 WHEN 'ISLR' THEN 'Impuesto Sobre la Renta' WHEN 'ADEL' THEN 'Adelanto / Pago'
                 ELSE docTip END AS descripcion,
               COUNT(*) AS cantidad,
               ROUND(SUM(docTtl),2) AS total, ROUND(SUM(docSld),2) AS saldo_pendiente
        FROM cmpDoc {where} GROUP BY docTip ORDER BY docTip
    """, params)
    if not rows:
        return 'No hay compras registradas para el período indicado.'
    lines = ['Resumen de compras por tipo:']
    for r in rows:
        lines.append(f"  {r['descripcion']} ({r['tipo']}): {r['cantidad']} docs | Total: {r['total']} | Saldo: {r['saldo_pendiente']}")
    return '\n'.join(lines)


def _tool_consultar_socios(args):
    conditions, params = [], []
    if args.get('buscar'):
        conditions.append('(socCdg LIKE %s OR socDsc LIKE %s OR socRif LIKE %s)')
        t = f"%{args['buscar']}%"; params.extend([t, t, t])
    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    limit = min(int(args.get('limite', 20)), 100); params.append(limit)
    rows = _query(f"""
        SELECT TRIM(socCdg) AS socCdg, TRIM(socDsc) AS socDsc,
               socRif, prcTip, socTlf, socEml
        FROM prv {where} ORDER BY socDsc LIMIT %s
    """, params)
    if not rows:
        return 'No se encontraron socios comerciales.'
    lines = [f'Socios comerciales ({len(rows)} registros):']
    for r in rows:
        lines.append(f"  {r['socCdg']} | {(r.get('socDsc') or '').strip()} | RIF: {r.get('socRif','')} | Tel: {r.get('socTlf','')}")
    return '\n'.join(lines)


def _call_tool(name, arguments):
    if not DB_AVAILABLE:
        return 'Error: PyMySQL no está instalado.'
    try:
        if name == 'Corporativo_compras_ayer':    return _tool_compras_ayer()
        if name == 'Corporativo_compras_mes':     return _tool_compras_mes()
        if name == 'Corporativo_tasas_hoy':       return _tool_tasas_hoy()
        if name == 'Corporativo_saldos_pendientes': return _tool_saldos_pendientes()
        if name == 'consultar_compras':           return _tool_consultar_compras(arguments)
        if name == 'buscar_compra':               return _tool_buscar_compra(arguments)
        if name == 'resumen_compras':             return _tool_resumen_compras(arguments)
        if name == 'consultar_socios':            return _tool_consultar_socios(arguments)
        return f'Herramienta desconocida: {name}'
    except Exception as e:
        return f'Error al ejecutar {name}: {str(e)}'


# ---------------------------------------------------------------------------
# MCP JSON-RPC
# ---------------------------------------------------------------------------

def _handle_mcp(body_bytes):
    try:
        req = json.loads(body_bytes)
    except Exception:
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}

    method = req.get('method', '')
    params = req.get('params') or {}
    req_id = req.get('id')

    if req_id is None and method.startswith('notifications/'):
        return None

    if method == 'initialize':
        return {'jsonrpc': '2.0', 'id': req_id, 'result': {
            'protocolVersion': MCP_VERSION,
            'capabilities': {'tools': {}},
            'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION},
        }}
    if method == 'tools/list':
        return {'jsonrpc': '2.0', 'id': req_id, 'result': {'tools': TOOLS}}
    if method == 'tools/call':
        return {'jsonrpc': '2.0', 'id': req_id, 'result': {
            'content': [{'type': 'text', 'text': _call_tool(params.get('name', ''), params.get('arguments') or {})}],
            'isError': False,
        }}
    if method == 'ping':
        return {'jsonrpc': '2.0', 'id': req_id, 'result': {}}

    return {'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32601, 'message': f'Method not found: {method}'}}


# ---------------------------------------------------------------------------
# WSGI helpers
# ---------------------------------------------------------------------------

def _parse_query(qs):
    params = {}
    for part in (qs or '').split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    return params


def _parse_body(environ):
    try:
        length = int(environ.get('CONTENT_LENGTH') or 0)
        return environ['wsgi.input'].read(length) if length > 0 else b''
    except Exception:
        return b''


def _json_resp(start_response, status, data, extra_headers=None):
    body = json.dumps(data, ensure_ascii=False).encode('utf-8')
    headers = [('Content-Type', 'application/json; charset=utf-8'),
               ('Content-Length', str(len(body))), ('Cache-Control', 'no-store')]
    if extra_headers:
        headers.extend(extra_headers)
    start_response(status, headers)
    return [body]


def _html_resp(start_response, status, html):
    body = html.encode('utf-8')
    start_response(status, [('Content-Type', 'text/html; charset=utf-8'), ('Content-Length', str(len(body)))])
    return [body]


# ---------------------------------------------------------------------------
# WSGI application
# ---------------------------------------------------------------------------

def application(environ, start_response):
    path   = environ.get('PATH_INFO', '/')
    method = environ.get('REQUEST_METHOD', 'GET')
    params = _parse_query(environ.get('QUERY_STRING', ''))

    # ── Health ──────────────────────────────────────────────────────────────
    if path == '/health':
        return _json_resp(start_response, '200 OK', {
            'status': 'ok', 'service': SERVER_NAME, 'version': SERVER_VERSION,
            'language': 'Python 3',
            'db': 'pymysql disponible' if DB_AVAILABLE else 'pymysql NO instalado',
            'oauth': 'configurado' if OAUTH_CLIENT_ID else 'sin configurar',
        })

    # ── Reload ──────────────────────────────────────────────────────────────
    if path == '/reload':
        if not RELOAD_TOKEN or params.get('token') != RELOAD_TOKEN:
            return _json_resp(start_response, '401 Unauthorized', {'error': 'Token inválido'})
        def _exit():
            import time as _t; _t.sleep(0.5); os._exit(0)
        threading.Thread(target=_exit, daemon=True).start()
        return _json_resp(start_response, '200 OK', {'mensaje': 'Reiniciando proceso...'})

    # ── OAuth discovery ──────────────────────────────────────────────────────
    if path == '/.well-known/oauth-authorization-server':
        return _json_resp(start_response, '200 OK', {
            'issuer': BASE_URL,
            'authorization_endpoint': f'{BASE_URL}/oauth/authorize',
            'token_endpoint': f'{BASE_URL}/oauth/token',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code'],
            'code_challenge_methods_supported': ['S256'],
        })

    # ── OAuth authorize ──────────────────────────────────────────────────────
    if path == '/oauth/authorize':
        client_id      = params.get('client_id', '')
        redirect_uri   = params.get('redirect_uri', '')
        state          = params.get('state', '')
        code_challenge = params.get('code_challenge', '')

        if client_id != OAUTH_CLIENT_ID:
            return _json_resp(start_response, '400 Bad Request', {'error': 'invalid_client'})

        if method == 'POST':
            body_params = _parse_query(_parse_body(environ).decode('utf-8', errors='replace'))
            action = body_params.get('action', '')
            if action == 'approve':
                code = _new_auth_code(client_id, redirect_uri, code_challenge)
                location = f"{redirect_uri}?code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
                start_response('302 Found', [('Location', location)])
                return [b'']
            location = f"{redirect_uri}?error=access_denied&state={urllib.parse.quote(state)}"
            start_response('302 Found', [('Location', location)])
            return [b'']

        html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Corporativo C.A. — Autorizar acceso</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f5f5}}
  .card{{background:#fff;border-radius:12px;padding:40px;max-width:420px;width:90%;box-shadow:0 4px 24px rgba(0,0,0,.1);text-align:center}}
  h1{{font-size:1.4rem;margin:0 0 8px}}
  p{{color:#555;margin:0 0 28px;font-size:.95rem}}
  .logo{{font-size:2.5rem;margin-bottom:16px}}
  .btn{{display:inline-block;padding:12px 32px;border:none;border-radius:8px;font-size:1rem;cursor:pointer;width:100%;margin-bottom:10px}}
  .btn-primary{{background:#2563eb;color:#fff}}
  .btn-secondary{{background:#e5e7eb;color:#374151}}
</style></head>
<body><div class="card">
  <div class="logo">🏢</div>
  <h1>Corporativo C.A.</h1>
  <p>Claude solicita acceso a los datos corporativos de compras, socios y tasas de cambio.</p>
  <form method="POST" action="/oauth/authorize?client_id={urllib.parse.quote(client_id)}&redirect_uri={urllib.parse.quote(redirect_uri)}&state={urllib.parse.quote(state)}&code_challenge={urllib.parse.quote(code_challenge)}&code_challenge_method=S256">
    <button class="btn btn-primary" name="action" value="approve">✅ Autorizar acceso</button>
    <button class="btn btn-secondary" name="action" value="deny">Cancelar</button>
  </form>
</div></body></html>"""
        return _html_resp(start_response, '200 OK', html)

    # ── OAuth token ──────────────────────────────────────────────────────────
    if path == '/oauth/token' and method == 'POST':
        body_params = _parse_query(_parse_body(environ).decode('utf-8', errors='replace'))
        grant_type    = body_params.get('grant_type', '')
        code          = body_params.get('code', '')
        code_verifier = body_params.get('code_verifier', '')
        client_id     = body_params.get('client_id', '')
        client_secret = body_params.get('client_secret', '')

        # Validate client
        if not secrets.compare_digest(client_id, OAUTH_CLIENT_ID) or \
           not secrets.compare_digest(client_secret, OAUTH_CLIENT_SECRET):
            return _json_resp(start_response, '401 Unauthorized', {'error': 'invalid_client'})

        if grant_type != 'authorization_code':
            return _json_resp(start_response, '400 Bad Request', {'error': 'unsupported_grant_type'})

        with _oauth_lock:
            entry = _auth_codes.pop(code, None)

        if not entry or time.time() > entry['exp']:
            return _json_resp(start_response, '400 Bad Request', {'error': 'invalid_grant'})

        if entry.get('code_challenge') and not _verify_pkce(code_verifier, entry['code_challenge']):
            return _json_resp(start_response, '400 Bad Request', {'error': 'invalid_grant'})

        token = _new_access_token(client_id)
        return _json_resp(start_response, '200 OK', {
            'access_token': token, 'token_type': 'Bearer', 'expires_in': 3600,
        })

    # ── MCP endpoint ─────────────────────────────────────────────────────────
    if path == '/mcp':
        if method == 'OPTIONS':
            start_response('204 No Content', [
                ('Access-Control-Allow-Origin', '*'),
                ('Access-Control-Allow-Methods', 'POST, OPTIONS'),
                ('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization, mcp-session-id'),
                ('Content-Length', '0'),
            ])
            return [b'']

        if method == 'POST':
            # Require auth only if OAuth is configured
            if OAUTH_CLIENT_ID and not _valid_token(_bearer(environ)):
                return _json_resp(start_response, '401 Unauthorized',
                                  {'error': 'invalid_token'},
                                  [('WWW-Authenticate',
                                    f'Bearer realm="{BASE_URL}"'),
                                   ('Access-Control-Allow-Origin', '*')])

            body = _parse_body(environ) or b'{}'
            result = _handle_mcp(body)
            if result is None:
                start_response('204 No Content', [('Content-Length', '0')])
                return [b'']
            resp_body = json.dumps(result, cls=_Enc, ensure_ascii=False).encode('utf-8')
            start_response('200 OK', [
                ('Content-Type', 'application/json; charset=utf-8'),
                ('Content-Length', str(len(resp_body))),
                ('Access-Control-Allow-Origin', '*'),
            ])
            return [resp_body]

    return _json_resp(start_response, '404 Not Found', {'error': 'Ruta no encontrada'})
