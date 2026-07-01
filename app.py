import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime
from decimal import Decimal

RELOAD_TOKEN        = os.environ.get('RELOAD_TOKEN', '')
OAUTH_CLIENT_ID     = os.environ.get('OAUTH_CLIENT_ID', '')
OAUTH_CLIENT_SECRET = os.environ.get('OAUTH_CLIENT_SECRET', '')
BASE_URL            = os.environ.get('BASE_URL', 'https://mcp.pintuandes.com')
SERVER_NAME          = 'corp-mcp-py'
SERVER_VERSION       = '4.19.0'
API_BASE_URL         = os.environ.get('API_BASE_URL',  'https://api.pintuandes.com')
API_INTERNAL_KEY     = os.environ.get('INTERNAL_KEY',  '')
MCP_VERSION         = '2025-11-25'

# ---------------------------------------------------------------------------
# Request log — almacena últimas 100 entradas en memoria
# ---------------------------------------------------------------------------

_log_entries = []
_log_lock    = threading.Lock()
_LOG_FILE    = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mcp_requests.log')

def _log(tag, data):
    entry = {
        't':   time.strftime('%Y-%m-%d %H:%M:%S'),
        'tag': tag,
        'data': data,
    }
    with _log_lock:
        _log_entries.append(entry)
        if len(_log_entries) > 100:
            _log_entries.pop(0)
    try:
        with open(_LOG_FILE, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception:
        pass


def _log_request(environ, tag='req'):
    """Registra los headers y body de una petición entrante."""
    headers = {}
    for key, val in environ.items():
        if key.startswith('HTTP_'):
            headers[key[5:].replace('_', '-').title()] = val
        elif key in ('CONTENT_TYPE', 'CONTENT_LENGTH', 'REQUEST_METHOD',
                     'PATH_INFO', 'QUERY_STRING', 'REMOTE_ADDR'):
            headers[key] = val
    _log(tag, headers)


# ---------------------------------------------------------------------------
# OAuth 2.0 — persistido en disco para sobrevivir reinicios del proceso
# ---------------------------------------------------------------------------

_OAUTH_FILE    = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.oauth_store.json')
_auth_codes    = {}
_access_tokens = {}
_oauth_lock    = threading.Lock()


def _oauth_load():
    try:
        with open(_OAUTH_FILE) as f:
            data = json.load(f)
        now = time.time()
        _auth_codes.update({k: v for k, v in data.get('codes', {}).items() if v['exp'] > now})
        _access_tokens.update({k: v for k, v in data.get('tokens', {}).items() if v['exp'] > now})
    except Exception:
        pass


def _oauth_save():
    try:
        with open(_OAUTH_FILE, 'w') as f:
            json.dump({'codes': _auth_codes, 'tokens': _access_tokens}, f)
    except Exception:
        pass


_oauth_load()


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
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'code_challenge': code_challenge,
            'exp': time.time() + 600,
        }
        _oauth_save()
    return code


def _new_access_token(client_id):
    _clean_expired()
    token = secrets.token_urlsafe(40)
    with _oauth_lock:
        _access_tokens[token] = {'client_id': client_id, 'exp': time.time() + 31536000}
        _oauth_save()
    return token


def _valid_token(token):
    entry = _access_tokens.get(token)
    if entry and time.time() < entry['exp']:
        return True
    # Token not in this worker's memory — reload from disk in case another worker issued it
    _oauth_load()
    entry = _access_tokens.get(token)
    return bool(entry and time.time() < entry['exp'])


def _verify_pkce(verifier, challenge):
    digest  = hashlib.sha256(verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return secrets.compare_digest(computed, challenge)


def _bearer(environ):
    auth = environ.get('HTTP_AUTHORIZATION', '')
    return auth[7:] if auth.startswith('Bearer ') else None


# ---------------------------------------------------------------------------
# Login de usuario contra corp-api (para OAuth authorize)
# ---------------------------------------------------------------------------

def _validate_user_login(cod, pwd):
    """Valida credenciales contra corp-api. Retorna dict de usuario o None."""
    try:
        body = json.dumps({'cod': cod, 'pwd': pwd}).encode('utf-8')
        req  = urllib.request.Request(
            API_BASE_URL + '/auth/login',
            data=body,
            headers={'Content-Type': 'application/json; charset=utf-8'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get('usuario') if data.get('ok') else None
    except Exception:
        return None


def _proof_make(cod):
    """Genera token HMAC firmado para confirmar login en el paso de autorización."""
    exp = int(time.time()) + 600
    msg = f"{cod}|{exp}".encode()
    sig = hmac.new(RELOAD_TOKEN.encode(), msg, hashlib.sha256).hexdigest()
    return f"{cod}|{exp}|{sig}"


def _proof_verify(proof):
    """Verifica token HMAC. Retorna cod de usuario o None si inválido/expirado."""
    try:
        cod, exp_str, sig = proof.split('|')
        msg      = f"{cod}|{exp_str}".encode()
        expected = hmac.new(RELOAD_TOKEN.encode(), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if time.time() > int(exp_str):
            return None
        return cod
    except Exception:
        return None


_OAUTH_CSS = """
body{font-family:system-ui,sans-serif;display:flex;align-items:center;
     justify-content:center;min-height:100vh;margin:0;background:#f1f5f9}
.card{background:#fff;border-radius:14px;padding:40px 36px;max-width:380px;
      width:90%;box-shadow:0 4px 28px rgba(0,0,0,.10);text-align:center}
.logo{font-size:2.2rem;margin-bottom:12px}
h1{font-size:1.25rem;color:#0f172a;margin:0 0 4px;font-weight:700}
.sub{color:#6b7280;font-size:.88rem;margin:0 0 22px}
label{display:block;text-align:left;font-size:.82rem;font-weight:600;
      color:#374151;margin-bottom:4px}
.inp{width:100%;padding:10px 13px;border:1.5px solid #d1d5db;border-radius:8px;
     font-size:.95rem;margin-bottom:14px;box-sizing:border-box;transition:.2s}
.inp:focus{outline:none;border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.12)}
.btn{display:block;width:100%;padding:11px;border:none;border-radius:8px;
     font-size:.95rem;cursor:pointer;margin-bottom:10px;font-weight:600;transition:.15s}
.btn-primary{background:#2563eb;color:#fff}
.btn-primary:hover{background:#1d4ed8}
.btn-secondary{background:#f1f5f9;color:#374151}
.btn-secondary:hover{background:#e2e8f0}
.error{background:#fef2f2;border:1px solid #fca5a5;color:#b91c1c;
       border-radius:7px;padding:9px 12px;margin-bottom:14px;font-size:.87rem}
.ok-box{background:#f0fdf4;border:1px solid #86efac;border-radius:8px;
        padding:12px;margin-bottom:18px;color:#166534;font-size:.88rem;line-height:1.5}
"""


def _html_login(action_url, error=''):
    err = f'<div class="error">⚠ {error}</div>' if error else ''
    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Corporativo C.A. — Acceso</title>
<style>{_OAUTH_CSS}</style></head>
<body><div class="card">
  <img src="http://www.pintuandes.com/corporativo_logo.png" alt="Corporativo C.A." style="height:64px;margin-bottom:12px;object-fit:contain">
  <h1>Corporativo C.A.</h1>
  <p class="sub">Ingresa tus credenciales para conectar Claude AI</p>
  {err}
  <form method="POST" action="{action_url}">
    <label>Usuario</label>
    <input class="inp" type="text" name="cod" placeholder="Código de usuario"
           autocomplete="username" required autofocus>
    <label>Contraseña</label>
    <input class="inp" type="password" name="pwd" placeholder="Contraseña"
           autocomplete="current-password" required>
    <input type="hidden" name="action" value="login">
    <button class="btn btn-primary" type="submit">Ingresar →</button>
  </form>
</div></body></html>"""


def _html_approve(action_url, usuario, proof):
    nomb = usuario.get('nomb', '')
    rol  = usuario.get('rol', '').capitalize()
    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Corporativo C.A. — Autorizar</title>
<style>{_OAUTH_CSS}</style></head>
<body><div class="card">
  <img src="http://www.pintuandes.com/corporativo_logo.png" alt="Corporativo C.A." style="height:64px;margin-bottom:12px;object-fit:contain">
  <h1>Corporativo C.A.</h1>
  <div class="ok-box">
    ✅ Bienvenido, <strong>{nomb}</strong><br>
    <span style="color:#4b5563">Rol: {rol}</span>
  </div>
  <p class="sub">Claude AI solicita acceso a los datos corporativos con tu cuenta.</p>
  <form method="POST" action="{action_url}">
    <input type="hidden" name="auth_proof" value="{proof}">
    <button class="btn btn-primary"   name="action" value="approve">✅ Autorizar acceso</button>
    <button class="btn btn-secondary" name="action" value="deny">Cancelar</button>
  </form>
</div></body></html>"""


# ---------------------------------------------------------------------------
# Cliente HTTP hacia corp-api
# ---------------------------------------------------------------------------

def _api(path, params=None):
    url = API_BASE_URL + path
    if params:
        clean = {k: str(v) for k, v in params.items() if v not in (None, '')}
        if clean:
            url += '?' + urllib.parse.urlencode(clean)
    req = urllib.request.Request(url, headers={'X-Internal-Key': API_INTERNAL_KEY})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {'ok': False, 'error': f'API HTTP {e.code}'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


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

TOOLS = [
    {
        'name': 'consultar_ventas',
        'description': (
            'Consulta el DETALLE de ventas de Corporativo C.A. línea por línea (producto × cliente × vendedor × día). '
            'Úsalo cuando el usuario necesite ver el desglose completo de transacciones, no un resumen. '
            'Para resúmenes usa: ventas_por_mes, ventas_por_producto, ventas_por_cliente, ventas_por_vendedor o ventas_por_proveedor. '
            'Retorna por fila: Producto, Almacén, Cliente, Vendedor, Cantidad (Unidades), Monto (USD), Costo (USD). '
            'El campo Mes muestra el MES en formato YYYY-MM (ej: 2026-06 = junio 2026), no una fecha exacta. '
            'REGLA OBLIGATORIA: además del rango de fechas, SIEMPRE aplica al menos un filtro adicional '
            '(producto, almacén, cliente, vendedor o marca). Sin filtros la consulta puede retornar miles de registros. '
            'Si el usuario no indica filtro, pídele uno antes de ejecutar. '
            'Los filtros usan CÓDIGOS: si el usuario da un nombre, '
            'primero usa buscar_clientes / buscar_vendedores / buscar_productos para obtener el código. '
            'Ejemplos: '
            '"ventas al cliente REYES en enero" → buscar_clientes("REYES") → código → consultar_ventas; '
            '"ventas del producto BOLSA en febrero" → producto_desde=BOLSA, producto_hasta=BOLSA; '
            '"ventas del vendedor 24" → vendedor_desde=24, vendedor_hasta=24.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'desde':           {'type': 'string', 'description': 'Fecha inicio YYYY-MM-DD (default: primer día del año actual)'},
                'hasta':           {'type': 'string', 'description': 'Fecha fin YYYY-MM-DD (default: hoy)'},
                'producto_desde':  {'type': 'string', 'description': 'Código de producto inicial (ej: BOLSA, P0104093). Úsalo solo, sin desde/hasta si es un producto específico'},
                'producto_hasta':  {'type': 'string', 'description': 'Código de producto final. Dejar igual a producto_desde para un solo producto'},
                'almacen_desde':   {'type': 'string', 'description': 'Código de almacén inicial (ej: 001, 002)'},
                'almacen_hasta':   {'type': 'string', 'description': 'Código de almacén final. Igual a almacen_desde para un solo almacén'},
                'cliente_desde':   {'type': 'string', 'description': 'Código de cliente inicial (obtenido con buscar_clientes si solo se conoce el nombre)'},
                'cliente_hasta':   {'type': 'string', 'description': 'Código de cliente final. Igual a cliente_desde para un solo cliente'},
                'vendedor_desde':  {'type': 'string', 'description': 'Código de vendedor inicial (obtenido con buscar_vendedores si solo se conoce el nombre)'},
                'vendedor_hasta':  {'type': 'string', 'description': 'Código de vendedor final. Igual a vendedor_desde para un solo vendedor'},
                'sucursal_desde':  {'type': 'string', 'description': 'Código de sucursal inicial (ej: 0)'},
                'sucursal_hasta':  {'type': 'string', 'description': 'Código de sucursal final'},
                'marca_desde':     {'type': 'string', 'description': 'Código de marca/proveedor inicial (obtenido con buscar_socios si solo se conoce el nombre)'},
                'marca_hasta':     {'type': 'string', 'description': 'Código de marca/proveedor final'},
            },
            'required': [],
        },
    },
    {
        'name': 'buscar_clientes',
        'description': (
            'Busca clientes de ventas por nombre o código. '
            'Úsalo cuando el usuario mencione un cliente por nombre y necesites el código para filtrar consultar_ventas. '
            'Ejemplo: el usuario dice "ventas al cliente REYES CONTRERAS" → buscar_clientes("REYES") → obtener socCdg → pasar a consultar_ventas.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'buscar': {'type': 'string', 'description': 'Nombre o código de cliente a buscar (búsqueda parcial)'},
                'limite': {'type': 'integer', 'description': 'Máximo de registros (default 20)'},
            },
            'required': ['buscar'],
        },
    },
    {
        'name': 'buscar_vendedores',
        'description': (
            'Busca vendedores por nombre o código. '
            'Úsalo cuando el usuario mencione un vendedor por nombre y necesites el código para filtrar consultar_ventas.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'buscar': {'type': 'string', 'description': 'Nombre o código de vendedor a buscar (búsqueda parcial)'},
                'limite': {'type': 'integer', 'description': 'Máximo de registros (default 20)'},
            },
            'required': ['buscar'],
        },
    },
    {
        'name': 'buscar_productos',
        'description': (
            'Busca productos por nombre o código. '
            'Úsalo cuando el usuario mencione un producto por nombre y necesites el código para filtrar consultar_ventas o ventas_por_producto. '
            'El resultado también incluye el campo mrcCdg (código de marca/proveedor) útil para ventas_por_proveedor.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'buscar': {'type': 'string', 'description': 'Nombre o código de producto a buscar (búsqueda parcial)'},
                'limite': {'type': 'integer', 'description': 'Máximo de registros (default 20)'},
            },
            'required': ['buscar'],
        },
    },
    {
        'name': 'ventas_por_mes',
        'description': (
            'Retorna las ventas de Corporativo C.A. ACUMULADAS POR MES: total de unidades, monto y costo en cada mes del período. '
            'Úsalo cuando el usuario pida evolución mensual, tendencia de ventas, comparar meses o ver el resumen del año. '
            'No tiene filtros de producto, cliente ni vendedor — muestra el total global por mes. '
            'Si necesitas ver un período desde el inicio del año y el usuario no indica fecha, usa desde=primer día del año actual.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'desde': {'type': 'string', 'description': 'Fecha inicio YYYY-MM-DD (default: primer día del año actual)'},
                'hasta': {'type': 'string', 'description': 'Fecha fin YYYY-MM-DD (default: hoy)'},
            },
            'required': [],
        },
    },
    {
        'name': 'ventas_por_producto',
        'description': (
            'Retorna las ventas de Corporativo C.A. agrupadas por MES y PRODUCTO: unidades, monto y costo. '
            'Úsalo para ver qué productos se vendieron más, ranking de productos, o ventas de un producto específico en el tiempo. '
            'Si el usuario menciona un producto por nombre, primero usa buscar_productos para obtener el código (prdCdg). '
            'Si no indica fecha, usa desde=primer día del año actual. '
            'Los filtros producto_desde / producto_hasta son opcionales: sin ellos retorna todos los productos.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'desde':           {'type': 'string', 'description': 'Fecha inicio YYYY-MM-DD (default: primer día del año actual)'},
                'hasta':           {'type': 'string', 'description': 'Fecha fin YYYY-MM-DD (default: hoy)'},
                'producto_desde':  {'type': 'string', 'description': 'Código de producto inicial. Para un solo producto usa el mismo código en producto_desde y producto_hasta'},
                'producto_hasta':  {'type': 'string', 'description': 'Código de producto final'},
            },
            'required': [],
        },
    },
    {
        'name': 'ventas_por_cliente',
        'description': (
            'Retorna las ventas de Corporativo C.A. agrupadas por MES y CLIENTE: unidades, monto y costo. '
            'Úsalo para análisis de cartera, ver los mejores clientes, o ventas de un cliente específico en el tiempo. '
            'Si el usuario menciona un cliente por nombre, primero usa buscar_clientes para obtener el código (socCdg). '
            'Si no indica fecha, usa desde=primer día del año actual. '
            'Los filtros cliente_desde / cliente_hasta son opcionales: sin ellos retorna todos los clientes.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'desde':          {'type': 'string', 'description': 'Fecha inicio YYYY-MM-DD (default: primer día del año actual)'},
                'hasta':          {'type': 'string', 'description': 'Fecha fin YYYY-MM-DD (default: hoy)'},
                'cliente_desde':  {'type': 'string', 'description': 'Código de cliente inicial. Para un solo cliente usa el mismo código en ambos'},
                'cliente_hasta':  {'type': 'string', 'description': 'Código de cliente final'},
            },
            'required': [],
        },
    },
    {
        'name': 'ventas_por_vendedor',
        'description': (
            'Retorna las ventas de Corporativo C.A. agrupadas por MES y VENDEDOR: unidades, monto y costo. '
            'Úsalo para evaluar desempeño del equipo de ventas, ranking de vendedores, o seguimiento de un vendedor específico. '
            'Si el usuario menciona un vendedor por nombre, primero usa buscar_vendedores para obtener el código. '
            'Si no indica fecha, usa desde=primer día del año actual. '
            'Los filtros vendedor_desde / vendedor_hasta son opcionales: sin ellos retorna todos los vendedores.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'desde':            {'type': 'string', 'description': 'Fecha inicio YYYY-MM-DD (default: primer día del año actual)'},
                'hasta':            {'type': 'string', 'description': 'Fecha fin YYYY-MM-DD (default: hoy)'},
                'vendedor_desde':   {'type': 'string', 'description': 'Código de vendedor inicial. Para un solo vendedor usa el mismo código en ambos'},
                'vendedor_hasta':   {'type': 'string', 'description': 'Código de vendedor final'},
            },
            'required': [],
        },
    },
    {
        'name': 'ventas_por_proveedor',
        'description': (
            'Retorna las ventas de Corporativo C.A. agrupadas por MES y PROVEEDOR/MARCA: unidades, monto y costo. '
            'Úsalo para ver la participación de cada marca en las ventas (ej: AMANCO, TIGRE, DURMAN). '
            'El código de proveedor/marca es el campo mrcCdg que aparece en buscar_productos — '
            'si el usuario menciona una marca, usa buscar_productos para encontrar el mrcCdg. '
            'Si no indica fecha, usa desde=primer día del año actual. '
            'Los filtros marca_desde / marca_hasta son opcionales: sin ellos retorna todos los proveedores.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'desde':        {'type': 'string', 'description': 'Fecha inicio YYYY-MM-DD (default: primer día del año actual)'},
                'hasta':        {'type': 'string', 'description': 'Fecha fin YYYY-MM-DD (default: hoy)'},
                'marca_desde':  {'type': 'string', 'description': 'Código de proveedor/marca inicial (campo mrcCdg de buscar_productos)'},
                'marca_hasta':  {'type': 'string', 'description': 'Código de proveedor/marca final'},
            },
            'required': [],
        },
    },
]


def _tool_consultar_ventas(args):
    result = _api('/ventas', {
        'desde':          args.get('desde'),
        'hasta':          args.get('hasta'),
        'producto_desde': args.get('producto_desde'),
        'producto_hasta': args.get('producto_hasta'),
        'almacen_desde':  args.get('almacen_desde'),
        'almacen_hasta':  args.get('almacen_hasta'),
        'cliente_desde':  args.get('cliente_desde'),
        'cliente_hasta':  args.get('cliente_hasta'),
        'vendedor_desde': args.get('vendedor_desde'),
        'vendedor_hasta': args.get('vendedor_hasta'),
        'sucursal_desde': args.get('sucursal_desde'),
        'sucursal_hasta': args.get('sucursal_hasta'),
        'marca_desde':    args.get('marca_desde'),
        'marca_hasta':    args.get('marca_hasta'),
    })
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron ventas con los filtros indicados.'
    lines = [f'Estadística de ventas ({len(rows)} registros):',
             f'{"Mes":<9} {"Producto":<16} {"Almacén":<10} {"Cliente":<22} {"Vendedor":<20} '
             f'{"Cant.(Unid.)":>12} {"Monto (USD)":>12} {"Costo (USD)":>12}']
    lines.append('-' * 123)
    for r in rows:
        mes_raw = str(r.get('oprMes', ''))
        mes_fmt = mes_raw[:7] if len(mes_raw) >= 7 else mes_raw  # "2026-06-01" → "2026-06"
        lines.append(
            f"{mes_fmt:<9} "
            f"{str(r.get('prdCdg','')).strip():<16} "
            f"{str(r.get('Almacen','')).strip():<10} "
            f"{str(r.get('Cliente','')).strip():<22} "
            f"{str(r.get('Vendedor','')).strip():<20} "
            f"{float(r.get('oprCnt',0)):>12.2f} "
            f"{float(r.get('oprMnt',0)):>12.2f} "
            f"{float(r.get('oprCst',0)):>12.2f}"
        )
    total_cnt = sum(float(r.get('oprCnt', 0)) for r in rows)
    total_mnt = sum(float(r.get('oprMnt', 0)) for r in rows)
    total_cst = sum(float(r.get('oprCst', 0)) for r in rows)
    lines.append('-' * 123)
    lines.append(f"{'TOTALES':<59} {total_cnt:>12.2f} {total_mnt:>12.2f} {total_cst:>12.2f}")
    return '\n'.join(lines)


def _tool_buscar_clientes(args):
    result = _api('/clientes', {'buscar': args.get('buscar', ''), 'limite': args.get('limite', 20)})
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron clientes con ese criterio.'
    lines = [f'Clientes encontrados ({len(rows)} registros):']
    for r in rows:
        lines.append(f"  Código: {r['socCdg']} | {(r.get('socDsc') or '').strip()} | RIF: {r.get('socRif','')}")
    return '\n'.join(lines)


def _tool_buscar_vendedores(args):
    result = _api('/vendedores', {'buscar': args.get('buscar', ''), 'limite': args.get('limite', 20)})
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron vendedores con ese criterio.'
    lines = [f'Vendedores encontrados ({len(rows)} registros):']
    for r in rows:
        lines.append(f"  Código: {r['socCdg']} | {(r.get('socDsc') or '').strip()}")
    return '\n'.join(lines)


def _tool_buscar_productos(args):
    result = _api('/productos', {'buscar': args.get('buscar', ''), 'limite': args.get('limite', 20)})
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron productos con ese criterio.'
    lines = [f'Productos encontrados ({len(rows)} registros):']
    for r in rows:
        lines.append(f"  Código: {r['prdCdg']} | {(r.get('prdDsc') or '').strip()} | Marca: {r.get('mrcCdg','')}")
    return '\n'.join(lines)


def _year_start():
    return f'{date.today().year}-01-01'


def _tool_ventas_por_mes(args):
    result = _api('/ventas', {
        'modo':  'vntStdMes',
        'desde': args.get('desde') or _year_start(),
        'hasta': args.get('hasta'),
    })
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron ventas en el período indicado.'
    return _dumps({'total_meses': len(rows), 'data': rows})


def _tool_ventas_por_producto(args):
    result = _api('/ventas', {
        'modo':           'vntStdPrd',
        'desde':          args.get('desde') or _year_start(),
        'hasta':          args.get('hasta'),
        'producto_desde': args.get('producto_desde'),
        'producto_hasta': args.get('producto_hasta'),
    })
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron ventas con los filtros indicados.'
    return _dumps({'total': len(rows), 'data': rows})


def _tool_ventas_por_cliente(args):
    result = _api('/ventas', {
        'modo':          'vntStdClt',
        'desde':         args.get('desde') or _year_start(),
        'hasta':         args.get('hasta'),
        'cliente_desde': args.get('cliente_desde'),
        'cliente_hasta': args.get('cliente_hasta'),
    })
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron ventas con los filtros indicados.'
    return _dumps({'total': len(rows), 'data': rows})


def _tool_ventas_por_vendedor(args):
    result = _api('/ventas', {
        'modo':           'vntStdVnd',
        'desde':          args.get('desde') or _year_start(),
        'hasta':          args.get('hasta'),
        'vendedor_desde': args.get('vendedor_desde'),
        'vendedor_hasta': args.get('vendedor_hasta'),
    })
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron ventas con los filtros indicados.'
    return _dumps({'total': len(rows), 'data': rows})


def _tool_ventas_por_proveedor(args):
    result = _api('/ventas', {
        'modo':        'vntStdPrv',
        'desde':       args.get('desde') or _year_start(),
        'hasta':       args.get('hasta'),
        'marca_desde': args.get('marca_desde'),
        'marca_hasta': args.get('marca_hasta'),
    })
    if not result.get('ok'):
        return f"Error: {result.get('error')}"
    rows = result.get('data', [])
    if not rows:
        return 'No se encontraron ventas con los filtros indicados.'
    return _dumps({'total': len(rows), 'data': rows})


def _call_tool(name, arguments):
    try:
        if name == 'consultar_ventas':      return _tool_consultar_ventas(arguments)
        if name == 'buscar_clientes':       return _tool_buscar_clientes(arguments)
        if name == 'buscar_vendedores':     return _tool_buscar_vendedores(arguments)
        if name == 'buscar_productos':      return _tool_buscar_productos(arguments)
        if name == 'ventas_por_mes':        return _tool_ventas_por_mes(arguments)
        if name == 'ventas_por_producto':   return _tool_ventas_por_producto(arguments)
        if name == 'ventas_por_cliente':    return _tool_ventas_por_cliente(arguments)
        if name == 'ventas_por_vendedor':   return _tool_ventas_por_vendedor(arguments)
        if name == 'ventas_por_proveedor':  return _tool_ventas_por_proveedor(arguments)
        return f'Herramienta desconocida: {name}'
    except Exception as e:
        return f'Error al ejecutar {name}: {str(e)}'


# ---------------------------------------------------------------------------
# MCP JSON-RPC
# ---------------------------------------------------------------------------

def _handle_mcp(body_bytes, environ):
    try:
        req = json.loads(body_bytes)
    except Exception:
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}

    method = req.get('method', '')
    params = req.get('params') or {}
    req_id = req.get('id')

    _log('mcp', {
        'method': method,
        'id': req_id,
        'ip': environ.get('REMOTE_ADDR', ''),
        'ua': environ.get('HTTP_USER_AGENT', '')[:120],
        'params_keys': list(params.keys()) if isinstance(params, dict) else [],
    })

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
        tool_name = params.get('name', '')
        arguments = params.get('arguments') or {}
        _log('tool_call', {'name': tool_name, 'arguments': arguments})
        result_text = _call_tool(tool_name, arguments)
        return {'jsonrpc': '2.0', 'id': req_id, 'result': {
            'content': [{'type': 'text', 'text': result_text}],
            'isError': False,
        }}
    if method == 'ping':
        return {'jsonrpc': '2.0', 'id': req_id, 'result': {}}

    return {'jsonrpc': '2.0', 'id': req_id,
            'error': {'code': -32601, 'message': f'Method not found: {method}'}}


# ---------------------------------------------------------------------------
# WSGI helpers
# ---------------------------------------------------------------------------

def _parse_qs(qs):
    out = {}
    for part in (qs or '').split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            out[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    return out


def _read_body(environ):
    try:
        n = int(environ.get('CONTENT_LENGTH') or 0)
        return environ['wsgi.input'].read(n) if n > 0 else b''
    except Exception:
        return b''


def _json(start_response, status, data, extra=None):
    body = json.dumps(data, cls=_Enc, ensure_ascii=False).encode('utf-8')
    hdrs = [('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', str(len(body))),
            ('Cache-Control', 'no-store')]
    if extra:
        hdrs.extend(extra)
    start_response(status, hdrs)
    return [body]


def _html(start_response, html_str):
    body = html_str.encode('utf-8')
    start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8'),
                               ('Content-Length', str(len(body)))])
    return [body]


# ---------------------------------------------------------------------------
# WSGI application
# ---------------------------------------------------------------------------

def application(environ, start_response):
    path   = environ.get('PATH_INFO', '/')
    method = environ.get('REQUEST_METHOD', 'GET')
    qs     = _parse_qs(environ.get('QUERY_STRING', ''))

    _log('hit', {
        'm':  method, 'p': path,
        'ip': environ.get('REMOTE_ADDR', ''),
        'ua': environ.get('HTTP_USER_AGENT', '')[:80],
    })

    # ── Health ──────────────────────────────────────────────────────────────
    if path == '/health':
        return _json(start_response, '200 OK', {
            'status':  'ok',
            'service': SERVER_NAME,
            'version': SERVER_VERSION,
            'api':     API_BASE_URL,
            'oauth':   'configurado' if OAUTH_CLIENT_ID else 'sin configurar',
            'base_url': BASE_URL,
        })

    # ── Log viewer ──────────────────────────────────────────────────────────
    if path == '/log':
        if qs.get('token') != RELOAD_TOKEN:
            return _json(start_response, '401 Unauthorized', {'error': 'Token requerido'})
        # Lee del archivo compartido (visible desde todos los workers)
        file_entries = []
        try:
            with open(_LOG_FILE) as f:
                lines = f.readlines()
            for line in lines[-200:]:
                try:
                    file_entries.append(json.loads(line.strip()))
                except Exception:
                    pass
        except Exception:
            pass
        entries = file_entries if file_entries else list(_log_entries)
        if qs.get('fmt') == 'html':
            rows = ''.join(
                f'<tr><td>{e["t"]}</td><td><b>{e["tag"]}</b></td>'
                f'<td><pre>{json.dumps(e["data"], ensure_ascii=False, indent=2)}</pre></td></tr>'
                for e in reversed(entries)
            )
            html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Log — {SERVER_NAME}</title>
<style>body{{font-family:monospace;font-size:13px;background:#111;color:#eee;padding:16px}}
table{{border-collapse:collapse;width:100%}}
td{{border:1px solid #333;padding:6px 10px;vertical-align:top}}
td:first-child{{white-space:nowrap;color:#aaa}} b{{color:#7cf}}
pre{{margin:0;white-space:pre-wrap;word-break:break-all}}</style></head>
<body><h2>{SERVER_NAME} v{SERVER_VERSION} — Request Log ({len(entries)} entradas)</h2>
<table>{rows}</table></body></html>"""
            return _html(start_response, html)
        return _json(start_response, '200 OK', entries)

    # ── Reload ──────────────────────────────────────────────────────────────
    if path == '/reload':
        if not RELOAD_TOKEN or qs.get('token') != RELOAD_TOKEN:
            return _json(start_response, '401 Unauthorized', {'error': 'Token inválido'})
        _log('reload', {'ip': environ.get('REMOTE_ADDR', '')})
        def _exit():
            import time as _t
            _t.sleep(0.5)
            os._exit(0)
        threading.Thread(target=_exit, daemon=True).start()
        return _json(start_response, '200 OK', {'mensaje': 'Reiniciando proceso...'})

    # ── Deploy desde GitHub ──────────────────────────────────────────────────
    if path == '/deploy':
        if not RELOAD_TOKEN or qs.get('token') != RELOAD_TOKEN:
            return _json(start_response, '401 Unauthorized', {'error': 'Token inválido'})
        _log('deploy', {'ip': environ.get('REMOTE_ADDR', '')})
        app_dir = os.path.dirname(os.path.abspath(__file__))
        REPO_URL = 'https://github.com/Hercrak/corp-mcp.git'
        output = []

        def _run(cmd):
            r = subprocess.run(cmd, cwd=app_dir, capture_output=True, text=True, timeout=30)
            output.append(f"$ {' '.join(cmd)}\n{(r.stdout + r.stderr).strip()}")
            return r.returncode

        # Inicializar git si no existe .git en el directorio
        if not os.path.exists(os.path.join(app_dir, '.git')):
            _run(['git', 'init'])
            _run(['git', 'remote', 'add', 'origin', REPO_URL])

        # Sincronizar desde GitHub (sobreescribe cualquier cambio local)
        _run(['git', 'fetch', 'origin', 'main'])
        _run(['git', 'reset', '--hard', 'origin/main'])

        # Señalar a Passenger que reinicie en la próxima petición
        try:
            restart = os.path.join(app_dir, 'tmp', 'restart.txt')
            os.makedirs(os.path.dirname(restart), exist_ok=True)
            with open(restart, 'w') as f:
                f.write(time.strftime('%Y-%m-%d %H:%M:%S'))
            output.append('tmp/restart.txt actualizado — Passenger reiniciará en la próxima petición')
        except Exception as e:
            output.append(f'restart.txt error: {e}')

        return _json(start_response, '200 OK', {'deploy': '\n\n'.join(output)})

    # ── OAuth Protected Resource Metadata (RFC 9728) — nuevo estándar MCP 2025
    if path in ('/.well-known/oauth-protected-resource',
                '/.well-known/oauth-protected-resource/mcp'):
        _log('oauth_resource_meta', {'path': path, 'ip': environ.get('REMOTE_ADDR', '')})
        return _json(start_response, '200 OK', {
            'resource':               f'{BASE_URL}/mcp',
            'authorization_servers':  [BASE_URL],
            'bearer_methods_supported': ['header'],
            'scopes_supported':       ['mcp'],
        })

    # ── OAuth discovery ──────────────────────────────────────────────────────
    if path in ('/.well-known/oauth-authorization-server', '/.well-known/openid-configuration'):
        _log_request(environ, 'oauth_discovery')
        return _json(start_response, '200 OK', {
            'issuer': BASE_URL,
            'authorization_endpoint': f'{BASE_URL}/oauth/authorize',
            'token_endpoint':         f'{BASE_URL}/oauth/token',
            'registration_endpoint':  f'{BASE_URL}/oauth/register',
            'response_types_supported':            ['code'],
            'grant_types_supported':               ['authorization_code', 'client_credentials'],
            'code_challenge_methods_supported':    ['S256'],
            'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
        })

    # ── OAuth register ───────────────────────────────────────────────────────
    if path == '/oauth/register' and method == 'POST':
        body = _read_body(environ)
        _log('oauth_register', {
            'ip':   environ.get('REMOTE_ADDR', ''),
            'body': body.decode('utf-8', errors='replace')[:500],
            'ct':   environ.get('CONTENT_TYPE', ''),
        })
        return _json(start_response, '201 Created', {
            'client_id':             OAUTH_CLIENT_ID,
            'client_secret':         OAUTH_CLIENT_SECRET,
            'client_id_issued_at':   int(time.time()),
            'client_secret_expires_at': 0,
            'token_endpoint_auth_method': 'client_secret_basic',
            'grant_types':    ['authorization_code'],
            'response_types': ['code'],
        })

    # ── OAuth authorize ──────────────────────────────────────────────────────
    if path == '/oauth/authorize':
        client_id      = qs.get('client_id', '')
        redirect_uri   = qs.get('redirect_uri', '')
        state          = qs.get('state', '')
        code_challenge = qs.get('code_challenge', '')

        _log('oauth_authorize', {
            'method':       method,
            'client_id':    client_id,
            'redirect_uri': redirect_uri,
            'state':        state[:20],
            'has_challenge': bool(code_challenge),
            'ip':           environ.get('REMOTE_ADDR', ''),
            'ua':           environ.get('HTTP_USER_AGENT', '')[:80],
        })

        if OAUTH_CLIENT_ID and client_id != OAUTH_CLIENT_ID:
            return _json(start_response, '400 Bad Request', {'error': 'invalid_client'})

        action_url = (
            f"/oauth/authorize"
            f"?client_id={urllib.parse.quote(client_id)}"
            f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
            f"&state={urllib.parse.quote(state)}"
            f"&code_challenge={urllib.parse.quote(code_challenge)}"
            f"&code_challenge_method=S256"
        )

        if method == 'POST':
            bp     = _parse_qs(_read_body(environ).decode('utf-8', errors='replace'))
            action = bp.get('action', '')
            _log('oauth_authorize_post', {'action': action, 'keys': list(bp.keys())})
            try:
                if action == 'deny':
                    sep = '&' if '?' in redirect_uri else '?'
                    loc = f"{redirect_uri}{sep}error=access_denied&state={urllib.parse.quote(state)}"
                    start_response('302 Found', [('Location', loc)])
                    return [b'']

                if action == 'login':
                    cod = (bp.get('cod') or '').strip()
                    pwd = (bp.get('pwd') or '').strip()
                    usuario = _validate_user_login(cod, pwd) if cod and pwd else None
                    if not usuario:
                        return _html(start_response,
                                     _html_login(action_url, 'Usuario o contraseña incorrectos'))
                    proof = _proof_make(usuario['cod'])
                    _log('oauth_login_ok', {'cod': usuario['cod'], 'ip': environ.get('REMOTE_ADDR', '')})
                    return _html(start_response, _html_approve(action_url, usuario, proof))

                if action == 'approve':
                    cod = _proof_verify(bp.get('auth_proof', ''))
                    if not cod:
                        return _html(start_response,
                                     _html_login(action_url, 'Sesión expirada. Ingresa nuevamente.'))
                    code = _new_auth_code(client_id, redirect_uri, code_challenge)
                    _log('oauth_approved', {'cod': cod, 'ip': environ.get('REMOTE_ADDR', '')})
                    sep  = '&' if '?' in redirect_uri else '?'
                    loc  = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
                    start_response('302 Found', [('Location', loc), ('Cache-Control', 'no-store')])
                    return [b'']

            except Exception as e:
                _log('oauth_authorize_err', {'error': str(e), 'action': action})
                return _html(start_response, _html_login(action_url, f'Error interno: {str(e)}'))

        return _html(start_response, _html_login(action_url))

    # ── OAuth token ──────────────────────────────────────────────────────────
    if path == '/oauth/token' and method == 'POST':
        raw        = _read_body(environ)
        bp         = _parse_qs(raw.decode('utf-8', errors='replace'))
        grant_type    = bp.get('grant_type', '')
        code          = bp.get('code', '')
        code_verifier = bp.get('code_verifier', '')
        client_id     = bp.get('client_id', '')
        client_secret = bp.get('client_secret', '')
        auth_hdr      = environ.get('HTTP_AUTHORIZATION', '')
        auth_src      = 'body'

        if auth_hdr.startswith('Basic '):
            try:
                dec = base64.b64decode(auth_hdr[6:]).decode('utf-8')
                client_id, client_secret = dec.split(':', 1)
                client_id     = urllib.parse.unquote_plus(client_id)
                client_secret = urllib.parse.unquote_plus(client_secret)
                auth_src = 'basic'
            except Exception:
                pass

        _log('oauth_token', {
            'grant_type':  grant_type,
            'client_id':   client_id,
            'auth_src':    auth_src,
            'has_code':    bool(code),
            'has_verifier': bool(code_verifier),
            'body_keys':   list(bp.keys()),
            'auth_prefix': auth_hdr[:30] if auth_hdr else '',
            'ip':          environ.get('REMOTE_ADDR', ''),
        })

        if not client_id or not client_secret:
            _log('oauth_token_err', {'reason': 'missing credentials'})
            return _json(start_response, '401 Unauthorized', {'error': 'invalid_client'})

        if not secrets.compare_digest(client_id.strip(), OAUTH_CLIENT_ID) or \
           not secrets.compare_digest(client_secret.strip(), OAUTH_CLIENT_SECRET):
            _log('oauth_token_err', {'reason': 'bad credentials', 'client_id': client_id})
            return _json(start_response, '401 Unauthorized', {'error': 'invalid_client'})

        if grant_type == 'client_credentials':
            token = _new_access_token(client_id)
            _log('oauth_token_ok', {'client_id': client_id, 'grant': 'client_credentials'})
            return _json(start_response, '200 OK', {
                'access_token': token, 'token_type': 'Bearer', 'expires_in': 31536000,
            })

        if grant_type != 'authorization_code':
            return _json(start_response, '400 Bad Request', {'error': 'unsupported_grant_type'})

        with _oauth_lock:
            entry = _auth_codes.pop(code, None)

        # Código no encontrado en este worker — recargar del disco (otro worker lo pudo haber generado)
        if not entry:
            _oauth_load()
            with _oauth_lock:
                entry = _auth_codes.pop(code, None)

        if not entry or time.time() > entry['exp']:
            _log('oauth_token_err', {'reason': 'invalid or expired code'})
            return _json(start_response, '400 Bad Request', {'error': 'invalid_grant'})

        if entry.get('code_challenge') and code_verifier:
            if not _verify_pkce(code_verifier, entry['code_challenge']):
                _log('oauth_token_err', {'reason': 'pkce mismatch'})
                return _json(start_response, '400 Bad Request', {'error': 'invalid_grant'})

        token = _new_access_token(client_id)
        _log('oauth_token_ok', {'client_id': client_id})
        return _json(start_response, '200 OK', {
            'access_token': token, 'token_type': 'Bearer', 'expires_in': 31536000,
        })

    # ── MCP ─────────────────────────────────────────────────────────────────
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
            _log_request(environ, 'mcp_request')
            body = _read_body(environ)
            _log('mcp_body', {
                'len': len(body),
                'preview': body[:300].decode('utf-8', errors='replace'),
            })

            bearer = _bearer(environ)
            if OAUTH_CLIENT_ID and not _valid_token(bearer):
                _log('mcp_auth_fail', {'ip': environ.get('REMOTE_ADDR', ''),
                                       'auth': environ.get('HTTP_AUTHORIZATION', '')[:40]})
                return _json(start_response, '401 Unauthorized',
                             {'error': 'invalid_token'},
                             [('WWW-Authenticate', f'Bearer realm="{BASE_URL}"'),
                              ('Access-Control-Allow-Origin', '*')])

            body   = body or b'{}'
            t0     = time.time()
            result = _handle_mcp(body, environ)
            ms     = int((time.time() - t0) * 1000)

            try:
                req_data     = json.loads(body)
                mcp_method   = req_data.get('method', '')
                mcp_tool     = (req_data.get('params') or {}).get('name', '') if mcp_method == 'tools/call' else ''
                ip           = environ.get('REMOTE_ADDR', '')
                ua           = environ.get('HTTP_USER_AGENT', '')[:120]
                token_prefix = (bearer or '')[:8] + '…'
                _log('audit', {'ip': ip, 'ua': ua[:60], 'method': mcp_method,
                               'tool': mcp_tool, 'token': token_prefix, 'ms': ms})
            except Exception:
                pass
            if result is None:
                start_response('204 No Content', [('Content-Length', '0')])
                return [b'']
            resp = json.dumps(result, cls=_Enc, ensure_ascii=False).encode('utf-8')
            start_response('200 OK', [
                ('Content-Type', 'application/json; charset=utf-8'),
                ('Content-Length', str(len(resp))),
                ('Access-Control-Allow-Origin', '*'),
            ])
            return [resp]

    return _json(start_response, '404 Not Found', {'error': 'Ruta no encontrada'})
