import base64
import hashlib
import json
import os
import secrets
import subprocess
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

RELOAD_TOKEN        = os.environ.get('RELOAD_TOKEN', '')
OAUTH_CLIENT_ID     = os.environ.get('OAUTH_CLIENT_ID', '')
OAUTH_CLIENT_SECRET = os.environ.get('OAUTH_CLIENT_SECRET', '')
BASE_URL            = os.environ.get('BASE_URL', 'https://mcp.pintuandes.com')
SERVER_NAME         = 'corp-mcp-py'
SERVER_VERSION      = '4.7.0'
MCP_VERSION         = '2025-11-25'

# ---------------------------------------------------------------------------
# Request log — almacena últimas 100 entradas en memoria
# ---------------------------------------------------------------------------

_log_entries = []
_log_lock    = threading.Lock()

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
    return bool(entry and time.time() < entry['exp'])


def _verify_pkce(verifier, challenge):
    digest  = hashlib.sha256(verifier.encode()).digest()
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
    'FACT': 'Factura',          'N/CR': 'Nota de Crédito',
    'N/DB': 'Nota de Débito',   'RIVA': 'Retención de IVA',
    'ISLR': 'Impuesto Sobre la Renta', 'ADEL': 'Adelanto / Pago',
    'AJPA': 'Ajuste Positivo Automático', 'AJPM': 'Ajuste Positivo Manual',
    'AJNA': 'Ajuste Negativo Automático', 'AJNM': 'Ajuste Negativo Manual',
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
                'tipo':     {'type': 'string',  'description': 'Tipo: FACT, N/CR, N/DB, RIVA, ISLR'},
                'desde':    {'type': 'string',  'description': 'Fecha inicial YYYY-MM-DD'},
                'hasta':    {'type': 'string',  'description': 'Fecha final YYYY-MM-DD'},
                'con_saldo':{'type': 'boolean', 'description': 'Solo con saldo pendiente'},
                'limite':   {'type': 'integer', 'description': 'Máximo de registros (default 20)'},
            },
            'required': [],
        },
    },
    {
        'name': 'buscar_compra',
        'description': 'Busca un documento de compra por tipo y número. Ejemplo: tipo=FACT, numero=18102',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'tipo':   {'type': 'string',  'description': 'Tipo: FACT, N/CR, N/DB, RIVA, ISLR'},
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
                'buscar': {'type': 'string',  'description': 'Nombre o RIF a buscar'},
                'limite': {'type': 'integer', 'description': 'Máximo de registros (default 20)'},
            },
            'required': [],
        },
    },
    {
        'name': 'consultar_ventas',
        'description': (
            'Consulta estadísticas de ventas de Corporativo C.A. por período con filtros obligatorios. '
            'Retorna por fila: Cantidad (Unidades Vendidas), Monto (en dólares) y Costo (en dólares). '
            'REGLA OBLIGATORIA: además del rango de fechas, SIEMPRE debes aplicar al menos un filtro adicional '
            '(producto, almacén, cliente, vendedor o marca). Nunca ejecutes sin al menos uno de estos filtros '
            'porque la consulta retornaría miles de registros y la respuesta sería lenta o inutilizable. '
            'Si el usuario no especifica ningún filtro adicional, pídele que indique al menos uno antes de ejecutar. '
            'IMPORTANTE sobre nombres vs códigos: los filtros usan CÓDIGOS, no nombres. '
            'Si el usuario menciona un cliente, vendedor o producto por nombre (ej: "REYES CONTRERAS"), '
            'primero usa buscar_clientes, buscar_vendedores o buscar_productos para obtener su código, '
            'y luego llama a consultar_ventas con ese código. '
            'Ejemplos de interpretación: '
            '"ventas de enero 2026 al cliente REYES" → primero buscar_clientes("REYES"), obtener código, luego consultar_ventas; '
            '"ventas del producto BOLSA en febrero" → producto_desde=BOLSA, producto_hasta=BOLSA, desde=..., hasta=...; '
            '"ventas del vendedor 24 en 2026" → vendedor_desde=24, vendedor_hasta=24; '
            '"ventas del almacén 002 este mes" → almacen_desde=002, almacen_hasta=002.'
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
            'Úsalo cuando el usuario mencione un producto por nombre y necesites el código para filtrar consultar_ventas.'
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
        vnc  = r['docVnc'].isoformat() if hasattr(r.get('docVnc'), 'isoformat') else r.get('docVnc', '')
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
               ROUND(c.docTtl,2) AS docTtl, ROUND(c.docSld,2) AS docSld
        FROM cmpDoc c LEFT JOIN prv p ON p.socCdg=c.socCdg
        {where} ORDER BY c.docRgt DESC, c.docNmr DESC LIMIT %s
    """, params)
    if not rows:
        return 'No se encontraron documentos con los filtros indicados.'
    lines = [f'Compras encontradas ({len(rows)} registros):']
    for r in rows:
        tipo = TIPO_LABEL.get(r['docTip'], r['docTip'])
        rgt  = r['docRgt'].isoformat() if hasattr(r.get('docRgt'), 'isoformat') else r.get('docRgt', '')
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
               CASE docTip
                 WHEN 'FACT' THEN 'Factura'        WHEN 'N/CR' THEN 'Nota de Crédito'
                 WHEN 'N/DB' THEN 'Nota de Débito' WHEN 'RIVA' THEN 'Retención de IVA'
                 WHEN 'ISLR' THEN 'Impuesto Sobre la Renta'
                 WHEN 'ADEL' THEN 'Adelanto / Pago'
                 ELSE docTip END AS descripcion,
               COUNT(*) AS cantidad,
               ROUND(SUM(docTtl),2) AS total,
               ROUND(SUM(docSld),2) AS saldo_pendiente
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
               socRif, socTlf, socEml
        FROM prv {where} ORDER BY socDsc LIMIT %s
    """, params)
    if not rows:
        return 'No se encontraron socios comerciales.'
    lines = [f'Socios comerciales ({len(rows)} registros):']
    for r in rows:
        lines.append(f"  {r['socCdg']} | {(r.get('socDsc') or '').strip()} | RIF: {r.get('socRif','')} | Tel: {r.get('socTlf','')}")
    return '\n'.join(lines)


def _tool_consultar_ventas(args):
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.callproc('vnt', [
                'PINTUADM',
                'vntStd',
                args.get('desde')          or None,
                args.get('hasta')          or None,
                args.get('producto_desde') or '',
                args.get('producto_hasta') or '',
                args.get('almacen_desde')  or '',
                args.get('almacen_hasta')  or '',
                args.get('cliente_desde')  or '',
                args.get('cliente_hasta')  or '',
                args.get('vendedor_desde') or '',
                args.get('vendedor_hasta') or '',
                args.get('sucursal_desde') or '',
                args.get('sucursal_hasta') or '',
                args.get('marca_desde')    or '',
                args.get('marca_hasta')    or '',
            ])
            rows = []
            for result in cur.stored_results():
                rows = result.fetchall()
    finally:
        conn.close()

    if not rows:
        return 'No se encontraron ventas con los filtros indicados.'

    lines = [f'Estadística de ventas ({len(rows)} registros):',
             f'{"Mes":<12} {"Producto":<16} {"Almacén":<10} {"Cliente":<22} {"Vendedor":<20} '
             f'{"Cant.(Unid.)":>12} {"Monto (USD)":>12} {"Costo (USD)":>12}']
    lines.append('-' * 126)
    for r in rows:
        lines.append(
            f"{str(r.get('oprMes','')):<12} "
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
    lines.append('-' * 126)
    lines.append(f"{'TOTALES':<62} {total_cnt:>12.2f} {total_mnt:>12.2f} {total_cst:>12.2f}")
    return '\n'.join(lines)


def _tool_buscar_clientes(args):
    t = f"%{args.get('buscar', '')}%"
    limit = min(int(args.get('limite', 20)), 100)
    rows = _query("""
        SELECT TRIM(socCdg) AS socCdg, TRIM(socDsc) AS socDsc, socRif
        FROM clt WHERE socCdg LIKE %s OR socDsc LIKE %s
        ORDER BY socDsc LIMIT %s
    """, [t, t, limit])
    if not rows:
        return 'No se encontraron clientes con ese criterio.'
    lines = [f'Clientes encontrados ({len(rows)} registros):']
    for r in rows:
        lines.append(f"  Código: {r['socCdg']} | {(r.get('socDsc') or '').strip()} | RIF: {r.get('socRif','')}")
    return '\n'.join(lines)


def _tool_buscar_vendedores(args):
    t = f"%{args.get('buscar', '')}%"
    limit = min(int(args.get('limite', 20)), 100)
    rows = _query("""
        SELECT TRIM(socCdg) AS socCdg, TRIM(socDsc) AS socDsc
        FROM vnd WHERE socCdg LIKE %s OR socDsc LIKE %s
        ORDER BY socDsc LIMIT %s
    """, [t, t, limit])
    if not rows:
        return 'No se encontraron vendedores con ese criterio.'
    lines = [f'Vendedores encontrados ({len(rows)} registros):']
    for r in rows:
        lines.append(f"  Código: {r['socCdg']} | {(r.get('socDsc') or '').strip()}")
    return '\n'.join(lines)


def _tool_buscar_productos(args):
    t = f"%{args.get('buscar', '')}%"
    limit = min(int(args.get('limite', 20)), 100)
    rows = _query("""
        SELECT TRIM(prdCdg) AS prdCdg, TRIM(prdDsc) AS prdDsc, TRIM(mrcCdg) AS mrcCdg
        FROM prd WHERE prdCdg LIKE %s OR prdDsc LIKE %s
        ORDER BY prdDsc LIMIT %s
    """, [t, t, limit])
    if not rows:
        return 'No se encontraron productos con ese criterio.'
    lines = [f'Productos encontrados ({len(rows)} registros):']
    for r in rows:
        lines.append(f"  Código: {r['prdCdg']} | {(r.get('prdDsc') or '').strip()} | Marca: {r.get('mrcCdg','')}")
    return '\n'.join(lines)


def _call_tool(name, arguments):
    if not DB_AVAILABLE:
        return 'Error: PyMySQL no está instalado.'
    try:
        if name == 'Corporativo_compras_ayer':      return _tool_compras_ayer()
        if name == 'Corporativo_compras_mes':       return _tool_compras_mes()
        if name == 'Corporativo_tasas_hoy':         return _tool_tasas_hoy()
        if name == 'Corporativo_saldos_pendientes': return _tool_saldos_pendientes()
        if name == 'consultar_compras':             return _tool_consultar_compras(arguments)
        if name == 'buscar_compra':                 return _tool_buscar_compra(arguments)
        if name == 'resumen_compras':               return _tool_resumen_compras(arguments)
        if name == 'consultar_socios':              return _tool_consultar_socios(arguments)
        if name == 'consultar_ventas':              return _tool_consultar_ventas(arguments)
        if name == 'buscar_clientes':               return _tool_buscar_clientes(arguments)
        if name == 'buscar_vendedores':             return _tool_buscar_vendedores(arguments)
        if name == 'buscar_productos':              return _tool_buscar_productos(arguments)
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
            'db':      'pymysql disponible' if DB_AVAILABLE else 'pymysql NO instalado',
            'oauth':   'configurado' if OAUTH_CLIENT_ID else 'sin configurar',
            'base_url': BASE_URL,
        })

    # ── Log viewer ──────────────────────────────────────────────────────────
    if path == '/log':
        if qs.get('token') != RELOAD_TOKEN:
            return _json(start_response, '401 Unauthorized', {'error': 'Token requerido'})
        with _log_lock:
            entries = list(_log_entries)
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

        if method == 'POST':
            bp     = _parse_qs(_read_body(environ).decode('utf-8', errors='replace'))
            action = bp.get('action', '')
            _log('oauth_authorize_post', {'action': action})
            if action == 'approve':
                code = _new_auth_code(client_id, redirect_uri, code_challenge)
                sep  = '&' if '?' in redirect_uri else '?'
                loc  = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
                start_response('302 Found', [('Location', loc), ('Cache-Control', 'no-store')])
                return [b'']
            sep = '&' if '?' in redirect_uri else '?'
            loc = f"{redirect_uri}{sep}error=access_denied&state={urllib.parse.quote(state)}"
            start_response('302 Found', [('Location', loc)])
            return [b'']

        html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Corporativo C.A. — Autorizar acceso</title>
<style>
body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;
     min-height:100vh;margin:0;background:#f5f5f5}}
.card{{background:#fff;border-radius:12px;padding:40px;max-width:420px;width:90%;
       box-shadow:0 4px 24px rgba(0,0,0,.1);text-align:center}}
h1{{font-size:1.4rem;margin:0 0 8px}} p{{color:#555;margin:0 0 28px;font-size:.95rem}}
.logo{{font-size:2.5rem;margin-bottom:16px}}
.btn{{display:inline-block;padding:12px 32px;border:none;border-radius:8px;
      font-size:1rem;cursor:pointer;width:100%;margin-bottom:10px}}
.btn-primary{{background:#2563eb;color:#fff}} .btn-secondary{{background:#e5e7eb;color:#374151}}
</style></head>
<body><div class="card">
  <div class="logo">🏢</div>
  <h1>Corporativo C.A.</h1>
  <p>Claude solicita acceso a los datos corporativos de compras, socios y tasas de cambio.</p>
  <form method="POST" action="/oauth/authorize?client_id={urllib.parse.quote(client_id)}&redirect_uri={urllib.parse.quote(redirect_uri)}&state={urllib.parse.quote(state)}&code_challenge={urllib.parse.quote(code_challenge)}&code_challenge_method=S256">
    <button class="btn btn-primary"   name="action" value="approve">✅ Autorizar acceso</button>
    <button class="btn btn-secondary" name="action" value="deny">Cancelar</button>
  </form>
</div></body></html>"""
        return _html(start_response, html)

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

            if OAUTH_CLIENT_ID and not _valid_token(_bearer(environ)):
                _log('mcp_auth_fail', {'ip': environ.get('REMOTE_ADDR', ''),
                                       'auth': environ.get('HTTP_AUTHORIZATION', '')[:40]})
                return _json(start_response, '401 Unauthorized',
                             {'error': 'invalid_token'},
                             [('WWW-Authenticate', f'Bearer realm="{BASE_URL}"'),
                              ('Access-Control-Allow-Origin', '*')])

            body   = body or b'{}'
            result = _handle_mcp(body, environ)
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
