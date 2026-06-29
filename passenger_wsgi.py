import json
import os
import threading
from datetime import date, datetime
from decimal import Decimal

try:
    import pymysql
    import pymysql.cursors
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

RELOAD_TOKEN = os.environ.get('RELOAD_TOKEN', '')
SERVER_NAME = 'corp-mcp-py'
SERVER_VERSION = '2.0.0'
MCP_VERSION = '2024-11-05'

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
            'Tipos de documento: FACT (Factura), N/CR (Nota de Crédito), '
            'N/DB (Nota de Débito), RIVA (Retención de IVA), ISLR (Impuesto Sobre la Renta).'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'tipo': {'type': 'string', 'description': 'Tipo: FACT, N/CR, N/DB, RIVA, ISLR'},
                'desde': {'type': 'string', 'description': 'Fecha inicial YYYY-MM-DD'},
                'hasta': {'type': 'string', 'description': 'Fecha final YYYY-MM-DD'},
                'con_saldo': {'type': 'boolean', 'description': 'Solo documentos con saldo pendiente'},
                'limite': {'type': 'integer', 'description': 'Máximo de registros (default 20)'},
            },
            'required': [],
        },
    },
    {
        'name': 'buscar_compra',
        'description': 'Busca un documento de compra específico por tipo y número. Ejemplo: tipo=FACT, numero=1',
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
               ROUND(SUM(docTtl), 2) AS total, ROUND(SUM(docSld), 2) AS saldo_pendiente
        FROM cmpDoc
        WHERE docRgt = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
        GROUP BY mndCdg
        ORDER BY mndCdg
    """)
    if not rows:
        return 'No se registraron compras ayer.'
    lines = ['Compras de ayer:']
    for r in rows:
        lines.append(f"  {r['moneda']}: {r['cantidad']} documentos | Total: {r['total']} | Saldo pendiente: {r['saldo_pendiente']}")
    return '\n'.join(lines)


def _tool_compras_mes():
    rows = _query("""
        SELECT TRIM(mndCdg) AS moneda, COUNT(*) AS cantidad,
               ROUND(SUM(docTtl), 2) AS total, ROUND(SUM(docSld), 2) AS saldo_pendiente
        FROM cmpDoc
        WHERE MONTH(docRgt) = MONTH(CURDATE()) AND YEAR(docRgt) = YEAR(CURDATE())
        GROUP BY mndCdg
        ORDER BY mndCdg
    """)
    if not rows:
        return 'No se registraron compras en el mes actual.'
    lines = ['Compras del mes en curso:']
    for r in rows:
        lines.append(f"  {r['moneda']}: {r['cantidad']} documentos | Total: {r['total']} | Saldo pendiente: {r['saldo_pendiente']}")
    return '\n'.join(lines)


def _tool_tasas_hoy():
    rows = _query("""
        SELECT t.mndCdg AS moneda, t.tasFch AS fecha, t.tasCmb AS tasa
        FROM tas t
        INNER JOIN (
            SELECT mndCdg, MAX(tasFch) AS ultima FROM tas GROUP BY mndCdg
        ) u ON t.mndCdg = u.mndCdg AND t.tasFch = u.ultima
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
               ROUND(c.docTtl, 2) AS docTtl, ROUND(c.docSld, 2) AS docSld
        FROM cmpDoc c
        LEFT JOIN prv p ON p.socCdg = c.socCdg
        WHERE c.docSld > 0
        ORDER BY c.docVnc ASC, c.docSld DESC
        LIMIT 50
    """)
    if not rows:
        return 'No hay documentos con saldo pendiente.'
    lines = [f'Documentos con saldo pendiente ({len(rows)} registros):']
    for r in rows:
        tipo = TIPO_LABEL.get(r['docTip'], r['docTip'])
        vnc = r['docVnc'].isoformat() if hasattr(r.get('docVnc'), 'isoformat') else r.get('docVnc', '')
        lines.append(
            f"  {tipo} #{r['docNmr']} | {r.get('socDsc','').strip()} | "
            f"Vence: {vnc} | Saldo: {r['docSld']} {r['mndCdg']}"
        )
    return '\n'.join(lines)


def _tool_consultar_compras(args):
    conditions, params = [], []
    if args.get('tipo'):
        conditions.append('c.docTip = %s')
        params.append(args['tipo'])
    if args.get('desde'):
        conditions.append('c.docRgt >= %s')
        params.append(args['desde'])
    if args.get('hasta'):
        conditions.append('c.docRgt <= %s')
        params.append(args['hasta'])
    if args.get('con_saldo'):
        conditions.append('c.docSld > 0')

    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    limit = min(int(args.get('limite', 20)), 100)
    params.extend([limit])

    rows = _query(f"""
        SELECT c.docTip, c.docNmr, c.docRgt, c.docVnc,
               TRIM(c.socCdg) AS socCdg, TRIM(p.socDsc) AS socDsc, p.socRif,
               TRIM(c.mndCdg) AS mndCdg,
               ROUND(c.docTtl, 2) AS docTtl, ROUND(c.docSld, 2) AS docSld, c.docAnl
        FROM cmpDoc c
        LEFT JOIN prv p ON p.socCdg = c.socCdg
        {where}
        ORDER BY c.docRgt DESC, c.docNmr DESC
        LIMIT %s
    """, params)

    if not rows:
        return 'No se encontraron documentos con los filtros indicados.'
    lines = [f'Compras encontradas ({len(rows)} registros):']
    for r in rows:
        tipo = TIPO_LABEL.get(r['docTip'], r['docTip'])
        rgt = r['docRgt'].isoformat() if hasattr(r.get('docRgt'), 'isoformat') else r.get('docRgt', '')
        lines.append(
            f"  {tipo} #{r['docNmr']} | {r.get('socDsc','').strip()} | "
            f"{rgt} | {r['docTtl']} {r['mndCdg']} | Saldo: {r['docSld']}"
        )
    return '\n'.join(lines)


def _tool_buscar_compra(args):
    rows = _query("""
        SELECT c.*, TRIM(p.socDsc) AS prvNmb, p.socRif AS prvRif
        FROM cmpDoc c
        LEFT JOIN prv p ON p.socCdg = c.socCdg
        WHERE c.docTip = %s AND c.docNmr = %s
    """, [args.get('tipo'), args.get('numero')])
    if not rows:
        return f"Documento {args.get('tipo')} #{args.get('numero')} no encontrado."
    return _dumps(rows[0])


def _tool_resumen_compras(args):
    conditions, params = [], []
    if args.get('desde'):
        conditions.append('docRgt >= %s')
        params.append(args['desde'])
    if args.get('hasta'):
        conditions.append('docRgt <= %s')
        params.append(args['hasta'])
    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

    rows = _query(f"""
        SELECT docTip AS tipo,
               CASE docTip
                 WHEN 'FACT' THEN 'Factura'
                 WHEN 'N/CR' THEN 'Nota de Crédito'
                 WHEN 'N/DB' THEN 'Nota de Débito'
                 WHEN 'RIVA' THEN 'Retención de IVA'
                 WHEN 'ISLR' THEN 'Impuesto Sobre la Renta'
                 WHEN 'ADEL' THEN 'Adelanto / Pago'
                 ELSE docTip
               END AS descripcion,
               COUNT(*) AS cantidad,
               ROUND(SUM(docTtl), 2) AS total,
               ROUND(SUM(docSld), 2) AS saldo_pendiente
        FROM cmpDoc {where}
        GROUP BY docTip
        ORDER BY docTip
    """, params)

    if not rows:
        return 'No hay compras registradas para el período indicado.'
    lines = ['Resumen de compras por tipo:']
    for r in rows:
        lines.append(
            f"  {r['descripcion']} ({r['tipo']}): "
            f"{r['cantidad']} docs | Total: {r['total']} | Saldo pendiente: {r['saldo_pendiente']}"
        )
    return '\n'.join(lines)


def _tool_consultar_socios(args):
    conditions, params = [], []
    if args.get('buscar'):
        conditions.append('(socCdg LIKE %s OR socDsc LIKE %s OR socRif LIKE %s)')
        term = f"%{args['buscar']}%"
        params.extend([term, term, term])

    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
    limit = min(int(args.get('limite', 20)), 100)
    params.append(limit)

    rows = _query(f"""
        SELECT TRIM(socCdg) AS socCdg, TRIM(socDsc) AS socDsc,
               socRif, prcTip, socTlf, socEml
        FROM prv {where}
        ORDER BY socDsc
        LIMIT %s
    """, params)

    if not rows:
        return 'No se encontraron socios comerciales.'
    lines = [f'Socios comerciales ({len(rows)} registros):']
    for r in rows:
        lines.append(
            f"  {r['socCdg']} | {r.get('socDsc','').strip()} | "
            f"RIF: {r.get('socRif','')} | Tel: {r.get('socTlf','')}"
        )
    return '\n'.join(lines)


def _call_tool(name, arguments):
    if not DB_AVAILABLE:
        return 'Error: PyMySQL no está instalado en el servidor.'
    try:
        if name == 'Corporativo_compras_ayer':
            return _tool_compras_ayer()
        if name == 'Corporativo_compras_mes':
            return _tool_compras_mes()
        if name == 'Corporativo_tasas_hoy':
            return _tool_tasas_hoy()
        if name == 'Corporativo_saldos_pendientes':
            return _tool_saldos_pendientes()
        if name == 'consultar_compras':
            return _tool_consultar_compras(arguments)
        if name == 'buscar_compra':
            return _tool_buscar_compra(arguments)
        if name == 'resumen_compras':
            return _tool_resumen_compras(arguments)
        if name == 'consultar_socios':
            return _tool_consultar_socios(arguments)
        return f'Herramienta desconocida: {name}'
    except Exception as e:
        return f'Error al ejecutar {name}: {str(e)}'


# ---------------------------------------------------------------------------
# Protocolo MCP JSON-RPC
# ---------------------------------------------------------------------------

def _handle_mcp(body_bytes):
    try:
        req = json.loads(body_bytes)
    except Exception:
        return {'jsonrpc': '2.0', 'id': None,
                'error': {'code': -32700, 'message': 'Parse error'}}

    method = req.get('method', '')
    params = req.get('params') or {}
    req_id = req.get('id')

    if req_id is None and method.startswith('notifications/'):
        return None

    if method == 'initialize':
        return {
            'jsonrpc': '2.0', 'id': req_id,
            'result': {
                'protocolVersion': MCP_VERSION,
                'capabilities': {'tools': {}},
                'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION},
            },
        }

    if method == 'tools/list':
        return {'jsonrpc': '2.0', 'id': req_id, 'result': {'tools': TOOLS}}

    if method == 'tools/call':
        tool_name = params.get('name', '')
        arguments = params.get('arguments') or {}
        return {
            'jsonrpc': '2.0', 'id': req_id,
            'result': {
                'content': [{'type': 'text', 'text': _call_tool(tool_name, arguments)}],
                'isError': False,
            },
        }

    if method == 'ping':
        return {'jsonrpc': '2.0', 'id': req_id, 'result': {}}

    return {
        'jsonrpc': '2.0', 'id': req_id,
        'error': {'code': -32601, 'message': f'Method not found: {method}'},
    }


# ---------------------------------------------------------------------------
# WSGI
# ---------------------------------------------------------------------------

def _parse_query(qs):
    params = {}
    for part in (qs or '').split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            params[k] = v
    return params


def _json(start_response, status, data):
    body = json.dumps(data, ensure_ascii=False).encode('utf-8')
    start_response(status, [
        ('Content-Type', 'application/json; charset=utf-8'),
        ('Content-Length', str(len(body))),
        ('Cache-Control', 'no-store'),
    ])
    return [body]


def application(environ, start_response):
    path = environ.get('PATH_INFO', '/')
    method = environ.get('REQUEST_METHOD', 'GET')
    params = _parse_query(environ.get('QUERY_STRING', ''))

    if path == '/health':
        return _json(start_response, '200 OK', {
            'status': 'ok', 'service': SERVER_NAME,
            'version': SERVER_VERSION, 'language': 'Python 3',
            'db': 'pymysql disponible' if DB_AVAILABLE else 'pymysql NO instalado',
        })

    if path == '/reload':
        if not RELOAD_TOKEN or params.get('token') != RELOAD_TOKEN:
            return _json(start_response, '401 Unauthorized', {'error': 'Token inválido'})
        def _exit():
            import time; time.sleep(0.5); os._exit(0)
        threading.Thread(target=_exit, daemon=True).start()
        return _json(start_response, '200 OK', {'mensaje': 'Reiniciando proceso...'})

    if path == '/mcp' and method == 'POST':
        try:
            length = int(environ.get('CONTENT_LENGTH') or 0)
            body = environ['wsgi.input'].read(length) if length > 0 else b'{}'
        except Exception:
            body = b'{}'
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

    if method == 'OPTIONS':
        start_response('204 No Content', [
            ('Access-Control-Allow-Origin', '*'),
            ('Access-Control-Allow-Methods', 'POST, GET, OPTIONS'),
            ('Access-Control-Allow-Headers', 'Content-Type, Accept, mcp-session-id'),
            ('Content-Length', '0'),
        ])
        return [b'']

    return _json(start_response, '404 Not Found', {'error': 'Ruta no encontrada'})
