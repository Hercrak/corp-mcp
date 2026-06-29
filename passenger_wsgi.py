import json
import os
import threading

RELOAD_TOKEN = os.environ.get('RELOAD_TOKEN', '')
SERVER_NAME = 'crp-mcp-py'
SERVER_VERSION = '2.0.0'
MCP_VERSION = '2024-11-05'

# ---------------------------------------------------------------------------
# Herramientas MCP
# ---------------------------------------------------------------------------

TOOLS = [
    {
        'name': 'Corporativo_compras_ayer',
        'description': (
            'Retorna el total de compras realizadas ayer en Corporativo C.A. '
            'Muestra monto total, cantidad de documentos y desglose por moneda.'
        ),
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'Corporativo_compras_mes',
        'description': (
            'Retorna el total de compras del mes en curso en Corporativo C.A. '
            'Incluye monto acumulado, cantidad de documentos y moneda.'
        ),
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'Corporativo_tasas_hoy',
        'description': (
            'Retorna las tasas de cambio vigentes hoy registradas en Corporativo C.A. '
            'Incluye tasa BCV y otras monedas configuradas.'
        ),
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'Corporativo_saldos_pendientes',
        'description': (
            'Retorna los documentos de compra con saldo pendiente de pago en Corporativo C.A. '
            'Incluye facturas, notas de débito y retenciones por cobrar.'
        ),
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'consultar_compras',
        'description': (
            'Consulta el listado de compras con filtros opcionales. '
            'Tipos de documento: FCT (Factura), NCR (Nota de Crédito), '
            'NDB (Nota de Débito), RIV (Retención de IVA), ISL (Impuesto sobre la Renta).'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'tipo': {
                    'type': 'string',
                    'description': 'Tipo de documento: FCT, NCR, NDB, RIV, ISL',
                },
                'desde': {
                    'type': 'string',
                    'description': 'Fecha inicial YYYY-MM-DD',
                },
                'hasta': {
                    'type': 'string',
                    'description': 'Fecha final YYYY-MM-DD',
                },
                'con_saldo': {
                    'type': 'boolean',
                    'description': 'Solo documentos con saldo pendiente',
                },
            },
            'required': [],
        },
    },
    {
        'name': 'buscar_compra',
        'description': (
            'Busca un documento de compra específico por tipo y número. '
            'Ejemplo: tipo=FCT, numero=1'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'tipo': {
                    'type': 'string',
                    'description': 'Tipo de documento: FCT, NCR, NDB, RIV, ISL',
                },
                'numero': {
                    'type': 'integer',
                    'description': 'Número del documento',
                },
            },
            'required': ['tipo', 'numero'],
        },
    },
    {
        'name': 'resumen_compras',
        'description': (
            'Retorna un resumen de compras agrupado por tipo de documento '
            'con totales, cantidades y montos. Útil para reportes gerenciales.'
        ),
        'inputSchema': {'type': 'object', 'properties': {}, 'required': []},
    },
    {
        'name': 'consultar_socios',
        'description': (
            'Consulta el listado de socios comerciales (proveedores, suplidor, '
            'acreedor, proveedor, socio) con su información de contacto y RIF.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'buscar': {
                    'type': 'string',
                    'description': 'Nombre o RIF del socio a buscar',
                },
            },
            'required': [],
        },
    },
]


def _call_tool(name, arguments):
    """Ejecuta una herramienta y retorna el resultado como texto."""
    # TODO Fase 2: conectar MySQL y ejecutar queries reales
    placeholder = {
        'Corporativo_compras_ayer': 'Servidor MCP Python activo. Conexión a base de datos pendiente (Fase 2).',
        'Corporativo_compras_mes': 'Servidor MCP Python activo. Conexión a base de datos pendiente (Fase 2).',
        'Corporativo_tasas_hoy': 'Servidor MCP Python activo. Conexión a base de datos pendiente (Fase 2).',
        'Corporativo_saldos_pendientes': 'Servidor MCP Python activo. Conexión a base de datos pendiente (Fase 2).',
        'consultar_compras': f'Servidor MCP Python activo. Filtros recibidos: {json.dumps(arguments)}. Conexión a base de datos pendiente (Fase 2).',
        'buscar_compra': f'Servidor MCP Python activo. Buscando {arguments}. Conexión a base de datos pendiente (Fase 2).',
        'resumen_compras': 'Servidor MCP Python activo. Conexión a base de datos pendiente (Fase 2).',
        'consultar_socios': f'Servidor MCP Python activo. Filtros recibidos: {json.dumps(arguments)}. Conexión a base de datos pendiente (Fase 2).',
    }
    return placeholder.get(name, f'Herramienta desconocida: {name}')


# ---------------------------------------------------------------------------
# Manejador del protocolo MCP JSON-RPC
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

    # Notificaciones (sin id) — no requieren respuesta
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
        return {
            'jsonrpc': '2.0', 'id': req_id,
            'result': {'tools': TOOLS},
        }

    if method == 'tools/call':
        tool_name = params.get('name', '')
        arguments = params.get('arguments') or {}
        result_text = _call_tool(tool_name, arguments)
        return {
            'jsonrpc': '2.0', 'id': req_id,
            'result': {
                'content': [{'type': 'text', 'text': result_text}],
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
# Helpers HTTP
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


# ---------------------------------------------------------------------------
# WSGI application
# ---------------------------------------------------------------------------

def application(environ, start_response):
    path = environ.get('PATH_INFO', '/')
    method = environ.get('REQUEST_METHOD', 'GET')
    params = _parse_query(environ.get('QUERY_STRING', ''))

    # Health check
    if path == '/health':
        return _json(start_response, '200 OK', {
            'status': 'ok', 'service': SERVER_NAME,
            'version': SERVER_VERSION, 'language': 'Python 3',
        })

    # Reload
    if path == '/reload':
        if not RELOAD_TOKEN or params.get('token') != RELOAD_TOKEN:
            return _json(start_response, '401 Unauthorized', {'error': 'Token inválido'})
        def _exit():
            import time; time.sleep(0.5); os._exit(0)
        threading.Thread(target=_exit, daemon=True).start()
        return _json(start_response, '200 OK', {'mensaje': 'Reiniciando proceso...'})

    # MCP Streamable HTTP  — POST /mcp
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

        resp_body = json.dumps(result, ensure_ascii=False).encode('utf-8')
        start_response('200 OK', [
            ('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', str(len(resp_body))),
            ('Access-Control-Allow-Origin', '*'),
        ])
        return [resp_body]

    # CORS preflight
    if method == 'OPTIONS':
        start_response('204 No Content', [
            ('Access-Control-Allow-Origin', '*'),
            ('Access-Control-Allow-Methods', 'POST, GET, OPTIONS'),
            ('Access-Control-Allow-Headers', 'Content-Type, Accept, mcp-session-id'),
            ('Content-Length', '0'),
        ])
        return [b'']

    return _json(start_response, '404 Not Found', {'error': 'Ruta no encontrada'})
