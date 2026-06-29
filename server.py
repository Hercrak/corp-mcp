import json
import os
import threading


RELOAD_TOKEN = os.environ.get('RELOAD_TOKEN', '')
VERSION = '1.0.0'


def _parse_query(query_string):
    params = {}
    for part in (query_string or '').split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            params[k] = v
    return params


def _json_response(start_response, status, data):
    body = json.dumps(data, ensure_ascii=False).encode('utf-8')
    start_response(status, [
        ('Content-Type', 'application/json; charset=utf-8'),
        ('Content-Length', str(len(body))),
        ('Cache-Control', 'no-store'),
    ])
    return [body]


def application(environ, start_response):
    path = environ.get('PATH_INFO', '/')
    params = _parse_query(environ.get('QUERY_STRING', ''))

    if path == '/health':
        return _json_response(start_response, '200 OK', {
            'status': 'ok',
            'service': 'crp-mcp-py',
            'version': VERSION,
            'language': 'Python 3'
        })

    if path == '/reload':
        if not RELOAD_TOKEN or params.get('token') != RELOAD_TOKEN:
            return _json_response(start_response, '401 Unauthorized',
                                  {'error': 'Token inválido'})
        def _exit():
            import time
            time.sleep(0.5)
            os._exit(0)
        threading.Thread(target=_exit, daemon=True).start()
        return _json_response(start_response, '200 OK',
                              {'mensaje': 'Reiniciando proceso...'})

    return _json_response(start_response, '404 Not Found',
                          {'error': 'Ruta no encontrada'})
