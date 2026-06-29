#!/home/pintuand/virtualenv/repositories/crp-mcp-py/3.11/bin/python3
import json
import os
import sys
import threading


RELOAD_TOKEN = os.environ.get('RELOAD_TOKEN', '')
VERSION = '1.0.0'


def _parse_query(qs):
    params = {}
    for part in (qs or '').split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            params[k] = v
    return params


def respond(status, data):
    body = json.dumps(data, ensure_ascii=False)
    print(f"Status: {status}")
    print("Content-Type: application/json; charset=utf-8")
    print("Cache-Control: no-store")
    print()
    print(body)


def main():
    path = os.environ.get('PATH_INFO', '/')
    params = _parse_query(os.environ.get('QUERY_STRING', ''))

    if path == '/health' or path == '/' or path == '':
        respond('200 OK', {
            'status': 'ok',
            'service': 'crp-mcp-py',
            'version': VERSION,
            'language': 'Python 3'
        })

    elif path == '/reload':
        if not RELOAD_TOKEN or params.get('token') != RELOAD_TOKEN:
            respond('401 Unauthorized', {'error': 'Token inválido'})
        else:
            respond('200 OK', {'mensaje': 'Reiniciando proceso...'})
            def _exit():
                import time
                time.sleep(0.5)
                os._exit(0)
            threading.Thread(target=_exit, daemon=True).start()

    else:
        respond('404 Not Found', {'error': 'Ruta no encontrada'})


main()
