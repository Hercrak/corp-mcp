import json


def application(environ, start_response):
    body = json.dumps({
        "status": "ok",
        "service": "crp-mcp-py",
        "version": "1.0.0",
        "language": "Python"
    }, ensure_ascii=False).encode('utf-8')

    start_response('200 OK', [
        ('Content-Type', 'application/json; charset=utf-8'),
        ('Content-Length', str(len(body)))
    ])
    return [body]
