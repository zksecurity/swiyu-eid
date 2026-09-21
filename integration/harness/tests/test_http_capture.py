import http.server
import sys
import threading
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime'))
from transcript.http_capture import exchange

class CaptureTests(unittest.TestCase):
    def test_captures_sent_headers_and_preserves_response_headers_without_following_redirects(self):
        received = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                received.append(list(self.headers.items()))
                self.send_response(302)
                self.send_header('Location', '/next')
                self.send_header('X-Observable', 'one')
                self.send_header('X-Observable', 'two')
                self.end_headers()
                self.wfile.write(b'ok')
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            event = exchange(boundary='test', method='GET', url=f'http://127.0.0.1:{server.server_port}/', headers=[['X-Wallet-Tag', 'private-test']])
            self.assertEqual(event['response']['status'], 302)
            self.assertEqual([v for k,v in event['response']['headers'] if k.lower()=='location'], ['/next'])
            self.assertEqual(len(received), 1)
            self.assertEqual([(k.lower(), v) for k,v in event['request']['headers']], [(k.lower(),v) for k,v in received[0]])
            self.assertNotIn('content-length', [k.lower() for k,v in event['response']['headers']])
            self.assertEqual([v for k,v in event['response']['headers'] if k.lower() == 'x-observable'], ['one', 'two'])
        finally:
            server.shutdown(); server.server_close(); thread.join()

if __name__ == '__main__': unittest.main()
