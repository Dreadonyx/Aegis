"""Local-only Compose entry point forwarding solely to the isolated Cowrie SSH port."""
import selectors
import socket
import socketserver
import threading
import time

slots = threading.BoundedSemaphore(16)


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        if not slots.acquire(blocking=False):
            return
        try:
            with socket.create_connection(("cowrie", 2222), timeout=5) as upstream, selectors.DefaultSelector() as selector:
                self.request.settimeout(5)
                upstream.settimeout(5)
                selector.register(self.request, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, self.request)
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    for key, _ in selector.select(timeout=1):
                        chunk = key.fileobj.recv(16384)
                        if not chunk:
                            return
                        key.data.sendall(chunk)
        except OSError:
            pass
        finally:
            slots.release()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


with Server(("0.0.0.0", 2222), Relay) as server:
    server.serve_forever()
