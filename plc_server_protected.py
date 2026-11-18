"""
plc_server_protected.py
------------------------
PAS 5 din cerinta proiectului: aceeasi logica de "PLC", dar cu protectii
implementate impotriva atacului DoS demonstrat cu plc_server.py:

  1. Accept loop NE-BLOCANT: bucla principala doar accepta conexiuni si le
     preda imediat unui thread pool marginit (ThreadPoolExecutor). Asta
     evita ca procesarea lenta a unei cereri sa blocheze acceptarea altora.

  2. Coada de procesare MARGINITA (bounded queue): thread pool-ul are un
     numar fix de muncitori (MAX_WORKERS) si o coada cu dimensiune maxima
     (MAX_QUEUE). Daca se umple, cererile noi sunt respinse imediat cu
     "BUSY" in loc sa se acumuleze la infinit si sa consume memorie / sa
     creasca latenta la nesfarsit.

  3. Rate limiting per-IP (token bucket): fiecare adresa IP are un buget de
     RATE_LIMIT_PER_SEC cereri/secunda. Cererile peste limita sunt respinse
     imediat cu "RATE_LIMIT", INAINTE sa ajunga in coada de procesare -
     astfel un singur atacator nu poate monopoliza thread pool-ul.

  4. Timeout agresiv pe conexiuni, ca sa nu ramana socket-uri deschise la
     nesfarsit (protectie suplimentara, tip slowloris).

Rulare:
    python plc_server_protected.py

Oprire: Ctrl+C
"""

import socket
import threading
import time
import csv
import os
import queue
from concurrent.futures import ThreadPoolExecutor

from common import HOST, PORT, PROCESSING_DELAY_SEC, make_registers, handle_command

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
STATS_LOG = os.path.join(LOG_DIR, "server_protected_stats.csv")

registers = make_registers()

# ---- Parametri de protectie (usor de ajustat pentru experimente) ----
MAX_WORKERS = 10          # cate cereri se proceseaza in paralel
MAX_QUEUE = 50             # cate cereri pot astepta in coada inainte sa respingem
RATE_LIMIT_PER_SEC = 5     # cereri/secunda admise per IP
RATE_LIMIT_BUCKET = 5      # capacitate maxima a "galetii" de token-uri

stats_lock = threading.Lock()
total_handled = 0
total_rejected_busy = 0
total_rejected_rate_limit = 0
total_connections_seen = 0
start_time = None

# Semafor care materializeaza limita MAX_QUEUE: fiecare cerere acceptata in
# coada consuma un "permis"; cand nu mai sunt permise libere, respingem.
queue_semaphore = threading.BoundedSemaphore(MAX_WORKERS + MAX_QUEUE)

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# ---- Rate limiter: token bucket per IP ----
rate_lock = threading.Lock()
buckets = {}  # ip -> [tokens, last_refill_timestamp]


def allow_request(ip: str) -> bool:
    with rate_lock:
        now = time.time()
        tokens, last = buckets.get(ip, (RATE_LIMIT_BUCKET, now))
        # reface token-uri proportional cu timpul scurs
        tokens = min(RATE_LIMIT_BUCKET, tokens + (now - last) * RATE_LIMIT_PER_SEC)
        if tokens >= 1:
            tokens -= 1
            buckets[ip] = (tokens, now)
            return True
        buckets[ip] = (tokens, now)
        return False


def stats_logger():
    with open(STATS_LOG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "t_sec", "total_handled", "total_rejected_busy",
            "total_rejected_rate_limit", "total_connections_seen",
            "throughput_req_per_sec",
        ])
        last_handled = 0
        while True:
            time.sleep(0.5)
            with stats_lock:
                handled = total_handled
                rej_busy = total_rejected_busy
                rej_rl = total_rejected_rate_limit
                seen = total_connections_seen
            elapsed = time.time() - start_time
            throughput = (handled - last_handled) / 0.5
            last_handled = handled
            writer.writerow([f"{elapsed:.2f}", handled, rej_busy, rej_rl, seen, f"{throughput:.1f}"])
            f.flush()


def process_request(conn: socket.socket, addr, line: str):
    """Ruleaza in thread pool: simuleaza procesarea PLC si raspunde."""
    global total_handled
    try:
        time.sleep(PROCESSING_DELAY_SEC)
        response = handle_command(line, registers)
        conn.sendall((response + "\n").encode())
    except Exception:
        pass
    finally:
        conn.close()
        with stats_lock:
            total_handled += 1
        queue_semaphore.release()


def main():
    global start_time, total_connections_seen, total_rejected_busy, total_rejected_rate_limit

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(256)

    start_time = time.time()
    threading.Thread(target=stats_logger, daemon=True).start()

    print(f"[plc_server PROTEJAT] Ascult pe {HOST}:{PORT}")
    print(f"[plc_server PROTEJAT] rate_limit={RATE_LIMIT_PER_SEC}/s/IP, "
          f"workers={MAX_WORKERS}, coada_max={MAX_QUEUE}")
    print(f"[plc_server PROTEJAT] Statistici scrise in: {STATS_LOG}")

    try:
        while True:
            conn, addr = server_sock.accept()
            ip = addr[0]
            with stats_lock:
                total_connections_seen += 1

            conn.settimeout(2.0)

            # 1) Rate limiting - respingem INAINTE sa citim/procesam, ca sa nu
            #    consumam resurse pe cereri abuzive.
            if not allow_request(ip):
                try:
                    conn.sendall(b"RATE_LIMIT\n")
                except Exception:
                    pass
                conn.close()
                with stats_lock:
                    total_rejected_rate_limit += 1
                continue

            # 2) Coada marginita - daca thread pool-ul + coada sunt pline,
            #    respingem imediat cu BUSY in loc sa lasam conexiunea sa
            #    astepte la nesfarsit.
            if not queue_semaphore.acquire(blocking=False):
                try:
                    conn.sendall(b"BUSY\n")
                except Exception:
                    pass
                conn.close()
                with stats_lock:
                    total_rejected_busy += 1
                continue

            try:
                data = conn.recv(1024)
                if not data:
                    conn.close()
                    queue_semaphore.release()
                    continue
                line = data.decode(errors="ignore")
            except Exception:
                conn.close()
                queue_semaphore.release()
                continue

            executor.submit(process_request, conn, addr, line)
    except KeyboardInterrupt:
        print("\n[plc_server PROTEJAT] Oprire server.")
    finally:
        executor.shutdown(wait=False)
        server_sock.close()


if __name__ == "__main__":
    main()
