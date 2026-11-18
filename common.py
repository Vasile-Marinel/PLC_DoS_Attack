"""
common.py
---------
Cod comun folosit de toate componentele proiectului (server, client legitim,
atacator): protocolul simplu de tip PLC, constante și funcții utilitare.

Protocolul simulat (text, peste TCP, inspirat de stilul Modbus TCP, dar
simplificat pentru proiect):

    Cerere client -> server (un singur rand, terminat cu '\n'):
        READ <registru>
        WRITE <registru> <valoare>

    Raspuns server -> client (un singur rand, terminat cu '\n'):
        OK <registru> <valoare>        - pentru READ reusit
        OK <registru> WRITTEN          - pentru WRITE reusit
        ERR <mesaj>                    - comanda invalida
        BUSY                           - server suprasolicitat (doar varianta protejata)
        RATE_LIMIT                     - IP-ul a depasit limita de cereri/secunda
"""

import time

HOST = "127.0.0.1"
PORT = 5020

# Pe o singura masina, clientul legitim si atacatorul ar avea, implicit,
# aceeasi adresa sursa (127.0.0.1), ceea ce ar face ca rate limiting-ul
# per-IP din server-ul protejat sa-i trateze identic (incorect, pedagogic
# vorbind). Pentru a simula doua "gazde" distincte fara sa avem nevoie de
# doua masini fizice/VM-uri, clientul legitim isi leaga socket-ul pe o a
# doua adresa de loopback, 127.0.0.2, care este valida atat pe Windows
# (intregul bloc 127.0.0.0/8 e loopback) cat si pe Linux.
LEGIT_CLIENT_SOURCE_IP = "127.0.0.2"

# Numarul de "registre" simulate ale PLC-ului (ca niste adrese de memorie PLC)
NUM_REGISTERS = 20

# Intarziere artificiala pentru a simula timpul de scanare / procesare al unui
# PLC real (PLC-urile industriale au cicluri de scan relativ lente, de ordinul
# milisecundelor). Aceasta intarziere este cea care, combinata cu un server
# single-threaded, face flooding-ul eficient.
PROCESSING_DELAY_SEC = 0.015  # 15 ms per cerere

SOCKET_TIMEOUT_SEC = 3.0


def now_ms():
    return time.time() * 1000.0


def make_registers():
    return [0] * NUM_REGISTERS


def handle_command(line: str, registers: list) -> str:
    """Interpreteaza o comanda text si intoarce raspunsul text.
    Functia e comuna serverului vulnerabil si celui protejat."""
    parts = line.strip().split()
    if not parts:
        return "ERR EMPTY"

    cmd = parts[0].upper()

    if cmd == "READ" and len(parts) == 2:
        try:
            reg = int(parts[1])
        except ValueError:
            return "ERR BAD_REGISTER"
        if not (0 <= reg < len(registers)):
            return "ERR OUT_OF_RANGE"
        return f"OK {reg} {registers[reg]}"

    if cmd == "WRITE" and len(parts) == 3:
        try:
            reg = int(parts[1])
            val = int(parts[2])
        except ValueError:
            return "ERR BAD_ARGS"
        if not (0 <= reg < len(registers)):
            return "ERR OUT_OF_RANGE"
        registers[reg] = val
        return f"OK {reg} WRITTEN"

    return "ERR UNKNOWN_COMMAND"
