# Demonstrarea unui atac DoS asupra unui server PLC simulat

Un atac DoS (Denial of Service) la nivel de aplicație asupra unui server
care imită un PLC, apoi implementează și testează contramăsuri.

## Structura proiectului

| Fișier | Rol |
|---|---|
| `common.py` | protocolul text simplu (READ/WRITE) folosit de toate componentele |
| `plc_server.py` | server PLC simulat, **vulnerabil** (single-threaded, fără protecții) |
| `legit_client.py` | client legitim — 1 cerere/secundă, măsoară latența |
| `attacker.py` | atacator — inundă serverul cu conexiuni, pe multe fire de execuție |
| `plc_server_protected.py` | aceeași logică de PLC + rate limiting per-IP + coadă de procesare mărginită |
| `run_experiment.py` | orchestrează server + client legitim + atacator într-un singur experiment |
| `compare_results.py` | citește rezultatele ambelor experimente, scoate raport text + grafic |

## Cum funcționează "PLC-ul" simulat

Un server TCP simplu, pe `127.0.0.1:5020`, cu un protocol text minimal:

```
READ <registru>         -> OK <registru> <valoare>
WRITE <registru> <val>  -> OK <registru> WRITTEN
```

Fiecare cerere e procesată cu o întârziere artificială de 15ms, care
simulează timpul de scanare/procesare al unui PLC industrial real.

## Instalare

Ai nevoie doar de Python 3.8+ (fără librării externe, cu excepția
`matplotlib` pentru grafic — opțional):

```powershell
pip install matplotlib
```

## Rulare rapidă (recomandat — un singur calculator, Windows + VS Code)

Nu ai nevoie de Kali sau de o a doua mașină: scripturile simulează
"atacatorul" și "clientul legitim" ca două gazde distincte folosind două
adrese de loopback diferite (`127.0.0.1` pentru atacator, `127.0.0.2` pentru
clientul legitim), ca rate limiting-ul per-IP din server-ul protejat să se
comporte corect, exact ca într-o rețea reală cu două calculatoare separate.

Deschide un terminal în VS Code, în folderul proiectului:

```powershell
# 1. Ruleaza experimentul pe server-ul VULNERABIL
python run_experiment.py baseline

# 2. Ruleaza experimentul pe server-ul PROTEJAT
python run_experiment.py protected

# 3. Genereaza raportul comparativ + graficul
python compare_results.py
```

Fiecare experiment durează implicit 60s (15s trafic normal, 30s atac, 15s
revenire) — parametrii sunt în capul fișierului `run_experiment.py`
(`TOTAL_DURATION`, `ATTACK_START_DELAY`, `ATTACK_DURATION`, `ATTACK_THREADS`)
și pot fi micșorați pentru teste rapide.

La final vei avea:
- `results/legit_baseline.csv`, `results/legit_protected.csv` — latența
  fiecărei cereri legitime, cu timestamp
- `logs/server_baseline_stats.csv`, `logs/server_protected_stats.csv` —
  throughput-ul server-ului în timp
- `results/raport_comparativ.txt` — statistici pe cele 3 ferestre
  (înainte / în timpul / după atac)
- `results/comparatie_latenta.png` — grafic cu latența în timp, pentru
  ambele variante, cu fereastra de atac evidențiată

## Rulare manuală, pas cu pas (utilă pentru a observa live degradarea — cerința 4)

Trei terminale separate:

```powershell
# Terminal 1: server-ul vulnerabil
python plc_server.py

# Terminal 2: clientul legitim (ruleaza 90s)
python legit_client.py results/manual_test.csv 90

# Terminal 3 (porneste dupa ~15s): atacatorul, 50 fire, 30s
python attacker.py 30 50
```

Urmărești în Terminalul 2 cum latența sare de la ~15ms la sute/mii de ms în
momentul în care pornește atacul — exact căderea de performanță cerută la
punctul 4. Repetă apoi cu `plc_server_protected.py` în loc de `plc_server.py`
și observă că latența rămâne stabilă.

## De ce ai nevoie de Kali Linux? (opțional, nu obligatoriu)

Pentru acest proiect **nu e nevoie de Kali** — atacul e implementat de tine
în Python (`attacker.py`), Windows 11 + VS Code
e suficient pentru toate cele 6 cerințe.

Kali ar aduce ceva în plus doar dacă vrei să:
- folosești unelte consacrate de testare (ex. `hping3`, `scapy`) pentru a
  arăta și varianta de atac la nivel de rețea (SYN flood), pe lângă cea la
  nivel de aplicație implementată aici;
- rulezi atacatorul de pe o mașină/VM fizic separată, ca sursă IP reală
  diferită, în loc de trucul cu `127.0.0.2` descris mai sus.

Dacă vrei totuși varianta cu 2 mașini (host Windows = server + client
legitim, VM Kali = atacator): pune VM-ul în modul rețea **Host-only** sau
**Bridged**, pornește `plc_server.py` pe Windows legat pe adresa IP a
mașinii (schimbă `HOST` din `common.py` din `127.0.0.1` în IP-ul real al
Windows-ului, ex. `192.168.x.x`), apoi rulează `attacker.py` din Kali către
acel IP.

## Interpretarea rezultatelor (pentru raportul de proiect)

- **Succes rate** — procentul de cereri legitime reușite. Pe server-ul
  vulnerabil rămâne ridicat (conexiunile reușesc, doar că foarte lent), dar
  cu suficient de mulți atacatori concurenți poate ajunge la eșecuri reale
  (timeout). Pe server-ul protejat rămâne ~100% pe tot parcursul atacului.
- **Latență medie / p95 / max** — arată clar degradarea: pe server-ul
  vulnerabil crește de zeci de ori în fereastra de atac; pe cel protejat
  rămâne constantă (~15ms, egală cu întârzierea simulată de procesare).
- **`total_rejected_rate_limit` / `total_rejected_busy`** (în
  `server_protected_stats.csv`) — arată mecanismul de apărare în acțiune:
  cererile atacatorului sunt respinse rapid (`RATE_LIMIT` / `BUSY`) fără să
  consume resursele serverului, în timp ce cele ale clientului legitim
  (altă adresă sursă) trec normal.

## Parametrii de protecție (în `plc_server_protected.py`)

```python
MAX_WORKERS = 10          # cereri procesate in paralel
MAX_QUEUE = 50             # cereri care pot astepta in coada
RATE_LIMIT_PER_SEC = 5     # cereri/secunda admise per IP
RATE_LIMIT_BUCKET = 5      # capacitatea galetii de token-uri (token bucket)
```

Poți varia acești parametri și relua experimentul, pentru a discuta în
raport trade-off-ul dintre protecție și disponibilitate pentru traficul
legitim intens (de ex. ce se întâmplă dacă un client legitim trimite mai
mult de 5 cereri/secundă).
