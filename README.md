# IWsServer

IWsServer è un server HTTPS leggero sviluppato in C++, progettato per comprendere e implementare manualmente una versione semplificata del protocollo TLS. Utilizza OpenSSL per le operazioni crittografiche e ASIO per la gestione asincrona delle connessioni di rete.

## Caratteristiche principali

* Implementazione manuale del handshake TLS.
* Utilizzo di OpenSSL per le operazioni crittografiche.
* Gestione asincrona delle connessioni tramite ASIO.
* Struttura modulare con classi dedicate per l'accettazione delle connessioni e la gestione delle sessioni TLS.

## Struttura del progetto

* `src/` - Contiene i file sorgente principali.
* `include/` - Contiene i file header.
* `cert/` - Contiene i certificati SSL utilizzati per le connessioni sicure.
* `bin/` - Directory di output per i file binari compilati.
* `build.sh` - Script per la compilazione del progetto.

## Requisiti

* C++17 o superiore.
* OpenSSL installato nel sistema.
* ASIO library.

## Compilazione

Per compilare il progetto, eseguire lo script `build.sh`:

```bash
./build.sh
```



Assicurarsi che le librerie necessarie siano installate e accessibili.

## Esecuzione

Dopo la compilazione, eseguire il server:

```bash
./bin/server
```



Il server ascolterà sulla porta specificata e gestirà le connessioni HTTPS in arrivo.

## Contributi

I contributi sono benvenuti! Sentiti libero di aprire issue o pull request per migliorare il progetto.

## Licenza

Questo progetto è distribuito sotto la licenza MIT. Vedi il file [LICENSE](LICENSE) per maggiori dettagli.

---
