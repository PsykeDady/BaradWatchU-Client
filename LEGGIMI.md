# Client BaradWatchU

*Nove di questi furono dati ai Dev, che i tristi bug attendono; sette ai SysAdmin, nelle loro sale di server; tre ai Security Officer, custodi delle policy segrete.*

[Read in English](README.md)

BaradWatchU Client controlla la postazione su cui viene eseguito. Audit, impostazioni e storico restano locali; il Server non è necessario. Il target di sviluppo attuale è Arch Linux; il catalogo dei requisiti non supporta ancora altri sistemi operativi.

## Requisiti ed esiti

Il catalogo incluso è [catalog/requirements.json](catalog/requirements.json). Contiene nove requisiti leggibili, ognuno con ID, nome, descrizione funzionale, stato di abilitazione locale, priorità predefinita e percorso del tool specifico per sistema operativo. I tool Arch sono in `tools/linux/`. Le priorità sono `HIGHEST`, `HIGH`, `MEDIUM`, `LOW` e `OPTIONAL`; non modificano l'esito del controllo.

Ogni tool viene avviato direttamente, senza shell implicita, con durata e output limitati. Restituisce un oggetto JSON con ID del requisito, stato, riepilogo breve e dettagli facoltativi. Gli stati sono `PASS`, `FAIL`, `WARN`, `ERROR`, `DISABLED` e `NOT_APPLICABLE`. Evidenze mancanti o ambigue restano `WARN`; errori di avvio o di protocollo diventano `ERROR`. I tool non elevano i privilegi e non modificano la configurazione di sistema.

`REQ-001` verifica gli aggiornamenti dei pacchetti usando `/usr/bin/checkupdates --nocolor` fornito da `pacman-contrib`. `checkupdates` usa un database temporaneo e può contattare i mirror Arch: il controllo non è offline. Se `checkupdates` manca, i mirror non rispondono o l'esito non è determinabile, viene restituito `WARN`. Gli aggiornamenti trovati producono `FAIL`; nessun aggiornamento produce `PASS`. Il controllo non determina la presenza di vulnerabilità. Vedi il [manuale Arch di checkupdates](https://man.archlinux.org/man/extra/pacman-contrib/checkupdates.8.en).

Altri controlli restituiscono intenzionalmente `WARN` quando gli indicatori locali non dimostrano la proprietà di sicurezza. In particolare, la presenza di un servizio antivirus non dimostra la copertura delle scansioni; le impostazioni DNS non dimostrano il filtraggio; lo stato VPN non dimostra la raggiungibilità del tunnel; e i tool attuali per cifratura, password e avvio non dichiarano più di quanto consentano le evidenze disponibili. Valutare il riepilogo e i dettagli prima di considerare conforme un requisito.

## CLI

Compilare con Rust e le dipendenze Angular installate, poi eseguire:

```sh
cargo run -p baradwatchu-agent -- list
cargo run -p baradwatchu-agent -- enable REQ-001
cargo run -p baradwatchu-agent -- disable REQ-005
cargo run -p baradwatchu-agent -- priority REQ-001 HIGH
cargo run -p baradwatchu-agent -- configure REQ-006 '{"sensitivePaths":["/srv/archive"]}'
cargo run -p baradwatchu-agent -- check REQ-001
cargo run -p baradwatchu-agent -- check REQ-001 --log
cargo run -p baradwatchu-agent -- audit
cargo run -p baradwatchu-agent -- audit --json
cargo run -p baradwatchu-agent -- audit --log
cargo run -p baradwatchu-agent -- status
```

Usare `--json` esplicitamente per l’output destinato alle macchine e aggiungere `--log` a `audit` o `check ID` per salvare un log di testo `.log` in `~/.local/state/baradwatchu/audits/`. I log di testo sono disattivati per impostazione predefinita. I report JSON strutturati restano salvati per `status` e dashboard in `audits/reports/`: sono la cronologia dell’applicazione, non copie dei log. Il log richiesto mostra risultati, tool eseguiti e diagnostiche. L’installer suggerisce anche i pacchetti Arch per i comandi di audit opzionali mancanti. Disabilitare un requisito lo conserva insieme alle impostazioni. I parametri sono oggetti JSON passati tramite standard input; i tool che non li leggono li ignorano.

I controlli Linux riportano separatamente le evidenze dei metodi: REQ-003 supporta UFW, firewalld e nftables operativi; REQ-004 restituisce PASS se dnsmasq è installato e attivo oppure, se dnsmasq è assente, sono presenti voci di blocco personalizzate in `/etc/hosts`; REQ-005 supporta Cato e WireGuard e restituisce PASS solo se almeno una VPN è connessa. Un dnsmasq installato ma inattivo produce FAIL; una VPN installata ma disconnessa produce WARN perché i servizi aziendali potrebbero non essere raggiungibili. Antivirus e controlli analoghi richiedono che i servizi pertinenti siano attivi: la sola installazione non basta. REQ-003 restituisce `PASS` solo quando l'operatività di un metodo è verificata. Se tutti i servizi firewall gestiti risultano esplicitamente inattivi/disabilitati, restituisce `FAIL` anche quando il ruleset kernel non è leggibile; l'incertezza resta nei dettagli diagnostici. Negli altri casi, regole nftables inaccessibili producono `WARN`, senza presumerne l'assenza o l'efficacia.

I precedenti comandi `workstation`, `policy validate`, `audit --policy`, `audit --format` e `audit --local-config` sono stati rimossi; la CLI li rifiuta. I vecchi file d'implementazione restano temporaneamente per test e codice interno della migrazione, ma non sono esposti come comandi.

## Dashboard e notifiche

`baradwatchu-agent dashboard` avvia la dashboard Angular su un indirizzo loopback con porta temporanea e prova ad aprirla con `xdg-open`. Non avvia un servizio dell'agente né espone un listener alla rete. La dashboard usa le stesse impostazioni locali, lo stesso runner di audit e lo storico dei report della CLI; l'audit funziona anche senza browser. Per lo sviluppo, compilare prima Angular e poi avviare il bridge Rust; Cargo copia il bundle locale accanto all'eseguibile:

```sh
cd web
npm ci
npm run build
cd ..
cargo run -p baradwatchu-agent -- dashboard
```

`baradwatchu-agent audit --notify` chiede a `notify-send` di mostrare un riepilogo al termine dell'audit, se il programma è installato e la sessione desktop accetta notifiche. Le notifiche sono facoltative e non servono per eseguire l'audit.

## Compilazione e installazione su Arch Linux

L'installer dei sorgenti mantiene il flusso di cache di build, staging, reinstallazione e disinstallazione tramite manifest. Avviarlo come utente normale; chiede `sudo` solo per copiare i file in un prefisso protetto:

```sh
./install.sh --missing-deps
./install.sh --build-only
./install.sh
```

Servono Rust/Cargo, tool di compilazione C/C++, Python, tar, Node.js 20 (almeno 20.11.1) e npm. Se nvm è già installato, l'installer seleziona la versione indicata da `web/.nvmrc`; non scarica Node automaticamente. Installare `pacman-contrib` per eseguire `REQ-001`. `./install.sh --help` elenca le opzioni per build-only, cache, prefisso e disinstallazione. L'installer non crea un servizio di sistema né un pacchetto per il package manager.

## Verifiche di sviluppo

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cd web && npm test && npm run build
```

I comandi npm usano la versione Node selezionata da `web/.nvmrc`.

## Limiti attuali della migrazione

Questo è il primo checkpoint d'implementazione del Client semplificato, non la migrazione conclusa. Il valutatore legacy delle policy, i collector nativi e il registro workstation sono ancora nel codice, ma i relativi vecchi comandi CLI sono stati rimossi. Alcuni dei nove tool Arch sono prudenti e restituiscono `WARN`; la verifica della cifratura dei percorsi e una più ampia validazione su host reale sono incomplete. Non sono presenti pianificazione/daemon, comunicazione con il Server, policy remote, download dinamico dei tool, implementazioni Windows/macOS o correzione automatica.
