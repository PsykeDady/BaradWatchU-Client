# Client BaradWatchU

*Nove di questi furono dati ai Dev, che i tristi bug attendono; sette ai SysAdmin, nelle loro sale di server; tre ai Security Officer, custodi delle policy segrete.*

[Read in English](README.md)

BaradWatchU è una piattaforma di audit della conformità di sicurezza degli endpoint. Questo repository contiene l'agente Rust indipendente e il visualizzatore locale di stato Angular. L'agente esegue offline una prima parte dell'audit autonomo Fedora e in futuro comunicherà le evidenze al repository server separato.

## Stato

**Implementato in L0.1:** eseguibile Rust di bootstrap che stampa la piattaforma rilevata in compilazione e termina; confini adapter per Linux, Windows e macOS; scaffold del visualizzatore locale Angular che segnala che non sono collegati servizi o dati di audit.

**Validato in L0.1.1:** versione `0.0.1`, CLI Rust, build debug/release e build Angular production. Sono presenti test di regressione per avvio e metadati versione. L’installer è stato verificato con cache e prefissi isolati per installazione/aggiornamento/disinstallazione; la build completa arriva alla fase Rust ma l’installazione npm in una cache nuova è bloccata nell’ambiente offline. Servizi di sistema e package nativi restano pianificati.

**Implementato in L1.1 / Checkpoint 1:** audit Rust autonomo, cinque stati di risultato, report JSON versionato e leggibile, identità OS, aggiornamenti Fedora DNF5 in cache e ispezione della cifratura a blocchi del filesystem root. Non richiede processi Server o Angular.

**Smoke L0.1.1 confermati dall’operatore:** `/health` Server HTTP 200 con JSON atteso; entrambi i dev server Angular funzionanti; Ctrl+C del launcher arresta i servizi. Build installer con cache nuova, pacchetti nativi, audit dipendenze su tutte le distribuzioni e audit vulnerabilità restano debito tecnico.

**Pianificato:** servizi persistenti, pianificazione, policy firmate, controlli custom autorizzati, controlli per altre piattaforme, storage, arruolamento, sincronizzazione autenticata e remediation. Non fanno parte di questo checkpoint.

## Architettura

- `crates/agent/src/main.rs`: parsing CLI, compatibilità bootstrap, rendering audit e codici di uscita.
- `service.rs`: confine del ciclo di vita del servizio in background.
- `audit.rs`: `Check`/`Clock` riutilizzabili, tipi report/risultato/evidenza, riepilogo deterministico e rendering.
- `checks/builtin.rs`: tre identificatori stabili e applicabilità; `checks/custom.rs` resta differito.
- `policy.rs`, `communication.rs`: confini di policy e trasporto server; non esistono elaborazione policy o comportamento di rete.
- `platform/mod.rs`: `AuditPlatform` iniettabile; `linux.rs`: parser os-release sicuro; `fedora/`: sonde aggiornamenti/cifratura; `command.rs`: subprocessi limitati; `read_only.rs`: vincolo Linux sul filesystem del solo processo figlio. Gli adapter Windows/macOS restano confini.
- `web`: visualizzatore locale di stato Angular, indipendente dall'agente in background. Non è implementato IPC locale.

## Versione e CLI

Server e Client hanno cicli di release indipendenti. La versione prodotto autorevole del Client è `[workspace.package].version` nel `Cargo.toml` radice di questo repository; i package Rust la ereditano. La versione Angular nel `package.json` e quella visualizzata sono generate/sincronizzate da questa fonte con `node web/sync-version.mjs` (eseguito anche automaticamente da `npm run build`). Per cambiare versione, aggiornare quella workspace secondo SemVer e lanciare la sincronizzazione. La versione prodotto è distinta dallo schema report Client `baradwatchu.audit-report.v1`; ingestion Server e protocolli condivisi della flotta restano da definire.

```sh
cargo run -p baradwatchu-agent -- --version
cargo run -p baradwatchu-agent -- --help
cargo run -p baradwatchu-agent -- audit
cargo run -p baradwatchu-agent -- audit --format json
```

L'eseguibile release supporta questi flag senza avviare un servizio. Il bootstrap corrente, se eseguito senza opzioni, stampa la piattaforma e termina.

## Audit autonomo (L1.1 / Checkpoint 1)

Usare il binario compilato con `target/debug/baradwatchu-agent audit` oppure `target/release/baradwatchu-agent audit --format json`. Senza argomenti resta il bootstrap. L'audit non avvia servizi e non richiede root, Node, browser o Server.

Prerequisiti Fedora: installazione tradizionale RPM/DNF5 con `/usr/bin/dnf5` dotato di `--skip-file-locks`, `findmnt` e `lsblk` (util-linux), metadati di sistema leggibili e metadati dei repository già disponibili. DNF4 senza DNF5, installazioni ostree/Atomic/a immagine e altre distribuzioni non sono supportati. Un derivato con `ID_LIKE=fedora` non basta. Sono necessari `ID=fedora` effettivo e `VERSION_ID` numerico; ciò non certifica il supporto o la fine vita della release Fedora.

La sonda aggiornamenti richiede Linux **Landlock ABI 3+** abilitato e consentito. Il figlio vieta scrittura dei contenuti, creazione, rimozione, rinomina e troncamento dei file, e imposta `no_new_privs`; se il vincolo non è applicabile restituisce `ERROR/READ_ONLY_GUARD_UNAVAILABLE`, senza riprovare senza protezione. DNF5 usa soltanto la cache, disabilita plugin, output persistente dei log e creazione cache libsolv, e omette creazione/acquisizione del lock del repository di sistema; lo stato DNF esistente resta leggibile e il vincolo blocca le scritture. L’osservazione non è uno snapshot protetto dal lock delle transazioni ed è soggetta a modifiche concorrenti dei pacchetti; non invoca refresh o transazioni di pacchetti. L'auditor non popola né aggiorna metadati mancanti. Legge `/etc/os-release`, ripiegando su `/usr/lib/os-release` solo se assente; non valuta codice shell. Le sonde usano percorsi eseguibili fissi, ambiente minimo con locale C, stdin nullo, timeout 30 secondi e limite di 256 KiB per flusso di output. Il report esclude elenchi pacchetti grezzi, stderr, URL dei repository, seriali e UUID dei dischi.

| Controllo | Interpretazione e politica degli esiti |
|---|---|
| `SYS-OS-001` — identità OS | `PASS`: distribuzione identificata, con versione se presente (le rolling possono ometterla). Un OS non supportato mantiene limiti di copertura espliciti; errori di lettura/parsing sono `ERROR`. Questa osservazione non certifica conformità di sicurezza. |
| `SEC-001` — aggiornamenti pendenti | DNF5 `check-upgrade`: uscita 100 è `FAIL` (aggiornamenti in cache disponibili). Uscita 0 è `WARN/NO_CACHED_UPDATES`, perché freschezza/copertura non sono verificate. Cache mancante o nessun repository è `WARN`; DNF5 mancante, permessi, timeout, opzioni non valide e altri errori di esecuzione sono `ERROR`. Non esiste volutamente `PASS` finché freschezza/copertura non saranno attendibili. La futura policy trimestrale non viene valutata. |
| `SEC-006` — cifratura a blocchi della root | `findmnt` identifica `/` tramite major:minor; `lsblk` segue **ogni percorso osservato dei dispositivi sottostanti**. `PASS` richiede percorsi semplici disco/partizione/LVM con mapping dm-crypt attivo direttamente su metadati LUKS in ogni percorso. Un percorso provato in chiaro è `FAIL`. Un volume LUKS estraneo non basta. Ascendenza mancante/incompleta/sconosciuta, metadati incoerenti, dm-crypt senza LUKS provato, Btrfs (compreso il comune default Fedora), RAID/multipath, loop, overlay o root di rete sono `WARN`; strumenti mancanti, permessi, errori dei comandi e output malformato sono `ERROR`. |

L'ambito cifratura è **solo il filesystem root**, non tutti i dati di sistema/utente: `/home` separata, boot/EFI, swap, dischi esterni, cifratura hardware, robustezza delle chiavi e boot autenticato non sono certificati. Lo storage complesso richiede lavoro futuro e non viene presunto conforme. Le piattaforme non supportate producono controlli Fedora `NOT_APPLICABLE`, nessun comando di sonda e riepilogo `WARN`. Identità OS non rilevabile produce `ERROR`, non un salto riuscito.

Codici di uscita: **0** tutti i controlli applicabili PASS (anche bootstrap/help/version); **1** almeno un ERROR di esecuzione; **2** CLI non valida; **3** FAIL senza ERROR; **4** WARN, piattaforma non supportata o copertura incompleta senza ERROR/FAIL. Precedenza ERROR > FAIL > WARN > PASS. I conteggi dei cinque stati restano separati e deterministici.

Contratto JSON: `schemaVersion`, `agentVersion`, `startedAtUnixMs`, `completedAtUnixMs`, `operatingSystem`, `overall`, `summary`, `results`. Ogni risultato contiene metadati `check` (`id`, `name`, `description`, `version` dell'implementazione), `observedAtUnixMs`, `status`, `reasonCode`, `message`, `evidence` (`source`, `scope`, `values` strutturati). Timestamp interi in millisecondi Unix UTC; quelli dei risultati indicano l'inizio del controllo. Non vengono inventati identità dispositivo, policy applicata, firma o compatibilità Server. Gli audit completati emettono un report completo anche con esito non zero; errori fatali di clock/output possono impedire il report. Per gli audit completati, conservare il codice quando si salva JSON:

```sh
./target/release/baradwatchu-agent audit --format json > report.json
result=$?
printf 'Audit exit: %s\n' "$result"
```

Validazione: 38 test Rust, formattazione, Clippy con warning vietati e build debug/release con lock superati su Arch. Entrambi i binari producono report leggibili/JSON validi per piattaforma non supportata (riepilogo WARN, uscita 4); il test Linux di divieto di scrittura è stato eseguito con successo. Fixture per parser/contratto/piattaforma e test dei subprocessi non richiedono configurazione Fedora né root. L'esecuzione effettiva Fedora DNF5/storage root resta uno smoke test dell'operatore; le fixture non sono evidenze di conformità dell'endpoint. Riferimenti tecnici: [cache/configurazione DNF5](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html), [uscite check-upgrade](https://dnf5.readthedocs.io/en/stable/commands/check-upgrade.8.html), [Landlock](https://docs.kernel.org/userspace-api/landlock.html), [lsblk](https://man7.org/linux/man-pages/man8/lsblk.8.html).

## Prerequisiti

- Toolchain Rust stable con Cargo e rustfmt (base workspace: Rust 1.80+).
- Node.js 20.11.1 o successivo nella serie 20 e npm 8+; `web/.nvmrc` seleziona Node 20. I comandi rifiutano versioni Node incompatibili con un messaggio esplicito.
- Accesso di rete alla prima risoluzione delle dipendenze, salvo dipendenze già in cache.
- GNU/Linux con glibc 2.17+ per compilare; la cache registra la glibc effettiva del sistema di build e richiede conservativamente una versione uguale o successiva.
- Per la build sorgente completa: compilatori C/C++, make, Python 3 e tar (anche per eventuali dipendenze npm native).

## Comandi

Dalla radice del repository:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo build --release --workspace --locked
cargo run -p baradwatchu-agent
cargo run -p baradwatchu-agent -- --version
cargo run -p baradwatchu-agent -- --help
```

Compilare separatamente il visualizzatore di stato:

```sh
cd web
npm ci
npm start       # sviluppo locale
npm test        # test degli strumenti di versione
npm run build   # production
```

Se si usa nvm, eseguire `nvm use` in `web/` prima dei comandi npm. L’interfaccia di sviluppo ascolta su `http://127.0.0.1:4201` e rimane indipendente dal processo Rust. `npm start` resta in primo piano; fermarlo con Ctrl-C prima di eseguire altri comandi nello stesso terminale.

## Installazione Linux da sorgenti

Rilevamento installer supportato: Arch Linux, Fedora, Debian e Ubuntu, anche tramite `ID_LIKE`. `--missing-deps` controlla solo le dipendenze, rileva i package Angular locali mancanti e mostra comandi package manager/progetto; non installa pacchetti di sistema. Strumenti richiesti per compilare: Rust/Cargo 1.80+, Node.js 20 >=20.11.1, npm 8+, C/C++, make, Python 3 e tar; glibc 2.17+ è il minimo controllato sul sistema di build. Una cache precompilata e validata non richiede Node/Angular, mentre la build sorgente eseguita dall'installer compila anche questi asset.

```sh
./install.sh --help
./install.sh --missing-deps
./install.sh --dry-run --prefix=/tmp/baradwatchu-preview
./install.sh --local                         # copia di sviluppo limitata all'utente
./install.sh --build-only --build-dir="$HOME/.cache/baradwatchu/baradwatchu-agent-0.0.1"
sudo ./install.sh --no-build --build-dir="$HOME/.cache/baradwatchu/baradwatchu-agent-0.0.1" --prefix=/usr/local
./install.sh --uninstall --prefix=/usr/local
```

`--no-build` richiede una cache completa prodotta dallo stesso albero sorgente, versione e piattaforma. Per un prefisso di sistema, compilare prima come utente non privilegiato e poi installare con `sudo` e `--no-build`; non compilare come root. `--local` installa in `~/.local` solo per sviluppo manuale: non fornisce servizio di sistema, controlli privilegiati o monitoraggio di conformità. L'installazione sorgente di sistema installa solo file, senza creare o riavviare servizi. La disinstallazione rimuove solo file invariati elencati nel manifest sorgente; rifiuta file gestiti da package manager o modificati e conserva configurazione, identità di arruolamento, audit e controlli custom. Gli aggiornamenti usano lo stesso manifest.

`--build-only` usa Cargo `--locked` e una copia temporanea di Angular nella cache: `npm ci` non sostituisce `node_modules` del checkout. Dipendenze, log npm e header node-gyp rimangono nella cache. I sorgenti devono restare invariati durante la build. `-h` è alias di `--help`, `-U` di `--uninstall` e `--build-dir=DIR` seleziona la cache marcata. Codici di uscita: 0 successo, 1 errore di esecuzione/validazione, 2 opzioni non valide o in conflitto.

L'installazione da sorgenti compila da questo checkout. Arch `pacman`, pacchetto `.deb` Debian/Ubuntu e `.rpm` Fedora sono pianificati in [`packaging/README.md`](packaging/README.md). Sono pianificati anche Windows `setup.exe` e macOS `.dmg`; nessuno di questi artefatti è stato compilato o testato. L'installer sorgente rifiuta conflitti di proprietà con package manager.

I test audit Rust coprono serializzazione, riepilogo/codici, applicabilità, fixture ed errori dei subprocessi limitati, senza root o configurazione reale degli endpoint. `npm test` copre ancora 4 casi degli strumenti di versione; non è configurato un runner UI Angular. Gli smoke dell’operatore confermano i dev server Angular e l’arresto del launcher; questo checkpoint non modifica le UI. Il lock npm v1 resta debito tecnico, come la build installer completa con cache nuova e gli audit vulnerabilità. La cache v2 verifica hash/glibc; cache precedenti richiedono una nuova build e configurazione/dati installati sono conservati.

## Principi di sicurezza

L'agente è progettato per effettuare prima audit, operare con privilegi minimi, funzionare indipendentemente dall'interfaccia e classificare come sconosciuti i controlli non osservabili, senza considerarli superati. Le policy server devono autorizzare i controlli; gli artefatti custom richiedono approvazione locale e verifica d'identità. Non sono ammessi shell remota o interventi correttivi impliciti. Questo checkpoint applica sonde native in sola lettura e stati veritieri. Autorizzazione policy, controlli custom ed evidenze autenticate restano futuri; le osservazioni locali non sono una certificazione resistente a manomissioni.

## Requisiti e roadmap

I requisiti canonici e le fasi sono nel file locale `REQUIREMENTS.md` della cartella padre (§§ 2–14). È un documento locale di sviluppo, non una dipendenza né un file pubblico di questo repository.

## Mappa del repository

```text
Cargo.toml                 Workspace Rust
crates/agent/               Eseguibile/libreria audit autonomo e confini futuri
crates/agent/tests/         Contratti, test comandi, fixture Fedora sintetiche
web/                        Visualizzatore locale di stato Angular indipendente
install.sh                  Installer Linux da sorgenti; servizio differito
packaging/README.md         Piano pacchetti Linux/Windows/macOS
packaging/product.toml      Metadati piano: percorsi e proprietà
```
