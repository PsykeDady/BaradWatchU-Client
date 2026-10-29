# Client BaradWatchU

*Nove di questi furono dati ai Dev, che i tristi bug attendono; sette ai SysAdmin, nelle loro sale di server; tre ai Security Officer, custodi delle policy segrete.*

[Read in English](README.md)

BaradWatchU è una piattaforma di audit della conformità di sicurezza degli endpoint. Questo repository contiene l'agente Rust indipendente e il visualizzatore locale di stato Angular. L'agente effettuerà audit degli endpoint offline e in futuro comunicherà le evidenze al repository server separato.

## Stato

**Implementato in L0.1:** eseguibile Rust di bootstrap che stampa la piattaforma rilevata in compilazione e termina; confini adapter per Linux, Windows e macOS; scaffold del visualizzatore locale Angular che segnala che non sono collegati servizi o dati di audit.

**Implementato in L0.1.1:** versione prodotto `0.0.1`; flag Rust `--version`/`-V` e `--help`/`-h`; base dell'installer Linux da sorgenti con audit dipendenze, dry-run, validazione cache build, prefissi utente/sistema e disinstallazione tramite manifest hash. Installer, ciclo di vita del servizio e artefatti release non sono ancora verificati; nessun canale è dichiarato pronto per la produzione.

**Pianificato:** integrazione come servizio in background, motore di audit, controlli built-in e custom autorizzati, validazione policy, ispezione specifica per piattaforma, storage locale dei risultati e comunicazione autenticata col server. Non sono implementati controlli, installazione del servizio, elaborazione policy, arruolamento, sincronizzazione, helper privilegiato o remediation.

## Architettura

- `crates/agent/src/main.rs`: termina correttamente dopo aver identificato la piattaforma per il bootstrap.
- `service.rs`: confine del ciclo di vita del servizio in background.
- `audit.rs`, `checks/builtin.rs`, `checks/custom.rs`: confini di audit e controlli; non viene eseguito alcun controllo.
- `policy.rs`, `communication.rs`: confini di policy e trasporto server; non esistono elaborazione policy o comportamento di rete.
- `platform/{linux,windows,macos}.rs`: confini adapter selezionati in compilazione.
- `web`: visualizzatore locale di stato Angular, indipendente dall'agente in background. Non è implementato IPC locale.

## Versione e CLI

Server e Client hanno cicli di release indipendenti. La versione prodotto autorevole del Client è `[workspace.package].version` nel `Cargo.toml` radice di questo repository; i package Rust la ereditano. La versione Angular nel `package.json` e quella visualizzata sono generate/sincronizzate da questa fonte con `node web/sync-version.mjs` (eseguito anche automaticamente da `npm run build`). Per cambiare versione, aggiornare quella workspace secondo SemVer e lanciare la sincronizzazione. La versione prodotto è distinta dalle future versioni API/protocollo/schema, ancora da definire.

```sh
cargo run -p baradwatchu-agent -- --version
cargo run -p baradwatchu-agent -- --help
```

L'eseguibile release supporta questi flag senza avviare un servizio. Il bootstrap corrente, se eseguito senza opzioni, stampa la piattaforma e termina.

## Prerequisiti

- Toolchain Rust stable con Cargo e rustfmt (base workspace: Rust 1.80+).
- Node.js 20.11+ e npm 8+ per Angular 18 (consigliato Node 20).
- Accesso di rete alla prima risoluzione delle dipendenze, salvo dipendenze già in cache.
- GNU/Linux con glibc 2.17+ per questo target di compilazione.

## Comandi

Dalla radice del repository:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p baradwatchu-agent
cargo run -p baradwatchu-agent -- --version
cargo run -p baradwatchu-agent -- --help
```

Compilare separatamente il visualizzatore di stato:

```sh
cd web
npm install
npm run build
```

## Installazione Linux da sorgenti

Rilevamento installer supportato: Arch Linux, Fedora, Debian e Ubuntu, anche tramite `ID_LIKE`. `--missing-deps` controlla solo le dipendenze, rileva i package Angular locali mancanti e mostra comandi package manager/progetto; non installa pacchetti di sistema. Strumenti richiesti per compilare: Rust/Cargo 1.80+, Node.js 20.11+ e npm 8+; glibc 2.17+ è il requisito runtime GNU/Linux. Una cache precompilata e validata non richiede Node/Angular, mentre la build sorgente eseguita dall'installer compila anche questi asset.

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

`--build-only` prepara e valida una cache senza toccare un'installazione. `-h` è alias di `--help`, `-U` di `--uninstall` e `--build-dir=DIR` seleziona la cache marcata. Codici di uscita: 0 successo, 1 errore di esecuzione/validazione, 2 opzioni non valide o in conflitto.

L'installazione da sorgenti compila da questo checkout. Arch `pacman`, pacchetto `.deb` Debian/Ubuntu e `.rpm` Fedora sono pianificati in [`packaging/README.md`](packaging/README.md). Sono pianificati anche Windows `setup.exe` e macOS `.dmg`; nessuno di questi artefatti è stato compilato o testato. L'installer sorgente rifiuta conflitti di proprietà con package manager.

Non sono configurati runner o test Angular; i test Rust si eseguono con `cargo test --workspace`. Le release Angular/server restano non verificate se i registry delle dipendenze sono irraggiungibili; l'installer sorgente non è dichiarato validato end-to-end finché build release reali non superano i controlli.

## Principi di sicurezza

L'agente è progettato per effettuare prima audit, operare con privilegi minimi, funzionare indipendentemente dall'interfaccia e classificare come sconosciuti i controlli non osservabili, senza considerarli superati. Le policy server devono autorizzare i controlli; gli artefatti custom richiedono approvazione locale e verifica d'identità. Non sono ammessi shell remota o interventi correttivi impliciti. Sono principi progettuali; l'applicazione effettiva è lavoro futuro.

## Requisiti e roadmap

I requisiti canonici e le fasi sono nel file locale `REQUIREMENTS.md` della cartella padre (§§ 2–14). È un documento locale di sviluppo, non una dipendenza né un file pubblico di questo repository.

## Mappa del repository

```text
Cargo.toml                 Workspace Rust
crates/agent/               Eseguibile agente e confini modulari
web/                        Visualizzatore locale di stato Angular indipendente
install.sh                  Installer Linux da sorgenti; servizio differito
packaging/README.md         Piano pacchetti Linux/Windows/macOS
packaging/product.toml      Metadati piano: percorsi e proprietà
```
