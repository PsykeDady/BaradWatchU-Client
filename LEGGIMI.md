# Client BaradWatchU

*Nove di questi furono dati ai Dev, che i tristi bug attendono; sette ai SysAdmin, nelle loro sale di server; tre ai Security Officer, custodi delle policy segrete.*

[Read in English](README.md)

BaradWatchU è una piattaforma di audit della conformità di sicurezza degli endpoint. Questo repository contiene l'agente Rust indipendente e il visualizzatore locale di stato Angular. L'agente effettuerà audit degli endpoint offline e in futuro comunicherà le evidenze al repository server separato.

## Stato

**Implementato in L0.1:** eseguibile Rust di bootstrap che stampa la piattaforma rilevata in compilazione e termina; confini adapter per Linux, Windows e macOS; scaffold del visualizzatore locale Angular che segnala che non sono collegati servizi o dati di audit. Rust è stato compilato ed eseguito; qui la build Angular non è verificata perché i registry delle dipendenze non erano raggiungibili.

**Pianificato:** integrazione come servizio in background, motore di audit, controlli built-in e custom autorizzati, validazione policy, ispezione specifica per piattaforma, storage locale dei risultati e comunicazione autenticata col server. Non sono implementati controlli, installazione del servizio, elaborazione policy, arruolamento, sincronizzazione, helper privilegiato o remediation.

## Architettura

- `crates/agent/src/main.rs`: termina correttamente dopo aver identificato la piattaforma per il bootstrap.
- `service.rs`: confine del ciclo di vita del servizio in background.
- `audit.rs`, `checks/builtin.rs`, `checks/custom.rs`: confini di audit e controlli; non viene eseguito alcun controllo.
- `policy.rs`, `communication.rs`: confini di policy e trasporto server; non esistono elaborazione policy o comportamento di rete.
- `platform/{linux,windows,macos}.rs`: confini adapter selezionati in compilazione.
- `web`: visualizzatore locale di stato Angular, indipendente dall'agente in background. Non è implementato IPC locale.

## Prerequisiti

- Toolchain Rust stable con Cargo e rustfmt (base workspace: Rust 1.80+).
- Node.js 20.11+ e npm 8+ per Angular 18 (consigliato Node 20).
- Accesso di rete alla prima risoluzione delle dipendenze, salvo dipendenze già in cache.

## Comandi

Dalla radice del repository:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p baradwatchu-agent
```

Compilare separatamente il visualizzatore di stato:

```sh
cd web
npm install
npm run build
```

In questo bootstrap non sono configurati runner o test Angular; i test Rust si eseguono con `cargo test --workspace`.

## Principi di sicurezza

L'agente è progettato per effettuare prima audit, operare con privilegi minimi, funzionare indipendentemente dall'interfaccia e classificare come sconosciuti i controlli non osservabili, senza considerarli superati. Le policy server devono autorizzare i controlli; gli artefatti custom richiedono approvazione locale e verifica d'identità. Non sono ammessi shell remota o interventi correttivi impliciti. Sono principi progettuali; l'applicazione effettiva è lavoro futuro.

## Requisiti e roadmap

I requisiti canonici e le fasi sono nel file locale `REQUIREMENTS.md` della cartella padre (§§ 2–14). È un documento locale di sviluppo, non una dipendenza né un file pubblico di questo repository.

## Mappa del repository

```text
Cargo.toml                 Workspace Rust
crates/agent/               Eseguibile agente e confini modulari
web/                        Visualizzatore locale di stato Angular indipendente
```
