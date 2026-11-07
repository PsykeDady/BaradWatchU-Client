# Universal check adapters — MVP

## Vuoi supportare un nuovo sistema operativo?

Implementa **evidenze per un ID**, non un verdetto di conformità. Il percorso è:

`ID → registro locale → CheckExecutor::execute(ID) → CheckEvidence → policy → report`

Il port è in `crates/agent/src/check_port.rs`. `adapters/mod.rs` contiene il registro compilato e il ponte verso i collector Rust esistenti. `adapters/external.rs` avvia programmi con percorso assoluto e argv espliciti; non riconosce linguaggi né costruisce una shell implicita. Una voce può indicare esplicitamente un interprete e il suo file. Nessuna discovery/download, configurazione di comandi via policy, firma, marketplace o server.

### Contratto esterno v1

Il programma riceve, dopo gli eventuali argomenti statici del registro:

```text
--check-id SEC-013 --schema baradwatchu.check-evidence.v1
```

Stdin è chiuso; ambiente ripulito e locale C; working directory `/`. Non vengono passati policy, credenziali o comandi remoti. Le soglie della policy non servono al collector: deve riportare fatti indipendenti. L'MVP non implementa parametri dinamici per programmi esterni. Nuovi parametri richiedono un contratto tipizzato, non interpolazione di comandi.

Stdout contiene **un unico documento JSON**, senza banner o log. Esempio funzionale, ma con valori sintetici:

```json
{
  "schemaVersion": "baradwatchu.check-evidence.v1",
  "checkId": "SEC-013",
  "availability": "AVAILABLE",
  "data": {
    "kind": "SECURE_BOOT",
    "values": {
      "state": "ENABLED",
      "secureBoot": true,
      "setupMode": false
    }
  }
}
```

- `AVAILABLE`: `data` deve corrispondere al contratto dell'ID. Non significa PASS.
- `UNKNOWN`: evidenza inconclusiva/non leggibile; `data: null`.
- `NOT_APPLICABLE`: controllo non applicabile; `data: null`; non certifica la conformità.
- `ERROR`: errore dichiarato dal collector; `data: null`.
- Exit **0**: documento completo, anche per UNKNOWN/NOT_APPLICABLE/ERROR.
- Qualunque exit nonzero o terminazione anomala: errore di esecuzione; stdout non viene utilizzato. Non usare gli exit code PASS/FAIL del CLI come protocollo adapter.
- Stderr serve solo per diagnostica non sensibile: è limitato, ma scartato, non inserito nel report né usato per dedurre fatti. Output eccessivo su uno qualsiasi dei due stream invalida la raccolta.
- ID/schema errati, campi sconosciuti o duplicati, tipi/enum errati, documenti multipli e dati incompatibili con availability sono rifiutati. Non esistono campi PASS/FAIL o comandi nel contratto.

Contratti esterni iniziali, deliberatamente pochi:

| ID | `data.kind` | `data.values` |
| --- | --- | --- |
| SEC-011 | VPN_INDICATORS | `state`: CONNECTED, AUTH_REQUIRED, CONNECTING, DISCONNECTED, ERROR, UNKNOWN, UNAVAILABLE |
| SEC-013 | SECURE_BOOT | `state`: ENABLED, DISABLED, NON_UEFI_BOOT, VARIABLES_UNAVAILABLE, INCONSISTENT, RESTRICTED; `secureBoot` e `setupMode`: booleani o null |

SEC-011 rimane un indicatore: nemmeno CONNECTED dimostra routing/protezione e la valutazione resta WARN. Per SEC-013 il core converte i fatti nell'osservazione tipizzata esistente e riusa la policy. Il relativo binario esterno è **solo una fixture**, non un nuovo inspector firmware. Gli altri controlli conservano i collector nativi o i due raccoglitori incorporati: non sono tutti migrati al protocollo esterno.

### Aggiungere un'implementazione

1. Scegli l'ID funzionale e il contratto dei fatti. Non definire, per esempio, la complessità password come “PAM presente”: PAM è una possibile sorgente Linux, non il requisito.
2. Implementa il collector read-only nel linguaggio opportuno. Usa lo stesso contratto dell'ID indipendentemente dal linguaggio; se manca un contratto esterno per quell'ID, aggiungi una variante tipizzata e la conversione verso le osservazioni esistenti.
3. Aggiungi una voce **nel registro locale compilato**, con piattaforma, programma/argv statici e timeout. `ExternalSpec` non è deserializzabile da policy o report. Per un collector Rust nativo riusa l'adapter esistente senza riscriverlo come subprocesso.
4. Distribuisci l'artifact con l'installazione autorizzata. Aggiungi test di contratto, casi inconclusivi, errori e policy. Non basta inventare un ID o copiare un file perché venga eseguito.
5. Aggiungi e verifica l'applicabilità della nuova piattaforma nell'infrastruttura, separatamente dalla valutazione. Questa release **non** implementa altri OS: Arch/Fedora rimangono il perimetro attuale.

Il file distribuito è `scripts/adapters/SEC-011.sh`. Il runtime cerca sempre `../share/baradwatchu-client/checks/SEC-011.sh` rispetto alla directory del **binario effettivo** (`current_exe`): installazione `<prefix>/bin/baradwatchu-agent`, adapter `<prefix>/share/baradwatchu-client/checks/SEC-011.sh`. Nessuna dipendenza dalla directory corrente, dal checkout, da percorsi sorgente compilati o dai nomi debug/release. `build.rs` prepara lo stesso layout accanto agli artifact Cargo; l'installer include l'adapter nel fingerprint della cache e nel manifest, installandolo dalla cache validata insieme al binario. Spostare il solo binario non basta: occorre distribuire anche il file dati approvato.

Permessi: binario `0755`, script Bash `0644`, directory non scrivibili da gruppo/altri. Lo script deve essere **leggibile**, non eseguibile: viene aperto esplicitamente da `/usr/bin/bash --noprofile --norc`. Su Linux sono richiesti gli strumenti usati dallo script e Landlock ABI≥3/no_new_privs; Cato assente o inconclusivo può produrre UNKNOWN/WARN legittimamente. La mancanza del file distribuito è invece un problema di installazione.

Prima dell'avvio vengono verificati byte approvati, proprietari, permessi e assenza di symlink lungo i percorsi di binario e adapter. Sono accettati root e il proprietario del binario; directory sticky fidate, come `/tmp`, sono ammesse solo mantenendo protetta la catena di elementi posseduti. Directory ordinarie scrivibili da gruppo/altri vengono rifiutate; anche l'installer le rifiuta e usa umask022. Un checkout sotto un antenato insicuro può quindi produrre PERMISSION_DENIED: non viene modificata la sicurezza del checkout, utilizzare un build-dir privato o un prefisso protetto.

Per un'installazione amministrativa il binario e la catena devono essere di root: l'utente ordinario non può sostituire l'adapter attraverso directory scrivibili. Una copia locale/staging posseduta dall'utente **si fida di quell'utente**, che può comunque sostituire il proprio binario: non è una distribuzione system-wide resistente al proprietario. Nessuna firma o difesa contro root/amministratore ostile è dichiarata. La copia embedded storica non è un fallback per file esterni mancanti o alterati.

### Installazione e verifica fuori dal repository

Da `BaradWatchU-Client/`, con Rust/Cargo e Node20/npm richiesti dall'installer:

```sh
client_source=$(pwd -P)
adapter_test_root=$(mktemp -d /tmp/baradwatchu-install.XXXXXXXX)
bash install.sh --build-only --build-dir="$adapter_test_root/cache"
bash install.sh --no-build --build-dir="$adapter_test_root/cache" --prefix="$adapter_test_root/prefix"
cd /tmp
"$adapter_test_root/prefix/bin/baradwatchu-agent" workstation check SEC-011
"$adapter_test_root/prefix/bin/baradwatchu-agent" workstation audit --policy "$client_source/policies/workstation.example.json"
bash "$client_source/install.sh" --uninstall --prefix="$adapter_test_root/prefix"
```

Questa è una sequenza interattiva: `check` restituisce exit4 per design, l'audit può restituire exit3 per violazioni della policy. Non interpretarli come fallimento dell'installazione. Per il controllo funzionante cercare `executionState=COMPLETED` e JSON valido, anche se la conformità resta WARN. `MISSING_EXECUTABLE/MISSING_TOOL` identifica il file mancante; `NOT_STARTED/PERMISSION_DENIED` permessi o percorso non fidato; `NOT_STARTED/INVALID_OUTPUT` file non conforme alla copia distribuita. Nessuno di questi casi diventa PASS.

Validazione 2026-11-06: build completa Rust+Angular (`npm ci`, cache privata), installazione non privilegiata in prefisso temporaneo con spazi, smoke Arch dal cwd progetto e da `/tmp`, audit nativo del binario installato, riapplicazione dell'installazione e uninstall reali. SEC011 COMPLETED/WARN prima e dopo; medesimo contratto JSON. Provati realmente file mancante, permessi000, directory0777 e contenuto alterato: rifiuto prima dell'esecuzione. L'installer rifiuta directory insicure; uninstall rifiuta file alterati senza rimozioni parziali, poi rimuove i6 file del manifest dopo il ripristino e preserva un file estraneo. Timeout, JSON malformato, programma senza execute bit e symlink sono coperti dalle fixture/test. Totale305 test superati,1 opzionale ignorato. Nessuna installazione di sistema modificata; deployment root-owned e Fedora nativo non eseguiti.

### Esempi realmente eseguibili

```sh
# Registro e audit applicativo, con le policy già esistenti.
./target/debug/baradwatchu-agent workstation list
./target/debug/baradwatchu-agent workstation check SEC-011
./target/debug/baradwatchu-agent workstation audit --policy policies/workstation.example.json --local-config policies/workstation-local.example.json

# Fixture, non evidenze della macchina: Bash e Rust compilato senza Bash.
bash crates/agent/tests/fixtures/check-evidence.sh --check-id SEC-013 --schema baradwatchu.check-evidence.v1
cargo run --offline --locked --example check_evidence_fixture -- available --check-id SEC-013 --schema baradwatchu.check-evidence.v1
cargo test --offline --locked --test adapters
```

I test compilano anche la fixture con rustc in una directory temporanea e la avviano con il vero executor e la guardia read-only. Nessun runtime aggiuntivo. Le invocazioni manuali delle fixture qui sopra mostrano il protocollo; solo l'executor applica i limiti e la guardia.

### Esecuzione, policy e compatibilità

`executionState` distingue COMPLETED, NOT_STARTED, MISSING_EXECUTABLE, TIMEOUT, OUTPUT_LIMIT, INVALID_EVIDENCE, UNEXPECTED_EXIT e FAILED. `evidenceAvailability` distingue i fatti dal successo del processo. Sono campi additivi nel report workstation v1; i vecchi campi restano. Lettori esterni che rifiutano campi nuovi devono essere aggiornati. I report nativi v1/v2 e policy v1/v2/v3 non cambiano.

Il port mantiene un `Outcome` come vista compatibile dei collector Rust: il suo status storico è osservazionale e non sostituisce `evaluation`. Un adapter esterno non può impostarlo. La policy non distingue Native/External; la provenienza rimane metadato. Le indicazioni 003/004/011 mantengono la valutazione prudente precedente, non legata al tipo di implementazione.

La selezione locale viene applicata **prima** di chiamare il port. I disabilitati non hanno nuove evidenze/stato esecuzione; l'interruzione di un requisito resta esplicita. 008/009 condividono la raccolta aging ma chiamano l'ID abilitato. La diagnostica manuale `check` continua a ignorare la selezione dell'audit, senza valutazione di conformità.

Limiti di sicurezza: per le registrazioni Linux attuali l'executor richiede la guardia Landlock/no_new_privs esistente e non ritenta senza protezione. Landlock non è considerato disponibile su ogni OS; fuori dalle piattaforme supportate o senza guardia il collector non parte. Non viene introdotto un nuovo sandbox né una pretesa di protezione dal traffico di rete. I timeout nativi restano quelli dei rispettivi adapter; il limite del registro riguarda i subprocessi esterni, non preempie funzioni Rust in-process.

Nessun server, notifica remota, aggiornamento automatico, UI Angular o nuovo sistema operativo è implementato. `remoteDelivery=NOT_IMPLEMENTED` rimane esplicito.
