# Client BaradWatchU

*Nove di questi furono dati ai Dev, che i tristi bug attendono; sette ai SysAdmin, nelle loro sale di server; tre ai Security Officer, custodi delle policy segrete.*

[Read in English](README.md)

BaradWatchU Client controlla la postazione su cui viene eseguito. Audit, impostazioni e storico restano locali; il Server non è necessario. I target di sviluppo sono Arch Linux e, dal 2026-11-08, Windows 11 (in sviluppo, vedi [Windows](#windows-in-sviluppo)); macOS non è supportato.

## Controlli: una cartella ciascuno

Ogni controllo, integrato o personalizzato, è una cartella con il nome del suo ID che contiene `configuration.json` e il tool da eseguire:

```text
custom-checks/
└── CUSTOM-001/
    ├── configuration.json
    └── CUSTOM-001.sh
```

```json
{
  "schemaVersion": "baradwatchu.custom-checks.v1",
  "id": "CUSTOM-001",
  "name": "Password Reminder",
  "description": "Che cosa verifica il controllo",
  "priority": "OPTIONAL",
  "enabled": true,
  "toolPath": "./CUSTOM-001.sh",
  "arguments": [],
  "expectedSha256": "<sha256 del tool>",
  "version": 1,
  "timeoutSeconds": 20,
  "parameters": {},
  "overrideBuiltinId": null
}
```

- I controlli integrati stanno in `share/baradwatchu-client/catalog/checks/REQ-*/` dell'installazione (Windows: `catalog/checks-windows/REQ-*/`); quelli personalizzati in `$XDG_CONFIG_HOME/baradwatchu/custom-checks/CUSTOM-*/` (predefinito `~/.config/baradwatchu/custom-checks/`; Windows `%APPDATA%\baradwatchu\custom-checks\`). Una cartella `custom-tools` della versione precedente viene rinominata in `custom-checks` al primo utilizzo, senza modificarne il contenuto.
- `id` deve coincidere con il nome della cartella e iniziare con `CUSTOM-` (lettere maiuscole, cifre, trattini). `toolPath` è relativo alla cartella. `arguments` viene passato direttamente al tool, senza shell. `timeoutSeconds` (1–300, predefinito 20) e `version` sono facoltativi. `parameters` è un oggetto JSON inviato al tool su stdin come `{"requirementId":…,"parameters":{…}}`. I campi sconosciuti sono rifiutati. Le priorità sono `HIGHEST`, `HIGH`, `MEDIUM`, `LOW` e `OPTIONAL` e non cambiano l'esito.
- Un controllo personalizzato stampa su stdout **un solo** oggetto JSON ed esce con codice 0: `{"status":"PASS","summary":"Esito leggibile","details":["prova"]}`. Gli stati sono `PASS`, `FAIL`, `WARNING` (mostrato come `WARN`) ed `ERROR`; `details` è facoltativo, stringa o array. Non ripete il proprio ID. I tool integrati restituiscono anche il loro `id`.
- Il tool viene avviato nella propria cartella con l'utente corrente, senza shell né elevazione di privilegi, con un ambiente pulito (`PATH` è `/usr/bin:/bin`, più `~/.local/bin` per i controlli personalizzati), un proprio process group e un output limitato. Al timeout viene terminato l'intero process group, compresi gli helper avviati dallo script. Codice di uscita diverso da zero, JSON non valido o timeout danno `ERROR`, e lo stderr del tool compare nei dettagli. Per come vengono avviati i tool su Windows vedi [Windows](#windows-in-sviluppo).
- **Integrità:** prima di ogni esecuzione lo SHA-256 del tool viene confrontato con `expectedSha256` (per gli integrati: il manifest incorporato nell'agente). Se non coincide il tool **non viene eseguito** e l'esito è `ERROR`. Dopo una modifica voluta, registra il nuovo file con `baradwatchu-agent custom accept CUSTOM-ID` oppure con **Accetta versione attuale** nella dashboard; caricare un nuovo file dalla dashboard fa lo stesso e incrementa `version`. Un controllo scritto a mano senza `expectedSha256` resta bloccato finché non viene accettato. L'hash copre solo il file di ingresso.
- **Isolamento dei guasti:** una cartella personalizzata con configurazione non valida non blocca gli altri controlli. Compare come controllo in `ERROR` con il motivo esatto (per esempio un campo sconosciuto) e si può eliminare da CLI o dashboard. Le cartelle il cui nome non è un ID `CUSTOM-` valido vengono segnalate come ignorate da `refresh` e dalla dashboard.

Le cartelle vengono riscansionate a ogni `list`, audit e richiesta della dashboard; `baradwatchu-agent refresh` o **Riscansiona cartelle** nella dashboard forzano la scansione e segnalano le cartelle non valide.

## Controlli integrati (Arch Linux)

I criteri seguono la baseline delle postazioni in `REQUIREMENTS.md` §5. Le soglie sono parametri nei rispettivi `configuration.json` e si cambiano con `configure` o dalla dashboard. Se le prove mancano o non sono leggibili l'esito è `WARN`, mai `PASS`; ciò che risulta spento è `FAIL`.

| ID | PASS quando |
|---|---|
| REQ-001 | `checkupdates` (pacman-contrib) non trova aggiornamenti nei repository ufficiali (AUR escluso). Viene riportata la data dell'ultimo full upgrade da `pacman.log`. Contatta i mirror Arch; timeout 90 s. |
| REQ-002 | Daemon ClamAV, freshclam e clamonacc attivi, `OnAccessPrevention yes` con almeno un percorso sorvegliato, firme giornaliere vecchie al massimo 3 giorni. |
| REQ-003 | UFW, firewalld o nftables mostrano un filtraggio operativo verificato. Tutti i firewall gestiti esplicitamente inattivi danno `FAIL`; regole non leggibili altrimenti `WARN`. |
| REQ-004 | Almeno un metodo di filtro DNS è completo: dnsmasq attivo **e** abilitato all'avvio con almeno `minimumDnsmasqRules` (1000) regole di blocco, oppure una blocklist [HaGeZi](https://github.com/hagezi/dns-blocklists-legacy) in `/etc/hosts` (vedi [Liste hosts HaGeZi](#liste-hosts-hagezi)). Un `resolv.conf` che non punta a loopback (per esempio con una VPN connessa) viene riportato come osservazione. |
| REQ-005 | Cato o WireGuard connessi. Installato ma disconnesso dà `WARN`; nessuno dei due installato dà `FAIL`. |
| REQ-006 | Almeno un metodo di cifratura attivo: dispositivo LUKS/dm-crypt, eCryptfs montato (i dettagli indicano se copre la home) o container CryFS montato. Non certifica tutte le aree dati. |
| REQ-007 | KDE Plasma 6 Wayland: `Autolock=true`, `Timeout` ≤ `maxTimeoutMinutes` (5), `LockGrace` ≤ `maxLockGraceSeconds` (0, password richiesta subito), blocco alla ripresa attivo. Le altre sessioni sono `NOT_APPLICABLE`. |
| REQ-008 | Età massima della password dell'account ≤ `maxPasswordAgeDays` (60) e non "never"; preavviso ≥ `minimumWarningDays` (10); `PASS_MAX_DAYS` in `/etc/login.defs` entro lo stesso limite; pwquality `minlen` ≥ 14, `minclass` ≥ 4, `ucredit`/`lcredit`/`dcredit`/`ocredit` = -1 (`requireCharacterCredits`), con `pam_pwquality` o `pam_passwdqc` in PAM. |
| REQ-009 | Il firmware riporta Secure Boot attivo e SetupMode disattivato; l'output di `systemd-analyze has-tpm2` viene registrato. |

### Liste hosts HaGeZi

Il metodo del file hosts di REQ-004 (Linux e Windows) accetta solo una lista HaGeZi: un'intestazione che inizia con `# Title: HaGeZi's` e il cui `# Homepage:` è sotto `github.com/hagezi/`. HaGeZi ora pubblica il formato hosts nel [repository legacy](https://github.com/hagezi/dns-blocklists-legacy) (`hosts/*.txt`, anche nelle varianti `*-compressed.txt` con fino a 9 nomi per riga). Si possono concatenare più liste. Il file deve contenere almeno tante righe di blocco (`0.0.0.0` o `::`) quante ne dichiarano le intestazioni in `# Number of entries` (altrimenti la lista è troncata: `FAIL`) e almeno `minimumHostsEntries` (10000) nomi bloccati. Una lista il cui `# Last modified` è più vecchio di `maxListAgeDays` (30, `0` disattiva la verifica) dà `WARN`. Con `requireHagezi: false` è accettata qualsiasi blocklist di dimensione sufficiente. I nomi host non vengono mai riportati. Il controllo funziona offline: non scarica la lista per confrontarne il contenuto.

## Windows (in sviluppo)

I controlli integrati sono script PowerShell in `catalog/checks-windows/REQ-*/check.ps1`, elencati con i loro hash nello stesso `catalog/builtin-tools.sha256` (colonna piattaforma `windows`). Girano con l'utente corrente **senza diritti di amministratore**, quindi usano fonti leggibili da un utente standard (CIM/COM, registro, API Win32 documentate) e, dove possibile, non l'output localizzato dei comandi.

| ID | PASS quando (Windows) |
|---|---|
| REQ-001 | Windows Update (ricerca COM, senza elevazione) non trova aggiornamenti software non installati e non nascosti. Aggiornamenti in sospeso danno `FAIL` con il numero di quelli di sicurezza; una ricerca che non riesce a completarsi dà `WARN`. Può contattare Windows Update; timeout 240 s. |
| REQ-002 | Un antivirus registrato nel Centro sicurezza di Windows è attivo con firme aggiornate. Per Microsoft Defender la protezione in tempo reale deve essere attiva (altrimenti `FAIL`) e le firme vecchie al massimo `maxSignatureAgeDays` (7) giorni (altrimenti `WARN`). Nessun antivirus registrato dà `FAIL`. |
| REQ-003 | Windows Defender Firewall è attivo con traffico in ingresso `Block` su ogni profilo, letto dall'`ActiveStore` effettivo (locale e Criteri di gruppo), oppure è attivo un firewall di terze parti registrato nel Centro sicurezza. |
| REQ-004 | Una lista HaGeZi completa e recente nel file hosts di sistema (vedi sopra). Resolver configurati e criterio `DnsOverHttpsMode` di Chrome/Edge sono riportati come osservazioni. |
| REQ-005 | Cato Client è installato e firmato da Cato Networks, `CatoClientCliAT.exe antitamper status` risponde e una scheda di rete Cato è `Up`. Presente ma non connesso, o che non risponde, dà `WARN`; non installato dà `FAIL`. Quale delle due schede Cato porta il tunnel non è ancora stato verificato su un dispositivo connesso. |
| REQ-006 | BitLocker protegge l'unità di sistema, letto dalla proprietà di Esplora file `System.Volume.BitLockerProtection` (la classe WMI di BitLocker e `manage-bde` richiedono diritti di amministratore). Disattivato, in decifratura o sospeso dà `FAIL`; cifratura in corso, o altre unità fisse non protette o non determinabili, dà `WARN`. |
| REQ-007 | Almeno un metodo blocca la sessione entro `maxTimeoutMinutes` (5): il criterio di limite di inattività del computer, un salvaschermo protetto da password (prevalgono i valori dei criteri) oppure la sospensione con accesso richiesto alla riattivazione per ogni fonte di alimentazione del dispositivo. Un `ScreenSaverGracePeriod` superiore a `maxLockGraceSeconds` (0) rende insufficiente il metodo del salvaschermo. |
| REQ-008 | Criterio password locale letto tramite l'API SAM accessibile agli utenti standard (i dati per cui `secedit` richiede elevazione): età massima impostata e ≤ `maxPasswordAgeDays` (60), lunghezza minima ≥ `minimumLength` (14), complessità attiva (`requireComplexity`; Windows richiede 3 categorie di caratteri su 4), preavviso di scadenza ≥ `minimumWarningDays` (10, predefinito di Windows 5) e nessun account locale attivo con password che non scade mai. Account Microsoft e appartenenza a un dominio danno `WARN` perché li governa un'altra autorità. I nomi degli account non vengono mai riportati. Il PIN di Windows Hello non viene verificato. |
| REQ-009 | Firmware UEFI con Secure Boot attivo (stato registrato da Windows all'avvio) e un TPM 2.0 (TPM Base Services). BIOS legacy, Secure Boot disattivato o assenza di TPM 2.0 danno `FAIL`. |

Come vengono avviati i tool su Windows: gli script `.ps1` tramite Windows PowerShell 5.1 (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File`, con percorso assoluto), i file `.exe` direttamente; gli altri tipi di file danno `ERROR`. Il bypass della execution policy vale solo per quel processo: a decidere che cosa gira è il controllo SHA-256. L'ambiente viene ripulito (`PATH` = System32, Windows, WBEM e la cartella di PowerShell, più le cartelle standard dell'utente), non compare alcuna finestra di console, e il tool con tutti i processi che avvia appartiene a un Job Object che viene terminato al timeout e dopo l'uscita del tool. Gli script che stampano testo non ASCII vanno salvati in UTF-8 con BOM (Windows PowerShell 5.1 legge i file senza BOM nella code page ANSI); quelli integrati lo sono, e `.gitattributes` li mantiene in CRLF così il loro hash è identico a ogni checkout.

Cartelle dati su Windows (quando le variabili XDG non sono impostate): impostazioni e controlli personalizzati `%APPDATA%\baradwatchu\`, eventi e richieste di consenso `%LOCALAPPDATA%\baradwatchu\state\` (file di runtime in `state\run\`), storico degli audit `%LOCALAPPDATA%\baradwatchu\cache\audit\`. Il file di avvio della dashboard viene aperto con Esplora file, che usa il browser predefinito.

## CLI

```sh
baradwatchu-agent list [--json]
baradwatchu-agent refresh
baradwatchu-agent enable|disable ID
baradwatchu-agent priority ID HIGHEST|HIGH|MEDIUM|LOW|OPTIONAL
baradwatchu-agent configure REQ-007 '{"maxTimeoutMinutes":5,"maxLockGraceSeconds":0}'
baradwatchu-agent check ID [--log]
baradwatchu-agent audit [--json] [--notify] [--log]
baradwatchu-agent status [--json]
baradwatchu-agent custom accept CUSTOM-ID
baradwatchu-agent custom remove CUSTOM-ID
baradwatchu-agent dashboard [--no-browser] [--open status|custom|history|notifications]
baradwatchu-agent notifications [--json]
baradwatchu-agent notifications set enabled|informative on|off
baradwatchu-agent events --json [--after ID]
baradwatchu-agent consent simulate [--server ID] [--account NAME] [--account-id ID] [--device NAME] [--ttl SECONDS]
baradwatchu-agent consent list [--json]
baradwatchu-agent consent accept|reject REQUEST-ID
baradwatchu-tray [--version | --help | autostart enable|disable|status]
```

In sviluppo usa `cargo run -p baradwatchu-agent -- …`. Codici di uscita di `audit`/`check`: 0 tutto conforme (o disabilitato/non applicabile), 4 almeno un `WARN`, 3 almeno un `FAIL`, 1 almeno un `ERROR`, 2 errore d'uso. Ogni audit viene salvato in JSON in `~/.cache/baradwatchu/audit/reports/` per `status` e lo storico della dashboard; `--log` scrive anche un `.log` in testo semplice con tool, codici di uscita e diagnostica in `~/.cache/baradwatchu/audit/`. La cartella si può cancellare: si perdono solo lo storico e l'ultimo risultato. Lo storico in `~/.local/state/baradwatchu/audits/` viene spostato lì automaticamente una volta. `list --json` e l'API della dashboard usano nomi di campo camelCase. `custom accept` e `custom remove` funzionano anche se la configurazione della cartella non è valida. I vecchi comandi `workstation`, `policy validate`, `audit --policy`, `audit --format` e `audit --local-config` sono stati rimossi; la CLI li rifiuta prima di leggere qualsiasi dato locale. Ogni audit completato (da CLI, dashboard o tray) aggiunge anche un evento a `~/.local/state/baradwatchu/events.jsonl` (si tengono gli ultimi 200); `events --json` è lo stato compatto che la tray interroga e `notifications` mostra o modifica le preferenze di notifica (`~/.config/baradwatchu/notifications.json`).

## Dashboard e notifiche

`baradwatchu-agent dashboard` serve la dashboard Angular su una porta effimera di `127.0.0.1` e la apre nel browser quando c'è una sessione desktop. Non avvia servizi e non ascolta sulla rete. Il loopback non è considerato un confine di sicurezza: ogni chiamata `/api/` richiede un token casuale di sessione (altrimenti `401`), le richieste che modificano dati devono anche provenire dall'origine della dashboard con corpo JSON, e l'intestazione `Host` deve corrispondere. Il browser riceve il token tramite un file di avvio privato (`$XDG_RUNTIME_DIR/baradwatchu/open-dashboard.html`, permessi 0600), quindi il token non compare mai sulla riga di comando di un processo; la scheda lo conserva in `sessionStorage` e lo toglie dalla barra degli indirizzi. Una seconda chiamata a `dashboard` (per esempio dalla tray) riusa l'istanza attiva registrata in `$XDG_RUNTIME_DIR/baradwatchu/dashboard.json` invece di avviarne un'altra. Usa le stesse impostazioni, lo stesso runner e lo stesso storico della CLI.

- **Stato postazione:** riepilogo dell'ultimo audit (i contatori filtrano l'elenco), filtri per esito, ricerca, requisiti ordinati per gravità dopo un audit, dettagli per requisito, impostazioni, parametri e dettagli tecnici/integrità compressi. Gli audit storici si aprono dal pannello laterale senza modificare lo stato corrente.
- **Controlli personalizzati:** una sezione separata elenca i tuoi controlli con stato d'integrità e ultimo esito, e offre **Controlla ora**, **Accetta versione attuale**, **Carica nuovo file**, **Ripristina** l'integrato (per gli override) ed **Elimina**. Le cartelle non valide compaiono con il loro errore e si possono eliminare. **Nuovo controllo** apre il modulo di importazione: ID (viene proposto il primo `CUSTOM-NNN` libero), nome, descrizione, priorità, timeout, file, argomenti e, nelle opzioni avanzate, copia dei metadati o sostituzione di un integrato. Il file mantiene il suo nome nella nuova cartella. La sezione spiega anche la struttura delle cartelle e il formato dell'output.
- **Notifiche:** preferenze di notifica (notifiche desktop sì/no, informative sì/no), stato della tray, storico locale degli eventi e richieste di consenso. **Simula una richiesta** crea una richiesta di prova locale da 60 secondi; la dashboard non decide mai una richiesta. `#/history` apre la pagina di stato sullo storico degli audit.

Build di sviluppo:

```sh
cd web && npm ci && npm run build && cd ..
cargo run -p baradwatchu-agent -- dashboard
```

Le notifiche native sono inviate dalla tray (vedi sotto), anche quando nessun browser è aperto. Senza tray, `baradwatchu-agent audit --notify` chiede ancora a `notify-send` di mostrare il riepilogo dell'audit; con la tray attiva duplica la notifica della tray. Gli audit dalla dashboard non chiamano più `notify-send`.

Un `PASS` personalizzato è un'affermazione del tool stesso, non una prova di sicurezza indipendente. Il Server non ha ancora un catalogo degli audit né una registrazione autenticata, quindi non verifica questi hash.

## Tray

`baradwatchu-tray` è un piccolo processo separato per la sessione desktop dell'utente. Non esegue audit da solo: avvia l'agente installato accanto a sé con un insieme fisso di sottocomandi (`events --json`, `audit --json`, `dashboard --open …`, `consent accept|reject ID --via window`), senza shell e con timeout. L'agente funziona anche senza tray, e chiudere la tray non arresta l'agente né una dashboard aperta. Gira una sola tray per utente (file di lock `$XDG_RUNTIME_DIR/baradwatchu/tray.lock`); un secondo avvio segnala che è già attiva.

- **Menu:** riga di stato e ultimo audit, Apri dashboard, Esegui audit (disattivato durante l'esecuzione), Visualizza ultimo risultato, Storico audit, Richieste in sospeso, Notifiche recenti, Avvia al login, Informazioni, Chiudi tray.
- **Icona:** verde operativo, blu ardesia nessun audit ancora, ambra `FAIL`/`WARN`, rossa `ERROR` o blocco di integrità, blu richiesta in attesa di decisione, grigia agente non raggiungibile. Il tooltip riporta separatamente conteggi, blocchi di integrità e controlli personalizzati e precisa che l'esito dei controlli locali non è una certificazione di sicurezza.
- **Notifiche:** una per audit, classificata in base all'aspetto più grave (problema di integrità, errore di esecuzione, anomalie, completato). Ogni evento compare una sola volta; al massimo tre per interrogazione, le altre riassunte; un insieme di anomalie identico all'audit precedente conta come informativo. L'agente non raggiungibile viene notificato una volta, dopo due interrogazioni fallite (ogni 5 s), e il ripristino una volta. Preferenze: tutte le notifiche disattivate, oppure solo le informative; le richieste di consenso non si possono silenziare.
- **Richieste di consenso (solo predisposizione):** l'agente modella una richiesta del report della postazione con `requestId`, ID del server, nome e ID dell'account, dispositivo dichiarato, operazione (`AUDIT_REPORT`), scadenza e stato. In questa milestone le richieste si possono solo simulare in locale (`consent simulate`, pulsante della dashboard); non ci sono richieste remote, autenticazione del Server né contratti crittografici. La tray apre una finestra dedicata (zenity, oppure kdialog in alternativa su Linux): **Accetta**, **Rifiuta**, **Decidi più tardi**. Accetta non è mai il pulsante predefinito. Solo un Accetta esplicito autorizza, e solo quella richiesta; rifiuto, chiusura, «decidi più tardi», timeout e una notifica soltanto mostrata non autorizzano nulla, e una richiesta scaduta non si può accettare. Si può decidere anche con `baradwatchu-agent consent accept|reject ID`.
- **Avvio al login:** `baradwatchu-tray autostart enable|disable|status` oppure la casella nel menu. Su Linux scrive `~/.config/autostart/baradwatchu-tray.desktop` (XDG, usato da KDE Plasma); su Windows usa la chiave per utente `HKCU\…\Run`; su macOS un LaunchAgent per utente limitato alla sessione Aqua. Nessun privilegio di amministratore e nessun servizio di sistema.

Librerie: [`tray-icon`](https://github.com/tauri-apps/tray-icon) 0.26 (su Linux il backend `ksni` StatusNotifierItem via D-Bus, quindi non servono librerie GTK/AppIndicator), [`notify-rust`](https://github.com/hoodie/notify-rust) 4.18 (D-Bus freedesktop, toast di Windows, Centro notifiche di macOS) e, solo su Windows/macOS, `tao` 0.37 (ciclo di eventi) e `rfd` 0.18 (finestre di messaggio). Il framework Tauri completo e le WebView non sono usati; la dashboard resta nel browser.

**Stato delle piattaforme.** Linux (Arch, KDE Plasma 6 su Wayland) è compilato e verificato da cima a fondo. Il codice Windows e macOS supera il controllo dei tipi e Clippy (`cargo check`/`cargo clippy --target x86_64-pc-windows-msvc|x86_64-pc-windows-gnu|aarch64-apple-darwin|x86_64-apple-darwin`; per macOS la parte Objective-C di `mac-notification-sys` richiede l'SDK Apple e non è stata compilata). Su Windows 11 girano l'agente, i suoi controlli, la dashboard e la tray (vedi [Windows](#windows-in-sviluppo)); la tray è stata avviata, ha interrogato l'agente, ha rifiutato una seconda istanza e si è chiusa su richiesta, ma menu, notifiche e finestra di consenso non sono ancora stati provati lì. macOS non è mai stato eseguito e **non è supportato**. Su Windows la tray è un programma con sottosistema grafico (nessuna finestra di console); --version, --help e utostart scrivono sul terminale che l'ha avviata o sull'output reindirizzato (in PowerShell usa una pipe, per esempio `baradwatchu-tray --version | Out-String`, così PowerShell ne attende la fine). Si chiude in modo pulito quando riceve un WM_CLOSE sulla sua finestra invisibile «BaradWatchU Tray», ed è così che install.ps1 le chiede di chiudersi. Su Windows/macOS la finestra di consenso non si chiude da sola alla scadenza (un Accetta tardivo viene rifiutato dall'agente).

## Build e installazione

L'installer da sorgente compila come utente normale e usa `sudo` solo per copiare i file in un prefix protetto:

```sh
./install.sh --missing-deps                        # controllo dipendenze in sola lettura
./install.sh --dry-run                             # mostra il piano
./install.sh                                       # compila e installa in /usr/local
./install.sh --build-only --build-dir=DIR          # compila e valida solo la cache
./install.sh --tray-autostart                      # installa e avvia la tray al login
./install.sh --without-tray                        # solo agente e dashboard
./install.sh -U                                    # disinstalla
```

Ogni esecuzione inizia con un riepilogo delle opzioni effettive. Il controllo delle dipendenze elenca:

- **[REQUIRED] strumenti di build** (Rust/Cargo ≥ 1.92 con la tray, ≥ 1.80 con `--without-tray`; strumenti C/C++, make, tar, glibc, Node.js 20 ≥ 20.11.1 selezionato tramite `web/.nvmrc` e nvm se disponibile, npm) e **[REQUIRED] strumenti di runtime** usati da agente e controlli (bash, python3, awk, sed, grep, coreutils). Se ne manca uno l'installer si ferma prima di compilare o modificare file e stampa il comando per installarlo.
- **[optional] strumenti di audit — solo Arch Linux** (`checkupdates`, `systemctl`, `ufw`/`firewalld`/`nftables`, `dnsmasq`, Cato/`wg`, `lsblk`, `findmnt`, `kreadconfig6`, `pgrep`, `chage`, `systemd-analyze`, `notify-send`, `xdg-open`), ciascuno con il controllo che lo usa. Se ne manca uno l'installazione non si blocca; il relativo controllo dà `WARN`. Per le alternative (un firewall, un client VPN) ne basta uno. Sulle altre distribuzioni la sezione viene saltata con una nota, perché i controlli integrati sono pensati per Arch.
- **[optional] tray:** `zenity` o `kdialog` per la finestra di consenso (senza, la tray chiede di decidere con la CLI). La tray richiede anche una sessione desktop con D-Bus e un host StatusNotifierItem (KDE Plasma; GNOME richiede l'estensione AppIndicator).

Con la tray (predefinito) l'installer aggiunge al manifest `bin/baradwatchu-tray` e la voce di menu `share/applications/baradwatchu-tray.desktop`. `--tray-autostart` attiva l'avvio al login per l'utente che lancia l'installer dopo aver installato i file (come quell'utente, mai come root). La disinstallazione rimuove la voce di avvio automatico di quell'utente se punta a questa installazione.

**Istanze in esecuzione:** prima di sostituire o rimuovere file, un `baradwatchu-agent` o `baradwatchu-tray` avviato dalla stessa installazione (riconosciuto dal percorso dell'eseguibile, mai dal nome; per esempio una dashboard aperta) riceve SIGTERM e ha fino a `BARADWATCHU_STOP_TIMEOUT` secondi (predefinito 10) per chiudersi. Non viene mai ucciso: se non si chiude, l'installer si ferma senza modificare nulla. Le istanze di altri utenti vengono solo segnalate. `--dry-run` mostra che cosa verrebbe chiuso.

L'installer mantiene cache di build, reinstallazione e disinstallazione basate sul manifest; impostazioni utente, controlli personalizzati e storico non vengono mai toccati. Non crea servizi di sistema né pacchetti del package manager. `./install.sh --help` elenca tutte le opzioni.

### Windows: install.ps1 e setup.exe

`install.ps1` è l'equivalente Windows di `install.sh`. Installa **per utente, senza diritti di amministratore** e senza servizi. Windows blocca per impostazione predefinita gli script non firmati, quindi va avviato tramite Windows PowerShell con un bypass valido solo per quel processo:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -MissingDeps   # controllo dipendenze in sola lettura
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -DryRun        # mostra il piano
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1                # compila e installa
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -TrayAutostart # installa e avvia la tray all'accesso
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -WithoutTray   # solo agente e dashboard
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall     # disinstalla
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Package       # genera invece setup.exe
```

- **Dipendenze:** [REQUIRED] Rust ≥ 1.92 con toolchain MSVC (≥ 1.80 con `-WithoutTray`), Visual Studio Build Tools con il carico di lavoro C++, Node.js 20 ≥ 20.11.1 e npm; a runtime Windows PowerShell 5.1. [optional] Inno Setup 6 per `-Package` e le fonti dei controlli (modalità FullLanguage di PowerShell, cmdlet di Defender e NetSecurity, Cato Client). Per ogni elemento mancante viene stampato il comando `winget`.
- **Build:** come su Linux, una cache validata fuori dal sorgente (predefinita `%LOCALAPPDATA%\baradwatchu\build\baradwatchu-agent-VERSIONE`, `-BuildDir`, `-BuildOnly`, `-NoBuild`), con la build Angular in una copia privata di `web`, un'impronta dei sorgenti (modifiche durante la build o dopo la build in cache vengono rifiutate), il controllo della versione di entrambi gli eseguibili e la stessa verifica di integrità dei controlli integrati Windows rispetto a `builtin-tools.sha256`.
- **Installazione:** predefinita `%LOCALAPPDATA%\Programs\BaradWatchU` (`-Prefix`), struttura `bin\*.exe` + `share\baradwatchu-client\{catalog,web}`, manifest `share\baradwatchu-source\baradwatchu-agent.manifest` con lo SHA-256 di ogni file. File non gestiti o modificati localmente non vengono mai sovrascritti né rimossi; collegamenti simbolici e junction nel percorso sono rifiutati. Le voci **BaradWatchU Dashboard** e **BaradWatchU Tray** vengono create nel menu Start dell'utente e registrate nel manifest. La disinstallazione rimuove anche la voce `HKCU\…\Run` della tray se punta a questa installazione e le cartelle rimaste vuote.
- **Istanze in esecuzione:** i programmi avviati dalla stessa installazione (riconosciuti dal percorso dell'eseguibile) vengono invitati a chiudersi prima di modificare i file: un helper di breve durata invia una richiesta di chiusura (WM_CLOSE) alla finestra della tray e un Ctrl+C sulla console di agente e dashboard (mai sulla console dell'installer). Hanno fino a `BARADWATCHU_STOP_TIMEOUT` secondi (predefinito 10) e non vengono mai terminati a forza: se uno resta attivo l'installer si ferma senza modificare nulla. Una dashboard avviata dal tuo terminale condivide quella console, quindi anche gli altri programmi collegati a essa ricevono lo stesso Ctrl+C.
- **Setup (`-Package`):** usa la stessa build validata e compila `packaging\windows\baradwatchu-client.iss` con Inno Setup 6 in `BaradWatchU-Client-VERSIONE-setup.exe` (predefinito `BUILDDIR\dist`, `-OutputDir`), stampandone lo SHA-256. Il setup installa per utente in `%LOCALAPPDATA%\Programs\BaradWatchU` senza diritti di amministratore, in italiano o inglese, con voci nel menu Start, un'attività facoltativa «Avvia la tray all'accesso» e il programma di disinstallazione in **Impostazioni › App**; gli aggiornamenti sostituiscono la stessa installazione. Setup e disinstallazione si rifiutano di procedere mentre un programma BaradWatchU di quella cartella è in esecuzione (codice di uscita 7 / 1, nulla modificato) e non lo terminano mai: chiudi prima dashboard e tray. Supporta le opzioni silenziose standard (`/VERYSILENT /SUPPRESSMSGBOXES`, `/DIR=`). `install.ps1` rifiuta una cartella gestita dal setup: usa un solo metodo per cartella. Il setup **non è firmato**: SmartScreen mostra l'avviso di editore sconosciuto finché l'organizzazione non lo firma (per esempio con `signtool`), passaggio che qui non è automatizzato.

## Verifiche di sviluppo

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cd web && npm test && npm run build
```

Su Windows gli stessi comandi funzionano da una shell con la toolchain MSVC (Visual Studio Build Tools, carico di lavoro C++) e Node.js 20; per installare usa `install.ps1` (vedi sopra). I tool di prova sono script shell su Unix e script PowerShell su Windows; i test del runner basati solo su shell e le suite degli script integrati girano solo su Unix. I test puntano ogni directory XDG a cartelle temporanee private e serializzano le modifiche all'ambiente, quindi girano in parallelo e non toccano mai configurazione o storico dello sviluppatore. Gli script dei controlli integrati sono testati con file di fixture e comandi stub (`tests/workstation_criteria.rs`, `tests/req003_firewall.rs`, `tests/req004_005_methods.rs`). La logica della tray (stato dell'icona, politica delle notifiche, contratto dello snapshot) è testata senza GUI in `crates/tray/src/model.rs`.

## Limiti attuali

L'architettura legacy (valutazione delle policy, collector nativi Fedora/Arch, adapter, registro workstation, `policies/`, `scripts/`, `configs/`) è stata rimossa il 2026-11-07; il sorgente contiene solo catalogo a cartelle, runner, CLI e dashboard. Alcuni controlli sono volutamente prudenti e restituiscono `WARN`; la validazione su host reali diversi dalla postazione Arch dello sviluppatore è ancora da fare. Non ci sono scheduler/daemon, comunicazione con il Server, policy remote o richieste di consenso remote, download dinamico dei tool, implementazioni di audit per macOS o remediation automatica. Su Windows ci sono un installer per utente e un setup per utente non firmato, ma ancora nessun servizio, firma del codice o installazione per tutto il computer; i suoi controlli girano senza diritti di amministratore, quindi dettagli di BitLocker, interrogazioni complete di Secure Boot/TPM e dati di `secedit` restano fuori portata, e la scheda Cato che segnala la connessione non è stata verificata su un dispositivo connesso. Le decisioni di consenso sono legate all'utente locale: qualsiasi processo dello stesso utente può chiamare `consent accept`, così come può leggere i file di quell'utente.
