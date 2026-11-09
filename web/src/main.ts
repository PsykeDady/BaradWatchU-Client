import { CommonModule } from '@angular/common';
import { Component, HostListener, OnInit } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { APP_VERSION } from './app-version';

type Priority = 'HIGHEST' | 'HIGH' | 'MEDIUM' | 'LOW' | 'OPTIONAL';
type ResultStatus = 'PASS' | 'FAIL' | 'WARN' | 'ERROR' | 'DISABLED' | 'NOT_APPLICABLE';
type Integrity = 'VERIFIED' | 'MISMATCH' | 'UNKNOWN';
type View = 'overview' | 'custom' | 'notifications' | 'settings';
type StatusFilter = 'ALL' | 'FAIL' | 'WARN' | 'ERROR' | 'PASS' | 'PENDING';
interface Provenance { toolId: string; toolVersion?: number; origin: 'BUILTIN' | 'CUSTOM'; toolPath?: string; expectedSha256?: string; actualSha256?: string; integrityStatus: Integrity; integrityScope: string; isOverride: boolean; overrideBuiltinId?: string; builtinToolPath?: string; builtinExpectedSha256?: string; }
interface Requirement { id: string; name: string; description: string; enabled: boolean; priority: Priority; parameters: Record<string, unknown>; arguments: string[]; timeoutSeconds: number; tools: Record<string, string>; configurationError?: string; origin: 'BUILTIN' | 'CUSTOM'; expectedSha256?: string; actualSha256?: string; integrityStatus: Integrity; replacesBuiltin?: string; customToolId?: string; customToolVersion?: number; }
interface AuditResult { id: string; name: string; priority: Priority; status: ResultStatus; complianceStatus?: ResultStatus; summary: string; details: string[]; completedAtUnixMs: number; provenance?: Provenance; }
interface AuditReport { schemaVersion: string; completedAtUnixMs: number; logFile?: string; results: AuditResult[]; }
interface DashboardData { schemaVersion: string; requirements: Requirement[]; customChecksDir?: string; ignoredFolders?: string[]; }
interface HistoryUsage { audits: number; files: number; bytes: number; }
interface HistoryRemoval { removedAudits: number; removedFiles: number; freedBytes: number; usage: HistoryUsage; }
interface HistoryEntry { completedAtUnixMs: number; overallStatus: ResultStatus; pass: number; fail: number; warn: number; error: number; other: number; }
interface SummaryCounts { pass: number; fail: number; warn: number; error: number; other: number; }
type EventSeverity = 'INFO' | 'WARNING' | 'CRITICAL' | 'ACTION';
type ConsentState = 'PENDING' | 'ACCEPTED' | 'REJECTED' | 'EXPIRED';
interface AppEvent { id: number; atUnixMs: number; kind: string; severity: EventSeverity; title: string; body: string; repeated: boolean; }
interface NotificationPreferences { schemaVersion?: string; enabled: boolean; informative: boolean; }
interface ConsentView { requestId: string; serverId: string; accountName: string; accountId: string; declaredDevice: string; operation: string; source: string; createdAtUnixMs: number; expiresAtUnixMs: number; state: ConsentState; decidedAtUnixMs?: number; decidedVia?: string; effect: string; remainingSeconds: number; }
interface NotificationsView { preferences: NotificationPreferences; events: AppEvent[]; consents: ConsentView[]; trayRunning: boolean | null; }
interface ConfigurationView { version: string; platform: string; installRoot: string; tray: { installed: boolean; running: boolean | null; autostart: boolean | null; error?: string }; paths: { configuration: string; customChecks: string; state: string; history: string; runtime: string }; }

const TOKEN_KEY = 'bwu-session-token';
/** The agent opens the dashboard with ?k=<token>; keep it for this tab only and drop it from the address bar. */
function sessionToken(): string {
  const fromUrl = new URLSearchParams(location.search).get('k');
  if (fromUrl && /^[0-9a-f]{64}$/.test(fromUrl)) {
    try { sessionStorage.setItem(TOKEN_KEY, fromUrl); } catch { /* storage unavailable: keep in memory */ }
    window.history.replaceState(null, '', location.pathname + location.hash);
    return fromUrl;
  }
  try { return sessionStorage.getItem(TOKEN_KEY) ?? ''; } catch { return ''; }
}

const PRIORITIES: Priority[] = ['HIGHEST', 'HIGH', 'MEDIUM', 'LOW', 'OPTIONAL'];
const SEVERITY: Record<string, number> = { ERROR: 0, FAIL: 1, WARN: 2, PENDING: 3, PASS: 4, NOT_APPLICABLE: 5, DISABLED: 6 };

@Component({
  selector: 'bwu-root', standalone: true, imports: [CommonModule],
  template: `
    <main class="shell">
      <header class="topbar">
        <a class="brand" href="#/" (click)="go('overview', $event)" aria-label="BaradWatchU, stato della postazione"><span class="brand-mark" aria-hidden="true">B</span><span><strong>BaradWatchU</strong><small>CLIENT · AUDIT LOCALE</small></span></a>
        <nav class="tabs" role="tablist" aria-label="Sezioni">
          <button type="button" role="tab" class="tab" [class.active]="view === 'overview'" [attr.aria-selected]="view === 'overview'" (click)="go('overview')">Stato postazione</button>
          <button type="button" role="tab" class="tab" [class.active]="view === 'custom'" [attr.aria-selected]="view === 'custom'" (click)="go('custom')">Controlli personalizzati<span class="tab-count" *ngIf="customs.length">{{ customs.length }}</span><span class="tab-alert" *ngIf="customProblems > 0" [attr.aria-label]="customProblems + ' da sistemare'">!</span></button>
          <button type="button" role="tab" class="tab" [class.active]="view === 'notifications'" [attr.aria-selected]="view === 'notifications'" (click)="go('notifications')">Notifiche<span class="tab-alert" *ngIf="pendingConsents > 0" [attr.aria-label]="pendingConsents + ' richieste in sospeso'">{{ pendingConsents }}</span></button>
          <button type="button" role="tab" class="tab" [class.active]="view === 'settings'" [attr.aria-selected]="view === 'settings'" (click)="go('settings')">Impostazioni</button>
        </nav>
        <button class="button primary" type="button" (click)="runAudit()" [disabled]="busy || loading || saving"><span class="play-icon" aria-hidden="true">▶</span>{{ busy ? 'Audit in corso…' : 'Esegui audit' }}</button>
      </header>

      <div class="notices" aria-live="polite">
        <div *ngIf="error" class="notice error" role="alert"><span class="notice-icon">!</span><span>{{ error }}</span><button type="button" class="text-button" (click)="refresh()">Riprova</button><button type="button" class="dismiss" (click)="error = ''" aria-label="Chiudi">×</button></div>
        <div *ngIf="message" class="notice success" role="status"><span class="notice-icon">✓</span><span>{{ message }}</span><button type="button" class="dismiss" (click)="message = ''" aria-label="Chiudi">×</button></div>
      </div>
      <div *ngIf="loading" class="loading-panel" role="status"><span class="spinner"></span>Caricamento dei dati locali…</div>

      <!-- ============================== STATO POSTAZIONE ============================== -->
      <ng-container *ngIf="!loading && view === 'overview'">
        <section class="intro">
          <div><p class="eyebrow">POSTAZIONE · {{ platformLabel() }}</p><h1>Stato della sicurezza</h1><p class="intro-copy">Controlli e risultati restano su questo dispositivo. La dashboard non richiede il Server.</p></div>
        </section>

        <section class="summary-panel" aria-labelledby="summary-title">
          <div class="summary-heading">
            <div><p class="eyebrow">{{ viewingHistory ? 'ESECUZIONE STORICA' : 'ULTIMA ESECUZIONE' }}</p><h2 id="summary-title">{{ visibleReport ? formatDate(visibleReport.completedAtUnixMs) : 'Nessun audit eseguito' }}</h2></div>
            <span class="overall-pill" *ngIf="visibleReport" [attr.data-status]="overallStatus(visibleReport)">{{ statusText(overallStatus(visibleReport)) }}</span>
            <span class="overall-pill empty" *ngIf="!visibleReport">In attesa del primo audit</span>
          </div>
          <div class="summary-bottom">
            <div class="metrics" *ngIf="visibleReport; else emptySummary">
              <button type="button" class="metric pass" (click)="setFilter('PASS')" [class.selected]="filter === 'PASS'"><span class="metric-symbol">✓</span><span><strong>{{ counts.pass }}</strong><small>Conformi</small></span></button>
              <button type="button" class="metric fail" (click)="setFilter('FAIL')" [class.selected]="filter === 'FAIL'"><span class="metric-symbol">×</span><span><strong>{{ counts.fail }}</strong><small>Da correggere</small></span></button>
              <button type="button" class="metric warn" (click)="setFilter('WARN')" [class.selected]="filter === 'WARN'"><span class="metric-symbol">!</span><span><strong>{{ counts.warn }}</strong><small>Da verificare</small></span></button>
              <button type="button" class="metric error" (click)="setFilter('ERROR')" [class.selected]="filter === 'ERROR'"><span class="metric-symbol">⚠</span><span><strong>{{ counts.error }}</strong><small>Errori</small></span></button>
              <div class="metric other"><span class="metric-symbol">·</span><span><strong>{{ counts.other }}</strong><small>Esclusi</small></span></div>
            </div>
            <ng-template #emptySummary><p class="empty-copy">{{ viewingHistory && historyLoading ? 'Caricamento del dettaglio storico…' : 'Premi «Esegui audit» per controllare tutti i requisiti abilitati.' }}</p></ng-template>
            <div class="run-context" *ngIf="viewingHistory"><span>Stai guardando un audit passato.</span><button class="text-button" type="button" (click)="showCurrent()">Torna allo stato corrente</button></div>
          </div>
          <div *ngIf="busy" class="progress-line" role="status"><span></span><span>{{ busyLabel }}</span></div>
        </section>

        <div class="content-grid">
          <section class="requirements-section" aria-labelledby="requirements-title">
            <div class="section-heading">
              <div><p class="eyebrow">CATALOGO</p><h2 id="requirements-title">Requisiti di sicurezza</h2></div>
              <span class="section-count">{{ visibleRequirements.length }} di {{ requirements.length }}</span>
            </div>
            <div class="toolbar">
              <div class="chips" role="group" aria-label="Filtra per esito">
                <button type="button" class="chip" *ngFor="let option of filterOptions" [class.active]="filter === option.value" (click)="setFilter(option.value)">{{ option.label }}</button>
              </div>
              <input class="search" type="search" placeholder="Cerca per nome o ID" [value]="search" (input)="search = inputValue($event)" aria-label="Cerca requisito">
            </div>
            <div *ngIf="requirements.length === 0" class="empty-card">Il catalogo dei requisiti non è disponibile.</div>
            <div *ngIf="requirements.length > 0 && visibleRequirements.length === 0" class="empty-card">Nessun requisito corrisponde ai filtri. <button class="text-button" type="button" (click)="setFilter('ALL'); search = ''">Mostra tutti</button></div>

            <article class="requirement-card" *ngFor="let item of visibleRequirements; trackBy: trackById" [class.disabled]="!item.enabled" [attr.data-status]="statusOf(item)">
              <div class="requirement-head">
                <span class="status-dot" [attr.data-status]="statusOf(item)" aria-hidden="true"></span>
                <div class="requirement-title">
                  <div class="tags"><span class="requirement-id">{{ item.id }}</span><span class="priority" [attr.data-priority]="item.priority">{{ priorityText(item.priority) }}</span><span class="tag custom" *ngIf="item.origin === 'CUSTOM' && !item.replacesBuiltin">Personalizzato</span><span class="tag override" *ngIf="item.replacesBuiltin">Sostituito da {{ item.customToolId }}</span><span class="tag danger" *ngIf="item.configurationError">Configurazione non valida</span><span class="tag danger" *ngIf="!item.configurationError && item.integrityStatus === 'MISMATCH'">Tool modificato</span><span class="tag muted" *ngIf="!item.enabled">Disabilitato</span></div>
                  <h3>{{ item.name }}</h3>
                </div>
                <span *ngIf="resultFor(item.id) as result" class="status-badge" [attr.data-status]="result.status">{{ statusLabel(result.status) }}</span>
                <span *ngIf="!resultFor(item.id)" class="status-badge pending">Non verificato</span>
              </div>
              <p class="result-summary" *ngIf="resultFor(item.id) as result">{{ result.summary }}</p>
              <p class="result-summary error-text" *ngIf="!resultFor(item.id) && item.configurationError">{{ item.configurationError }}</p>
              <details class="requirement-details">
                <summary><span>Dettagli e impostazioni</span><span class="chevron" aria-hidden="true">⌄</span></summary>
                <div class="detail-content">
                  <p class="description">{{ item.description }}</p>
                  <div *ngIf="resultFor(item.id) as result" class="result-detail-block">
                    <h4>Esito del {{ formatDate(result.completedAtUnixMs) }}</h4>
                    <ul *ngIf="result.details.length" class="evidence"><li *ngFor="let detail of result.details">{{ detail }}</li></ul>
                  </div>
                  <p *ngIf="!resultFor(item.id)" class="no-result">{{ viewingHistory && historyLoading ? 'Caricamento del risultato storico…' : 'Nessun risultato per questo requisito nell’esecuzione mostrata.' }}</p>
                  <p *ngIf="viewingHistory" class="history-config-note">Le impostazioni qui sotto sono quelle attuali, non una copia storica.</p>
                  <div class="settings-row">
                    <label class="toggle"><input type="checkbox" [checked]="item.enabled" [disabled]="busy || saving || viewingHistory" (change)="setEnabled(item, $event)"><span>{{ item.enabled ? 'Abilitato' : 'Disabilitato' }}</span></label>
                    <label class="priority-label">Priorità<select [value]="item.priority" [disabled]="saving || viewingHistory" (change)="setPriority(item, $event)"><option *ngFor="let p of priorities" [value]="p">{{ priorityText(p) }}</option></select></label>
                    <button *ngIf="!viewingHistory" class="button secondary" type="button" [disabled]="busy || saving || !item.enabled" (click)="check(item)">Controlla ora</button>
                    <button *ngIf="item.origin === 'CUSTOM'" class="text-button" type="button" (click)="go('custom')">Gestisci controllo personalizzato →</button>
                  </div>
                  <details class="technical">
                    <summary>Parametri avanzati</summary>
                    <p class="hint">Oggetto JSON passato al tool su stdin come <code>{{ '{"requirementId":…,"parameters":{…}}' }}</code>.</p>
                    <textarea rows="5" spellcheck="false" [value]="parameterText[item.id]" [disabled]="viewingHistory" (input)="editParameters(item, $event)" [attr.aria-label]="'Parametri JSON per ' + item.name"></textarea>
                    <button class="button secondary small" type="button" [disabled]="saving || viewingHistory" (click)="saveParameters(item)">Salva parametri</button>
                  </details>
                  <details class="technical">
                    <summary>Dettagli tecnici e integrità</summary>
                    <dl class="facts">
                      <dt>Origine</dt><dd>{{ item.origin === 'BUILTIN' ? 'Integrato' : 'Personalizzato' }}<span *ngIf="item.replacesBuiltin"> · sostituisce {{ item.replacesBuiltin }}</span></dd>
                      <dt>Tool</dt><dd><code>{{ toolPath(item) || 'non disponibile' }}</code></dd>
                      <dt>Argomenti</dt><dd><code>{{ item.arguments | json }}</code></dd>
                      <dt>Timeout</dt><dd>{{ item.timeoutSeconds }} s</dd>
                      <dt>Integrità</dt><dd><span class="integrity" [attr.data-integrity]="item.integrityStatus">{{ integrityText(item.integrityStatus) }}</span></dd>
                      <dt>SHA-256 atteso</dt><dd><code>{{ item.expectedSha256 || 'non disponibile' }}</code></dd>
                      <dt>SHA-256 attuale</dt><dd><code>{{ item.actualSha256 || 'non disponibile' }}</code></dd>
                      <ng-container *ngIf="resultFor(item.id)?.provenance as provenance">
                        <dt>Eseguito</dt><dd>{{ provenance.toolId }}<span *ngIf="provenance.toolVersion"> v{{ provenance.toolVersion }}</span> · integrità al momento dell’esecuzione: {{ integrityText(provenance.integrityStatus) }}</dd>
                      </ng-container>
                      <ng-container *ngIf="resultFor(item.id) && !resultFor(item.id)?.provenance"><dt>Provenienza</dt><dd class="integrity-warning">Report legacy: provenienza e hash non disponibili.</dd></ng-container>
                    </dl>
                  </details>
                </div>
              </details>
            </article>
          </section>

          <aside class="history-section" aria-labelledby="history-title">
            <div class="section-heading"><div><p class="eyebrow">ARCHIVIO LOCALE</p><h2 id="history-title">Storico audit</h2></div><span class="section-count">{{ history.length }}</span></div>
            <div class="history-card">
              <div class="history-tools" *ngIf="historyUsage">
                <span class="history-usage">{{ historyUsage.audits }} audit · {{ formatBytes(historyUsage.bytes) }} su disco</span>
                <button class="button danger small" type="button" [disabled]="busy || saving || historyUsage.files === 0" (click)="clearHistory()">Svuota cronologia</button>
              </div>
              <div *ngIf="historyLoading" class="history-loading"><span class="spinner small"></span>Caricamento storico…</div>
              <p *ngIf="!historyLoading && history.length === 0" class="history-empty">Gli audit completati appariranno qui.</p>
              <div *ngFor="let entry of history" class="history-row">
              <button type="button" class="history-item" [class.selected]="selectedHistoryStamp === entry.completedAtUnixMs" (click)="showHistory(entry)" [attr.aria-current]="selectedHistoryStamp === entry.completedAtUnixMs ? 'true' : null">
                <span class="history-item-top"><span class="history-status" [attr.data-status]="entry.overallStatus">{{ statusLabel(entry.overallStatus) }}</span><span class="history-time">{{ formatDate(entry.completedAtUnixMs) }}</span></span>
                <span class="history-counts"><span class="mini-count pass">{{ entry.pass }} ok</span><span class="mini-count fail" *ngIf="entry.fail">{{ entry.fail }} da correggere</span><span class="mini-count warn" *ngIf="entry.warn">{{ entry.warn }} da verificare</span><span class="mini-count error" *ngIf="entry.error">{{ entry.error }} errori</span></span>
              </button>
              <button type="button" class="history-delete" [disabled]="busy || saving" (click)="deleteHistory(entry)" [attr.aria-label]="'Elimina l’audit del ' + formatDate(entry.completedAtUnixMs)" title="Elimina questo audit (report, log e PDF)">✕</button>
              </div>
              <p *ngIf="history.length >= 50" class="history-limit">Sono mostrate le 50 esecuzioni più recenti.</p>
            </div>
          </aside>
        </div>
      </ng-container>

      <!-- ============================ CONTROLLI PERSONALIZZATI ============================ -->
      <ng-container *ngIf="!loading && view === 'custom'">
        <section class="intro">
          <div><p class="eyebrow">ESTENSIONI LOCALI</p><h1>Controlli personalizzati</h1><p class="intro-copy">Script o eseguibili tuoi, eseguiti con i privilegi del tuo utente insieme ai controlli integrati.</p></div>
          <div class="intro-actions">
            <button class="button secondary" type="button" (click)="forceRefreshChecks()" [disabled]="busy || saving">Riscansiona cartelle</button>
            <button class="button primary" type="button" (click)="openForm()" [disabled]="showForm">+ Nuovo controllo</button>
          </div>
        </section>

        <section class="form-panel" *ngIf="showForm" aria-labelledby="form-title">
          <div class="form-head"><h2 id="form-title">Nuovo controllo personalizzato</h2><button type="button" class="dismiss" (click)="closeForm()" aria-label="Chiudi il modulo">×</button></div>
          <p class="warning-box"><strong>Attenzione:</strong> il file è codice eseguibile e verrà avviato con i privilegi del tuo utente a ogni audit. Importa solo tool di cui ti fidi.</p>
          <div class="form-grid">
            <label>ID<input [value]="form.id" (input)="form.id = upper($event)" placeholder="CUSTOM-001" [class.invalid]="form.id && !validId(form.id)" aria-describedby="id-help"><small id="id-help">CUSTOM- seguito da lettere maiuscole, cifre o trattini. Diventa il nome della cartella.</small></label>
            <label>Nome<input [value]="form.name" (input)="form.name = inputValue($event)" placeholder="Es. Password reminder installato"></label>
            <label class="wide">Descrizione<textarea rows="2" [value]="form.description" (input)="form.description = inputValue($event)" placeholder="Che cosa verifica e perché"></textarea></label>
            <label>Priorità<select [value]="form.priority" (change)="form.priority = $any(inputValue($event))"><option *ngFor="let p of priorities" [value]="p">{{ priorityText(p) }}</option></select></label>
            <label>Timeout (secondi)<input type="number" min="1" max="300" [value]="form.timeout" (input)="form.timeout = inputValue($event)"><small>Da 1 a 300; predefinito 20.</small></label>
            <label class="wide file-drop">File del tool<input type="file" (change)="selectImportFile($event)"><small>{{ importFile ? importFile.name + ' · ' + formatSize(importFile.size) : 'Script con shebang (es. #!/bin/bash) o eseguibile, massimo 1 MiB.' }}</small></label>
            <label class="wide">Argomenti (array JSON)<input spellcheck="false" [value]="form.arguments" (input)="form.arguments = inputValue($event)" placeholder='["--verbose"]'><small>Passati direttamente al tool, senza shell.</small></label>
            <details class="wide advanced-form"><summary>Opzioni avanzate</summary>
              <div class="form-grid inner">
                <label>Copia nome e descrizione da<select [value]="form.cloneFrom" (change)="form.cloneFrom = inputValue($event); cloneMetadata()"><option value="">Nessuno</option><option *ngFor="let item of requirements" [value]="item.id">{{ item.id }} · {{ item.name }}</option></select></label>
                <label>Sostituisci un controllo integrato<select [value]="form.overrideBuiltinId" (change)="form.overrideBuiltinId = inputValue($event)"><option value="">Nessuna sostituzione</option><option *ngFor="let item of overridableBuiltins" [value]="item.id">{{ item.id }} · {{ item.name }}</option></select><small>L’integrato resta disponibile e si ripristina in un clic.</small></label>
              </div>
            </details>
          </div>
          <div class="form-actions"><button class="button secondary" type="button" (click)="closeForm()">Annulla</button><button class="button primary" type="button" [disabled]="saving || busy || !canImport" (click)="importCustom()">{{ saving ? 'Importazione…' : 'Importa controllo' }}</button></div>
        </section>

        <div class="custom-layout">
          <section aria-labelledby="custom-list-title">
            <div class="section-heading"><div><p class="eyebrow">INSTALLATI</p><h2 id="custom-list-title">I tuoi controlli</h2></div><span class="section-count">{{ customs.length }}</span></div>
            <div *ngIf="ignoredFolders.length" class="notice warn"><span class="notice-icon">!</span><span>Cartelle ignorate perché il nome non è un ID valido (CUSTOM-…): {{ ignoredFolders.join(', ') }}.</span></div>
            <div *ngIf="customs.length === 0" class="empty-card column">
              <strong>Nessun controllo personalizzato.</strong>
              <span>Creane uno con «Nuovo controllo», oppure crea a mano una cartella in <code>{{ customChecksDir || '~/.config/baradwatchu/custom-checks' }}</code> e premi «Riscansiona cartelle».</span>
            </div>
            <article class="custom-card" *ngFor="let item of customs; trackBy: trackById" [class.broken]="!!item.configurationError" [class.mismatch]="!item.configurationError && item.integrityStatus !== 'VERIFIED'">
              <div class="custom-head">
                <div>
                  <div class="tags"><span class="requirement-id">{{ item.customToolId || item.id }}</span><span class="priority" [attr.data-priority]="item.priority">{{ priorityText(item.priority) }}</span><span class="tag" *ngIf="item.customToolVersion">v{{ item.customToolVersion }}</span><span class="tag override" *ngIf="item.replacesBuiltin">Sostituisce {{ item.replacesBuiltin }}</span><span class="tag muted" *ngIf="!item.enabled">Disabilitato</span></div>
                  <h3>{{ item.name }}</h3>
                </div>
                <span *ngIf="resultFor(item.id) as result" class="status-badge" [attr.data-status]="result.status">{{ statusLabel(result.status) }}</span>
              </div>
              <div *ngIf="item.configurationError" class="problem"><strong>Configurazione non valida.</strong> {{ item.configurationError }}</div>
              <div *ngIf="!item.configurationError && item.integrityStatus === 'MISMATCH'" class="problem"><strong>Il file del tool è cambiato</strong> rispetto all’hash registrato: non verrà eseguito finché non accetti la nuova versione o carichi un file.</div>
              <div *ngIf="!item.configurationError && item.integrityStatus === 'UNKNOWN'" class="problem"><strong>Tool non leggibile.</strong> Controlla che il file indicato in toolPath esista.</div>
              <p class="result-summary" *ngIf="resultFor(item.id) as result">{{ result.summary }}</p>
              <p class="description" *ngIf="!item.configurationError">{{ item.description }}</p>
              <dl class="facts compact" *ngIf="!item.configurationError">
                <dt>Tool</dt><dd><code>{{ toolPath(item) }}</code></dd>
                <dt>Integrità</dt><dd><span class="integrity" [attr.data-integrity]="item.integrityStatus">{{ integrityText(item.integrityStatus) }}</span></dd>
                <dt>SHA-256</dt><dd><code>{{ item.expectedSha256 }}</code></dd>
              </dl>
              <div class="custom-actions">
                <button class="button secondary small" type="button" *ngIf="!item.configurationError" [disabled]="busy || saving || !item.enabled || item.integrityStatus !== 'VERIFIED'" (click)="check(item)">Controlla ora</button>
                <button class="button secondary small" type="button" *ngIf="canAccept(item)" [disabled]="saving" (click)="acceptCustom(item)">Accetta versione attuale</button>
                <label class="button secondary small file-button" *ngIf="!item.configurationError">Carica nuovo file<input type="file" (change)="updateCustom(item, $event)" [disabled]="saving"></label>
                <button class="button secondary small" type="button" *ngIf="item.replacesBuiltin" [disabled]="saving" (click)="restoreBuiltin(item)">Ripristina {{ item.replacesBuiltin }}</button>
                <span class="spacer"></span>
                <button class="button danger small" type="button" [disabled]="saving" (click)="removeCustom(item)">Elimina</button>
              </div>
            </article>
          </section>

          <aside class="guide" aria-labelledby="guide-title">
            <h2 id="guide-title">Come funzionano</h2>
            <ol>
              <li>Ogni controllo è una cartella con il suo <code>configuration.json</code> e il tool:<pre>{{ guideTree }}</pre></li>
              <li>Il tool stampa su stdout <strong>un solo</strong> oggetto JSON ed esce con codice 0:<pre>{{ guideOutput }}</pre>Stati: <code>PASS</code>, <code>FAIL</code>, <code>WARNING</code>, <code>ERROR</code>. <code>details</code> è opzionale (stringa o array).</li>
              <li>L’hash SHA-256 del tool è registrato in <code>expectedSha256</code>. Se modifichi il file a mano il controllo si blocca: premi «Accetta versione attuale» oppure usa <code>baradwatchu-agent custom accept ID</code>.</li>
              <li>Il tool parte nella propria cartella, senza shell, con timeout (<code>timeoutSeconds</code>, predefinito 20 s); <code>~/.local/bin</code> è nel PATH. Lo stderr compare nei dettagli in caso di errore.</li>
            </ol>
            <p class="hint">Cartella: <code>{{ customChecksDir || '~/.config/baradwatchu/custom-checks' }}</code></p>
          </aside>
        </div>
      </ng-container>

      <!-- ================================== NOTIFICHE ================================== -->
      <ng-container *ngIf="!loading && view === 'notifications'">
        <section class="intro">
          <div><p class="eyebrow">TRAY E NOTIFICHE DESKTOP</p><h1>Notifiche</h1><p class="intro-copy">Le notifiche native sono inviate da BaradWatchU Tray, anche a dashboard chiusa. L’agente registra gli eventi qui sotto.</p></div>
          <div class="intro-actions"><button class="button secondary" type="button" (click)="loadNotifications()" [disabled]="saving">Aggiorna</button></div>
        </section>
        <div class="custom-layout">
          <section aria-labelledby="events-title">
            <div class="form-panel">
              <div class="form-head"><h2>Preferenze</h2><span class="tag" [class.muted]="notifications?.trayRunning !== true">{{ trayText }}</span></div>
              <div class="settings-row" *ngIf="notifications as data">
                <label class="toggle"><input type="checkbox" [checked]="data.preferences.enabled" [disabled]="saving" (change)="setPreference('enabled', $event)"><span>Notifiche desktop su audit, errori e integrità</span></label>
                <label class="toggle"><input type="checkbox" [checked]="data.preferences.informative" [disabled]="saving || !data.preferences.enabled" (change)="setPreference('informative', $event)"><span>Anche quelle informative (audit senza anomalie, anomalie ripetute, esiti del consenso)</span></label>
              </div>
              <p class="hint">Le richieste di consenso aprono sempre la finestra dedicata della tray e non si possono silenziare.</p>
            </div>
            <div class="section-heading"><div><p class="eyebrow">STORICO LOCALE</p><h2 id="events-title">Eventi recenti</h2></div><span class="section-count">{{ notifications?.events?.length ?? 0 }}</span></div>
            <div *ngIf="!notifications?.events?.length" class="empty-card">Nessun evento: gli audit completati e le richieste di consenso appariranno qui.</div>
            <article class="custom-card" *ngFor="let event of notifications?.events ?? []" [attr.data-severity]="event.severity">
              <div class="custom-head"><div><div class="tags"><span class="tag" [class.danger]="event.severity === 'CRITICAL'" [class.override]="event.severity === 'ACTION'">{{ severityText(event.severity) }}</span><span class="tag muted" *ngIf="event.repeated">Ripetuto</span></div><h3>{{ event.title }}</h3></div><span class="history-time">{{ formatDate(event.atUnixMs) }}</span></div>
              <p class="result-summary">{{ event.body }}</p>
            </article>
          </section>
          <aside class="guide" aria-labelledby="consent-title">
            <h2 id="consent-title">Richieste di consenso</h2>
            <p class="hint">In futuro il Server potrà chiedere il report di questa postazione. Ogni richiesta vale una sola volta: solo «Accetta» nella finestra della tray autorizza; rifiuto, chiusura o scadenza non autorizzano nulla. La dashboard non decide.</p>
            <button class="button secondary small" type="button" (click)="simulateConsent()" [disabled]="saving">Simula una richiesta (60 s)</button>
            <p *ngIf="!notifications?.consents?.length" class="history-empty">Nessuna richiesta.</p>
            <dl class="facts compact" *ngFor="let consent of notifications?.consents ?? []">
              <dt>Stato</dt><dd><strong>{{ consentText(consent.state) }}</strong><span *ngIf="consent.state === 'PENDING'"> · scade tra {{ consent.remainingSeconds }} s</span><span *ngIf="consent.source === 'LOCAL_SIMULATION'"> · simulata</span></dd>
              <dt>Server</dt><dd>{{ consent.serverId }}</dd>
              <dt>Account</dt><dd>{{ consent.accountName }} ({{ consent.accountId }})</dd>
              <dt>Dispositivo</dt><dd>{{ consent.declaredDevice }}</dd>
              <dt>Esito</dt><dd>{{ consent.effect }}</dd>
              <dt>ID</dt><dd><code>{{ consent.requestId }}</code></dd>
            </dl>
          </aside>
        </div>
      </ng-container>

      <!-- ============================== IMPOSTAZIONI ============================== -->
      <ng-container *ngIf="!loading && view === 'settings'">
        <section class="intro">
          <div><p class="eyebrow">CONFIGURAZIONE LOCALE</p><h1>Impostazioni</h1><p class="intro-copy">Impostazioni di questa postazione. Soglie e priorità dei singoli controlli si cambiano da «Dettagli e impostazioni» in Stato postazione.</p></div>
          <div class="intro-actions"><button class="button secondary" type="button" (click)="loadConfiguration()" [disabled]="saving">Aggiorna</button></div>
        </section>
        <div *ngIf="!configuration" class="empty-card">Impostazioni non disponibili: premi «Aggiorna».</div>
        <div class="custom-layout" *ngIf="configuration as config">
          <section aria-labelledby="startup-title">
            <div class="form-panel">
              <div class="form-head"><h2 id="startup-title">Tray e avvio</h2><span class="tag" [class.muted]="config.tray.running !== true">{{ configTrayText }}</span></div>
              <div class="settings-row">
                <label class="toggle"><input type="checkbox" [checked]="config.tray.autostart === true" [disabled]="saving || !config.tray.installed || config.tray.autostart === null" (change)="setAutostart($event)"><span>Avvia BaradWatchU Tray all’accesso</span></label>
              </div>
              <p class="hint" *ngIf="!config.tray.installed">BaradWatchU Tray non è installata accanto all’agente (installazione senza tray).</p>
              <p class="hint" *ngIf="config.tray.error">Stato non leggibile: {{ config.tray.error }}</p>
              <p class="hint">È la stessa impostazione della voce «Avvia al login» nel menu della tray. Gli installer la attivano alla prima installazione e poi rispettano la tua scelta. Riguarda solo il tuo utente e non richiede privilegi di amministratore.</p>
            </div>
            <div class="form-panel">
              <div class="form-head"><h2>Notifiche desktop</h2></div>
              <p class="hint">Le preferenze delle notifiche e le richieste di consenso sono nella sezione <a href="#/notifiche" (click)="go('notifications', $event)">Notifiche</a>.</p>
            </div>
            <div class="section-heading"><div><p class="eyebrow">DATI LOCALI</p><h2 id="paths-title">Cartelle dei dati</h2></div></div>
            <dl class="facts" aria-labelledby="paths-title">
              <dt>Impostazioni</dt><dd><code>{{ config.paths.configuration }}</code></dd>
              <dt>Controlli personalizzati</dt><dd><code>{{ config.paths.customChecks }}</code></dd>
              <dt>Eventi e consenso</dt><dd><code>{{ config.paths.state }}</code></dd>
              <dt>Storico audit</dt><dd><code>{{ config.paths.history }}</code><br><span class="hint">Si può svuotare dalla sezione «Storico audit» (un audit alla volta o tutto) oppure con «baradwatchu-agent history clear --yes»: si perdono solo lo storico e l’ultimo risultato.</span></dd>
              <dt>File di sessione</dt><dd><code>{{ config.paths.runtime }}</code></dd>
            </dl>
          </section>
          <aside class="guide" aria-labelledby="about-title">
            <h2 id="about-title">Informazioni</h2>
            <dl class="facts compact">
              <dt>Versione</dt><dd>{{ config.version }}</dd>
              <dt>Sistema</dt><dd>{{ platformName(config.platform) }}</dd>
              <dt>Installazione</dt><dd><code>{{ config.installRoot }}</code></dd>
            </dl>
            <p class="hint">La disinstallazione non cancella le cartelle dei dati: impostazioni, controlli personalizzati e storico restano finché non le elimini tu.</p>
          </aside>
        </div>
      </ng-container>

      <footer><span>BaradWatchU Client {{ version }}</span><span>I dati di audit restano sul dispositivo.</span><button class="text-button" type="button" (click)="refresh()" [disabled]="busy || saving">Aggiorna dati</button></footer>
    </main>
  `,
  styleUrl: './styles.css'
})
class AppComponent implements OnInit {
  readonly version = APP_VERSION;
  readonly priorities = PRIORITIES;
  readonly filterOptions: { value: StatusFilter; label: string }[] = [
    { value: 'ALL', label: 'Tutti' }, { value: 'FAIL', label: 'Da correggere' }, { value: 'WARN', label: 'Da verificare' },
    { value: 'ERROR', label: 'Errori' }, { value: 'PASS', label: 'Conformi' }, { value: 'PENDING', label: 'Non verificati' }
  ];
  readonly guideTree = 'custom-checks/\n└── CUSTOM-001/\n    ├── configuration.json\n    └── CUSTOM-001.sh';
  readonly guideOutput = '{"status":"PASS",\n "summary":"Esito leggibile",\n "details":["prova raccolta"]}';
  view: View = 'overview';
  requirements: Requirement[] = [];
  customChecksDir = '';
  ignoredFolders: string[] = [];
  currentReport: AuditReport | null = null;
  history: HistoryEntry[] = [];
  historyUsage: HistoryUsage | null = null;
  selectedHistoryStamp: number | null = null;
  historicalReport: AuditReport | null = null;
  parameterText: Record<string, string> = {};
  filter: StatusFilter = 'ALL';
  search = '';
  loading = true;
  historyLoading = false;
  busy = false;
  busyLabel = '';
  saving = false;
  error = '';
  message = '';
  showForm = false;
  form = this.emptyForm();
  importFile: File | null = null;
  notifications: NotificationsView | null = null;
  configuration: ConfigurationView | null = null;
  private readonly token = sessionToken();
  private messageTimer: ReturnType<typeof setTimeout> | undefined;

  get viewingHistory(): boolean { return this.selectedHistoryStamp !== null; }
  get visibleReport(): AuditReport | null { return this.viewingHistory ? this.historicalReport : this.currentReport; }
  get counts(): SummaryCounts { return this.visibleReport ? this.countsFor(this.visibleReport) : { pass: 0, fail: 0, warn: 0, error: 0, other: 0 }; }
  get customs(): Requirement[] { return this.requirements.filter(item => item.origin === 'CUSTOM'); }
  get pendingConsents(): number { return this.notifications?.consents.filter(item => item.state === 'PENDING').length ?? 0; }
  get trayText(): string { const running = this.notifications?.trayRunning; return running === true ? 'Tray attiva' : running === false ? 'Tray non attiva' : 'Stato tray non rilevabile'; }
  get customProblems(): number { return this.customs.filter(item => item.configurationError || item.integrityStatus !== 'VERIFIED').length; }
  get overridableBuiltins(): Requirement[] { return this.requirements.filter(item => item.origin === 'BUILTIN'); }
  get canImport(): boolean { return !!this.importFile && this.validId(this.form.id) && this.form.name.trim().length > 0; }
  get visibleRequirements(): Requirement[] {
    const term = this.search.trim().toLowerCase();
    return this.requirements.filter(item => {
      if (term && !`${item.id} ${item.name}`.toLowerCase().includes(term)) return false;
      if (this.filter === 'ALL') return true;
      const status = this.statusOf(item);
      return status === this.filter;
    }).sort((a, b) => this.visibleReport ? (SEVERITY[this.statusOf(a)] ?? 9) - (SEVERITY[this.statusOf(b)] ?? 9) : 0);
  }

  ngOnInit(): void { this.view = this.viewFromHash(); void this.refresh().then(() => this.scrollToHistory()); }
  @HostListener('window:hashchange') onHashChange(): void { this.view = this.viewFromHash(); this.scrollToHistory(); }

  go(view: View, event?: Event): void {
    event?.preventDefault();
    this.view = view;
    const hash = view === 'custom' ? '#/custom' : view === 'notifications' ? '#/notifiche' : view === 'settings' ? '#/impostazioni' : '#/';
    if (view === 'settings') void this.loadConfiguration().catch(error => { this.error = `Impostazioni: ${this.errorText(error)}`; });
    if (location.hash !== hash) window.history.replaceState(null, '', hash);
    window.scrollTo({ top: 0 });
  }

  async refresh(): Promise<void> {
    this.loading = true;
    this.error = '';
    if (!this.token) { this.error = 'Sessione mancante: apri la dashboard dalla tray oppure con «baradwatchu-agent dashboard».'; this.loading = false; return; }
    const outcomes = await Promise.allSettled([
      this.request<DashboardData>('/api/requirements'),
      this.request<AuditReport | null>('/api/status'),
      this.loadHistory(),
      this.loadNotifications(),
      this.view === 'settings' ? this.loadConfiguration() : Promise.resolve()
    ]);
    const errors: string[] = [];
    if (outcomes[0].status === 'fulfilled') this.setData(outcomes[0].value);
    else errors.push(`Requisiti: ${this.errorText(outcomes[0].reason)}`);
    if (outcomes[1].status === 'fulfilled') this.currentReport = outcomes[1].value;
    else errors.push(`Ultimo risultato: ${this.errorText(outcomes[1].reason)}`);
    if (outcomes[2].status === 'rejected') errors.push(`Storico: ${this.errorText(outcomes[2].reason)}`);
    if (outcomes[3].status === 'rejected') errors.push(`Notifiche: ${this.errorText(outcomes[3].reason)}`);
    if (outcomes[4].status === 'rejected') errors.push(`Impostazioni: ${this.errorText(outcomes[4].reason)}`);
    this.error = errors.join(' · ');
    this.loading = false;
  }

  async forceRefreshChecks(): Promise<void> {
    await this.mutate(() => this.post<DashboardData>('/api/refresh'), data => `Scansione completata: ${data.requirements.length} controlli, di cui ${data.requirements.filter(r => r.origin === 'CUSTOM').length} personalizzati.`);
  }

  setFilter(filter: StatusFilter): void { this.filter = this.filter === filter && filter !== 'ALL' ? 'ALL' : filter; }

  async setEnabled(item: Requirement, event: Event): Promise<void> {
    item.enabled = (event.target as HTMLInputElement).checked;
    await this.saveSettings(`${item.name}: ${item.enabled ? 'abilitato' : 'disabilitato'}`);
  }

  async setPriority(item: Requirement, event: Event): Promise<void> {
    item.priority = (event.target as HTMLSelectElement).value as Priority;
    await this.saveSettings(`Priorità di ${item.name} aggiornata`);
  }

  editParameters(item: Requirement, event: Event): void { this.parameterText[item.id] = (event.target as HTMLTextAreaElement).value; }

  async saveParameters(item: Requirement): Promise<void> {
    try {
      const value: unknown = JSON.parse(this.parameterText[item.id] ?? '{}');
      if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('I parametri devono essere un oggetto JSON.');
      item.parameters = value as Record<string, unknown>;
      await this.saveSettings(`Parametri di ${item.name} salvati`);
    } catch (error: unknown) { this.error = this.errorText(error); }
  }

  async check(item: Requirement): Promise<void> {
    await this.runWithProgress(`Controllo di ${item.name} in corso…`, async () => {
      this.currentReport = await this.post<AuditReport>(`/api/check/${encodeURIComponent(item.id)}`);
      this.showCurrent();
      await this.loadHistory();
      this.flash(`Controllo di ${item.name} completato.`);
    });
  }

  async runAudit(): Promise<void> {
    await this.runWithProgress('Controllo dei requisiti in corso. Può richiedere alcuni minuti (REQ-001 interroga il servizio di aggiornamento del sistema).', async () => {
      this.currentReport = await this.post<AuditReport>('/api/audit');
      this.showCurrent();
      await this.loadHistory();
      this.flash('Audit completato e salvato nello storico locale.');
    });
  }

  async showHistory(entry: HistoryEntry): Promise<void> {
    this.historyLoading = true; this.error = '';
    this.selectedHistoryStamp = entry.completedAtUnixMs;
    this.historicalReport = null;
    try {
      this.historicalReport = await this.request<AuditReport>(`/api/history/${entry.completedAtUnixMs}`);
    } catch (error: unknown) {
      this.error = `Impossibile aprire l’audit storico: ${this.errorText(error)}`;
      this.selectedHistoryStamp = null;
    } finally { this.historyLoading = false; }
  }

  async deleteHistory(entry: HistoryEntry): Promise<void> {
    if (!window.confirm(`Eliminare l’audit del ${this.formatDate(entry.completedAtUnixMs)}?\n\nVerranno cancellati il report, il log e l’eventuale PDF. L’operazione non si può annullare.`)) return;
    await this.removeHistory(`/api/history/${entry.completedAtUnixMs}`, entry.completedAtUnixMs);
  }

  async clearHistory(): Promise<void> {
    const usage = this.historyUsage;
    if (!usage || !window.confirm(`Svuotare tutta la cronologia?\n\nVerranno cancellati ${usage.audits} audit (${this.formatBytes(usage.bytes)}): report, log e PDF, compreso l’ultimo risultato. L’operazione non si può annullare.`)) return;
    await this.removeHistory('/api/history', null);
  }

  formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KiB', 'MiB', 'GiB']; let value = bytes / 1024; let unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
    return `${value.toLocaleString('it-IT', { maximumFractionDigits: 1 })} ${units[unit]}`;
  }

  private async removeHistory(path: string, stamp: number | null): Promise<void> {
    this.saving = true; this.error = '';
    try {
      const removal = await this.request<HistoryRemoval>(path, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (stamp === null || this.selectedHistoryStamp === stamp) this.showCurrent();
      this.historyUsage = removal.usage;
      this.currentReport = await this.request<AuditReport | null>('/api/status');
      await this.loadHistory();
      this.flash(`Eliminati ${removal.removedAudits} audit, liberati ${this.formatBytes(removal.freedBytes)}.`);
    } catch (error: unknown) { this.error = this.errorText(error); await this.loadHistory().catch(() => undefined); }
    finally { this.saving = false; }
  }

  showCurrent(): void { this.selectedHistoryStamp = null; this.historicalReport = null; }
  resultFor(id: string): AuditResult | undefined { return this.visibleReport?.results.find(result => result.id === id); }
  statusOf(item: Requirement): string { return this.resultFor(item.id)?.status ?? 'PENDING'; }
  trackById(_: number, item: Requirement): string { return item.id; }
  overallStatus(report: AuditReport): ResultStatus {
    const counts = this.countsFor(report);
    if (counts.error > 0) return 'ERROR';
    if (counts.fail > 0) return 'FAIL';
    if (counts.warn > 0 || report.results.length === 0) return 'WARN';
    return 'PASS';
  }
  statusLabel(status: ResultStatus): string {
    const labels: Record<ResultStatus, string> = { PASS: 'Conforme', FAIL: 'Da correggere', WARN: 'Da verificare', ERROR: 'Errore', DISABLED: 'Disabilitato', NOT_APPLICABLE: 'Non applicabile' };
    return labels[status];
  }
  statusText(status: ResultStatus): string {
    const labels: Record<ResultStatus, string> = { PASS: 'Postazione conforme', FAIL: 'Interventi necessari', WARN: 'Da verificare', ERROR: 'Alcuni controlli in errore', DISABLED: 'Disabilitato', NOT_APPLICABLE: 'Non applicabile' };
    return labels[status];
  }
  integrityText(status: Integrity): string { return { VERIFIED: 'Verificata', MISMATCH: 'Hash diverso: tool modificato', UNKNOWN: 'Non verificabile' }[status]; }
  priorityText(priority: Priority): string {
    const labels: Record<Priority, string> = { HIGHEST: 'Massima', HIGH: 'Alta', MEDIUM: 'Media', LOW: 'Bassa', OPTIONAL: 'Facoltativa' };
    return labels[priority];
  }
  canAccept(item: Requirement): boolean {
    return item.integrityStatus === 'MISMATCH' || (!!item.configurationError && item.configurationError.includes('expectedSha256 mancante'));
  }
  validId(id: string): boolean { return /^CUSTOM-[A-Z0-9-]{1,57}$/.test(id); }
  inputValue(event: Event): string { return (event.target as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value; }
  upper(event: Event): string { return this.inputValue(event).toUpperCase(); }
  formatSize(bytes: number): string { return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`; }
  selectImportFile(event: Event): void { this.importFile = (event.target as HTMLInputElement).files?.[0] ?? null; }

  openForm(): void { this.form = this.emptyForm(); this.form.id = this.nextCustomId(); this.importFile = null; this.showForm = true; }
  closeForm(): void { this.showForm = false; this.importFile = null; }
  cloneMetadata(): void {
    const item = this.requirements.find(value => value.id === this.form.cloneFrom);
    if (item) { this.form.name = item.name; this.form.description = item.description; this.form.priority = item.priority; }
  }

  async importCustom(): Promise<void> {
    const file = this.importFile;
    if (!file) return;
    let parsedArguments: unknown;
    try { parsedArguments = JSON.parse(this.form.arguments || '[]'); } catch { parsedArguments = null; }
    if (!Array.isArray(parsedArguments) || parsedArguments.some(value => typeof value !== 'string')) { this.error = 'Gli argomenti devono essere un array JSON di stringhe, es. ["--verbose"].'; return; }
    const timeout = this.form.timeout.trim() === '' ? undefined : Number(this.form.timeout);
    if (timeout !== undefined && (!Number.isInteger(timeout) || timeout < 1 || timeout > 300)) { this.error = 'Il timeout deve essere un intero tra 1 e 300 secondi.'; return; }
    if (!window.confirm(`Importare ${file.name} come ${this.form.id}?\n\nIl file verrà eseguito con i privilegi del tuo utente a ogni audit.`)) return;
    const body = { id: this.form.id, name: this.form.name, description: this.form.description, priority: this.form.priority, enabled: true, cloneFrom: this.form.cloneFrom || undefined, overrideBuiltinId: this.form.overrideBuiltinId || undefined, fileName: file.name, fileBase64: await this.fileBase64(file).catch((error: unknown) => { this.error = this.errorText(error); return ''; }), arguments: parsedArguments, timeoutSeconds: timeout };
    if (!body.fileBase64) return;
    const id = this.form.id;
    const ok = await this.mutate(() => this.post<DashboardData>('/api/custom-checks', body), () => `Controllo ${id} importato: hash SHA-256 registrato. Premi «Controlla ora» per provarlo.`);
    if (ok) this.closeForm();
  }
  async updateCustom(item: Requirement, event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file || !item.customToolId) return;
    if (!window.confirm(`Sostituire il tool di ${item.customToolId} con ${file.name}?\n\nVerrà registrato il nuovo hash SHA-256 e la versione salirà di uno.`)) return;
    const base64 = await this.fileBase64(file).catch((error: unknown) => { this.error = this.errorText(error); return ''; });
    if (!base64) return;
    await this.mutate(() => this.post<DashboardData>(`/api/custom-checks/update/${encodeURIComponent(item.customToolId!)}`, { fileBase64: base64 }), () => `Tool di ${item.customToolId} aggiornato.`);
  }
  async acceptCustom(item: Requirement): Promise<void> {
    const id = item.customToolId ?? item.id;
    if (!window.confirm(`Accettare il file attuale di ${id} come versione fidata?\n\nFallo solo se hai modificato tu il tool.`)) return;
    await this.mutate(() => this.post<DashboardData>(`/api/custom-checks/accept/${encodeURIComponent(id)}`), () => `Nuovo hash di ${id} registrato.`);
  }
  async restoreBuiltin(item: Requirement): Promise<void> {
    const builtin = item.replacesBuiltin;
    if (!builtin) return;
    await this.mutate(() => this.post<DashboardData>(`/api/custom-checks/restore/${encodeURIComponent(builtin)}`), () => `${builtin} usa di nuovo il controllo integrato; ${item.customToolId} resta come controllo separato.`);
  }
  async removeCustom(item: Requirement): Promise<void> {
    const id = item.customToolId ?? item.id;
    const extra = item.replacesBuiltin ? `\n${item.replacesBuiltin} tornerà a usare il controllo integrato.` : '';
    if (!window.confirm(`Eliminare definitivamente ${id}?\n\nVerrà cancellata la cartella con configuration.json e il tool.${extra}`)) return;
    await this.mutate(() => this.request<DashboardData>(`/api/custom-checks/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: '{}' }), () => `Controllo ${id} eliminato.`);
  }

  async loadConfiguration(): Promise<void> { this.configuration = await this.request<ConfigurationView>('/api/configuration'); }
  get configTrayText(): string { const tray = this.configuration?.tray; if (!tray) return ''; if (!tray.installed) return 'Tray non installata'; return tray.running === true ? 'Tray attiva' : tray.running === false ? 'Tray non attiva' : 'Stato tray non rilevabile'; }
  platformName(platform: string): string { return platform === 'windows' ? 'Windows' : platform === 'linux' ? 'Linux' : platform === 'macos' ? 'macOS' : platform; }
  async setAutostart(event: Event): Promise<void> {
    const enabled = (event.target as HTMLInputElement).checked;
    this.saving = true;
    try {
      this.configuration = await this.request<ConfigurationView>('/api/configuration/autostart', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) });
      this.flash(enabled ? 'Avvio automatico della tray attivato.' : 'Avvio automatico della tray disattivato.');
    } catch (error: unknown) { this.error = this.errorText(error); await this.loadConfiguration().catch(() => undefined); }
    finally { this.saving = false; }
  }
  async loadNotifications(): Promise<void> { this.notifications = await this.request<NotificationsView>('/api/notifications'); }
  async setPreference(key: 'enabled' | 'informative', event: Event): Promise<void> {
    if (!this.notifications) return;
    const preferences = { ...this.notifications.preferences, [key]: (event.target as HTMLInputElement).checked };
    this.saving = true; this.error = '';
    try {
      this.notifications = await this.request<NotificationsView>('/api/notifications', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(preferences) });
      this.flash('Preferenze di notifica salvate.');
    } catch (error: unknown) { this.error = this.errorText(error); await this.loadNotifications().catch(() => undefined); }
    finally { this.saving = false; }
  }
  async simulateConsent(): Promise<void> {
    this.saving = true; this.error = '';
    try {
      this.notifications = await this.post<NotificationsView>('/api/consent/simulate', { ttlSeconds: 60 });
      this.flash(this.notifications.trayRunning === true ? 'Richiesta simulata creata: la tray aprirà la finestra di consenso.' : 'Richiesta simulata creata. Avvia BaradWatchU Tray per decidere, oppure usa baradwatchu-agent consent accept|reject ID.');
    } catch (error: unknown) { this.error = this.errorText(error); }
    finally { this.saving = false; }
  }
  severityText(severity: EventSeverity): string { return { INFO: 'Informativa', WARNING: 'Attenzione', CRITICAL: 'Critica', ACTION: 'Richiede decisione' }[severity]; }
  consentText(state: ConsentState): string { return { PENDING: 'In attesa', ACCEPTED: 'Accettata', REJECTED: 'Rifiutata', EXPIRED: 'Scaduta (non autorizzata)' }[state]; }

  formatDate(timestamp: number): string {
    if (!Number.isFinite(timestamp)) return 'Data non disponibile';
    return new Intl.DateTimeFormat('it-IT', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(timestamp));
  }

  private emptyForm() { return { id: '', name: '', description: '', priority: 'MEDIUM' as Priority, timeout: '', arguments: '[]', cloneFrom: '', overrideBuiltinId: '' }; }
  private nextCustomId(): string {
    const used = this.customs.map(item => /^CUSTOM-(\d+)$/.exec(item.customToolId ?? item.id)?.[1]).filter((n): n is string => !!n).map(Number);
    return `CUSTOM-${String((used.length ? Math.max(...used) : 0) + 1).padStart(3, '0')}`;
  }
  private viewFromHash(): View { return location.hash.startsWith('#/custom') ? 'custom' : location.hash.startsWith('#/notifiche') ? 'notifications' : location.hash.startsWith('#/impostazioni') ? 'settings' : 'overview'; }
  private scrollToHistory(): void {
    if (location.hash.startsWith('#/history')) setTimeout(() => document.getElementById('history-title')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
  }
  private flash(message: string): void {
    this.message = message;
    clearTimeout(this.messageTimer);
    this.messageTimer = setTimeout(() => { if (this.message === message) this.message = ''; }, 6000);
  }
  private async runWithProgress(label: string, task: () => Promise<void>): Promise<void> {
    this.busy = true; this.busyLabel = label; this.error = ''; this.message = '';
    try { await task(); } catch (error: unknown) { this.error = this.errorText(error); }
    finally { this.busy = false; }
  }
  private async mutate(call: () => Promise<DashboardData>, success: (data: DashboardData) => string): Promise<boolean> {
    this.saving = true; this.error = '';
    try { const data = await call(); this.setData(data); this.flash(success(data)); return true; }
    catch (error: unknown) { this.error = this.errorText(error); return false; }
    finally { this.saving = false; }
  }
  private async fileBase64(file: File): Promise<string> {
    if (file.size < 1 || file.size > 1024 * 1024) throw new Error('Il tool deve avere dimensione compresa tra 1 byte e 1 MiB.');
    const bytes = new Uint8Array(await file.arrayBuffer()); let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
  }
  private countsFor(report: AuditReport): SummaryCounts {
    const counts: SummaryCounts = { pass: 0, fail: 0, warn: 0, error: 0, other: 0 };
    for (const result of report.results) {
      if (result.status === 'PASS') counts.pass += 1;
      else if (result.status === 'FAIL') counts.fail += 1;
      else if (result.status === 'WARN') counts.warn += 1;
      else if (result.status === 'ERROR') counts.error += 1;
      else counts.other += 1;
    }
    return counts;
  }
  /** Tool path for this OS: the agent lists only the running platform's tool. */
  toolPath(item: Requirement): string {
    return Object.values(item.tools ?? {})[0] ?? '';
  }
  /** Operating system of the audited device, from the platform key of the built-in tools. */
  platformLabel(): string {
    const keys = new Set(this.requirements.flatMap(item => Object.keys(item.tools ?? {})));
    if (keys.has('windows')) return 'WINDOWS';
    if (keys.has('macos')) return 'MACOS';
    if (keys.has('linux')) return 'LINUX';
    return 'LOCALE';
  }
  private setData(data: DashboardData): void {
    this.requirements = data.requirements.map(item => ({ ...item, parameters: item.parameters ?? {}, arguments: item.arguments ?? [] }));
    this.customChecksDir = data.customChecksDir ?? '';
    this.ignoredFolders = data.ignoredFolders ?? [];
    this.parameterText = Object.fromEntries(this.requirements.map(item => [item.id, JSON.stringify(item.parameters, null, 2)]));
  }
  private async loadHistory(): Promise<void> {
    this.historyLoading = true;
    try {
      const [history, usage] = await Promise.all([this.request<HistoryEntry[]>('/api/history'), this.request<HistoryUsage>('/api/history/usage')]);
      this.history = history; this.historyUsage = usage;
    }
    finally { this.historyLoading = false; }
  }
  private async saveSettings(message: string): Promise<void> {
    const settings = { schema_version: 'baradwatchu.settings.v1', requirements: Object.fromEntries(this.requirements.map(item => [item.id, { enabled: item.enabled, priority: item.priority, parameters: item.parameters }])) };
    const ok = await this.mutate(() => this.request<DashboardData>('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings) }), () => message);
    if (!ok) await this.refresh();
  }
  private post<T>(path: string, body: unknown = {}): Promise<T> {
    return this.request<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  }
  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const headers = new Headers(options?.headers);
    headers.set('X-BaradWatchU-Token', this.token);
    const response = await fetch(path, { ...options, headers, cache: 'no-store' });
    if (response.status === 401) throw new Error('Sessione non valida o scaduta: riapri la dashboard dalla tray oppure con «baradwatchu-agent dashboard».');
    const body: unknown = await response.json();
    if (!response.ok) {
      const detail = typeof body === 'object' && body !== null && 'error' in body ? String(body.error) : `Richiesta non riuscita (${response.status})`;
      throw new Error(detail);
    }
    return body as T;
  }
  private errorText(error: unknown): string {
    if (error instanceof TypeError) return 'L’agente locale non risponde. Riavvia la dashboard con: baradwatchu-agent dashboard';
    return error instanceof Error ? error.message : 'Impossibile comunicare con BaradWatchU.';
  }
}

bootstrapApplication(AppComponent).catch((error: unknown) => console.error(error));
