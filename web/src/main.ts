import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { APP_VERSION } from './app-version';

type Priority = 'HIGHEST' | 'HIGH' | 'MEDIUM' | 'LOW' | 'OPTIONAL';
type ResultStatus = 'PASS' | 'FAIL' | 'WARN' | 'ERROR' | 'DISABLED' | 'NOT_APPLICABLE';
interface Provenance { toolId: string; toolVersion?: number; origin: 'BUILTIN' | 'CUSTOM'; toolPath?: string; expectedSha256?: string; actualSha256?: string; integrityStatus: 'VERIFIED' | 'MISMATCH' | 'UNKNOWN'; integrityScope: string; isOverride: boolean; overrideBuiltinId?: string; builtinToolPath?: string; builtinExpectedSha256?: string; }
interface Requirement { id: string; name: string; description: string; enabled: boolean; priority: Priority; parameters: Record<string, unknown>; arguments: string[]; tools: Record<string, string>; origin: 'BUILTIN' | 'CUSTOM'; expectedSha256?: string; actualSha256?: string; integrityStatus: 'VERIFIED' | 'MISMATCH' | 'UNKNOWN'; replacesBuiltin?: string; customToolId?: string; customToolVersion?: number; }
interface AuditResult { id: string; name: string; priority: Priority; status: ResultStatus; complianceStatus?: ResultStatus; summary: string; details: string[]; completedAtUnixMs: number; provenance?: Provenance; }
interface AuditReport { schemaVersion: string; completedAtUnixMs: number; logFile?: string; results: AuditResult[]; }
interface DashboardData { schemaVersion: string; requirements: Requirement[]; }
interface HistoryEntry { completedAtUnixMs: number; overallStatus: ResultStatus; pass: number; fail: number; warn: number; error: number; other: number; }
interface SummaryCounts { pass: number; fail: number; warn: number; error: number; other: number; }

@Component({
  selector: 'bwu-root', standalone: true, imports: [CommonModule],
  template: `
    <main class="shell">
      <header class="topbar">
        <a class="brand" href="/" aria-label="BaradWatchU, pagina iniziale"><span class="brand-mark" aria-hidden="true">B</span><span><strong>BaradWatchU</strong><small>CLIENT · AUDIT LOCALE</small></span></a>
        <div class="header-actions"><span class="local-badge"><span></span> Solo su questo dispositivo</span><button class="button primary" type="button" (click)="runAudit()" [disabled]="busy || loading || saving"><span class="play-icon" aria-hidden="true">▶</span>{{ busy ? 'Audit in corso…' : 'Esegui audit' }}</button></div>
      </header>

      <section class="intro">
        <div><p class="eyebrow">POSTAZIONE · ARCH LINUX</p><h1>Stato della sicurezza</h1><p class="intro-copy">Controlli e risultati restano in locale. La dashboard non richiede il Server.</p></div>
        <div class="last-run" *ngIf="currentReport; else noRun"><span class="last-run-dot"></span><span>Ultima esecuzione<strong>{{ formatDate(currentReport.completedAtUnixMs) }}</strong></span></div>
        <ng-template #noRun><div class="last-run muted"><span class="last-run-dot"></span><span>Nessun audit eseguito<strong>Avvia un audit per iniziare</strong></span></div></ng-template>
      </section>

      <div *ngIf="loading" class="loading-panel" role="status"><span class="spinner"></span>Caricamento dei dati locali…</div>
      <div *ngIf="error" class="notice error" role="alert"><span class="notice-icon">!</span><span>{{ error }}</span><button type="button" class="text-button" (click)="refresh()">Riprova</button></div>
      <div *ngIf="message" class="notice success" role="status"><span class="notice-icon">✓</span><span>{{ message }}</span><button type="button" class="dismiss" (click)="message = ''" aria-label="Chiudi">×</button></div>

      <ng-container *ngIf="!loading">
        <section class="summary-panel" aria-labelledby="summary-title">
          <div class="summary-heading"><div><p class="eyebrow">{{ viewingHistory ? 'ESECUZIONE SELEZIONATA' : 'ULTIMA ESECUZIONE' }}</p><h2 id="summary-title">{{ viewingHistory ? 'Risultato storico' : 'Riepilogo audit' }}</h2></div><span class="overall-pill" *ngIf="visibleReport" [attr.data-status]="overallStatus(visibleReport)">{{ statusText(overallStatus(visibleReport)) }}</span><span class="overall-pill empty" *ngIf="!visibleReport">In attesa del primo audit</span></div>
          <div class="summary-bottom">
            <div class="metrics" *ngIf="visibleReport; else emptySummary">
              <div class="metric pass"><span class="metric-symbol">✓</span><span><strong>{{ counts.pass }}</strong><small>Conformi</small></span></div>
              <div class="metric fail"><span class="metric-symbol">×</span><span><strong>{{ counts.fail }}</strong><small>Da correggere</small></span></div>
              <div class="metric warn"><span class="metric-symbol">!</span><span><strong>{{ counts.warn }}</strong><small>Da verificare</small></span></div>
              <div class="metric other"><span class="metric-symbol">·</span><span><strong>{{ counts.error + counts.other }}</strong><small>Errori o esclusi</small></span></div>
            </div>
            <ng-template #emptySummary><p class="empty-copy">{{ viewingHistory && historyLoading ? 'Caricamento del dettaglio storico…' : 'Esegui il primo audit per vedere il riepilogo dei requisiti.' }}</p></ng-template>
            <div class="run-context" *ngIf="visibleReport"><span>{{ formatDate(visibleReport.completedAtUnixMs) }}</span><button *ngIf="viewingHistory" class="text-button" type="button" (click)="showCurrent()">Torna allo stato corrente</button><span *ngIf="!viewingHistory">Esiti del controllo locale</span></div>
          </div>
          <div *ngIf="busy" class="progress-line" role="status"><span></span><span>Controllo dei requisiti in corso. Può richiedere alcuni istanti.</span></div>
        </section>

        <div class="content-grid">
          <section class="requirements-section" aria-labelledby="requirements-title">
            <div class="section-heading"><div><p class="eyebrow">CATALOGO</p><h2 id="requirements-title">Requisiti di sicurezza</h2></div><span class="section-count">{{ requirements.length }} requisiti</span></div>
            <section class="history-card custom-manager" aria-labelledby="custom-title">
              <h3 id="custom-title">Controlli personalizzati</h3>
              <p class="history-intro">Importa uno script o eseguibile locale. Il tool verrà eseguito come codice con i privilegi del tuo utente. Importa solo file di cui ti fidi.</p>
              <p class="history-intro custom-contract">Lo script deve stampare su stdout un solo JSON, senza ID: <code>{{ '{"status":"PASS","summary":"Esito","details":["Metodo usato"]}' }}</code>. Stati ammessi: PASS, FAIL, WARNING, ERROR. Il campo details può essere una stringa o un array; non aggiungere messaggi di debug su stdout.</p>
              <div class="custom-form">
                <label>ID custom<input [value]="customId" (input)="customId = inputValue($event)" placeholder="CUSTOM-001"></label>
                <label>Nome<input [value]="customName" (input)="customName = inputValue($event)" placeholder="Controllo personalizzato"></label>
                <label>Clona metadati<select [value]="cloneFrom" (change)="cloneFrom = inputValue($event); cloneMetadata()"><option value="">Nessuno</option><option *ngFor="let item of requirements" [value]="item.id">{{ item.id }} · {{ item.name }}</option></select></label>
                <label>Sostituisci builtin<select [value]="overrideBuiltinId" (change)="overrideBuiltinId = inputValue($event)"><option value="">Nessun override</option><option *ngFor="let item of builtins" [value]="item.id">{{ item.id }} · {{ item.name }}</option></select></label>
                <label class="custom-description">Descrizione<textarea rows="2" [value]="customDescription" (input)="customDescription = inputValue($event)"></textarea></label>
                <label>Priorità<select [value]="customPriority" (change)="selectCustomPriority($event)"><option value="HIGHEST">Massima</option><option value="HIGH">Alta</option><option value="MEDIUM">Media</option><option value="LOW">Bassa</option><option value="OPTIONAL">Facoltativa</option></select></label>
                <label>Tool locale<input type="file" (change)="selectImportFile($event)"></label>
                <label>Argomenti JSON<textarea rows="2" spellcheck="false" [value]="customArguments" (input)="customArguments = inputValue($event)" aria-label="Argomenti del tool come array JSON"></textarea></label>
                <button class="button primary" type="button" [disabled]="saving || busy || !importFile" (click)="importCustom()">Importa controllo</button>
              </div>
              <div *ngFor="let item of requirements" class="custom-existing" [class.is-override]="!!item.replacesBuiltin" [hidden]="item.origin === 'BUILTIN' && !item.replacesBuiltin">
                <div><strong>{{ item.customToolId }} · {{ item.name }}</strong><span>CUSTOM v{{ item.customToolVersion || 1 }}<span *ngIf="item.replacesBuiltin"> · OVERRIDE di {{ item.replacesBuiltin }}</span> · integrità <strong [class.integrity-warning]="item.integrityStatus !== 'VERIFIED'">{{ item.integrityStatus }}</strong></span><code>atteso {{ item.expectedSha256 || 'UNKNOWN' }}</code><code>attuale {{ item.actualSha256 || 'UNKNOWN' }}</code><code>{{ item.tools['linux'] }}</code></div>
                <label class="update-tool">Aggiorna versione<input type="file" (change)="updateCustom(item, $event)"></label>
                <button *ngIf="item.replacesBuiltin" class="button secondary" type="button" [disabled]="saving" (click)="restoreBuiltin(item.id)">Ripristina builtin</button>
                <button class="text-button" type="button" [disabled]="saving" (click)="removeCustom(item)">Rimuovi custom</button>
              </div>
            </section>
            <div *ngIf="requirements.length === 0" class="empty-card">Il catalogo dei requisiti non è disponibile.</div>
            <article class="requirement-card" *ngFor="let item of requirements">
              <div class="requirement-head">
                <span class="status-dot" [attr.data-status]="resultFor(item.id)?.status || 'UNKNOWN'" aria-hidden="true"></span>
                <div class="requirement-title"><div><span class="requirement-id">{{ item.id }}</span><span class="priority" [attr.data-priority]="item.priority">{{ priorityText(item.priority) }}</span></div><h3>{{ item.name }}</h3></div>
                <span *ngIf="resultFor(item.id) as result" class="status-badge" [attr.data-status]="result.status">{{ statusText(result.status) }}</span>
                <span *ngIf="!resultFor(item.id)" class="status-badge pending">Non verificato</span>
              </div>
              <p class="result-summary" *ngIf="resultFor(item.id) as result">{{ result.summary }}</p>
              <details class="requirement-details">
                <summary><span>Dettagli e impostazioni</span><span class="chevron" aria-hidden="true">⌄</span></summary>
                <div class="detail-content">
                  <p class="description">{{ item.description }}</p>
                  <div class="result-detail-block control-origin"><h4>Controllo attivo · {{ item.origin }}<span *ngIf="item.replacesBuiltin"> · OVERRIDE</span></h4><p *ngFor="let tool of toolEntries(item)"><code>{{ tool[0] }}: {{ tool[1] }}</code></p><p>Argomenti diretti: <code>{{ item.arguments | json }}</code></p><p>Integrità corrente: <strong>{{ item.integrityStatus }}</strong></p><p>SHA-256 atteso: <code>{{ item.expectedSha256 || 'non disponibile' }}</code></p><p>SHA-256 corrente: <code>{{ item.actualSha256 || 'UNKNOWN' }}</code></p><p *ngIf="item.replacesBuiltin">Sostituisce il controllo integrato {{ item.replacesBuiltin }}.</p></div>
                  <div *ngIf="resultFor(item.id) as result" class="result-detail-block"><h4>Motivazione</h4><p>{{ result.summary }}</p><div *ngIf="result.details.length"><h4>Dettagli diagnostici</h4><ul><li *ngFor="let detail of result.details">{{ detail }}</li></ul></div><small>Risultato rilevato il {{ formatDate(result.completedAtUnixMs) }}</small></div>
                  <div *ngIf="resultFor(item.id)?.provenance as provenance" class="result-detail-block"><h4>Provenienza · {{ provenance.origin }}<span *ngIf="provenance.isOverride"> · OVERRIDE</span></h4><p>Tool {{ provenance.toolId }}<span *ngIf="provenance.toolVersion"> v{{ provenance.toolVersion }}</span> · conformità {{ resultFor(item.id)?.complianceStatus || resultFor(item.id)?.status }}</p><p>Stato integrità: <strong [class.integrity-warning]="provenance.integrityStatus !== 'VERIFIED'">{{ provenance.integrityStatus }}</strong> · ambito: {{ provenance.integrityScope }}</p><p>Percorso usato: <code>{{ provenance.toolPath || 'non disponibile' }}</code></p><p>SHA-256 atteso: <code>{{ provenance.expectedSha256 || 'UNKNOWN' }}</code></p><p>SHA-256 rilevato: <code>{{ provenance.actualSha256 || 'UNKNOWN' }}</code></p><div *ngIf="provenance.isOverride"><p>Sostituisce builtin {{ provenance.overrideBuiltinId }}: <code>{{ provenance.builtinToolPath || 'non disponibile' }}</code></p><p>Hash builtin atteso: <code>{{ provenance.builtinExpectedSha256 || 'UNKNOWN' }}</code></p></div></div>
                  <p *ngIf="resultFor(item.id) && !resultFor(item.id)?.provenance" class="integrity-warning">Report legacy: provenienza e hash non disponibili; l'integrità non è verificabile.</p>
                  <p *ngIf="!resultFor(item.id)" class="no-result">{{ viewingHistory && historyLoading ? 'Caricamento del risultato storico…' : 'Questo requisito non compare nell’esecuzione selezionata.' }}</p>
                  <p *ngIf="viewingHistory" class="history-config-note">Le impostazioni mostrate sotto sono quelle locali attuali, non una copia storica.</p>
                  <div class="settings-row">
                    <label class="toggle"><input type="checkbox" [checked]="item.enabled" [disabled]="busy || saving || viewingHistory" (change)="setEnabled(item, $event)"><span>{{ item.enabled ? 'Requisito abilitato' : 'Requisito disabilitato' }}</span></label>
                    <label class="priority-label">Priorità<select [value]="item.priority" [disabled]="saving || viewingHistory" (change)="setPriority(item, $event)"><option value="HIGHEST">Massima</option><option value="HIGH">Alta</option><option value="MEDIUM">Media</option><option value="LOW">Bassa</option><option value="OPTIONAL">Facoltativa</option></select></label>
                    <button *ngIf="!viewingHistory" class="button secondary" type="button" [disabled]="busy || saving || !item.enabled" (click)="check(item)">Controlla ora</button>
                  </div>
                  <details class="parameters"><summary>Parametri avanzati</summary><textarea rows="4" spellcheck="false" [value]="parameterText[item.id]" [disabled]="viewingHistory" (input)="editParameters(item, $event)" [attr.aria-label]="'Parametri JSON per ' + item.name"></textarea><button class="text-button" type="button" [disabled]="saving || viewingHistory" (click)="saveParameters(item)">Salva parametri</button></details>
                </div>
              </details>
            </article>
          </section>

          <aside class="history-section" aria-labelledby="history-title">
            <div class="section-heading"><div><p class="eyebrow">ARCHIVIO LOCALE</p><h2 id="history-title">Storico audit</h2></div><span class="section-count">{{ history.length }}</span></div>
            <div class="history-card">
              <p class="history-intro">Le esecuzioni precedenti non modificano lo stato corrente.</p>
              <div *ngIf="historyLoading" class="history-loading"><span class="spinner small"></span>Caricamento storico…</div>
              <p *ngIf="!historyLoading && history.length === 0" class="history-empty">Gli audit completati appariranno qui.</p>
              <button *ngFor="let entry of history" type="button" class="history-item" [class.selected]="selectedHistoryStamp === entry.completedAtUnixMs" (click)="showHistory(entry)" [attr.aria-current]="selectedHistoryStamp === entry.completedAtUnixMs ? 'true' : null">
                <span class="history-item-top"><span class="history-status" [attr.data-status]="entry.overallStatus">{{ statusText(entry.overallStatus) }}</span><span class="history-time">{{ formatDate(entry.completedAtUnixMs) }}</span></span>
                <span class="history-counts"><span class="mini-count pass">{{ entry.pass }} PASS</span><span class="mini-count fail">{{ entry.fail }} FAIL</span><span class="mini-count warn">{{ entry.warn }} WARN</span></span>
              </button>
              <p *ngIf="history.length >= 50" class="history-limit">Sono mostrate le 50 esecuzioni più recenti.</p>
            </div>
          </aside>
        </div>
      </ng-container>

      <footer><span>BaradWatchU Client {{ version }}</span><span>I dati di audit restano sul dispositivo.</span><button class="text-button" type="button" (click)="refresh()" [disabled]="busy || saving">Aggiorna dati</button><button class="text-button" type="button" (click)="forceRefreshChecks()" [disabled]="busy || saving || loading">Riscansiona controlli</button></footer>
    </main>
  `,
  styleUrl: './styles.css'
})
class AppComponent implements OnInit {
  readonly version = APP_VERSION;
  requirements: Requirement[] = [];
  currentReport: AuditReport | null = null;
  history: HistoryEntry[] = [];
  selectedHistoryStamp: number | null = null;
  historicalReport: AuditReport | null = null;
  parameterText: Record<string, string> = {};
  loading = true;
  historyLoading = false;
  busy = false;
  saving = false;
  error = '';
  message = '';
  customId = '';
  customName = '';
  customDescription = '';
  customPriority: Priority = 'HIGH';
  customArguments = '[]';
  overrideBuiltinId = '';
  cloneFrom = '';
  importFile: File | null = null;

  get viewingHistory(): boolean { return this.selectedHistoryStamp !== null; }
  get visibleReport(): AuditReport | null { return this.viewingHistory ? this.historicalReport : this.currentReport; }
  get counts(): SummaryCounts {
    const counts: SummaryCounts = { pass: 0, fail: 0, warn: 0, error: 0, other: 0 };
    for (const result of this.visibleReport?.results ?? []) {
      if (result.status === 'PASS') counts.pass += 1;
      else if (result.status === 'FAIL') counts.fail += 1;
      else if (result.status === 'WARN') counts.warn += 1;
      else if (result.status === 'ERROR') counts.error += 1;
      else counts.other += 1;
    }
    return counts;
  }

  ngOnInit(): void { void this.refresh(); }

  async refresh(): Promise<void> {
    this.loading = true;
    this.error = '';
    const outcomes = await Promise.allSettled([
      this.request<DashboardData>('/api/requirements'),
      this.request<AuditReport | null>('/api/status'),
      this.loadHistory()
    ]);
    const errors: string[] = [];
    if (outcomes[0].status === 'fulfilled') this.setRequirements(outcomes[0].value.requirements);
    else errors.push(`Requisiti: ${this.errorText(outcomes[0].reason)}`);
    if (outcomes[1].status === 'fulfilled') this.currentReport = outcomes[1].value;
    else errors.push(`Ultimo risultato: ${this.errorText(outcomes[1].reason)}`);
    if (outcomes[2].status === 'rejected') errors.push(`Storico: ${this.errorText(outcomes[2].reason)}`);
    this.error = errors.join(' · ');
    this.loading = false;
  }

  async forceRefreshChecks(): Promise<void> {
    this.loading = true; this.error = ''; this.message = '';
    try {
      const data = await this.request<DashboardData>('/api/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      this.setRequirements(data.requirements);
      this.message = `Scansione completata: ${data.requirements.length} controlli rilevati dalle cartelle.`;
    } catch (error: unknown) { this.error = this.errorText(error); }
    finally { this.loading = false; }
  }

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
    this.busy = true; this.error = ''; this.message = '';
    try {
      this.currentReport = await this.request<AuditReport>(`/api/check/${encodeURIComponent(item.id)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      this.showCurrent();
      await this.loadHistory();
      this.message = `Controllo di ${item.name} completato.`;
    } catch (error: unknown) { this.error = this.errorText(error); }
    finally { this.busy = false; }
  }

  async runAudit(): Promise<void> {
    this.busy = true; this.error = ''; this.message = '';
    try {
      this.currentReport = await this.request<AuditReport>('/api/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      this.showCurrent();
      await this.loadHistory();
      this.message = 'Audit completato e salvato nello storico locale.';
    } catch (error: unknown) { this.error = this.errorText(error); }
    finally { this.busy = false; }
  }

  async showHistory(entry: HistoryEntry): Promise<void> {
    this.historyLoading = true; this.error = ''; this.message = '';
    this.selectedHistoryStamp = entry.completedAtUnixMs;
    this.historicalReport = null;
    try {
      this.historicalReport = await this.request<AuditReport>(`/api/history/${entry.completedAtUnixMs}`);
    } catch (error: unknown) {
      this.error = `Impossibile aprire l’audit storico: ${this.errorText(error)}`;
      this.selectedHistoryStamp = null;
    } finally { this.historyLoading = false; }
  }

  showCurrent(): void { this.selectedHistoryStamp = null; this.historicalReport = null; }
  resultFor(id: string): AuditResult | undefined { return this.visibleReport?.results.find(result => result.id === id); }
  overallStatus(report: AuditReport): ResultStatus {
    const counts = this.countsFor(report);
    if (counts.error > 0) return 'ERROR';
    if (counts.fail > 0) return 'FAIL';
    if (counts.warn > 0 || counts.other > 0 || report.results.length === 0) return 'WARN';
    return 'PASS';
  }
  statusText(status: ResultStatus): string {
    const labels: Record<ResultStatus, string> = { PASS: 'Conforme', FAIL: 'Da correggere', WARN: 'Da verificare', ERROR: 'Errore', DISABLED: 'Disabilitato', NOT_APPLICABLE: 'Non applicabile' };
    return `${status} · ${labels[status]}`;
  }
  priorityText(priority: Priority): string {
    const labels: Record<Priority, string> = { HIGHEST: 'Massima', HIGH: 'Alta', MEDIUM: 'Media', LOW: 'Bassa', OPTIONAL: 'Facoltativa' };
    return labels[priority];
  }
  toolEntries(item: Requirement): [string, string][] { return Object.entries(item.tools); }
  get builtins(): Requirement[] { return this.requirements.filter(item => item.origin === 'BUILTIN'); }
  inputValue(event: Event): string { return (event.target as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value; }
  selectCustomPriority(event: Event): void { this.customPriority = this.inputValue(event) as Priority; }
  selectImportFile(event: Event): void { this.importFile = (event.target as HTMLInputElement).files?.[0] ?? null; }
  cloneMetadata(): void {
    const item = this.requirements.find(value => value.id === this.cloneFrom);
    if (item) { this.customName = item.name; this.customDescription = item.description; this.customPriority = item.priority; }
  }
  async importCustom(): Promise<void> {
    const file = this.importFile;
    if (!file) return;
    if (!window.confirm('Questo file è codice eseguibile e verrà eseguito con i privilegi del tuo utente. Importa solo tool affidabili. Continuare?')) return;
    this.saving = true; this.error = '';
    try {
      const parsedArguments: unknown = JSON.parse(this.customArguments);
      if (!Array.isArray(parsedArguments) || parsedArguments.some(value => typeof value !== 'string')) throw new Error('Gli argomenti devono essere un array JSON di stringhe.');
      const data = await this.request<DashboardData>('/api/custom-checks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: this.customId, name: this.customName, description: this.customDescription, priority: this.customPriority, enabled: true, cloneFrom: this.cloneFrom || undefined, overrideBuiltinId: this.overrideBuiltinId || undefined, fileName: file.name, fileBase64: await this.fileBase64(file), arguments: parsedArguments }) });
      this.setRequirements(data.requirements); this.message = `Controllo ${this.customId} importato; SHA-256 fissato alla versione importata.`; this.customId = ''; this.importFile = null;
    } catch (error: unknown) { this.error = this.errorText(error); }
    finally { this.saving = false; }
  }
  async updateCustom(item: Requirement, event: Event): Promise<void> {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (!file || !item.customToolId) return;
    if (!window.confirm('Aggiornare intenzionalmente questo tool? Verrà registrato un nuovo SHA-256 atteso.')) return;
    try { const data = await this.request<DashboardData>(`/api/custom-checks/update/${encodeURIComponent(item.customToolId)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ fileBase64: await this.fileBase64(file) }) }); this.setRequirements(data.requirements); this.message = 'Tool aggiornato con nuovo hash atteso.'; }
    catch (error: unknown) { this.error = this.errorText(error); }
  }
  async restoreBuiltin(id: string): Promise<void> {
    try { const data = await this.request<DashboardData>(`/api/custom-checks/restore/${encodeURIComponent(id)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); this.setRequirements(data.requirements); this.message = `Controllo builtin ${id} ripristinato.`; }
    catch (error: unknown) { this.error = this.errorText(error); }
  }
  async removeCustom(item: Requirement): Promise<void> {
    if (!item.customToolId || !window.confirm(`Rimuovere il controllo custom ${item.customToolId}?`)) return;
    try { const data = await this.request<DashboardData>(`/api/custom-checks/${encodeURIComponent(item.customToolId)}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: '{}' }); this.setRequirements(data.requirements); this.message = `Controllo ${item.customToolId} rimosso.`; }
    catch (error: unknown) { this.error = this.errorText(error); }
  }
  private async fileBase64(file: File): Promise<string> {
    if (file.size < 1 || file.size > 1024 * 1024) throw new Error('Il tool deve avere dimensione compresa tra 1 byte e 1 MiB.');
    const bytes = new Uint8Array(await file.arrayBuffer()); let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
  }
  formatDate(timestamp: number): string {
    if (!Number.isFinite(timestamp)) return 'Data non disponibile';
    return new Intl.DateTimeFormat('it-IT', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(timestamp));
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

  private setRequirements(items: Requirement[]): void {
    this.requirements = items.map(item => ({ ...item, parameters: item.parameters ?? {} }));
    this.parameterText = Object.fromEntries(this.requirements.map(item => [item.id, JSON.stringify(item.parameters, null, 2)]));
  }

  private async loadHistory(): Promise<void> {
    this.historyLoading = true;
    try { this.history = await this.request<HistoryEntry[]>('/api/history'); }
    finally { this.historyLoading = false; }
  }

  private async saveSettings(message: string): Promise<void> {
    this.saving = true; this.error = '';
    try {
      const settings = { schema_version: 'baradwatchu.settings.v1', requirements: Object.fromEntries(this.requirements.map(item => [item.id, { enabled: item.enabled, priority: item.priority, parameters: item.parameters }])) };
      const data = await this.request<DashboardData>('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings) });
      this.setRequirements(data.requirements); this.message = message;
    } catch (error: unknown) { this.error = this.errorText(error); await this.refresh(); }
    finally { this.saving = false; }
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const response = await fetch(path, { ...options, cache: 'no-store' });
    const body: unknown = await response.json();
    if (!response.ok) {
      const detail = typeof body === 'object' && body !== null && 'error' in body ? String(body.error) : `Richiesta non riuscita (${response.status})`;
      throw new Error(detail);
    }
    return body as T;
  }

  private errorText(error: unknown): string {
    if (error instanceof TypeError) return 'L’agente locale non risponde. Riavvia la dashboard con baradwatchu-agent dashboard.';
    return error instanceof Error ? error.message : 'Impossibile comunicare con BaradWatchU.';
  }
}

bootstrapApplication(AppComponent).catch((error: unknown) => console.error(error));
