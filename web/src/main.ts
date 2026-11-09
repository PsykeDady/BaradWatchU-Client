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
interface AuditResult { id: string; name: string; description?: string; priority: Priority; status: ResultStatus; complianceStatus?: ResultStatus; summary: string; details: string[]; completedAtUnixMs: number; provenance?: Provenance; }
interface PdfArtifact { status: 'GENERATED' | 'FAILED'; path?: string; error?: string; warning?: string; }
interface AuditReport { schemaVersion: string; completedAtUnixMs: number; logFile?: string; results: AuditResult[]; client?: { version: string; sha256?: string; sha256Error?: string }; pdf?: PdfArtifact; }
interface ReportThemeOption { id: string; name: string; logoPath: string | null; primaryColor: string; secondaryColor: string; accentColor: string; }
interface ReportThemeCatalog { schemaVersion: string; selectedThemeId: string; themes: ReportThemeOption[]; }
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
interface ConfigurationView { version: string; platform: string; installRoot: string; language: 'system' | 'italian' | 'english'; effectiveLanguage: string; tray: { installed: boolean; running: boolean | null; autostart: boolean | null; error?: string }; paths: { configuration: string; customChecks: string; state: string; history: string; runtime: string }; }
interface UiMessages { language: 'system' | 'italian' | 'english'; effectiveLanguage: string; messages: Record<string, string>; }

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
        <a class="brand" href="#/" (click)="go('overview', $event)" [attr.aria-label]="t('ui.brand.aria')"><span class="brand-mark" aria-hidden="true">B</span><span><strong>BaradWatchU</strong><small>{{ t('ui.brand.subtitle') }}</small></span></a>
        <nav class="tabs" role="tablist" [attr.aria-label]="t('ui.sections')">
          <button type="button" role="tab" class="tab" [class.active]="view === 'overview'" [attr.aria-selected]="view === 'overview'" (click)="go('overview')">{{ t('ui.nav.status') }}</button>
          <button type="button" role="tab" class="tab" [class.active]="view === 'custom'" [attr.aria-selected]="view === 'custom'" (click)="go('custom')">{{ t('ui.nav.custom') }}<span class="tab-count" *ngIf="customs.length">{{ customs.length }}</span><span class="tab-alert" *ngIf="customProblems > 0" [attr.aria-label]="customProblems + ' ' + t('ui.alert.custom_issues')">!</span></button>
          <button type="button" role="tab" class="tab" [class.active]="view === 'notifications'" [attr.aria-selected]="view === 'notifications'" (click)="go('notifications')">{{ t('ui.nav.notifications') }}<span class="tab-alert" *ngIf="pendingConsents > 0" [attr.aria-label]="pendingConsents + ' ' + t('ui.alert.pending_requests')">{{ pendingConsents }}</span></button>
          <button type="button" role="tab" class="tab" [class.active]="view === 'settings'" [attr.aria-selected]="view === 'settings'" (click)="go('settings')">{{ t('ui.nav.settings') }}</button>
        </nav>
        <button class="button primary" type="button" (click)="runAudit()" [disabled]="busy || loading || saving"><span class="play-icon" aria-hidden="true">▶</span>{{ busy ? t('ui.audit.running') : t('ui.audit.run') }}</button>
      </header>

      <div class="notices" aria-live="polite">
          <div *ngIf="error" class="notice error" role="alert"><span class="notice-icon">!</span><span>{{ error }}</span><button type="button" class="text-button" (click)="refresh()">{{ t('ui.retry') }}</button><button type="button" class="dismiss" (click)="error = ''" [attr.aria-label]="t('ui.close')">×</button></div>
        <div *ngIf="message" class="notice success" role="status"><span class="notice-icon">✓</span><span>{{ message }}</span><button type="button" class="dismiss" (click)="message = ''" [attr.aria-label]="t('ui.close')">×</button></div>
      </div>
      <div *ngIf="loading" class="loading-panel" role="status"><span class="spinner"></span>{{ t('ui.loading') }}</div>

      <!-- ============================== STATO POSTAZIONE ============================== -->
      <ng-container *ngIf="!loading && view === 'overview'">
        <section class="intro">
          <div><p class="eyebrow">{{ t('ui.platform').replace('{platform}', platformLabel()) }}</p><h1>{{ t('ui.intro.status') }}</h1><p class="intro-copy">{{ t('ui.intro.copy') }}</p></div>
        </section>

        <section class="summary-panel" aria-labelledby="summary-title">
          <div class="summary-heading">
            <div><p class="eyebrow">{{ viewingHistory ? t('ui.summary.historical') : t('ui.summary.latest') }}</p><h2 id="summary-title">{{ visibleReport ? formatDate(visibleReport.completedAtUnixMs) : t('ui.summary.none') }}</h2></div>
            <span class="overall-pill" *ngIf="visibleReport" [attr.data-status]="overallStatus(visibleReport)">{{ statusText(overallStatus(visibleReport)) }}</span>
            <span class="overall-pill empty" *ngIf="!visibleReport">{{ t('ui.summary.waiting') }}</span>
          </div>
          <div class="summary-bottom">
            <div class="metrics" *ngIf="visibleReport; else emptySummary">
              <button type="button" class="metric pass" (click)="setFilter('PASS')" [class.selected]="filter === 'PASS'"><span class="metric-symbol">✓</span><span><strong>{{ counts.pass }}</strong><small>{{ t('ui.metric.pass') }}</small></span></button>
              <button type="button" class="metric fail" (click)="setFilter('FAIL')" [class.selected]="filter === 'FAIL'"><span class="metric-symbol">×</span><span><strong>{{ counts.fail }}</strong><small>{{ t('ui.metric.fail') }}</small></span></button>
              <button type="button" class="metric warn" (click)="setFilter('WARN')" [class.selected]="filter === 'WARN'"><span class="metric-symbol">!</span><span><strong>{{ counts.warn }}</strong><small>{{ t('ui.metric.warn') }}</small></span></button>
              <button type="button" class="metric error" (click)="setFilter('ERROR')" [class.selected]="filter === 'ERROR'"><span class="metric-symbol">⚠</span><span><strong>{{ counts.error }}</strong><small>{{ t('ui.metric.error') }}</small></span></button>
              <div class="metric other"><span class="metric-symbol">·</span><span><strong>{{ counts.other }}</strong><small>{{ t('ui.metric.other') }}</small></span></div>
            </div>
            <ng-template #emptySummary><p class="empty-copy">{{ viewingHistory && historyLoading ? t('ui.history.loading') : t('ui.summary.empty') }}</p></ng-template>
            <div class="run-context" *ngIf="viewingHistory"><span>{{ t('ui.history.viewing') }}</span><button class="text-button" type="button" (click)="showCurrent()">{{ t('ui.summary.back') }}</button></div>
          </div>
          <div class="settings-row report-meta" *ngIf="visibleReport as report">
            <span>{{ t('ui.pdf.client') }} {{ report.client?.version || 'legacy' }} · SHA-256 <code>{{ report.client?.sha256 || report.client?.sha256Error || t('ui.value.unavailable') }}</code></span>
            <a class="button secondary small" *ngIf="report.pdf?.status === 'GENERATED'" href="#" (click)="openPdf(report, $event)">{{ t('ui.pdf.open') }}</a>
            <span class="hint" *ngIf="report.pdf?.status === 'GENERATED'">{{ t('ui.pdf.saved') }} <code>{{ report.pdf?.path }}</code></span>
            <span class="hint" *ngIf="report.pdf?.warning">{{ t('ui.pdf.warning') }} {{ report.pdf?.warning }}</span>
            <span class="hint" *ngIf="report.pdf?.status === 'FAILED'">{{ t('ui.pdf.failed') }} {{ report.pdf?.error }}</span>
          </div>
          <div *ngIf="busy" class="progress-line" role="status"><span></span><span>{{ busyLabel }}</span></div>
        </section>

        <div class="content-grid">
          <section class="requirements-section" aria-labelledby="requirements-title">
            <div class="section-heading">
              <div><p class="eyebrow">{{ t('ui.catalog') }}</p><h2 id="requirements-title">{{ t('ui.requirements') }}</h2></div>
              <span class="section-count">{{ visibleRequirements.length }} / {{ requirements.length }}</span>
            </div>
            <div class="toolbar">
              <div class="chips" role="group" [attr.aria-label]="t('ui.filter')">
                <button type="button" class="chip" *ngFor="let option of filterOptions" [class.active]="filter === option.value" (click)="setFilter(option.value)">{{ option.label }}</button>
              </div>
              <input class="search" type="search" [placeholder]="t('ui.search')" [value]="search" (input)="search = inputValue($event)" [attr.aria-label]="t('ui.search')">
            </div>
            <div *ngIf="requirements.length === 0" class="empty-card">{{ t('ui.catalog.missing') }}</div>
            <div *ngIf="requirements.length > 0 && visibleRequirements.length === 0" class="empty-card">{{ t('ui.filters.none') }} <button class="text-button" type="button" (click)="setFilter('ALL'); search = ''">{{ t('ui.filters.show_all') }}</button></div>

            <article class="requirement-card" *ngFor="let item of visibleRequirements; trackBy: trackById" [class.disabled]="!item.enabled" [attr.data-status]="statusOf(item)">
              <div class="requirement-head">
                <span class="status-dot" [attr.data-status]="statusOf(item)" aria-hidden="true"></span>
                <div class="requirement-title">
                  <div class="tags"><span class="requirement-id">{{ item.id }}</span><span class="priority" [attr.data-priority]="item.priority">{{ priorityText(item.priority) }}</span><span class="tag custom" *ngIf="item.origin === 'CUSTOM' && !item.replacesBuiltin">{{ t('ui.tag.custom') }}</span><span class="tag override" *ngIf="item.replacesBuiltin">{{ t('ui.tag.replaced_by') }} {{ item.customToolId }}</span><span class="tag danger" *ngIf="item.configurationError">{{ t('ui.tag.invalid') }}</span><span class="tag danger" *ngIf="!item.configurationError && item.integrityStatus === 'MISMATCH'">{{ t('ui.tag.modified') }}</span><span class="tag muted" *ngIf="!item.enabled">{{ t('ui.tag.disabled') }}</span></div>
                  <h3>{{ item.name }}</h3>
                </div>
                <span *ngIf="resultFor(item.id) as result" class="status-badge" [attr.data-status]="result.status">{{ statusLabel(result.status) }}</span>
                <span *ngIf="!resultFor(item.id)" class="status-badge pending">{{ t('ui.tag.pending') }}</span>
              </div>
              <p class="result-summary" *ngIf="resultFor(item.id) as result">{{ result.summary }}</p>
              <p class="result-summary error-text" *ngIf="!resultFor(item.id) && item.configurationError">{{ item.configurationError }}</p>
              <details class="requirement-details">
                <summary><span>{{ t('ui.details.settings') }}</span><span class="chevron" aria-hidden="true">⌄</span></summary>
                <div class="detail-content">
                  <p class="description">{{ item.description }}</p>
                  <div *ngIf="resultFor(item.id) as result" class="result-detail-block">
                    <h4>{{ t('ui.requirement.result_date') }} {{ formatDate(result.completedAtUnixMs) }}</h4>
                    <ul *ngIf="result.details.length" class="evidence"><li *ngFor="let detail of result.details">{{ detail }}</li></ul>
                  </div>
                  <p *ngIf="!resultFor(item.id)" class="no-result">{{ viewingHistory && historyLoading ? t('ui.history.loading') : t('ui.details.no_result') }}</p>
                  <p *ngIf="viewingHistory" class="history-config-note">{{ t('ui.details.current_settings') }}</p>
                  <div class="settings-row">
                    <label class="toggle"><input type="checkbox" [checked]="item.enabled" [disabled]="busy || saving || viewingHistory" (change)="setEnabled(item, $event)"><span>{{ item.enabled ? t('ui.requirement.enabled') : t('ui.requirement.disabled') }}</span></label>
                    <label class="priority-label">{{ t('ui.custom.priority') }}<select [value]="item.priority" [disabled]="saving || viewingHistory" (change)="setPriority(item, $event)"><option *ngFor="let p of priorities" [value]="p">{{ priorityText(p) }}</option></select></label>
                    <button *ngIf="!viewingHistory" class="button secondary" type="button" [disabled]="busy || saving || !item.enabled" (click)="check(item)">{{ t('ui.check.now') }}</button>
                    <button *ngIf="item.origin === 'CUSTOM'" class="text-button" type="button" (click)="go('custom')">{{ t('ui.requirement.manage_custom') }}</button>
                  </div>
                  <details class="technical">
                    <summary>{{ t('ui.requirement.advanced') }}</summary>
                    <p class="hint">{{ t('ui.requirement.parameters_hint') }} <code>{{ '{"requirementId":…,"parameters":{…}}' }}</code>.</p>
                    <textarea rows="5" spellcheck="false" [value]="parameterText[item.id]" [disabled]="viewingHistory" (input)="editParameters(item, $event)" [attr.aria-label]="t('ui.requirement.parameters_for') + ' ' + item.name"></textarea>
                    <button class="button secondary small" type="button" [disabled]="saving || viewingHistory" (click)="saveParameters(item)">{{ t('ui.requirement.save_parameters') }}</button>
                  </details>
                  <details class="technical">
                    <summary>{{ t('ui.requirement.technical') }}</summary>
                    <dl class="facts">
                      <dt>{{ t('ui.field.origin') }}</dt><dd>{{ item.origin === 'BUILTIN' ? t('ui.field.builtin') : t('ui.field.custom') }}<span *ngIf="item.replacesBuiltin"> · {{ t('ui.tag.replaces').toLowerCase() }} {{ item.replacesBuiltin }}</span></dd>
                      <dt>{{ t('ui.field.tool') }}</dt><dd><code>{{ toolPath(item) || t('ui.value.unavailable') }}</code></dd>
                      <dt>{{ t('ui.field.arguments') }}</dt><dd><code>{{ item.arguments | json }}</code></dd>
                      <dt>{{ t('ui.field.timeout') }}</dt><dd>{{ item.timeoutSeconds }} s</dd>
                      <dt>{{ t('ui.field.integrity') }}</dt><dd><span class="integrity" [attr.data-integrity]="item.integrityStatus">{{ integrityText(item.integrityStatus) }}</span></dd>
                      <dt>{{ t('ui.field.sha_expected') }}</dt><dd><code>{{ item.expectedSha256 || t('ui.value.unavailable') }}</code></dd>
                      <dt>{{ t('ui.field.sha_actual') }}</dt><dd><code>{{ item.actualSha256 || t('ui.value.unavailable') }}</code></dd>
                      <ng-container *ngIf="resultFor(item.id)?.provenance as provenance">
                        <dt>{{ t('ui.field.executed') }}</dt><dd>{{ provenance.toolId }}<span *ngIf="provenance.toolVersion"> v{{ provenance.toolVersion }}</span> {{ t('ui.field.integrity_at_run') }} {{ integrityText(provenance.integrityStatus) }}</dd>
                      </ng-container>
                      <ng-container *ngIf="resultFor(item.id) && !resultFor(item.id)?.provenance"><dt>{{ t('ui.field.provenance') }}</dt><dd class="integrity-warning">{{ t('ui.field.legacy_report') }}</dd></ng-container>
                    </dl>
                  </details>
                </div>
              </details>
            </article>
          </section>

          <aside class="history-section" aria-labelledby="history-title">
            <div class="section-heading"><div><p class="eyebrow">{{ t('ui.eyebrow.local_archive') }}</p><h2 id="history-title">{{ t('ui.history') }}</h2></div><span class="section-count">{{ history.length }}</span></div>
            <div class="history-card">
              <div class="history-tools" *ngIf="historyUsage">
                <span class="history-usage">{{ historyUsage.audits }} audit · {{ formatBytes(historyUsage.bytes) }} {{ t('ui.history.disk') }}</span>
                <button class="button danger small" type="button" [disabled]="busy || saving || historyUsage.files === 0" (click)="clearHistory()">{{ t('ui.history.clear') }}</button>
              </div>
              <div *ngIf="historyLoading" class="history-loading"><span class="spinner small"></span>{{ t('ui.history.loading_short') }}</div>
              <p *ngIf="!historyLoading && history.length === 0" class="history-empty">{{ t('ui.history.empty') }}</p>
              <div *ngFor="let entry of history" class="history-row">
              <button type="button" class="history-item" [class.selected]="selectedHistoryStamp === entry.completedAtUnixMs" (click)="showHistory(entry)" [attr.aria-current]="selectedHistoryStamp === entry.completedAtUnixMs ? 'true' : null">
                <span class="history-item-top"><span class="history-status" [attr.data-status]="entry.overallStatus">{{ statusLabel(entry.overallStatus) }}</span><span class="history-time">{{ formatDate(entry.completedAtUnixMs) }}</span></span>
                <span class="history-counts"><span class="mini-count pass">{{ entry.pass }} {{ t('ui.history.ok') }}</span><span class="mini-count fail" *ngIf="entry.fail">{{ entry.fail }} {{ t('ui.history.fail') }}</span><span class="mini-count warn" *ngIf="entry.warn">{{ entry.warn }} {{ t('ui.history.warn') }}</span><span class="mini-count error" *ngIf="entry.error">{{ entry.error }} {{ t('ui.history.errors') }}</span></span>
              </button>
              <button type="button" class="history-delete" [disabled]="busy || saving" (click)="deleteHistory(entry)" [attr.aria-label]="t('ui.history.delete_aria').replace('{date}', formatDate(entry.completedAtUnixMs))" [title]="t('ui.history.delete_title')">✕</button>
              </div>
              <p *ngIf="history.length >= 50" class="history-limit">{{ t('ui.history.limit') }}</p>
            </div>
          </aside>
        </div>
      </ng-container>

      <!-- ============================ CONTROLLI PERSONALIZZATI ============================ -->
      <ng-container *ngIf="!loading && view === 'custom'">
        <section class="intro">
          <div><p class="eyebrow">{{ t('ui.custom.eyebrow') }}</p><h1>{{ t('ui.nav.custom') }}</h1><p class="intro-copy">{{ t('ui.custom.intro') }}</p></div>
          <div class="intro-actions">
            <button class="button secondary" type="button" (click)="forceRefreshChecks()" [disabled]="busy || saving">{{ t('ui.custom.rescan') }}</button>
            <button class="button primary" type="button" (click)="openForm()" [disabled]="showForm">{{ t('ui.custom.new') }}</button>
          </div>
        </section>

        <section class="form-panel" *ngIf="showForm" aria-labelledby="form-title">
          <div class="form-head"><h2 id="form-title">{{ t('ui.custom.new_title') }}</h2><button type="button" class="dismiss" (click)="closeForm()" [attr.aria-label]="t('ui.custom.close_form')">×</button></div>
          <p class="warning-box"><strong>{{ t('ui.warning') }}:</strong> {{ t('ui.custom.warning') }}</p>
          <div class="form-grid">
            <label>ID<input [value]="form.id" (input)="form.id = upper($event)" placeholder="CUSTOM-001" [class.invalid]="form.id && !validId(form.id)" aria-describedby="id-help"><small id="id-help">{{ t('ui.custom.id_help') }}</small></label>
            <label>{{ t('ui.custom.name') }}<input [value]="form.name" (input)="form.name = inputValue($event)" [placeholder]="t('ui.custom.name_placeholder')"></label>
            <label class="wide">{{ t('ui.custom.description') }}<textarea rows="2" [value]="form.description" (input)="form.description = inputValue($event)" [placeholder]="t('ui.custom.description_placeholder')"></textarea></label>
            <label>{{ t('ui.custom.priority') }}<select [value]="form.priority" (change)="form.priority = $any(inputValue($event))"><option *ngFor="let p of priorities" [value]="p">{{ priorityText(p) }}</option></select></label>
            <label>{{ t('ui.timeout') }}<input type="number" min="1" max="300" [value]="form.timeout" (input)="form.timeout = inputValue($event)"><small>{{ t('ui.custom.timeout_help') }}</small></label>
            <label class="wide file-drop">{{ t('ui.custom.tool_file') }}<input type="file" (change)="selectImportFile($event)"><small>{{ importFile ? importFile.name + ' · ' + formatSize(importFile.size) : t('ui.custom.file_help') }}</small></label>
            <label class="wide">{{ t('ui.custom.arguments') }}<input spellcheck="false" [value]="form.arguments" (input)="form.arguments = inputValue($event)" placeholder='["--verbose"]'><small>{{ t('ui.custom.args_help') }}</small></label>
            <details class="wide advanced-form"><summary>{{ t('ui.custom.advanced') }}</summary>
              <div class="form-grid inner">
                <label>{{ t('ui.custom.clone_from') }}<select [value]="form.cloneFrom" (change)="form.cloneFrom = inputValue($event); cloneMetadata()"><option value="">{{ t('ui.custom.no_clone') }}</option><option *ngFor="let item of requirements" [value]="item.id">{{ item.id }} · {{ item.name }}</option></select></label>
                <label>{{ t('ui.custom.replace') }}<select [value]="form.overrideBuiltinId" (change)="form.overrideBuiltinId = inputValue($event)"><option value="">{{ t('ui.custom.no_override') }}</option><option *ngFor="let item of overridableBuiltins" [value]="item.id">{{ item.id }} · {{ item.name }}</option></select><small>{{ t('ui.custom.override_help') }}</small></label>
              </div>
            </details>
          </div>
          <div class="form-actions"><button class="button secondary" type="button" (click)="closeForm()">{{ t('ui.custom.cancel') }}</button><button class="button primary" type="button" [disabled]="saving || busy || !canImport" (click)="importCustom()">{{ saving ? t('ui.custom.importing') : t('ui.custom.import') }}</button></div>
        </section>

        <div class="custom-layout">
          <section aria-labelledby="custom-list-title">
            <div class="section-heading"><div><p class="eyebrow">{{ t('ui.custom.installed') }}</p><h2 id="custom-list-title">{{ t('ui.custom.mine') }}</h2></div><span class="section-count">{{ customs.length }}</span></div>
            <div *ngIf="ignoredFolders.length" class="notice warn"><span class="notice-icon">!</span><span>{{ t('ui.custom.ignored_prefix') }} {{ ignoredFolders.join(', ') }}.</span></div>
            <div *ngIf="customs.length === 0" class="empty-card column">
              <strong>{{ t('ui.custom.none') }}</strong>
              <span>{{ t('ui.custom.create_hint') }} <code>{{ customChecksDir || '~/.config/baradwatchu/custom-checks' }}</code> {{ t('ui.custom.create_hint_end') }}</span>
            </div>
            <article class="custom-card" *ngFor="let item of customs; trackBy: trackById" [class.broken]="!!item.configurationError" [class.mismatch]="!item.configurationError && item.integrityStatus !== 'VERIFIED'">
              <div class="custom-head">
                <div>
                  <div class="tags"><span class="requirement-id">{{ item.customToolId || item.id }}</span><span class="priority" [attr.data-priority]="item.priority">{{ priorityText(item.priority) }}</span><span class="tag" *ngIf="item.customToolVersion">v{{ item.customToolVersion }}</span><span class="tag override" *ngIf="item.replacesBuiltin">{{ t('ui.tag.replaces') }} {{ item.replacesBuiltin }}</span><span class="tag muted" *ngIf="!item.enabled">{{ t('ui.tag.disabled') }}</span></div>
                  <h3>{{ item.name }}</h3>
                </div>
                <span *ngIf="resultFor(item.id) as result" class="status-badge" [attr.data-status]="result.status">{{ statusLabel(result.status) }}</span>
              </div>
              <div *ngIf="item.configurationError" class="problem"><strong>{{ t('ui.custom.invalid') }}</strong> {{ item.configurationError }}</div>
              <div *ngIf="!item.configurationError && item.integrityStatus === 'MISMATCH'" class="problem">{{ t('ui.custom.changed') }}</div>
              <div *ngIf="!item.configurationError && item.integrityStatus === 'UNKNOWN'" class="problem">{{ t('ui.custom.unreadable') }}</div>
              <p class="result-summary" *ngIf="resultFor(item.id) as result">{{ result.summary }}</p>
              <p class="description" *ngIf="!item.configurationError">{{ item.description }}</p>
              <dl class="facts compact" *ngIf="!item.configurationError">
                <dt>{{ t('ui.custom.tool') }}</dt><dd><code>{{ toolPath(item) }}</code></dd>
                <dt>{{ t('ui.custom.integrity') }}</dt><dd><span class="integrity" [attr.data-integrity]="item.integrityStatus">{{ integrityText(item.integrityStatus) }}</span></dd>
                <dt>SHA-256</dt><dd><code>{{ item.expectedSha256 }}</code></dd>
              </dl>
              <div class="custom-actions">
                <button class="button secondary small" type="button" *ngIf="!item.configurationError" [disabled]="busy || saving || !item.enabled || item.integrityStatus !== 'VERIFIED'" (click)="check(item)">{{ t('ui.custom.check_now') }}</button>
                <button class="button secondary small" type="button" *ngIf="canAccept(item)" [disabled]="saving" (click)="acceptCustom(item)">{{ t('ui.custom.accept') }}</button>
                <label class="button secondary small file-button" *ngIf="!item.configurationError">{{ t('ui.custom.upload') }}<input type="file" (change)="updateCustom(item, $event)" [disabled]="saving"></label>
                <button class="button secondary small" type="button" *ngIf="item.replacesBuiltin" [disabled]="saving" (click)="restoreBuiltin(item)">{{ t('ui.custom.restore') }} {{ item.replacesBuiltin }}</button>
                <span class="spacer"></span>
                <button class="button danger small" type="button" [disabled]="saving" (click)="removeCustom(item)">{{ t('ui.custom.delete') }}</button>
              </div>
            </article>
          </section>

          <aside class="guide" aria-labelledby="guide-title">
            <h2 id="guide-title">{{ t('ui.custom.guide') }}</h2>
            <ol>
              <li>{{ t('ui.custom.guide.folder') }}<pre>{{ guideTree }}</pre></li>
              <li>{{ t('ui.custom.guide.output') }}<pre>{{ guideOutput }}</pre>{{ t('ui.custom.guide.states') }}<code>PASS</code>, <code>FAIL</code>, <code>WARNING</code>, <code>ERROR</code>. <code>details</code>{{ t('ui.custom.guide.details') }}</li>
              <li>{{ t('ui.custom.guide.hash') }}<code>expectedSha256</code>{{ t('ui.custom.guide.hash_changed') }}<code>baradwatchu-agent custom accept ID</code>.</li>
              <li>{{ t('ui.custom.guide.run') }}</li>
            </ol>
            <p class="hint">{{ t('ui.custom.folder') }} <code>{{ customChecksDir || '~/.config/baradwatchu/custom-checks' }}</code></p>
          </aside>
        </div>
      </ng-container>

      <!-- ================================== NOTIFICHE ================================== -->
      <ng-container *ngIf="!loading && view === 'notifications'">
        <section class="intro">
          <div><p class="eyebrow">{{ t('ui.notifications.eyebrow') }}</p><h1>{{ t('ui.nav.notifications') }}</h1><p class="intro-copy">{{ t('ui.notifications.intro') }}</p></div>
          <div class="intro-actions"><button class="button secondary" type="button" (click)="loadNotifications()" [disabled]="saving">{{ t('ui.refresh') }}</button></div>
        </section>
        <div class="custom-layout">
          <section aria-labelledby="events-title">
            <div class="form-panel">
              <div class="form-head"><h2>{{ t('ui.notifications.preferences') }}</h2><span class="tag" [class.muted]="notifications?.trayRunning !== true">{{ trayText }}</span></div>
              <div class="settings-row" *ngIf="notifications as data">
                <label class="toggle"><input type="checkbox" [checked]="data.preferences.enabled" [disabled]="saving" (change)="setPreference('enabled', $event)"><span>{{ t('ui.notifications.audit') }}</span></label>
                <label class="toggle"><input type="checkbox" [checked]="data.preferences.informative" [disabled]="saving || !data.preferences.enabled" (change)="setPreference('informative', $event)"><span>{{ t('ui.notifications.informative') }}</span></label>
              </div>
              <p class="hint">{{ t('ui.notifications.consent_hint') }}</p>
            </div>
            <div class="section-heading"><div><p class="eyebrow">{{ t('ui.eyebrow.local_history') }}</p><h2 id="events-title">{{ t('ui.notifications.events') }}</h2></div><span class="section-count">{{ notifications?.events?.length ?? 0 }}</span></div>
            <div *ngIf="!notifications?.events?.length" class="empty-card">{{ t('ui.notifications.no_events') }}</div>
            <article class="custom-card" *ngFor="let event of notifications?.events ?? []" [attr.data-severity]="event.severity">
              <div class="custom-head"><div><div class="tags"><span class="tag" [class.danger]="event.severity === 'CRITICAL'" [class.override]="event.severity === 'ACTION'">{{ severityText(event.severity) }}</span><span class="tag muted" *ngIf="event.repeated">{{ t('ui.notifications.repeated') }}</span></div><h3>{{ event.title }}</h3></div><span class="history-time">{{ formatDate(event.atUnixMs) }}</span></div>
              <p class="result-summary">{{ event.body }}</p>
            </article>
          </section>
          <aside class="guide" aria-labelledby="consent-title">
            <h2 id="consent-title">{{ t('ui.notifications.consent') }}</h2>
            <p class="hint">{{ t('ui.notifications.consent_info') }}</p>
            <button class="button secondary small" type="button" (click)="simulateConsent()" [disabled]="saving">{{ t('ui.notifications.simulate') }}</button>
            <p *ngIf="!notifications?.consents?.length" class="history-empty">{{ t('ui.notifications.no_requests') }}</p>
            <dl class="facts compact" *ngFor="let consent of notifications?.consents ?? []">
              <dt>{{ t('ui.notifications.state') }}</dt><dd><strong>{{ consentText(consent.state) }}</strong><span *ngIf="consent.state === 'PENDING'"> {{ t('ui.notifications.expires') }} {{ consent.remainingSeconds }} s</span><span *ngIf="consent.source === 'LOCAL_SIMULATION'"> {{ t('ui.notifications.simulated') }}</span></dd>
              <dt>{{ t('ui.notifications.server') }}</dt><dd>{{ consent.serverId }}</dd>
              <dt>{{ t('ui.notifications.account') }}</dt><dd>{{ consent.accountName }} ({{ consent.accountId }})</dd>
              <dt>{{ t('ui.notifications.device') }}</dt><dd>{{ consent.declaredDevice }}</dd>
              <dt>{{ t('ui.notifications.result') }}</dt><dd>{{ consent.effect }}</dd>
              <dt>ID</dt><dd><code>{{ consent.requestId }}</code></dd>
            </dl>
          </aside>
        </div>
      </ng-container>

      <!-- ============================== IMPOSTAZIONI ============================== -->
      <ng-container *ngIf="!loading && view === 'settings'">
        <section class="intro">
          <div><p class="eyebrow">{{ t('ui.settings.local') }}</p><h1>{{ t('ui.nav.settings') }}</h1><p class="intro-copy">{{ t('ui.settings.intro') }}</p></div>
          <div class="intro-actions"><button class="button secondary" type="button" (click)="loadConfiguration()" [disabled]="saving">{{ t('ui.refresh') }}</button></div>
        </section>
        <div *ngIf="!configuration" class="empty-card">{{ t('ui.settings.unavailable') }}</div>
        <div class="custom-layout" *ngIf="configuration as config">
          <section aria-labelledby="startup-title">
            <div class="form-panel">
              <div class="form-head"><h2 id="startup-title">{{ t('ui.settings.tray') }}</h2><span class="tag" [class.muted]="config.tray.running !== true">{{ configTrayText }}</span></div>
              <div class="settings-row">
                <label class="toggle"><input type="checkbox" [checked]="config.tray.autostart === true" [disabled]="saving || !config.tray.installed || config.tray.autostart === null" (change)="setAutostart($event)"><span>{{ t('ui.settings.startup') }}</span></label>
              </div>
              <p class="hint" *ngIf="!config.tray.installed">{{ t('ui.settings.tray_missing') }}</p>
              <p class="hint" *ngIf="config.tray.error">{{ t('ui.settings.tray_status_error') }} {{ config.tray.error }}</p>
              <p class="hint">{{ t('ui.settings.tray_explanation') }}</p>
            </div>
            <div class="form-panel">
              <div class="form-head"><h2>{{ t('ui.settings.language') }}</h2></div>
              <label class="wide">{{ t('ui.settings.language') }}
                <select [value]="config.language" [disabled]="saving" (change)="setLanguage($event)">
                  <option value="system">{{ t('language.system') }}</option><option value="italian">{{ t('language.italian') }}</option><option value="english">{{ t('language.english') }}</option>
                </select>
                <small>{{ t('ui.settings.language_active').replace('{lang}', config.effectiveLanguage) }}</small>
              </label>
            </div>
            <div class="form-panel">
              <div class="form-head"><h2>{{ t('ui.settings.notifications') }}</h2></div>
              <p class="hint">{{ t('ui.settings.notifications_hint') }} <a href="#/notifiche" (click)="go('notifications', $event)">{{ t('ui.nav.notifications') }}</a>.</p>
            </div>
            <div class="form-panel" *ngIf="reportTheme as catalog">
              <div class="form-head"><h2>{{ t('ui.settings.pdf_theme') }}</h2></div>
              <p class="hint">{{ t('ui.settings.pdf_hint') }}</p>
              <p class="hint">{{ t('ui.settings.themes_folder') }} <code>{{ config.paths.configuration }}/themes/</code></p>
              <label class="wide">{{ t('ui.settings.pdf_theme') }}
                <select [disabled]="saving" (change)="saveReportTheme($event)">
                  <option *ngIf="!selectedReportTheme" [value]="catalog.selectedThemeId" [selected]="true" disabled>{{ t('ui.settings.theme_missing').replace('{id}', catalog.selectedThemeId) }}</option>
                  <option *ngFor="let theme of catalog.themes" [value]="theme.id" [selected]="theme.id === catalog.selectedThemeId">{{ theme.name }} ({{ theme.id }})</option>
                </select>
              </label>
              <p class="hint" *ngIf="selectedReportTheme as theme">{{ t('ui.settings.theme_accent') }} <code>{{ theme.accentColor }}</code> · {{ t('ui.settings.theme_logo') }} <code>{{ theme.logoPath || t('ui.settings.theme_default_logo') }}</code></p>
              <p class="hint">{{ t('ui.settings.theme_cli') }} <code>baradwatchu-agent report-theme list</code> · <code>baradwatchu-agent report-theme use ID</code></p>
            </div>
            <div class="section-heading"><div><p class="eyebrow">{{ t('ui.settings.local_data') }}</p><h2 id="paths-title">{{ t('ui.settings.folders') }}</h2></div></div>
            <dl class="facts" aria-labelledby="paths-title">
              <dt>{{ t('ui.settings.folders.configuration') }}</dt><dd><code>{{ config.paths.configuration }}</code></dd>
              <dt>{{ t('ui.settings.folders.custom') }}</dt><dd><code>{{ config.paths.customChecks }}</code></dd>
              <dt>{{ t('ui.settings.folders.events') }}</dt><dd><code>{{ config.paths.state }}</code></dd>
              <dt>{{ t('ui.settings.folders.history') }}</dt><dd><code>{{ config.paths.history }}</code><br><span class="hint">{{ t('ui.settings.history_hint') }}</span></dd>
              <dt>{{ t('ui.settings.folders.runtime') }}</dt><dd><code>{{ config.paths.runtime }}</code></dd>
            </dl>
          </section>
          <aside class="guide" aria-labelledby="about-title">
            <h2 id="about-title">{{ t('ui.settings.about') }}</h2>
            <dl class="facts compact">
              <dt>{{ t('ui.settings.version') }}</dt><dd>{{ config.version }}</dd>
              <dt>{{ t('ui.settings.system') }}</dt><dd>{{ platformName(config.platform) }}</dd>
              <dt>{{ t('ui.settings.installation') }}</dt><dd><code>{{ config.installRoot }}</code></dd>
            </dl>
            <p class="hint">{{ t('ui.settings.uninstall_hint') }}</p>
          </aside>
        </div>
      </ng-container>

      <footer><span>BaradWatchU Client {{ version }}</span><span>{{ t('ui.footer.local_data') }}</span><button class="text-button" type="button" (click)="refresh()" [disabled]="busy || saving">{{ t('ui.footer.refresh') }}</button></footer>
    </main>
  `,
  styleUrl: './styles.css'
})
class AppComponent implements OnInit {
  readonly version = APP_VERSION;
  readonly priorities = PRIORITIES;
  get filterOptions(): { value: StatusFilter; label: string }[] { return [
    { value: 'ALL', label: this.t('ui.all') },
    { value: 'FAIL', label: this.t('ui.status.fail') }, { value: 'WARN', label: this.t('ui.status.warn') },
    { value: 'ERROR', label: this.t('ui.status.error') }, { value: 'PASS', label: this.t('ui.status.pass') },
    { value: 'PENDING', label: this.t('ui.tag.pending') }
  ]; }
  readonly guideTree = 'custom-checks/\n└── CUSTOM-001/\n    ├── configuration.json\n    └── CUSTOM-001.sh';
  get guideOutput(): string { return `{"status":"PASS",\n "summary":"${this.t('ui.custom.guide.sample_summary')}",\n "details":["${this.t('ui.custom.guide.sample_detail')}"]}`; }
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
  reportTheme: ReportThemeCatalog | null = null;
  uiMessages: UiMessages | null = null;
  private readonly token = sessionToken();
  private messageTimer: ReturnType<typeof setTimeout> | undefined;

  get viewingHistory(): boolean { return this.selectedHistoryStamp !== null; }
  t(key: string): string { return this.uiMessages?.messages[key] ?? key; }
  get visibleReport(): AuditReport | null { return this.viewingHistory ? this.historicalReport : this.currentReport; }
  get counts(): SummaryCounts { return this.visibleReport ? this.countsFor(this.visibleReport) : { pass: 0, fail: 0, warn: 0, error: 0, other: 0 }; }
  get customs(): Requirement[] { return this.requirements.filter(item => item.origin === 'CUSTOM'); }
  get pendingConsents(): number { return this.notifications?.consents.filter(item => item.state === 'PENDING').length ?? 0; }
  get trayText(): string { const running = this.notifications?.trayRunning; return this.t(running === true ? 'ui.settings.tray_active' : running === false ? 'ui.settings.tray_inactive' : 'ui.settings.tray_unknown'); }
  get selectedReportTheme(): ReportThemeOption | undefined { return this.reportTheme?.themes.find(theme => theme.id === this.reportTheme?.selectedThemeId); }
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
    if (view === 'settings') void Promise.all([this.loadConfiguration(), this.loadReportTheme()]).catch(error => { this.error = `${this.t('ui.section.settings')} ${this.errorText(error)}`; });
    if (location.hash !== hash) window.history.replaceState(null, '', hash);
    window.scrollTo({ top: 0 });
  }

  async refresh(): Promise<void> {
    this.loading = true;
    this.error = '';
    if (!this.token) { this.error = this.t('ui.error.session_missing'); this.loading = false; return; }
    await this.loadUiMessages().catch(() => undefined);
    const outcomes = await Promise.allSettled([
      this.request<DashboardData>('/api/requirements'),
      this.request<AuditReport | null>('/api/status'),
      this.loadHistory(),
      this.loadNotifications(),
      this.view === 'settings' ? Promise.all([this.loadConfiguration(), this.loadReportTheme()]) : Promise.resolve()
    ]);
    const errors: string[] = [];
    if (outcomes[0].status === 'fulfilled') this.setData(outcomes[0].value);
    else errors.push(`${this.t('ui.section.requirements')} ${this.errorText(outcomes[0].reason)}`);
    if (outcomes[1].status === 'fulfilled') this.currentReport = outcomes[1].value;
    else errors.push(`${this.t('ui.section.latest')} ${this.errorText(outcomes[1].reason)}`);
    if (outcomes[2].status === 'rejected') errors.push(`${this.t('ui.section.history')} ${this.errorText(outcomes[2].reason)}`);
    if (outcomes[3].status === 'rejected') errors.push(`${this.t('ui.section.notifications')} ${this.errorText(outcomes[3].reason)}`);
    if (outcomes[4].status === 'rejected') errors.push(`${this.t('ui.section.settings')} ${this.errorText(outcomes[4].reason)}`);
      this.error = errors.join(' · ');
    this.loading = false;
  }

  async forceRefreshChecks(): Promise<void> {
    await this.mutate(() => this.post<DashboardData>('/api/refresh'), data => this.t('ui.custom.result_summary').replace('{total}', String(data.requirements.length)).replace('{custom}', String(data.requirements.filter(r => r.origin === 'CUSTOM').length)));
  }

  setFilter(filter: StatusFilter): void { this.filter = this.filter === filter && filter !== 'ALL' ? 'ALL' : filter; }

  async setEnabled(item: Requirement, event: Event): Promise<void> {
    item.enabled = (event.target as HTMLInputElement).checked;
    await this.saveSettings(this.t('ui.audit.setting').replace('{name}', item.name).replace('{state}', this.t(item.enabled ? 'ui.audit.enabled' : 'ui.audit.disabled')));
  }

  async setPriority(item: Requirement, event: Event): Promise<void> {
    item.priority = (event.target as HTMLSelectElement).value as Priority;
    await this.saveSettings(this.t('ui.audit.priority_saved').replace('{name}', item.name));
  }

  editParameters(item: Requirement, event: Event): void { this.parameterText[item.id] = (event.target as HTMLTextAreaElement).value; }

  async saveParameters(item: Requirement): Promise<void> {
    try {
      const value: unknown = JSON.parse(this.parameterText[item.id] ?? '{}');
      if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(this.t('ui.error.json_parameters'));
      item.parameters = value as Record<string, unknown>;
      await this.saveSettings(this.t('ui.audit.params_saved').replace('{name}', item.name));
    } catch (error: unknown) { this.error = this.errorText(error); }
  }

  async check(item: Requirement): Promise<void> {
    await this.runWithProgress(this.t('ui.audit.check_progress').replace('{name}', item.name), async () => {
      this.currentReport = await this.post<AuditReport>(`/api/check/${encodeURIComponent(item.id)}`);
      this.showCurrent();
      await this.loadHistory();
      this.flash(this.t('ui.audit.check_done').replace('{name}', item.name));
    });
  }

  async runAudit(): Promise<void> {
    await this.runWithProgress(this.t('ui.audit.run_progress'), async () => {
      this.currentReport = await this.post<AuditReport>('/api/audit');
      this.showCurrent();
      await this.loadHistory();
      this.flash(this.t('ui.audit.run_done'));
    });
  }

  async showHistory(entry: HistoryEntry): Promise<void> {
    this.historyLoading = true; this.error = '';
    this.selectedHistoryStamp = entry.completedAtUnixMs;
    this.historicalReport = null;
    try {
      this.historicalReport = await this.request<AuditReport>(`/api/history/${entry.completedAtUnixMs}`);
    } catch (error: unknown) {
      this.error = this.t('ui.history.open_error').replace('{error}', this.errorText(error));
      this.selectedHistoryStamp = null;
    } finally { this.historyLoading = false; }
  }

  async deleteHistory(entry: HistoryEntry): Promise<void> {
    if (!window.confirm(this.t('ui.history.delete_confirm').replace('{date}', this.formatDate(entry.completedAtUnixMs)))) return;
    await this.removeHistory(`/api/history/${entry.completedAtUnixMs}`, entry.completedAtUnixMs);
  }

  async clearHistory(): Promise<void> {
    const usage = this.historyUsage;
    if (!usage || !window.confirm(this.t('ui.history.clear_confirm').replace('{count}', String(usage.audits)).replace('{bytes}', this.formatBytes(usage.bytes)))) return;
    await this.removeHistory('/api/history', null);
  }

  formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KiB', 'MiB', 'GiB']; let value = bytes / 1024; let unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
    const locale = this.uiMessages?.effectiveLanguage === 'it_IT' ? 'it-IT' : 'en-GB';
    return `${value.toLocaleString(locale, { maximumFractionDigits: 1 })} ${units[unit]}`;
  }

  private async removeHistory(path: string, stamp: number | null): Promise<void> {
    this.saving = true; this.error = '';
    try {
      const removal = await this.request<HistoryRemoval>(path, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (stamp === null || this.selectedHistoryStamp === stamp) this.showCurrent();
      this.historyUsage = removal.usage;
      this.currentReport = await this.request<AuditReport | null>('/api/status');
      await this.loadHistory();
      this.flash(this.t('ui.history.removed').replace('{count}', String(removal.removedAudits)).replace('{bytes}', this.formatBytes(removal.freedBytes)));
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
    const key: Record<ResultStatus, string> = { PASS: 'ui.status.pass', FAIL: 'ui.status.fail', WARN: 'ui.status.warn', ERROR: 'ui.status.error', DISABLED: 'ui.status.disabled', NOT_APPLICABLE: 'ui.status.na' };
    return this.t(key[status]);
  }
  statusText(status: ResultStatus): string {
    const key: Record<ResultStatus, string> = { PASS: 'ui.overall.pass', FAIL: 'ui.overall.fail', WARN: 'ui.overall.warn', ERROR: 'ui.overall.error', DISABLED: 'ui.status.disabled', NOT_APPLICABLE: 'ui.status.na' };
    return this.t(key[status]);
  }
  integrityText(status: Integrity): string { return this.t(({ VERIFIED: 'ui.integrity.verified', MISMATCH: 'ui.integrity.mismatch', UNKNOWN: 'ui.integrity.unknown' } as const)[status]); }
  priorityText(priority: Priority): string {
    const labels: Record<Priority, string> = { HIGHEST: 'ui.priority.highest', HIGH: 'ui.priority.high', MEDIUM: 'ui.priority.medium', LOW: 'ui.priority.low', OPTIONAL: 'ui.priority.optional' };
    return this.t(labels[priority]);
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
    if (!Array.isArray(parsedArguments) || parsedArguments.some(value => typeof value !== 'string')) { this.error = this.t('ui.error.arguments'); return; }
    const timeout = this.form.timeout.trim() === '' ? undefined : Number(this.form.timeout);
    if (timeout !== undefined && (!Number.isInteger(timeout) || timeout < 1 || timeout > 300)) { this.error = this.t('ui.error.timeout'); return; }
    if (!window.confirm(this.t('ui.custom.import_confirm').replace('{file}', file.name).replace('{id}', this.form.id))) return;
    const body = { id: this.form.id, name: this.form.name, description: this.form.description, priority: this.form.priority, enabled: true, cloneFrom: this.form.cloneFrom || undefined, overrideBuiltinId: this.form.overrideBuiltinId || undefined, fileName: file.name, fileBase64: await this.fileBase64(file).catch((error: unknown) => { this.error = this.errorText(error); return ''; }), arguments: parsedArguments, timeoutSeconds: timeout };
    if (!body.fileBase64) return;
    const id = this.form.id;
    const ok = await this.mutate(() => this.post<DashboardData>('/api/custom-checks', body), () => this.t('ui.custom.import_success').replace('{id}', id));
    if (ok) this.closeForm();
  }
  async updateCustom(item: Requirement, event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file || !item.customToolId) return;
    if (!window.confirm(this.t('ui.custom.update_confirm').replace('{id}', item.customToolId).replace('{file}', file.name))) return;
    const base64 = await this.fileBase64(file).catch((error: unknown) => { this.error = this.errorText(error); return ''; });
    if (!base64) return;
    await this.mutate(() => this.post<DashboardData>(`/api/custom-checks/update/${encodeURIComponent(item.customToolId!)}`, { fileBase64: base64 }), () => this.t('ui.custom.update_success').replace('{id}', item.customToolId!));
  }
  async acceptCustom(item: Requirement): Promise<void> {
    const id = item.customToolId ?? item.id;
    if (!window.confirm(this.t('ui.custom.accept_confirm').replace('{id}', id))) return;
    await this.mutate(() => this.post<DashboardData>(`/api/custom-checks/accept/${encodeURIComponent(id)}`), () => this.t('ui.custom.accept_success').replace('{id}', id));
  }
  async restoreBuiltin(item: Requirement): Promise<void> {
    const builtin = item.replacesBuiltin;
    if (!builtin) return;
    await this.mutate(() => this.post<DashboardData>(`/api/custom-checks/restore/${encodeURIComponent(builtin)}`), () => this.t('ui.custom.restore_success').replace('{builtin}', builtin).replace('{custom}', item.customToolId ?? item.id));
  }
  async removeCustom(item: Requirement): Promise<void> {
    const id = item.customToolId ?? item.id;
    const extra = item.replacesBuiltin ? ` ${this.t('ui.custom.restore_extra').replace('{id}', item.replacesBuiltin)}` : '';
    if (!window.confirm(this.t('ui.custom.delete_confirm').replace('{id}', id).replace('{extra}', extra))) return;
    await this.mutate(() => this.request<DashboardData>(`/api/custom-checks/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: '{}' }), () => this.t('ui.custom.delete_success').replace('{id}', id));
  }

  async loadConfiguration(): Promise<void> { this.configuration = await this.request<ConfigurationView>('/api/configuration'); }
  async loadUiMessages(): Promise<void> {
    this.uiMessages = await this.request<UiMessages>('/api/messages');
    document.documentElement.lang = this.uiMessages.effectiveLanguage.startsWith('it') ? 'it' : 'en';
  }
  async setLanguage(event: Event): Promise<void> {
    if (!this.configuration) return;
    const language = (event.target as HTMLSelectElement).value;
    this.saving = true;
    try {
      this.configuration = await this.request<ConfigurationView>('/api/configuration/language', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ language }) });
      await this.refresh();
      this.flash(this.t('ui.settings.language_saved'));
    } catch (error: unknown) { this.error = this.errorText(error); await this.loadConfiguration().catch(() => undefined); }
    finally { this.saving = false; }
  }
  get configTrayText(): string { const tray = this.configuration?.tray; if (!tray) return ''; if (!tray.installed) return this.t('ui.settings.tray_not_installed'); return this.t(tray.running === true ? 'ui.settings.tray_active' : tray.running === false ? 'ui.settings.tray_inactive' : 'ui.settings.tray_unknown'); }
  platformName(platform: string): string { return platform === 'windows' ? 'Windows' : platform === 'linux' ? 'Linux' : platform === 'macos' ? 'macOS' : platform; }
  async setAutostart(event: Event): Promise<void> {
    const enabled = (event.target as HTMLInputElement).checked;
    this.saving = true;
    try {
      this.configuration = await this.request<ConfigurationView>('/api/configuration/autostart', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) });
      this.flash(this.t(enabled ? 'ui.settings.autostart_on' : 'ui.settings.autostart_off'));
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
      this.flash(this.t('ui.save.notifications'));
    } catch (error: unknown) { this.error = this.errorText(error); await this.loadNotifications().catch(() => undefined); }
    finally { this.saving = false; }
  }
  async simulateConsent(): Promise<void> {
    this.saving = true; this.error = '';
    try {
      this.notifications = await this.post<NotificationsView>('/api/consent/simulate', { ttlSeconds: 60 });
      this.flash(this.t(this.notifications.trayRunning === true ? 'ui.error.consent_tray' : 'ui.error.consent_cli'));
    } catch (error: unknown) { this.error = this.errorText(error); }
    finally { this.saving = false; }
  }
  severityText(severity: EventSeverity): string { return this.t(({ INFO: 'ui.severity.info', WARNING: 'ui.severity.warning', CRITICAL: 'ui.severity.critical', ACTION: 'ui.severity.action' } as const)[severity]); }
  consentText(state: ConsentState): string { return this.t(({ PENDING: 'ui.consent.pending', ACCEPTED: 'ui.consent.accepted', REJECTED: 'ui.consent.rejected', EXPIRED: 'ui.consent.expired' } as const)[state]); }

  formatDate(timestamp: number): string {
    if (!Number.isFinite(timestamp)) return this.t('ui.date.unavailable');
    const locale = this.uiMessages?.effectiveLanguage === 'it_IT' ? 'it-IT' : 'en-GB';
    return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(timestamp));
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
    if (file.size < 1 || file.size > 1024 * 1024) throw new Error(this.t('ui.error.tool_size'));
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
  private async loadReportTheme(): Promise<void> { this.reportTheme = await this.request<ReportThemeCatalog>('/api/report-theme'); }
  async saveReportTheme(event: Event): Promise<void> {
    if (!this.reportTheme) return;
    const value = { theme: this.inputValue(event) };
    this.saving = true; this.error = '';
    try {
      this.reportTheme = await this.request<ReportThemeCatalog>('/api/report-theme', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
      this.flash(this.t('ui.save.pdf_theme'));
    } catch (error: unknown) { this.error = this.errorText(error); }
    finally { this.saving = false; }
  }
  async openPdf(report: AuditReport, event?: Event): Promise<void> {
    event?.preventDefault();
    if (!report.pdf?.path) return;
    const headers = new Headers({ 'X-BaradWatchU-Token': this.token });
    const response = await fetch(`/api/history/${report.completedAtUnixMs}/pdf`, { headers, cache: 'no-store' });
    if (!response.ok) { this.error = this.t('ui.pdf.open_error').replace('{error}', response.status === 401 ? this.t('ui.error.session_invalid') : this.t('ui.value.unavailable')); return; }
    const url = URL.createObjectURL(await response.blob());
    window.open(url, '_blank', 'noopener');
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
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
    if (response.status === 401) throw new Error(this.t('ui.error.session_invalid'));
    const body: unknown = await response.json();
    if (!response.ok) {
      const detail = typeof body === 'object' && body !== null && 'error' in body ? String(body.error) : `Richiesta non riuscita (${response.status})`;
      throw new Error(detail);
    }
    return body as T;
  }
  private errorText(error: unknown): string {
    if (error instanceof TypeError) return this.t('ui.error.agent_unreachable');
    return error instanceof Error ? error.message : this.t('ui.error.communication');
  }
}

bootstrapApplication(AppComponent).catch((error: unknown) => console.error(error));
