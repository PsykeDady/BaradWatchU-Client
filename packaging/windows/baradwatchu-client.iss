; BaradWatchU Client: Windows setup (Inno Setup 6).
; Built (and run) by `install.ps1`, which stages the validated build and passes:
;   /DAppVersion=X.Y.Z  /DStageDir=<staged bin + share tree>  /DWithTray=1|0  /O<output dir>
; System-wide installation only (administrator): the complete Client in Program Files for all
; users, Windows service included, installed/updated/removed through
; packaging\service\install-service.ps1 (shipped in {app}\share\baradwatchu-client\service).
; The service is stopped before files change and restarted (and checked) on the new
; executable; a failed or cancelled setup restarts it. There is no per-user mode.
; Setup never generates keys, starts a Server connection or changes the firewall.
; Settings, identities, trust stores, custom checks and audit history live in
; %APPDATA% / %LOCALAPPDATA%\baradwatchu, service registrations in
; %ProgramData%\BaradWatchU\service: setup and uninstall never touch them.

#ifndef AppVersion
  #error AppVersion is required (use install.ps1 -Package)
#endif
#ifndef StageDir
  #error StageDir is required (use install.ps1 -Package)
#endif
#ifndef WithTray
  #define WithTray "1"
#endif

[Setup]
; Fixed AppId: upgrades replace the same installation.
AppId={{8F3D2B6A-4C1E-4B7A-9E52-6D0B1C7A3E94}
AppName=BaradWatchU Client
AppVersion={#AppVersion}
AppVerName=BaradWatchU Client {#AppVersion}
AppPublisher=BaradWatchU
VersionInfoVersion={#AppVersion}
VersionInfoDescription=BaradWatchU Client setup
; All users only (the service needs it); no "only for me" override.
PrivilegesRequired=admin
DefaultDirName={autopf}\BaradWatchU
DisableProgramGroupPage=yes
DefaultGroupName=BaradWatchU
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputBaseFilename=BaradWatchU-Client-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Restart Manager cannot close console programs gracefully: [Code] below refuses to install or
; uninstall while BaradWatchU programs of this folder run, and never terminates them.
CloseApplications=no
UninstallDisplayName=BaradWatchU Client
UninstallDisplayIcon={app}\bin\baradwatchu-agent.exe

[Languages]
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
it.TrayAutostart=Avvia la tray all'accesso
en.TrayAutostart=Start the tray at login
it.Dashboard=Dashboard BaradWatchU
en.Dashboard=BaradWatchU Dashboard
it.DashboardComment=Apre la dashboard locale (chiudi la finestra per fermarla)
en.DashboardComment=Opens the local dashboard (close the window to stop it)
it.Tray=Tray BaradWatchU
en.Tray=BaradWatchU Tray
it.TrayComment=Stato, notifiche e richieste di consenso
en.TrayComment=Status, notifications and consent requests
it.ServiceOther=Il servizio BaradWatchU appartiene a un'altra installazione (%1). Disinstalla prima quella installazione. Nessun file è stato modificato.
en.ServiceOther=The BaradWatchU service belongs to another installation (%1). Uninstall that installation first. No file was changed.
it.ServiceStopFailed=Impossibile fermare il servizio BaradWatchU prima dell'aggiornamento. Nessun file è stato modificato.
en.ServiceStopFailed=The BaradWatchU service could not be stopped before the update. No file was changed.
it.ServiceFailed=I file sono installati, ma il servizio BaradWatchU non è stato installato o avviato ed è fermo (nessun eseguibile vecchio in esecuzione). Da PowerShell amministratore esegui per vedere l'errore:
en.ServiceFailed=The files are installed, but the BaradWatchU service could not be installed or started and is stopped (no old executable is running). From an elevated PowerShell run this to see the error:
it.ServiceRemoveFailed=Impossibile rimuovere il servizio BaradWatchU; rimuovilo con: sc.exe delete BaradWatchU
en.ServiceRemoveFailed=The BaradWatchU service could not be removed; remove it with: sc.exe delete BaradWatchU
it.StillRunning=BaradWatchU è in esecuzione da questa cartella (dashboard o tray). Usa «Chiudi BaradWatchU» nella dashboard o nel menu della tray (o esegui: baradwatchu-agent quit), poi riprova. Nessun file è stato modificato.
en.StillRunning=BaradWatchU is running from this folder (dashboard or tray). Use "Quit BaradWatchU" in the dashboard or the tray menu (or run: baradwatchu-agent quit), then retry. No file was changed.

[Tasks]
#if WithTray == "1"
; Selected by default, offered only on a first installation: an upgrade keeps the user's
; choice (tray menu "Avvia al login"). Not offered while the start-at-login entry belongs to
; another BaradWatchU installation (install.ps1). Silent opt-out: /MERGETASKS="!trayautostart".
Name: "trayautostart"; Description: "{cm:TrayAutostart}"; Check: IsFirstInstall and AutostartFree
#endif

[Files]
Source: "{#StageDir}\bin\baradwatchu-agent.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
#if WithTray == "1"
Source: "{#StageDir}\bin\baradwatchu-tray.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
#endif
Source: "{#StageDir}\share\*"; DestDir: "{app}\share"; Flags: ignoreversion recursesubdirs createallsubdirs
; Service component (installed, updated and removed by every setup run).
Source: "{#SourcePath}..\service\install-service.ps1"; DestDir: "{app}\share\baradwatchu-client\service"; Flags: ignoreversion

[InstallDelete]
; Hashed Angular bundles change name between versions: replace the web folder as a whole.
Type: filesandordirs; Name: "{app}\share\baradwatchu-client\web"
; Every audit reports files that the agent's embedded manifest does not list: replace the
; built-in check folders as a whole so an upgrade never leaves an old check file behind.
Type: filesandordirs; Name: "{app}\share\baradwatchu-client\catalog\checks-windows"

[Icons]
Name: "{group}\{cm:Dashboard}"; Filename: "{app}\bin\baradwatchu-agent.exe"; Parameters: "dashboard"; WorkingDir: "{app}\bin"; Comment: "{cm:DashboardComment}"
#if WithTray == "1"
Name: "{group}\{cm:Tray}"; Filename: "{app}\bin\baradwatchu-tray.exe"; WorkingDir: "{app}\bin"; Comment: "{cm:TrayComment}"
#endif

#if WithTray == "1"
[Run]
; runasoriginaluser: in an all-users installation the entry goes to the user who started setup.
Filename: "{app}\bin\baradwatchu-tray.exe"; Parameters: "autostart enable"; Tasks: trayautostart; Flags: runhidden runasoriginaluser

#endif

[Code]
const
  ServiceName = 'BaradWatchU';
  ServiceKey = 'SYSTEM\CurrentControlSet\Services\BaradWatchU';

var
  { Set when this setup stopped a running service; cleared once the service step ran. }
  ServiceStopped: Boolean;
  ServiceStepDone: Boolean;

{ No uninstall entry for this AppId yet: first installation (HKA = HKLM in admin mode). }
function IsFirstInstall(): Boolean;
begin
  Result := not RegKeyExists(HKA, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8F3D2B6A-4C1E-4B7A-9E52-6D0B1C7A3E94}_is1');
end;

function AgentPath(): String;
begin
  Result := ExpandConstant('{app}\bin\baradwatchu-agent.exe');
end;

function PowerShell(const Arguments: String): Boolean;
var
  Code: Integer;
begin
  // sysnative constant = the 64-bit PowerShell. The setup itself is a 32-bit process, and a
  // 32-bit PowerShell sees ProgramFiles as "Program Files (x86)" (install-service.ps1 then
  // refused the x64 agent in "Program Files").
  Result := Exec(ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' + Arguments, '', SW_HIDE,
    ewWaitUntilTerminated, Code) and (Code = 0);
  Log('powershell ' + Arguments + ': ' + IntToStr(Code));
end;

{ The installed service, if any, runs this installation's agent. }
function OurServiceInstalled(): Boolean;
var
  ImagePath: String;
begin
  Result := IsAdminInstallMode and RegQueryStringValue(HKLM, ServiceKey, 'ImagePath', ImagePath)
    and (Pos(Lowercase(AgentPath()), Lowercase(ImagePath)) > 0);
end;

{ Image path of a service registered by another installation, or ''. }
function OtherServicePath(): String;
var
  ImagePath: String;
begin
  Result := '';
  if IsAdminInstallMode and RegQueryStringValue(HKLM, ServiceKey, 'ImagePath', ImagePath)
    and (Pos(Lowercase(AgentPath()), Lowercase(ImagePath)) = 0) then
    Result := ImagePath;
end;

function ServiceRunning(): Boolean;
begin
  Result := PowerShell('-Command "if ((Get-Service -Name ' + ServiceName + ').Status -eq ''Running'') { exit 0 } else { exit 3 }"');
end;

{ Stops this installation's running service before files change (no file has been touched). }
function StopOurService(): Boolean;
begin
  Result := True;
  if OurServiceInstalled() and ServiceRunning() then
  begin
    // Judged by the final state, not by Stop-Service's own result: agents up to 0.0.1 exited
    // inside the stop handler, so the SCM reported an error although the service stopped.
    // The short sleep lets the process end after reporting STOPPED, before files change.
    Result := PowerShell('-Command "Stop-Service -Name ' + ServiceName + ' -ErrorAction SilentlyContinue; (Get-Service -Name ' + ServiceName + ').WaitForStatus(''Stopped'', [TimeSpan]::FromSeconds(30)); Start-Sleep -Milliseconds 800"');
    ServiceStopped := Result;
  end;
end;

{ Failed or cancelled setup/uninstall: start the stopped service again on the files in place. }
procedure RestoreService();
begin
  if ServiceStopped and not ServiceStepDone then
  begin
    ServiceStopped := False;
    PowerShell('-Command "Start-Service -Name ' + ServiceName + '"');
  end;
end;

function ServiceScript(const Arguments: String): Boolean;
begin
  Result := PowerShell('-File "' + ExpandConstant('{app}\share\baradwatchu-client\service\install-service.ps1') + '" -Agent "' + AgentPath() + '" ' + Arguments);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and IsAdminInstallMode then
  begin
    ServiceStepDone := True;
    { The service is always installed or updated. }
    if not ServiceScript('') then
    begin
      ServiceScript('-Stop');
      SuppressibleMsgBox(CustomMessage('ServiceFailed') + #13#10 + '"' + ExpandConstant('{app}\share\baradwatchu-client\service\install-service.ps1') + '"', mbError, MB_OK, IDOK);
    end;
  end;
end;

procedure DeinitializeSetup();
begin
  RestoreService();
end;

{ Command of the per-user start-at-login entry shared by every BaradWatchU installation, or ''. }
function AutostartCommand(): String;
begin
  if not RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'BaradWatchU-Tray', Result) then
    Result := '';
end;

{ The entry starts this installation's tray (path compared case-insensitively). }
function AutostartIsOurs(): Boolean;
begin
  Result := Pos(Lowercase(AddBackslash(ExpandConstant('{app}'))), Lowercase(AutostartCommand())) > 0;
end;

{ No entry yet, or already this installation's: the default task may set it. }
function AutostartFree(): Boolean;
begin
  Result := (AutostartCommand() = '') or AutostartIsOurs();
end;

{ Counts BaradWatchU programs running from Dir (WMI, current user's view). Never stops them. }
function RunningFrom(const Dir: String): Integer;
var
  Locator, Service, Items, Item: Variant;
  I: Integer;
  Path, Prefix: String;
begin
  Result := 0;
  Prefix := Lowercase(AddBackslash(Dir));
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Service := Locator.ConnectServer('.', 'root\CIMV2');
    Items := Service.ExecQuery('SELECT ExecutablePath FROM Win32_Process WHERE Name = ''baradwatchu-agent.exe'' OR Name = ''baradwatchu-tray.exe''');
    for I := 0 to Items.Count - 1 do
    begin
      Item := Items.ItemIndex(I);
      if not VarIsNull(Item.ExecutablePath) then
      begin
        Path := Item.ExecutablePath;
        Path := Lowercase(Path);
        if Pos(Prefix, Path) = 1 then
          Result := Result + 1;
      end;
    end;
  except
    Result := 0;
  end;
end;

{ Upgrade: stop this installation's service, then refuse while other programs of the target
  folder run (no file has been touched yet; the service is started again on refusal). }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  { One service per machine: never take over another installation's one. }
  if OtherServicePath() <> '' then
  begin
    Result := FmtMessage(CustomMessage('ServiceOther'), [OtherServicePath()]);
    exit;
  end;
  if not StopOurService() then
  begin
    Result := CustomMessage('ServiceStopFailed');
    exit;
  end;
  if RunningFrom(ExpandConstant('{app}')) > 0 then
  begin
    Result := CustomMessage('StillRunning');
    RestoreService();
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := StopOurService();
  if not Result then
  begin
    SuppressibleMsgBox(CustomMessage('ServiceStopFailed'), mbError, MB_OK, IDOK);
    exit;
  end;
  Result := RunningFrom(ExpandConstant('{app}')) = 0;
  if not Result then
  begin
    SuppressibleMsgBox(CustomMessage('StillRunning'), mbError, MB_OK, IDOK);
    RestoreService();
  end;
end;

{ Uninstall: remove the per-user start-at-login entry only when it starts this installation's
  tray (another BaradWatchU installation may own it). Done here, not in [UninstallRun]: a Check
  there is evaluated at install time, before the entry exists. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usUninstall) and AutostartIsOurs() then
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'BaradWatchU-Tray');
  { Before any file is deleted: remove this installation's service (registrations in
    %ProgramData%\BaradWatchU\service and user identities are kept). }
  if (CurUninstallStep = usUninstall) and OurServiceInstalled() then
  begin
    ServiceStepDone := True;
    if not ServiceScript('-Uninstall') then
      SuppressibleMsgBox(CustomMessage('ServiceRemoveFailed'), mbError, MB_OK, IDOK);
  end;
end;

procedure DeinitializeUninstall();
begin
  RestoreService();
end;
