; BaradWatchU Client: per-user Windows setup (Inno Setup 6).
; Built by `install.ps1 -Package`, which stages the validated build and passes:
;   /DAppVersion=X.Y.Z  /DStageDir=<staged bin + share tree>  /DWithTray=1|0  /O<output dir>
; No administrator rights, no service, no system settings: files go to
; %LOCALAPPDATA%\Programs\BaradWatchU, entries to the user's Start menu and the
; uninstaller to Settings > Apps. Settings, custom checks and audit history live in
; %APPDATA% / %LOCALAPPDATA%\baradwatchu and are never touched by setup or uninstall.

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
; Fixed AppId: upgrades replace the same installation. install.ps1 refuses a -Prefix owned by it.
AppId={{8F3D2B6A-4C1E-4B7A-9E52-6D0B1C7A3E94}
AppName=BaradWatchU Client
AppVersion={#AppVersion}
AppVerName=BaradWatchU Client {#AppVersion}
AppPublisher=BaradWatchU
VersionInfoVersion={#AppVersion}
VersionInfoDescription=BaradWatchU Client setup
PrivilegesRequired=lowest
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
it.StillRunning=BaradWatchU è in esecuzione da questa cartella (dashboard o tray). Chiudi la dashboard (Ctrl+C o chiudi la sua finestra) e la tray (menu della tray › Chiudi tray), poi riprova. Nessun file è stato modificato.
en.StillRunning=BaradWatchU is running from this folder (dashboard or tray). Close the dashboard (Ctrl+C or close its window) and the tray (tray menu › Close tray), then retry. No file was changed.

#if WithTray == "1"
[Tasks]
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
Filename: "{app}\bin\baradwatchu-tray.exe"; Parameters: "autostart enable"; Tasks: trayautostart; Flags: runhidden

#endif

[Code]
{ No uninstall entry for this AppId yet: first installation for the current user. }
function IsFirstInstall(): Boolean;
begin
  Result := not RegKeyExists(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8F3D2B6A-4C1E-4B7A-9E52-6D0B1C7A3E94}_is1');
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

{ Upgrade: refuse while programs of the target folder run (no file has been touched yet). }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if RunningFrom(ExpandConstant('{app}')) > 0 then
    Result := CustomMessage('StillRunning');
end;

function InitializeUninstall(): Boolean;
begin
  Result := RunningFrom(ExpandConstant('{app}')) = 0;
  if not Result then
    SuppressibleMsgBox(CustomMessage('StillRunning'), mbError, MB_OK, IDOK);
end;

{ Uninstall: remove the per-user start-at-login entry only when it starts this installation's
  tray (another BaradWatchU installation may own it). Done here, not in [UninstallRun]: a Check
  there is evaluated at install time, before the entry exists. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usUninstall) and AutostartIsOurs() then
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'BaradWatchU-Tray');
end;
