; Windows installer for Claude Code Backdoor Hunter (NSIS 3, Modern UI 2).
; Bundles the C checker (hunter.exe), the C GTK4 GUI (hunter-gui.exe) and the GTK4 runtime.
; Build with: make windows
Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

!ifndef VERSION
  !define VERSION "1.0.0"
!endif
!ifndef ROOT
  !define ROOT "..\.."
!endif

!define APP "Claude Code Backdoor Hunter"
!define UNKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeCodeBackdoorHunter"

Name "${APP}"
OutFile "${ROOT}\dist\claude-code-backdoor-hunter-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\${APP}"
InstallDirRegKey HKLM "Software\ClaudeCodeBackdoorHunter" "InstallDir"
RequestExecutionLevel admin
BrandingText "${APP} ${VERSION}"

!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_ABORTWARNING
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "header.bmp"
!define MUI_HEADERIMAGE_RIGHT
!define MUI_WELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_WELCOMEPAGE_TITLE "${APP} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "This installs a read-only checker for the trojanized anthropic.claude-code 2.1.313 extension (SSH backdoor).$\r$\n$\r$\nIt does not change or remove anything on your computer."
!define MUI_FINISHPAGE_RUN "$INSTDIR\bin\hunter-gui.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Open ${APP}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${ROOT}\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "Windows 10 or later is required."
    Abort
  ${EndIf}
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "A 64-bit version of Windows is required."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

Section "Install"
  SetOutPath "$INSTDIR"
  File /r "${ROOT}\build\win-stage\*.*"
  File "${ROOT}\README.md"
  File "${ROOT}\LICENSE"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateDirectory "$SMPROGRAMS\${APP}"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP}.lnk" "$INSTDIR\bin\hunter-gui.exe" "" "$INSTDIR\bin\hunter-gui.exe" 0
  CreateShortcut "$SMPROGRAMS\${APP}\Command-line scan.lnk" "$SYSDIR\cmd.exe" '/k "$INSTDIR\bin\hunter.exe"' "$INSTDIR\bin\hunter-gui.exe" 0
  CreateShortcut "$SMPROGRAMS\${APP}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\ClaudeCodeBackdoorHunter" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNKEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNKEY}" "Publisher" "Prometheus Systems"
  WriteRegStr HKLM "${UNKEY}" "DisplayIcon" "$INSTDIR\bin\hunter-gui.exe"
  WriteRegStr HKLM "${UNKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "${UNKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNKEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  RMDir /r "$INSTDIR\bin"
  RMDir /r "$INSTDIR\lib"
  RMDir /r "$INSTDIR\share"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\${APP}\*.lnk"
  RMDir "$SMPROGRAMS\${APP}"
  DeleteRegKey HKLM "${UNKEY}"
  DeleteRegKey HKLM "Software\ClaudeCodeBackdoorHunter"
SectionEnd
