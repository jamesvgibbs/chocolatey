#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
#NoTrayIcon
; #Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.
WinWait, Zoiper5 Setup, , 60
WinActivate
BlockInput On
Sleep, 500      ; wait for space calculation
Send !n
Sleep, 500
Send !a
Send !n
Sleep, 500
Send !n
Sleep, 500
Send !i
BlockInput Off
WinWait, Zoiper Setup,Click the Finish button to exit the Setup Wizard
WinActivate
Send !f