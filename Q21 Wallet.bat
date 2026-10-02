@echo off
rem ---------------------------------------------------------------------------
rem  Q21 Wallet: double-click this file.
rem ---------------------------------------------------------------------------
rem
rem  Why this file exists
rem
rem  q21.exe waits to be told what to do: `init`, `mine`, `wallet`. Double-
rem  clicking it therefore opened a window that displayed the help and closed
rem  immediately, too fast to read anything. A first user ran into it, and he
rem  was right: he expected an application.
rem
rem  This file tells it `wallet`, and nothing else.
rem
rem  What it no longer does
rem
rem  It used to carry twenty lines of preparation: detect that there was no
rem  wallet, announce that a passphrase was about to be requested, run `init`,
rem  wait for the user to confirm they had copied down a code shown in the
rem  console. All of that now happens in screens, when the browser opens; see
rem  src/setup.rs. A command file that explains how to type a passphrase was
rem  the sign that an interface was missing.
rem
rem  About shutdown
rem
rem  A Ctrl-C received during a .bat file makes the interpreter ask its own
rem  question, "Terminate batch job (Y/N)?", to which both answers close the
rem  window. No line of this file can prevent it: it is the interpreter
rem  itself, before handing control back to the script. The first user read
rem  it as a crash.
rem
rem  It is not one. The wallet intercepts Ctrl-C, writes its state and shuts
rem  down; the Windows question comes afterwards. But no one is asked to trust
rem  a message that looks like an error: the wallet offers a "Close the
rem  wallet" button, and closing this window is intercepted as well.
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"
title Q21 Wallet

q21.exe wallet
if errorlevel 1 pause
