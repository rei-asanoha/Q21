@echo off
rem ---------------------------------------------------------------------------
rem  Portefeuille Q21 — double-cliquez sur ce fichier.
rem ---------------------------------------------------------------------------
rem
rem  Pourquoi ce fichier existe
rem
rem  q21.exe attend qu'on lui dise quoi faire : `init`, `mine`, `wallet`. Le
rem  double-cliquer ouvrait donc une fenetre qui affichait l'aide et se refermait
rem  aussitot — trop vite pour lire quoi que ce soit. Un premier utilisateur y a
rem  bute, et il avait raison : il attendait une application.
rem
rem  Ce fichier lui dit `wallet`, et rien d'autre.
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"
title Portefeuille Q21

if not exist "q21-data\wallet.dat" (
    echo.
    echo   Aucun portefeuille dans ce dossier. On va en creer un.
    echo.
    echo   Une phrase secrete vous sera demandee. Elle ne s'affichera pas
    echo   pendant la frappe : c'est voulu, pour que personne ne la lise
    echo   par-dessus votre epaule. Tapez-la, puis Entree.
    echo.
    echo   Un code de sauvegarde s'affichera ensuite. RECOPIEZ-LE SUR PAPIER.
    echo   C'est le seul moyen de retrouver vos fonds si ce dossier disparait.
    echo.
    pause
    q21.exe init testnet
    if errorlevel 1 (
        echo.
        echo   La creation a echoue. Rien n'a ete ecrit.
        pause
        exit /b 1
    )
    echo.
    echo   Avez-vous recopie le code de sauvegarde sur papier ?
    pause
)

rem ---------------------------------------------------------------------------
rem  Sur l'arret
rem
rem  Un Ctrl-C recu pendant un fichier .bat fait poser par l'interpreteur sa
rem  propre question — « Terminer le programme de commandes (O/N) ? » — a
rem  laquelle les deux reponses ferment la fenetre. Aucune ligne de ce fichier
rem  ne peut l'empecher : c'est l'interpreteur lui-meme, avant de rendre la main
rem  au script. Le premier utilisateur l'a lue comme une panne.
rem
rem  Ce n'en est pas une. Le portefeuille intercepte Ctrl-C, ecrit son etat et
rem  s'arrete ; la question de Windows arrive apres. Mais on ne demande a
rem  personne de faire confiance a un message qui ressemble a une erreur : le
rem  portefeuille offre desormais un bouton « Fermer le portefeuille », et la
rem  fermeture de cette fenetre est egalement interceptee. Les deux voies
rem  laissent l'interpreteur tranquille.
rem ---------------------------------------------------------------------------
q21.exe wallet
if errorlevel 1 pause
