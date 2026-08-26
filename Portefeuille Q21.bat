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
rem
rem  Ce qu'il ne fait plus
rem
rem  Il portait vingt lignes de preparation : detecter l'absence de portefeuille,
rem  annoncer qu'une phrase secrete allait etre demandee, lancer `init`, attendre
rem  que l'utilisateur confirme avoir recopie un code affiche dans la console.
rem  Tout cela se passe maintenant dans des ecrans, a l'ouverture du navigateur —
rem  voir src/installation.rs. Un fichier de commandes qui explique comment
rem  taper une phrase secrete etait le signe qu'il manquait une interface.
rem
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
rem  portefeuille offre un bouton « Fermer le portefeuille », et la fermeture de
rem  cette fenetre est egalement interceptee.
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"
title Portefeuille Q21

q21.exe wallet
if errorlevel 1 pause
