# IPSymconAdGuardHome

[![IPS-Version](https://img.shields.io/badge/Symcon_Version-6.2+-red.svg)](https://www.symcon.de/service/dokumentation/entwicklerbereich/sdk-tools/sdk-php/)
![Code](https://img.shields.io/badge/Code-PHP-blue.svg)
[![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-green.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

## Dokumentation

**Inhaltsverzeichnis**

1. [Funktionsumfang](#1-funktionsumfang)
2. [Voraussetzungen](#2-voraussetzungen)
3. [Installation](#3-installation)
4. [Funktionsreferenz](#4-funktionsreferenz)
5. [Konfiguration](#5-konfiguration)
6. [Anhang](#6-anhang)
7. [Versions-Historie](#7-versions-historie)

## 1. Funktionsumfang

Mittels dieses Moduls kann man den Werbeblocker [AdGuradHome](https://adguard.com/de/adguard-home/overview.html) in IP-Symcon einbinden.<br>
Das umfasst:
- Aktivieren/Deaktivierne des Schutzes
- Anzeige einiger wichtiger Variablen

Siehe auch [hier](https://github.com/AdguardTeam/AdGuardHome).

## 2. Voraussetzungen

- IP-Symcon ab Version 6.2
- Instanz vom AdGuard Home

## 3. Installation

### a. Installation des Moduls

Im [Module Store](https://www.symcon.de/service/dokumentation/komponenten/verwaltungskonsole/module-store/) ist das Modul unter dem Suchbegriff *AdGuard Home* zu finden.<br>
Alternativ kann das Modul über [Module Control](https://www.symcon.de/service/dokumentation/modulreferenz/module-control/) unter Angabe der URL `https://github.com/demel42/IPSymcomAdGuardHome` installiert werden.

### b. Einrichtung in IPS

## 4. Funktionsreferenz

alle Funktionen sind über _RequestAction_ der jew. Variablen ansteuerbar

`AdGuardHome_SwitchEnableProtection(int $InstanzID, bool $mode)`
Aktiviert/deaktiviert den Schutz.

## 5. Konfiguration

### IPSymcomAdGuardHome

#### Properties

| Eigenschaft               | Typ      | Standardwert | Beschreibung |
| :------------------------ | :------  | :----------- | :----------- |
| Instanz deaktivieren      | boolean  | false        | Instanz temporär deaktivieren |
|                           |          |              | |
| Host                      | string   |              | Hostname/IP-Adresse der AdGuardHome-Instanz |
| HTTPS benutzen            | boolean  | false        | HTTPS benutzen |
|                           |          |              | |
| Benutzer                  | string   |              | AdGuard-Benutzer mit entsprechender Berechtigung |
| Passwort                  | string   |              | zugrhöriges Passwort |
|                           |          |              | |
| Aktualisierungsintervall  | integer  | 60           | Intervall in Sekunden |

#### Aktionen

| Bezeichnung                | Beschreibung |
| :------------------------- | :----------- |
| Aktulisiere Status         | Daten abrufen |

### Variablenprofile

Es werden folgende Variablenprofile angelegt:
* Boolean<br>
* Integer<br>
* Float<br>
AdGuardHome.ms,
AdGuardHome.Rate
* String<br>

## 6. Anhang

### GUIDs
- Modul: `{F411A1B4-EE35-BCF6-41A3-0B6247381842}`
- Instanzen:
  - AdGuardHome: `{FE7566FC-ECA0-78E8-5114-C4C217231642}`
- Nachrichten:

### Quellen

## 7. Versions-Historie

- 1.1.1 @ 07.10.2022 13:59
  - update submodule CommonStubs
    Fix: Update-Prüfung wieder funktionsfähig

- 1.1 @ 14.07.2022 17:48
  - Fix: Division durch Null (vorzugsweise um 0 Uhr)

- 1.0 @ 12.07.2022 18:09
  - Initiale Version
