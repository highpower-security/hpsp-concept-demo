# Lancer la démo HPSP

*[English version: RUNNING.md](RUNNING.md)*

La démo se compose de deux programmes Windows qui communiquent entre eux avec le protocole HPSP :

| Programme | Nom du fichier | Rôle |
|---|---|---|
| **Simulateur d'ACU** | `HpspAcuSimulator.exe` | L'unité de contrôle d'accès (le contrôleur). Elle détient les clés du site et la liste d'accès, appaire les lecteurs et décide si une carte ouvre la porte. |
| **Simulateur de lecteur** | `HpspReaderSimulator.exe` | Un lecteur de cartes avec une gâche électrique et un voyant. On saisit un numéro de carte 26 bits et on la « présente ». |

Chacun est un unique fichier `.exe`. Il n'y a rien à installer, et .NET n'est pas nécessaire.

## 1. Choisir le bon téléchargement

Les programmes prêts à l'emploi se trouvent sur la page **Releases** de ce dépôt. Chaque build se présente sous forme de deux fichiers zip, nommés `HPSP-Demo-<version>-build<n>-<type de PC>.zip`, par exemple `HPSP-Demo-0.5.0-build2-win-arm64.zip`. Plus le numéro de build est élevé, plus il est récent. Choisissez le zip qui correspond au processeur de votre PC :

| Votre PC | Téléchargement |
|---|---|
| PC Intel ou AMD ordinaire (la plupart des PC) | le `…-win-x64.zip` |
| PC Arm : Windows sur un Mac à puce Apple (Parallels, VMware Fusion), Surface Pro X / Pro 11, portables Snapdragon | le `…-win-arm64.zip` |

Pour vérifier, ouvrez **Paramètres → Système → Informations système** et regardez le *Type du système*. « Processeur x64 » correspond au téléchargement x64, et « processeur ARM » au téléchargement Arm64. (La version x64 fonctionne aussi sur les PC Arm, plus lentement, en émulation. La barre d'état indique alors « x64 emulated ».)

Systèmes pris en charge : **Windows 11** et **Windows 10**. Sous Windows 10, l'option TLS « Intégré à Windows » est grisée, car Windows 10 n'a pas TLS 1.3. Les programmes utilisent à la place l'option BouncyCastle, qui fonctionne de la même façon.

## 2. Premier lancement : deux invites de Windows

Les programmes ne sont pas signés (c'est une démo), donc Windows pose deux questions au premier lancement :

1. **« Windows a protégé votre ordinateur »** (SmartScreen). Cliquez sur **Informations complémentaires**, puis sur **Exécuter quand même**.
   Si le fichier vient d'Internet, vous pouvez aussi faire un clic droit sur le `.exe`, choisir **Propriétés**, cocher **Débloquer**, puis cliquer sur **OK**.
2. **Le Pare-feu Windows Defender** demande si le programme peut utiliser le réseau. Autorisez les **réseaux privés**. L'ACU écoute sur le port TCP **7500**. Le lecteur écoute sur le port **7501**, mais seulement pendant que sa fenêtre d'appairage est ouverte.
   Si les deux programmes tournent sur le même ordinateur, le pare-feu n'a pas d'importance. Il n'intervient que lorsque le lecteur et l'ACU sont sur des ordinateurs différents.

## 3. Les démarrer : l'ACU d'abord, puis le lecteur

1. Lancez **`HpspAcuSimulator.exe`**.
2. Lancez **`HpspReaderSimulator.exe`**. Lancez-le une seconde fois pour avoir un deuxième lecteur : la seconde copie devient « Reader #2 », avec sa propre identité et le port d'appairage 7511 (un troisième utilise 7521, et ainsi de suite).

Les deux fenêtres ont un panneau **Liste de mise en service** sur la droite. Chaque étape se coche d'elle-même une fois faite, et elle explique ce qui se passe dans le protocole. Le menu **Language / Langue** passe de l'anglais au français.

## 4. Le parcours guidé (environ cinq minutes)

**Dans le simulateur d'ACU**

1. Cliquez sur **Créer un site de démo…** et acceptez les valeurs par défaut. Cela crée le certificat racine du site, le certificat TLS de l'ACU et le signataire des autorisations. Si le lecteur tourne sur un autre ordinateur, choisissez l'adresse réseau de cet ordinateur dans *Adresse que les lecteurs doivent appeler*.
2. L'ACU se met **à l'écoute sur le port 7500**.
3. Dans la **Liste d'accès**, ajoutez deux cartes. Par exemple :
   - Site **142**, carte **54321**, nom *Alice*, **Autorisée** cochée
   - Site **142**, carte **11111**, nom *Bob*, **Autorisée** non cochée

**Dans le simulateur de lecteur**

4. Notez le **code d'appairage** (par exemple `7KQ4-M9TW`). Il est imprimé sur l'étiquette d'un vrai lecteur.
5. Cliquez sur **Ouvrir la fenêtre d'appairage (bouton d'appairage)**. Le lecteur accepte maintenant l'appairage pendant 10 minutes.

**De retour dans le simulateur d'ACU**

6. Cliquez sur **Ajouter un lecteur…** et saisissez :
   - l'adresse `127.0.0.1` (ou celle de l'ordinateur du lecteur),
   - le port d'appairage `7501`,
   - le code d'appairage. À la place du code, vous pouvez coller le texte du QR obtenu avec le bouton **Copier le texte du QR** du lecteur.

   Cliquez ensuite sur **Appairer**. Les fenêtres d'activité montrent SPAKE2+ (`pake_…`), puis TLS avec la clé partagée, puis `attest_request`, `enroll` et `cert_install`.
7. Le lecteur se connecte de lui-même. Il affiche **En ligne**, et l'ACU lui envoie le certificat du signataire des autorisations (`trust_update`).

**Présenter des cartes**

8. Dans le lecteur, saisissez le site **142** et la carte **54321**, puis cliquez sur **Présenter la carte**. L'ACU envoie un `unlock` signé. Le lecteur vérifie l'autorisation, la porte passe au vert (**DÉVERROUILLÉE**) pendant la durée prévue, et le voyant s'allume en vert.
9. Présentez la carte **11111**. Elle est refusée : l'ACU n'émet aucune autorisation, et le voyant clignote en rouge.

**À essayer ensuite**

- **Démo d'attaque** (ACU, lecteur sélectionné) : rejouer la dernière autorisation, en envoyer une expirée, une destinée à la session précédente du lecteur, une modifiée, ou une signée par une clé non approuvée. Le lecteur les refuse toutes et la porte reste verrouillée.
- **Débrancher le câble réseau** (lecteur) : présentez une carte hors ligne, puis rebranchez le câble. La lecture arrive en retard, donc l'ACU la journalise mais n'ouvre aucune porte : la lecture est trop ancienne.
- **Mauvais code d'appairage** : après 5 codes erronés, le lecteur bloque l'appairage pendant 5 minutes (chaque blocage suivant dure deux fois plus longtemps, jusqu'à une heure).
- **Afficher les secrets (démo uniquement)** : affiche les clés, les valeurs SPAKE2+ et la clé pré-partagée dans le volet de détail de la fenêtre d'activité. Un vrai appareil ne les montre jamais.
- Cliquez sur une ligne de la fenêtre d'activité pour voir le message complet en JSON, ainsi que ses octets CBOR transmis.

## 5. Où les données sont conservées, et tout recommencer

Chaque programme conserve ses clés et ses réglages dans `%LOCALAPPDATA%\HPSP Demo\` (dossiers `ACU`, `Reader`, `Reader 2`…). **Fichier → Ouvrir le dossier des données** l'ouvre. Ce sont des clés de démo, conservées dans de simples fichiers. Ne les réutilisez jamais.

- Pour appairer un lecteur avec un autre site, utilisez **Réinitialisation d'usine…** dans le lecteur. Il conserve son identité d'usine et son code d'appairage.
- Pour créer un lecteur entièrement nouveau, utilisez **Nouvel appareil…**.
- Pour tout recommencer, fermez les deux programmes et supprimez le dossier `HPSP Demo`.

Options de ligne de commande facultatives : `--data <dossier>` pour les deux programmes, et `--pairing-port <n>` pour le lecteur.

## 6. Compiler soi-même

Il faut le [SDK .NET 8](https://dotnet.microsoft.com/download/dotnet/8.0) sous Windows. Ensuite :

Chaque programme a son propre dossier source, qui se compile seul :

```
cd demo\AcuSimulator
dotnet run --project HpspAcuSimulator
cd ..\ReaderSimulator
dotnet run --project HpspReaderSimulator
dotnet run --project Tests\Hpsp.Core.Tests      # les tests automatiques
```

Pour produire les fichiers `.exe` autonomes et les zips, utilisez `demo\build\publish.ps1 -Build <n>` (Windows) ou `demo/build/publish.sh <n>` (Linux/macOS), où `<n>` est le numéro de build.
