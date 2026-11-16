// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Localization/FrenchUi.cs
//  Purpose: French text for the two windows, their dialogs and the
//           provisioning checklist (and a few later engine messages).
//           Same rules as French.cs: key = English exactly as in the code.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================

namespace Hpsp.Core.Localization;

internal static partial class French
{
    static partial void AddUiText(Dictionary<string, string> d)
    {
        void A(string en, string fr) => d[en] = fr;

        // ---- menus ----
        A("&File", "&Fichier");
        A("&View", "&Affichage");
        A("&Help", "&Aide");
        A("&Language", "&Langue");
        A("About", "À propos");
        A("E&xit", "&Quitter");
        A("Open the data folder", "Ouvrir le dossier des données");
        A("Show secrets (keys, pairing values) in this window - demo only", "Afficher les secrets (clés, valeurs d'appairage) dans cette fenêtre - démo uniquement");
        A("Show secrets", "Afficher les secrets");
        A("Secrets are hidden. Turn on \"Show secrets\" to view them?\n\nThis also shows the secret values (keys, pairing values) in the activity window's details, and puts up the red banner.", "Les secrets sont masqués. Activer « Afficher les secrets » pour les voir ?\n\nCela affiche aussi les valeurs secrètes (clés, valeurs d'appairage) dans les détails de la fenêtre d'activité, et fait apparaître le bandeau rouge.");
        A("View secrets…", "Voir les secrets…");
        A("View this reader's secrets…", "Voir les secrets de ce lecteur…");
        A("View the ACU's secrets…", "Voir les secrets de l'ACU…");
        A("Reader secrets (demo only)", "Secrets du lecteur (démo uniquement)");
        A("ACU secrets (demo only)", "Secrets de l'ACU (démo uniquement)");
        A("Provisioning checklist", "Liste de mise en service");
        A("SECRETS VISIBLE (demo only). A real device never shows its keys or codes. Do not use these keys for anything else.", "SECRETS VISIBLES (démo uniquement). Un vrai appareil n'affiche jamais ses clés ni ses codes. N'utilisez ces clés pour rien d'autre.");

        // ---- titles and About ----
        A("HPSP Reader Simulator", "Simulateur de lecteur HPSP");
        A("HPSP ACU Simulator", "Simulateur d'ACU HPSP");
        A("HPSP Reader Simulator, version 0.5.0 (demo).\n\nA teaching demo of the High Performance Security Protocol: a simulated card reader that pairs with an ACU, reports 26-bit card swipes over TLS 1.3, and opens its door only for a valid signed grant.\n\nCopyright (c) 2026 Highpower Security Products LLC. Apache License 2.0.\nUses BouncyCastle (MIT licence) and QRCoder (MIT licence).",
          "Simulateur de lecteur HPSP, version 0.5.0 (démo).\n\nUne démonstration pédagogique du protocole HPSP (High Performance Security Protocol) : un lecteur de cartes simulé qui s'appaire avec une ACU, transmet les lectures de cartes 26 bits sur TLS 1.3 et n'ouvre sa porte que sur une autorisation signée valide.\n\nCopyright (c) 2026 Highpower Security Products LLC. Licence Apache 2.0.\nUtilise BouncyCastle (licence MIT) et QRCoder (licence MIT).");
        A("HPSP ACU Simulator, version 0.5.0 (demo).\n\nA teaching demo of the High Performance Security Protocol: a simulated access control unit that pairs readers, keeps an access list, and sends signed grants to open doors over TLS 1.3.\n\nCopyright (c) 2026 Highpower Security Products LLC. Apache License 2.0.\nUses BouncyCastle (MIT licence).",
          "Simulateur d'ACU HPSP, version 0.5.0 (démo).\n\nUne démonstration pédagogique du protocole HPSP (High Performance Security Protocol) : une unité de contrôle d'accès simulée qui appaire des lecteurs, tient une liste d'accès et envoie des autorisations signées pour ouvrir les portes sur TLS 1.3.\n\nCopyright (c) 2026 Highpower Security Products LLC. Licence Apache 2.0.\nUtilise BouncyCastle (licence MIT).");

        // ---- activity window ----
        A("Activity", "Activité");
        A("Time", "Heure");
        A("Channel", "Canal");
        A("Peer", "Pair");
        A("What happened", "Ce qui s'est passé");
        A("Hide heartbeats and fragments", "Masquer les signaux de vie et les fragments");
        A("Follow newest", "Suivre les plus récents");
        A("Pause", "Pause");
        A("Resume ({0} waiting)", "Reprendre ({0} en attente)");
        A("Clear", "Effacer");
        A("Save…", "Enregistrer…");
        A("Text files", "Fichiers texte");
        A("Select a line to see the full message (as JSON) and its CBOR bytes on the wire.", "Sélectionnez une ligne pour voir le message complet (en JSON) et ses octets CBOR transmis.");

        // ---- checklist panel ----
        A("Done (ticked by hand)", "Fait (coché à la main)");
        A("Start the checklist again", "Recommencer la liste");
        A("{0} of {1} steps done", "{0} étape(s) sur {1} terminée(s)");

        // ---- TLS engine picker ----
        A("TLS engine for sessions", "Moteur TLS des sessions");
        A("Windows built-in", "intégré à Windows");
        A("Windows built-in (SChannel)", "Intégré à Windows (SChannel)");
        A("BouncyCastle (post-quantum key exchange; works on Windows 10 too)", "BouncyCastle (échange de clés post-quantique ; fonctionne aussi sous Windows 10)");
        A("Pairing always uses BouncyCastle, because it needs TLS with a pre-shared key. BouncyCastle offers hybrid post-quantum key exchange (ML-KEM) first; Windows uses it only if its own TLS has been updated for it.", "L'appairage utilise toujours BouncyCastle, car il nécessite TLS avec une clé pré-partagée. BouncyCastle propose en priorité l'échange de clés hybride post-quantique (ML-KEM) ; Windows ne l'utilise que si son propre TLS a été mis à jour en conséquence.");
        A("Key exchange: {0}", "Échange de clés : {0}");
        A("not reported by the Windows TLS engine", "non communiqué par le moteur TLS de Windows");
        A("hybrid post-quantum", "hybride post-quantique");
        A("classical", "classique");
        A("Test the selected engine", "Tester le moteur choisi");
        A("TLS engine self-test", "Autotest du moteur TLS");
        A("The TLS 1.3 built into Windows 11.", "Le TLS 1.3 intégré à Windows 11.");
        A("Pairing always uses BouncyCastle, because it needs TLS with a pre-shared key.", "L'appairage utilise toujours BouncyCastle, car il nécessite TLS avec une clé pré-partagée.");
        A("Windows built-in TLS is not available here: this version of Windows has no TLS 1.3. BouncyCastle is used instead.", "Le TLS intégré à Windows n'est pas disponible ici : cette version de Windows n'a pas TLS 1.3. BouncyCastle est utilisé à la place.");
        A("The {0} TLS engine works on this computer (TLS 1.3 handshake on this machine).", "Le moteur TLS {0} fonctionne sur cet ordinateur (négociation TLS 1.3 sur cette machine).");
        A("The {0} TLS engine failed its self-test:\n\n{1}", "Le moteur TLS {0} a échoué à son autotest :\n\n{1}");
        A("TLS: {0}", "TLS : {0}");
        A("TLS: {0}, {1}", "TLS : {0}, {1}");
        A("the TLS handshake took too long", "la négociation TLS a pris trop de temps");

        // ---- reader window ----
        A("This reader", "Ce lecteur");
        A("Device ID (from the factory):", "Identifiant de l'appareil (d'usine) :");
        A("Serial number: {0}", "Numéro de série : {0}");
        A("Setup code (printed on the label):", "Code d'appairage (imprimé sur l'étiquette) :");
        A("Copy QR text (to paste into the ACU)", "Copier le texte du QR (à coller dans l'ACU)");
        A("Copied", "Copié");
        A("Pairing", "Appairage");
        A("Paired", "Appairé");
        A("Not paired", "Non appairé");
        A("Pairing locked", "Appairage bloqué");
        A("Site {0}\nACU address: {1}", "Site {0}\nAdresse de l'ACU : {1}");
        A("Too many wrong setup codes. Try again at {0:T}.", "Trop de codes d'appairage erronés. Réessayez à {0:T}.");
        A("Pairing window open ({0} left)", "Fenêtre d'appairage ouverte (reste {0})");
        A("Listening on port {0}. Add this reader from the ACU now. Wrong codes so far: {1} of {2}.", "À l'écoute sur le port {0}. Ajoutez maintenant ce lecteur depuis l'ACU. Codes erronés jusqu'ici : {1} sur {2}.");
        A("Close pairing window", "Fermer la fenêtre d'appairage");
        A("Press the pairing button to let an ACU pair with this reader (pairing port {0}).", "Appuyez sur le bouton d'appairage pour permettre à une ACU de s'appairer avec ce lecteur (port d'appairage {0}).");
        A("Wrong codes so far: {0} of {1}.", "Codes erronés jusqu'ici : {0} sur {1}.");
        A("Open pairing window (press the pairing button)", "Ouvrir la fenêtre d'appairage (bouton d'appairage)");
        A("Connection to the ACU", "Connexion à l'ACU");
        A("Network cable unplugged", "Câble réseau débranché");
        A("Online", "En ligne");
        A("Offline", "Hors ligne");
        A("Status: {0}", "État : {0}");
        A("Session value: {0}", "Valeur de session : {0}");
        A("Trust list: epoch {0}, {1} grant signer(s)", "Liste de confiance : époque {0}, {1} signataire(s) des autorisations");
        A("Events waiting for acknowledgement: {0}", "Événements en attente d'acquittement : {0}");
        A("Grant counter floor: {0}", "Plancher du compteur d'autorisations : {0}");
        A("Plug the network cable back in", "Rebrancher le câble réseau");
        A("Pull network cable (simulate an outage)", "Débrancher le câble réseau (simuler une coupure)");
        A("Card (26-bit H10301)", "Carte (26 bits H10301)");
        A("Facility", "Site (FC)");
        A("Card", "Carte");
        A("Swipe card", "Présenter la carte");
        A("26 bits (parity, facility, card, parity):\n{0}\nAs sent: {1}", "26 bits (parité, code site, carte, parité) :\n{0}\nTel qu'envoyé : {1}");
        A("Door and LED", "Porte et voyant");
        A("UNLOCKED", "DÉVERROUILLÉE");
        A("LOCKED", "VERROUILLÉE");
        A("LED: off", "Voyant : éteint");
        A("LED: {0}, {1}", "Voyant : {0}, {1}");
        A("Device", "Appareil");
        A("Factory reset…", "Réinitialisation d'usine…");
        A("Factory reset", "Réinitialisation d'usine");
        A("Factory reset removes this reader's site certificate and site settings. It keeps its factory identity and setup code, so it can be paired again.\n\nReset now?", "La réinitialisation d'usine supprime le certificat de site et les réglages de site de ce lecteur. Il conserve son identité d'usine et son code d'appairage, et peut donc être appairé à nouveau.\n\nRéinitialiser maintenant ?");
        A("New device…", "Nouvel appareil…");
        A("New device", "Nouvel appareil");
        A("Make this a brand-new simulated reader: new device ID, new factory identity and new setup code. The current one is forgotten (an ACU that paired it will no longer recognise it).\n\nContinue?", "Faire de ce lecteur simulé un appareil neuf : nouvel identifiant, nouvelle identité d'usine et nouveau code d'appairage. L'actuel est oublié (une ACU qui l'avait appairé ne le reconnaîtra plus).\n\nContinuer ?");
        A("{0}   ACU {1}", "{0}   ACU {1}");
        A("This reader is already paired: the pairing button is ignored. Use Factory reset to pair it with another site.", "Ce lecteur est déjà appairé : le bouton d'appairage est ignoré. Utilisez la réinitialisation d'usine pour l'appairer à un autre site.");
        A("Pairing stopped after an unexpected error: ", "Appairage arrêté après une erreur inattendue : ");
        A("too many wrong codes", "trop de codes erronés");
        A("Refused a second pairing connection from {0}: one attempt at a time.", "Seconde connexion d'appairage depuis {0} refusée : une seule tentative à la fois.");
        A("this reader has been removed", "ce lecteur a été retiré");
        A("Something went wrong, but the program can continue.\n\n{0}\n\nIf this keeps happening, please report it with this message.", "Un problème est survenu, mais le programme peut continuer.\n\n{0}\n\nSi cela se reproduit, merci de le signaler avec ce message.");
        A("The reader is busy with another pairing attempt; trying again…", "Le lecteur traite une autre tentative d'appairage ; nouvel essai…");
        A("trust_update refused: ", "trust_update refusé : ");
        A("{0} card read(s) from before the restart were discarded (card reads are not kept across a restart).", "{0} lecture(s) de carte antérieure(s) au redémarrage ont été abandonnée(s) (les lectures de carte ne sont pas conservées après un redémarrage).");

        // ---- reader checklist ----
        A("Note the setup code", "Noter le code d'appairage");
        A("A real reader has its setup code printed on a label (often also as a QR code). The installer types it into the ACU, or scans it. The code itself never crosses the network: the two sides use it in SPAKE2+, which proves both know it without revealing it.",
          "Un vrai lecteur porte son code d'appairage sur une étiquette (souvent aussi sous forme de code QR). L'installateur le saisit dans l'ACU ou le scanne. Le code lui-même ne transite jamais sur le réseau : les deux parties l'utilisent dans SPAKE2+, qui prouve que chacune le connaît sans le révéler.");
        A("Press the pairing button", "Appuyer sur le bouton d'appairage");
        A("Click \"Open pairing window\". This stands for a button inside the reader's case: it proves someone is physically at the device. Only now does the reader listen for pairing (port shown in the Pairing panel), for 10 minutes. After 5 wrong codes it locks pairing for 5 minutes.",
          "Cliquez sur « Ouvrir la fenêtre d'appairage ». Cela représente un bouton à l'intérieur du boîtier du lecteur : il prouve que quelqu'un est physiquement devant l'appareil. Ce n'est qu'à ce moment que le lecteur écoute les demandes d'appairage (port indiqué dans le panneau Appairage), pendant 10 minutes. Après 5 codes erronés, il bloque l'appairage pendant 5 minutes.");
        A("Add the reader from the ACU", "Ajouter le lecteur depuis l'ACU");
        A("In the ACU Simulator, click \"Add reader…\" and give this computer's address, the pairing port and the setup code (or paste the QR text). Watch the activity: pake_params and pake_share (SPAKE2+), then TLS with the shared key, then attest_request, enroll and cert_install.",
          "Dans le simulateur d'ACU, cliquez sur « Ajouter un lecteur… » et indiquez l'adresse de cet ordinateur, le port d'appairage et le code d'appairage (ou collez le texte du QR). Observez l'activité : pake_params et pake_share (SPAKE2+), puis TLS avec la clé partagée, puis attest_request, enroll et cert_install.");
        A("Reader connects to the ACU", "Le lecteur se connecte à l'ACU");
        A("Once it has a site certificate the reader dials the ACU (port 7500) over TLS 1.3 with mutual certificates, and sends hello with a fresh 32-byte session value. Every grant for this session must include that value. The Connection panel shows the key exchange: SecP256r1MLKEM768 is hybrid post-quantum, so a recording of this session stays private even from a future quantum computer.",
          "Une fois muni d'un certificat de site, le lecteur appelle l'ACU (port 7500) sur TLS 1.3 avec authentification mutuelle par certificats, et envoie hello avec une nouvelle valeur de session de 32 octets. Toute autorisation pour cette session doit inclure cette valeur. Le panneau Connexion indique l'échange de clés : SecP256r1MLKEM768 est hybride post-quantique, de sorte qu'un enregistrement de cette session reste confidentiel même face à un futur ordinateur quantique.");
        A("Receive the trust list", "Recevoir la liste de confiance");
        A("The ACU sends trust_update with the grant signer's certificate. From now on the reader opens its door only for grants signed by that key, for this reader, for this session, with a counter it has not seen before.",
          "L'ACU envoie trust_update avec le certificat du signataire des autorisations. Désormais, le lecteur n'ouvre sa porte que pour des autorisations signées par cette clé, destinées à ce lecteur et à cette session, avec un compteur qu'il n'a encore jamais vu.");
        A("Swipe a card", "Présenter une carte");
        A("Enter a facility code and card number and click Swipe. The reader packs them as 26-bit H10301 Wiegand data and sends a credential event. The reader itself decides nothing: the ACU checks its access list.",
          "Saisissez un code site et un numéro de carte, puis cliquez sur Présenter. Le lecteur les encode en données Wiegand 26 bits H10301 et envoie un événement credential. Le lecteur ne décide rien lui-même : c'est l'ACU qui consulte sa liste d'accès.");
        A("See the door open (or not)", "Voir la porte s'ouvrir (ou non)");
        A("For an allowed card the ACU sends unlock with a signed grant and turns the LED green; the reader checks the grant and opens the door for the unlock time. For a refused card the LED flashes red and the door stays locked. Try both.",
          "Pour une carte autorisée, l'ACU envoie unlock avec une autorisation signée et allume le voyant en vert ; le lecteur vérifie l'autorisation et ouvre la porte pendant la durée prévue. Pour une carte refusée, le voyant clignote en rouge et la porte reste verrouillée. Essayez les deux.");
        A("Pull the network cable", "Débrancher le câble réseau");
        A("Click \"Pull network cable\", swipe a card while offline, then plug the cable back in. The reader keeps events until the ACU acknowledges them, so the offline swipe is replayed after reconnecting. (The ACU logs it but opens no door: the card read is too old.)",
          "Cliquez sur « Débrancher le câble réseau », présentez une carte hors ligne, puis rebranchez le câble. Le lecteur conserve les événements jusqu'à leur acquittement par l'ACU : la lecture faite hors ligne est donc renvoyée après la reconnexion. (L'ACU la journalise mais n'ouvre aucune porte : la lecture est trop ancienne.)");

        // ---- ACU window ----
        A("Site", "Site");
        A("No site yet", "Pas encore de site");
        A("Create a demo site to make the keys and certificates.", "Créez un site de démo pour générer les clés et les certificats.");
        A("Create demo site…", "Créer un site de démo…");
        A("Create a new demo site…", "Créer un nouveau site de démo…");
        A("Site ID: {0}", "Identifiant du site : {0}");
        A("Root: {0}", "Racine : {0}");
        A("Grant signer: {0}", "Signataire des autorisations : {0}");
        A("ACU certificate names: {0}", "Noms du certificat de l'ACU : {0}");
        A("Readers are told to dial: {0}:{1}", "Adresse donnée aux lecteurs : {0}:{1}");
        A("Trust epoch: {0}    Grants signed: {1}", "Époque de confiance : {0}    Autorisations signées : {1}");
        A("Start listening on port {0}", "Écouter sur le port {0}");
        A("Stop listening", "Arrêter l'écoute");
        A("Listening on port {0}. {1} reader(s) online.", "À l'écoute sur le port {0}. {1} lecteur(s) en ligne.");
        A("Not listening", "À l'arrêt");
        A("Access rules", "Règles d'accès");
        A("Allow cards that are not in the access list", "Autoriser les cartes absentes de la liste d'accès");
        A("Unlock time (seconds):", "Durée de déverrouillage (secondes) :");
        A("Demo settings", "Réglages de la démo");
        A("Accept readers from any manufacturer (demo; a real site checks a trusted list)", "Accepter les lecteurs de tout fabricant (démo ; un vrai site vérifie une liste de confiance)");
        A("Readers", "Lecteurs");
        A("Name", "Nom");
        A("Status", "État");
        A("Address", "Adresse");
        A("Device ID", "Identifiant de l'appareil");
        A("Events", "Événements");
        A("Door", "Porte");
        A("Grants", "Autorisations");
        A("online", "en ligne");
        A("offline", "hors ligne");
        A("removed", "retiré");
        A("Add reader…", "Ajouter un lecteur…");
        A("Remove…", "Retirer…");
        A("Manual unlock", "Déverrouillage manuel");
        A("manual unlock", "déverrouillage manuel");
        A("Lock", "Verrouiller");
        A("Attack demo ▾", "Démo d'attaque ▾");
        A("Attack demo", "Démo d'attaque");
        A("Select a reader that is online first.", "Sélectionnez d'abord un lecteur en ligne.");
        A("Remove reader", "Retirer le lecteur");
        A("Remove this reader? Its site certificate is revoked and it will be refused if it connects. To use it again, factory-reset it and pair it again.", "Retirer ce lecteur ? Son certificat de site est révoqué et il sera refusé s'il se connecte. Pour le réutiliser, réinitialisez-le et appairez-le à nouveau.");
        A("Access list", "Liste d'accès");
        A("Allowed", "Autorisée");
        A("Notes", "Remarques");
        A("Add last card", "Ajouter la dernière carte");
        A("Delete selected", "Supprimer la sélection");
        A("No card has been swiped yet.", "Aucune carte n'a encore été présentée.");
        A("Last card: FC {0}, card {1} at {2}", "Dernière carte : FC {0}, carte {1} à {2}");
        A("added from {0}", "ajoutée depuis {0}");
        A("Enter a whole number from 0 to {0}.", "Saisissez un nombre entier de 0 à {0}.");
        A("{0}: event {1} already received; acknowledged again, not acted on.", "{0} : événement {1} déjà reçu ; acquitté à nouveau, sans action.");

        // ---- ACU dialogs ----
        A("Create demo site", "Créer un site de démo");
        A("Create site", "Créer le site");
        A("Cancel", "Annuler");
        A("This replaces the current site. Readers paired with it will not trust the new site: factory-reset them and pair them again.", "Ceci remplace le site actuel. Les lecteurs appairés avec lui ne feront pas confiance au nouveau site : réinitialisez-les et appairez-les à nouveau.");
        A("Site name:", "Nom du site :");
        A("Names and addresses in the ACU's certificate (a reader must dial one of these):", "Noms et adresses du certificat de l'ACU (un lecteur doit appeler l'un d'eux) :");
        A("Address readers are told to dial (readers on other computers need this computer's network address):", "Adresse que les lecteurs doivent appeler (les lecteurs sur d'autres ordinateurs ont besoin de l'adresse réseau de cet ordinateur) :");
        A("Port for reader sessions:", "Port des sessions des lecteurs :");
        A("Three key pairs are made: the site root (signs all certificates), the ACU's TLS identity and the grant signer (signs every unlock). On a real site the root is kept offline and the grant signer in a hardware security module.",
          "Trois paires de clés sont créées : la racine du site (signe tous les certificats), l'identité TLS de l'ACU et le signataire des autorisations (signe chaque déverrouillage). Sur un vrai site, la racine est conservée hors ligne et le signataire dans un module matériel de sécurité (HSM).");
        A("Enter the address readers should dial.", "Saisissez l'adresse que les lecteurs doivent appeler.");
        A("Add reader", "Ajouter un lecteur");
        A("Pair", "Appairer");
        A("Close", "Fermer");
        A("First press the pairing button on the reader (\"Open pairing window\" in the Reader Simulator). It then accepts pairing for 10 minutes.", "Appuyez d'abord sur le bouton d'appairage du lecteur (« Ouvrir la fenêtre d'appairage » dans le simulateur de lecteur). Il accepte alors l'appairage pendant 10 minutes.");
        A("Reader address (127.0.0.1 if it runs on this computer):", "Adresse du lecteur (127.0.0.1 s'il tourne sur cet ordinateur) :");
        A("Reader pairing port (shown in its Pairing panel):", "Port d'appairage du lecteur (indiqué dans son panneau Appairage) :");
        A("Setup code from the reader's label, or the QR text (HPSP:1:…):", "Code d'appairage figurant sur l'étiquette du lecteur, ou texte du QR (HPSP:1:…) :");
        A("Name for this reader (optional):", "Nom de ce lecteur (facultatif) :");
        A("Pairing… watch the activity window.", "Appairage en cours… observez la fenêtre d'activité.");
        A("Paired. The reader now connects to this ACU by itself.", "Appairé. Le lecteur se connecte désormais de lui-même à cette ACU.");
        A("Pairing failed: ", "Échec de l'appairage : ");

        // ---- ACU checklist ----
        A("Create the demo site", "Créer le site de démo");
        A("Click \"Create demo site…\". The ACU makes the site root (which signs every certificate on the site), its own TLS certificate, and the grant signer, the separate key that signs every unlock. Tick \"Show secrets\" to look at the keys.",
          "Cliquez sur « Créer un site de démo… ». L'ACU crée la racine du site (qui signe tous les certificats du site), son propre certificat TLS et le signataire des autorisations, la clé distincte qui signe chaque déverrouillage. Cochez « Afficher les secrets » pour voir les clés.");
        A("Start listening for readers", "Écouter les lecteurs");
        A("Readers always call the ACU, never the other way round: the ACU listens on port 7500 (allow it through the Windows firewall if asked). Paired readers connect by themselves.",
          "Ce sont toujours les lecteurs qui appellent l'ACU, jamais l'inverse : l'ACU écoute sur le port 7500 (autorisez-le dans le pare-feu Windows si on vous le demande). Les lecteurs appairés se connectent d'eux-mêmes.");
        A("Add cards to the access list", "Ajouter des cartes à la liste d'accès");
        A("Type a facility code (0-255), a card number (0-65535) and a name, and tick Allowed. Add one card that is allowed and one that is not, to see both outcomes. \"Add last card\" adds the card that was just swiped.",
          "Saisissez un code site (0-255), un numéro de carte (0-65535) et un nom, puis cochez Autorisée. Ajoutez une carte autorisée et une qui ne l'est pas, pour voir les deux résultats. « Ajouter la dernière carte » ajoute la carte qui vient d'être présentée.");
        A("Press the reader's pairing button", "Appuyer sur le bouton d'appairage du lecteur");
        A("In the Reader Simulator, click \"Open pairing window\". A reader accepts pairing only for 10 minutes after its button is pressed, which proves someone is at the device.",
          "Dans le simulateur de lecteur, cliquez sur « Ouvrir la fenêtre d'appairage ». Un lecteur n'accepte l'appairage que pendant 10 minutes après l'appui sur son bouton, ce qui prouve que quelqu'un est devant l'appareil.");
        A("Add the reader", "Ajouter le lecteur");
        A("Click \"Add reader…\" and enter the reader's address, its pairing port and its setup code (or paste its QR text). SPAKE2+ proves both sides know the code without sending it; then, inside TLS, the ACU checks the reader's factory identity and gives it a site certificate.",
          "Cliquez sur « Ajouter un lecteur… » et saisissez l'adresse du lecteur, son port d'appairage et son code d'appairage (ou collez le texte de son QR). SPAKE2+ prouve que les deux parties connaissent le code sans l'envoyer ; puis, dans TLS, l'ACU vérifie l'identité d'usine du lecteur et lui remet un certificat de site.");
        A("Reader comes online", "Le lecteur passe en ligne");
        A("The reader dials the ACU over TLS 1.3. Both sides show certificates from this site's root. The reader's hello carries a fresh session value; the ACU replies and sends trust_update with the grant signer's certificate.",
          "Le lecteur appelle l'ACU sur TLS 1.3. Les deux parties présentent des certificats émis par la racine de ce site. Le hello du lecteur porte une nouvelle valeur de session ; l'ACU répond et envoie trust_update avec le certificat du signataire des autorisations.");
        A("Swipe an allowed card", "Présenter une carte autorisée");
        A("Swipe a card from the list on the reader. The ACU finds it allowed, has the grant signer sign a grant for this reader, this session and a new counter, and sends unlock. The reader checks the signature and opens the door.",
          "Présentez sur le lecteur une carte de la liste. L'ACU la trouve autorisée, fait signer par le signataire une autorisation pour ce lecteur, cette session et un nouveau compteur, puis envoie unlock. Le lecteur vérifie la signature et ouvre la porte.");
        A("Swipe a refused card", "Présenter une carte refusée");
        A("Swipe a card that is not allowed (or not in the list). No grant is made at all, so there is nothing the reader could act on; the ACU just flashes the reader's LED red.",
          "Présentez une carte non autorisée (ou absente de la liste). Aucune autorisation n'est émise : le lecteur n'a donc rien sur quoi agir ; l'ACU fait simplement clignoter son voyant en rouge.");
        A("Try an attack", "Essayer une attaque");
        A("Select the online reader and use \"Attack demo\": replay an old grant, send an expired one, one for a previous session, a tampered one, or one from an untrusted key. The reader refuses each, keeps the door locked and reports a security event.",
          "Sélectionnez le lecteur en ligne et utilisez « Démo d'attaque » : rejouer une ancienne autorisation, en envoyer une expirée, une destinée à une session précédente, une modifiée, ou une signée par une clé non approuvée. Le lecteur les refuse toutes, garde la porte verrouillée et signale un événement de sécurité.");
    }
}
