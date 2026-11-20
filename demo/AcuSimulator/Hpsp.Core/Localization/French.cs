// =============================================================================
//  HPSP Demo  -  Hpsp.Core
//  File:    Localization/French.cs
//  Purpose: French text. Key = the English text exactly as written in the code;
//           value = the French. {0}, {1}... are filled in with values and must
//           be kept. "\n" is a line break.
//
//  Copyright (c) 2026 Highpower Security Products LLC
//  SPDX-License-Identifier: Apache-2.0
// =============================================================================
//
//  TERMINOLOGY used throughout (for reviewers):
//    ACU                   ACU (unité de contrôle d'accès) - kept as in the spec
//    reader                lecteur
//    pairing               appairage
//    setup code            code d'appairage
//    grant                 autorisation (signed grant = autorisation signée)
//    grant signer          signataire des autorisations
//    session value (nonce) valeur de session
//    trust epoch           époque de confiance
//    trust list            liste de confiance
//    factory identity      identité d'usine
//    site certificate      certificat de site
//    heartbeat             signal de vie
//    acknowledge           acquitter
//    access list           liste d'accès
//    card swiped           carte présentée
//    door strike           gâche électrique
//
//  Protocol content (message names, JSON members, error codes such as
//  "replay" or "bad_signature") is deliberately left in English.
// =============================================================================

namespace Hpsp.Core.Localization;

internal static partial class French
{
    public static readonly Dictionary<string, string> Text = Build();

    private static Dictionary<string, string> Build()
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        AddEngine(d);
        AddUi(d);
        return d;
    }

    // -------------------------------------------------------------------------
    //  Activity-window text produced by the ACU and reader engines
    // -------------------------------------------------------------------------
    private static void AddEngine(Dictionary<string, string> d)
    {
        void A(string en, string fr) => d[en] = fr;

        // ---- general ----
        A(" for {0:0.#} s.", " pendant {0:0.#} s.");
        A("(This step involves secrets. Turn on \"Show secrets\" to see them.)", "(Cette étape fait intervenir des secrets. Activez « Afficher les secrets » pour les voir.)");
        A("SECRETS (demo only - never shown on a real system):\n", "SECRETS (démo uniquement - jamais affichés sur un vrai système) :\n");
        A("CBOR on the wire ({0} bytes):\n", "CBOR transmis ({0} octets) :\n");
        A("Cannot listen on port {0}: {1}", "Impossible d'écouter sur le port {0} : {1}");
        A("unexpected message type ", "type de message inattendu ");
        A("attack demo", "démo d'attaque");

        // ---- message summaries ----
        A("ack up to seq {0}", "acquittement jusqu'au n° {0}");
        A("device {0}, session value {1}", "appareil {0}, valeur de session {1}");
        A("heartbeat {0} s, resume from seq {1}", "signal de vie {0} s, reprise au n° {1}");
        A("epoch {0}, {1} grant signer(s)", "époque {0}, {1} signataire(s) des autorisations");
        A("pairing: {0}", "appairage : {0}");
        A("{0} ERROR re #{1}: {2}", "{0} ERREUR en réponse à #{1} : {2}");
        A("{0} event seq {1}", "événement {0} n° {1}");
        A("{0} reply to #{1}", "{0} réponse à #{1}");
        A("joined from fragments", "réassemblé à partir de fragments");

        // ---- framing / fragments ----
        A("a fragment set may not contain another fragment", "un ensemble de fragments ne peut pas contenir un autre fragment");
        A("malformed fragment", "fragment mal formé");
        A("fragment does not belong to the set in progress", "le fragment n'appartient pas à l'ensemble en cours");
        A("fragment offset or length does not fit", "décalage ou longueur de fragment incohérent");
        A("fragment set of {0} bytes is larger than we assemble ({1})", "ensemble de fragments de {0} octets, plus grand que ce que nous assemblons ({1})");
        A("message of {0} bytes is larger than the peer can assemble ({1})", "message de {0} octets, plus grand que ce que le pair peut assembler ({1})");

        // ---- reader: device and secrets ----
        A("A new simulated device was created: new device ID, factory identity and setup code.", "Un nouvel appareil simulé a été créé : nouvel identifiant, nouvelle identité d'usine et nouveau code d'appairage.");
        A("Factory reset: site removed. The reader is unpaired and keeps its factory identity and setup code.", "Réinitialisation d'usine : site supprimé. Le lecteur n'est plus appairé et conserve son identité d'usine et son code d'appairage.");
        A("Setup code: {0}", "Code d'appairage : {0}");
        A("Verifier w0: {0}", "Vérificateur w0 : {0}");
        A("Verifier L:  {0}", "Vérificateur L :  {0}");
        A("Salt: {0}, iterations {1}", "Sel : {0}, itérations {1}");
        A("Factory identity private key (PKCS#8): ", "Clé privée de l'identité d'usine (PKCS#8) : ");
        A("Site identity private key (PKCS#8): ", "Clé privée de l'identité de site (PKCS#8) : ");
        A("Current session value: ", "Valeur de session actuelle : ");
        A("Reader started. Platform: {0}", "Lecteur démarré. Plateforme : {0}");
        A("reader stopped", "lecteur arrêté");
        A("Card swiped: FC {0}, card {1}. 26 bits: {2} = {3}", "Carte présentée : FC {0}, carte {1}. 26 bits : {2} = {3}");
        A("Door re-secured: the timed unlock ended.", "Porte resécurisée : le déverrouillage temporisé est terminé.");
        A("Event buffer full: dropped event seq {0} ({1}).", "Tampon d'événements plein : événement n° {0} ({1}) abandonné.");

        // ---- reader: session ----
        A("not connected", "non connecté");
        A("cable unplugged", "câble débranché");
        A("not paired: open the pairing window and add this reader from the ACU", "non appairé : ouvrez la fenêtre d'appairage et ajoutez ce lecteur depuis l'ACU");
        A("connecting to {0}:{1} ({2})", "connexion à {0}:{1} ({2})");
        A("TLS session established with the ACU: {0}", "Session TLS établie avec l'ACU : {0}");
        A("Connection to the ACU failed: ", "Échec de la connexion à l'ACU : ");
        A("disconnected; retrying in {0} s", "déconnecté ; nouvelle tentative dans {0} s");
        A("hello sent, waiting for the ACU", "hello envoyé, en attente de l'ACU");
        A("The ACU closed the session.", "L'ACU a fermé la session.");
        A("Session ended: ", "Session terminée : ");
        A("hello refused", "hello refusé");
        A("The ACU refused hello: {0} {1}", "L'ACU a refusé hello : {0} {1}");
        A("the ACU said goodbye", "l'ACU a envoyé goodbye");
        A("connected to {0}:{1}", "connecté à {0}:{1}");
        A("Session ready. Heartbeat every {0} s. Clock set from the ACU.", "Session prête. Signal de vie toutes les {0} s. Horloge réglée par l'ACU.");
        A("Replaying {0} unacknowledged event(s), seq {1} to {2}.", "Renvoi de {0} événement(s) non acquitté(s), n° {1} à {2}.");
        A("Unlock REFUSED: {0}. The door stays locked.", "Déverrouillage REFUSÉ : {0}. La porte reste verrouillée.");
        A("Grant verified (counter {0}). Door UNLOCKED", "Autorisation vérifiée (compteur {0}). Porte DÉVERROUILLÉE");
        A("replay (this grant's counter has already been used)", "rejeu (le compteur de cette autorisation a déjà été utilisé)");
        A("expired grant", "autorisation expirée");
        A("bad signature (wrong session, altered, or signed for something else)", "signature invalide (autre session, modifiée, ou signée pour autre chose)");
        A("unknown or untrusted signer", "signataire inconnu ou non approuvé");
        A("Trust updated: epoch {0}, {1} grant signer(s) now trusted.", "Confiance mise à jour : époque {0}, {1} signataire(s) des autorisations approuvé(s).");
        A("Three heartbeats unanswered: the session is dead. Dropping it and dialling again.", "Trois signaux de vie sans réponse : la session est morte. Abandon et nouvelle connexion.");
        A("Network cable pulled (simulated): the connection is dropped without a goodbye. Events are kept until it is plugged back in.", "Câble réseau débranché (simulé) : la connexion est coupée sans goodbye. Les événements sont conservés jusqu'au rebranchement.");
        A("Network cable plugged back in.", "Câble réseau rebranché.");

        // ---- reader: pairing ----
        A("Pairing is locked after {0} wrong codes, until {1:T}.", "Appairage bloqué après {0} codes erronés, jusqu'à {1:T}.");
        A("Pairing button pressed: listening on port {0} until {1:T}. Setup code {2}.", "Bouton d'appairage pressé : écoute sur le port {0} jusqu'à {1:T}. Code d'appairage {2}.");
        A("Pairing window closed.", "Fenêtre d'appairage fermée.");
        A("Pairing connection from {0}.", "Connexion d'appairage depuis {0}.");
        A("Refused: too many wrong codes.", "Refusé : trop de codes erronés.");
        A("invalid share: ", "part invalide : ");
        A("the ACU's code did not match ours", "le code de l'ACU ne correspond pas au nôtre");
        A("wrong setup code", "code d'appairage erroné");
        A("Setup code confirmed by SPAKE2+. Starting TLS with the shared key.", "Code d'appairage confirmé par SPAKE2+. Démarrage de TLS avec la clé partagée.");
        A("y (our random scalar): {0}\nK_shared: {1}\nPre-shared key for TLS: {2}", "y (notre scalaire aléatoire) : {0}\nK_shared : {1}\nClé pré-partagée pour TLS : {2}");
        A("Pairing TLS established: ", "TLS d'appairage établi : ");
        A("Pairing attempt ended: ", "Tentative d'appairage terminée : ");
        A("Pairing refused: {0}. Attempts left before lock-out: {1}.", "Appairage refusé : {0}. Tentatives restantes avant blocage : {1}.");
        A("Too many wrong codes: pairing locked until {0:T}.", "Trop de codes erronés : appairage bloqué jusqu'à {0:T}.");
        A("The ACU closed the pairing session before finishing.", "L'ACU a fermé la session d'appairage avant la fin.");
        A("Enrolling in site {0}. New key pair made; sending a certificate signing request. Will connect to {1}:{2}. Site trust epoch {3}.", "Inscription au site {0}. Nouvelle paire de clés créée ; envoi d'une demande de signature de certificat. Connexion prévue à {1}:{2}. Époque de confiance du site {3}.");
        A("certificate is for another device", "le certificat est destiné à un autre appareil");
        A("certificate is not for our new key", "le certificat ne correspond pas à notre nouvelle clé");
        A("Site certificate refused: ", "Certificat de site refusé : ");
        A("PAIRED with site {0}. Site certificate installed ({1}). Connecting to the ACU.", "APPAIRÉ avec le site {0}. Certificat de site installé ({1}). Connexion à l'ACU.");

        // ---- ACU: site and sessions ----
        A("(no site yet)", "(pas encore de site)");
        A("Site root private key (PKCS#8): {0}\nACU TLS private key (PKCS#8): {1}\nGrant signer private key (PKCS#8): {2}", "Clé privée de la racine du site (PKCS#8) : {0}\nClé privée TLS de l'ACU (PKCS#8) : {1}\nClé privée du signataire des autorisations (PKCS#8) : {2}");
        A("Demo site \"{0}\" created. Root {1}, ACU certificate for {2}, grant signer {3}.", "Site de démo « {0} » créé. Racine {1}, certificat de l'ACU pour {2}, signataire des autorisations {3}.");
        A("Create a demo site first.", "Créez d'abord un site de démo.");
        A("ACU listening on port {0} ({1} TLS engine). Platform: {2}", "ACU à l'écoute sur le port {0} (moteur TLS {1}). Plateforme : {2}");
        A("ACU stopped listening.", "L'ACU n'écoute plus.");
        A("Connection from {0} refused at TLS: {1}", "Connexion depuis {0} refusée au niveau TLS : {1}");
        A("TLS session with {0} from {1}: {2}", "Session TLS avec {0} depuis {1} : {2}");
        A("First message was not hello; closing.", "Le premier message n'était pas hello ; fermeture.");
        A("hello device_id does not match the TLS certificate.", "Le device_id de hello ne correspond pas au certificat TLS.");
        A("Reader {0} is not paired here or was removed.", "Le lecteur {0} n'est pas appairé ici ou a été retiré.");
        A("Events {0} to {1} are no longer held by the reader (a gap after a restart is normal).", "Les événements {0} à {1} ne sont plus conservés par le lecteur (un trou après un redémarrage est normal).");
        A("Reader {0} is online. Session value {1}, grant floor {2}.", "Le lecteur {0} est en ligne. Valeur de session {1}, plancher des autorisations {2}.");
        A("Reader {0} closed the session.", "Le lecteur {0} a fermé la session.");
        A("Session with {0} ended: {1}", "Session avec {0} terminée : {1}");
        A("Reader {0} is offline.", "Le lecteur {0} est hors ligne.");
        A("the reader's trust list is out of date", "la liste de confiance du lecteur n'est pas à jour");
        A("{0}: door {1}.", "{0} : porte {1}.");
        A("{0} refused {1}: {2}", "{0} a refusé {1} : {2}");
        A("SECURITY EVENT from {0}: {1} {2}", "ÉVÉNEMENT DE SÉCURITÉ de {0} : {1} {2}");
        A("{0}: card format not recognized.", "{0} : format de carte non reconnu.");
        A("{0}: card FC {1} / {2} is {3:0.#} s old. Logged only; no door opened (limit {4} s).", "{0} : la lecture de la carte FC {1} / {2} date de {3:0.#} s. Journalisée seulement ; aucune porte ouverte (limite {4} s).");
        A("unknown card", "carte inconnue");
        A("not in the access list", "absente de la liste d'accès");
        A("access disabled for this card", "accès désactivé pour cette carte");
        A("ACCESS DENIED at {0}: FC {1}, card {2} ({3}, {4}). No grant is made.", "ACCÈS REFUSÉ à {0} : FC {1}, carte {2} ({3}, {4}). Aucune autorisation n'est émise.");
        A("ACCESS GRANTED at {0}: FC {1}, card {2} ({3}). Asking the grant signer for a grant.", "ACCÈS AUTORISÉ à {0} : FC {1}, carte {2} ({3}). Demande d'une autorisation au signataire.");
        A("Reader {0} removed. Its certificate is revoked (trust epoch {1}); it will be refused if it connects.", "Lecteur {0} retiré. Son certificat est révoqué (époque de confiance {1}) ; il sera refusé s'il se connecte.");

        // ---- ACU: pairing ----
        A("create a demo site first", "créez d'abord un site de démo");
        A("QR text: ", "Texte du QR : ");
        A("the setup code must be 8 characters from the code alphabet (no 0, O, 1 or I)", "le code d'appairage doit comporter 8 caractères de l'alphabet du code (sans 0, O, 1 ni I)");
        A("Adding a reader at {0}:{1}…", "Ajout d'un lecteur à {0}:{1}…");
        A("cannot reach {0}:{1} ({2}). Is the reader's pairing window open?", "impossible de joindre {0}:{1} ({2}). La fenêtre d'appairage du lecteur est-elle ouverte ?");
        A("the reader did not start pairing correctly", "le lecteur n'a pas démarré l'appairage correctement");
        A("this is not the reader in the QR code (QR {0}, reader {1})", "ce n'est pas le lecteur du code QR (QR {0}, lecteur {1})");
        A("unreasonable iteration count from the reader", "nombre d'itérations du lecteur déraisonnable");
        A("the reader refused: wrong setup code", "le lecteur a refusé : code d'appairage erroné");
        A("unexpected reply from the reader", "réponse inattendue du lecteur");
        A("invalid share from the reader: ", "part invalide reçue du lecteur : ");
        A("wrong setup code (the reader's confirmation did not match)", "code d'appairage erroné (la confirmation du lecteur ne correspond pas)");
        A("SPAKE2+ succeeded: both sides proved they know the setup code.", "SPAKE2+ réussi : les deux parties ont prouvé qu'elles connaissent le code d'appairage.");
        A("Setup code: {0}\nw0: {1}\nw1: {2}\nx (our random scalar): {3}\nK_shared: {4}\nPre-shared key for TLS: {5}", "Code d'appairage : {0}\nw0 : {1}\nw1 : {2}\nx (notre scalaire aléatoire) : {3}\nK_shared : {4}\nClé pré-partagée pour TLS : {5}");
        A("attestation reply incomplete", "réponse d'attestation incomplète");
        A("factory identity does not chain to its manufacturer: ", "l'identité d'usine ne remonte pas à son fabricant : ");
        A("factory identity is for a different device", "l'identité d'usine appartient à un autre appareil");
        A("attestation signature is not valid for this session", "la signature d'attestation n'est pas valide pour cette session");
        A("manufacturer root {0} is not trusted", "la racine fabricant {0} n'est pas approuvée");
        A("Manufacturer root {0} seen for the first time and accepted (demo setting). A real site checks it against a trusted list.", "Racine fabricant {0} vue pour la première fois et acceptée (réglage de démo). Un vrai site la vérifie dans une liste de confiance.");
        A("Factory identity verified: {0}, bound to this TLS session.", "Identité d'usine vérifiée : {0}, liée à cette session TLS.");
        A("no certificate signing request", "pas de demande de signature de certificat");
        A("bad signing request: ", "demande de signature invalide : ");
        A("the reader did not accept its certificate", "le lecteur n'a pas accepté son certificat");
        A("Reader {0}", "Lecteur {0}");
        A("READER PAIRED: {0} ({1}). Site certificate {2} issued. It will now connect on port {3}.", "LECTEUR APPAIRÉ : {0} ({1}). Certificat de site {2} émis. Il va maintenant se connecter sur le port {3}.");
        A("pairing failed: ", "échec de l'appairage : ");
        A("the reader closed the pairing session", "le lecteur a fermé la session d'appairage");
        A("{0} refused by the reader: {1} {2}", "{0} refusé par le lecteur : {1} {2}");
        A("Add reader failed: ", "Échec de l'ajout du lecteur : ");

        // ---- ACU: attacks ----
        A("Replay the last grant (expected: replay)", "Rejouer la dernière autorisation (attendu : replay)");
        A("Grant that expired 2 minutes ago (expected: expired)", "Autorisation expirée depuis 2 minutes (attendu : expired)");
        A("Grant for the reader's previous session (expected: bad_signature)", "Autorisation pour la session précédente du lecteur (attendu : bad_signature)");
        A("Valid grant with one bit flipped (expected: bad_signature)", "Autorisation valide avec un bit inversé (attendu : bad_signature)");
        A("Grant signed by an untrusted key (expected: unauthorized)", "Autorisation signée par une clé non approuvée (attendu : unauthorized)");
        A("the reader is not online", "le lecteur n'est pas en ligne");
        A("no grant has been sent to this reader in this session yet: swipe an allowed card or use Manual unlock first", "aucune autorisation n'a encore été envoyée à ce lecteur dans cette session : présentez d'abord une carte autorisée ou utilisez le déverrouillage manuel");
        A("No previous session recorded for this reader; using a made-up session value instead.", "Aucune session précédente enregistrée pour ce lecteur ; utilisation d'une valeur de session inventée.");
        A("unknown attack", "attaque inconnue");
        A("ATTACK DEMO on {0}: {1}", "DÉMO D'ATTAQUE sur {0} : {1}");

        // ---- QR text ----
        A("not an HPSP QR code", "ce n'est pas un code QR HPSP");
        A("bad device id", "identifiant d'appareil invalide");
        A("bad setup code", "code d'appairage invalide");
        A("check characters do not match (misread?)", "les caractères de contrôle ne correspondent pas (mauvaise lecture ?)");
    }

    /// <summary>Window text; filled in by FrenchUi.cs.</summary>
    static partial void AddUiText(Dictionary<string, string> d);
    private static void AddUi(Dictionary<string, string> d) => AddUiText(d);
}
