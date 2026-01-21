<?php
header('Content-Type: application/json');

// IDS DE VOTRE .ENV (RECUPERES DEPUIS VOTRE FICHIER ACTUEL)
$host = 'sql3.minestrator.com';
$db   = 'minesr_VODW8dwu';
$user = 'minesr_VODW8dwu';
$pass = 'NfocLnAinfeyr9WU';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur de connexion BDD']);
    exit;
}

// IDS AZURE (POUR LE REFRESH TOKEN)
$azure_client_id = '6d1d88e9-bb5c-4d03-a4c9-58227e577ba7';
$azure_client_secret = 'fsj8Q~E.i8yiuk1bduRQvqZVFnpQJlmvxzFQ-avQ';

// Récupération des données JSON
$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? 'login'; // login ou refresh

// --- ACTION: REFRESH TOKEN MICROSOFT ---
if ($action === 'refresh') {
    $refreshToken = $input['refresh_token'] ?? '';
    
    if (empty($refreshToken)) {
        echo json_encode(['success' => false, 'message' => 'Refresh token manquant']);
        exit;
    }

    // Appel à Microsoft depuis le serveur (c'est ici qu'on utilise le SECRET caché)
    $url = 'https://login.live.com/oauth20_token.srf';
    $data = http_build_query([
        'client_id' => $azure_client_id,
        'client_secret' => $azure_client_secret,
        'refresh_token' => $refreshToken,
        'grant_type' => 'refresh_token' 
    ]);

    $options = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => $data,
            'ignore_errors' => true
        ]
    ];

    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $response = json_decode($result, true);

    if (isset($response['access_token'])) {
        echo json_encode(['success' => true, 'data' => $response]);
    } else {
        // En cas d'erreur de Microsoft, on la renvoie
        echo json_encode(['success' => false, 'message' => 'Erreur Microsoft', 'details' => $response]);
    }
    exit;
}

// --- ACTION: LOGIN (BASE DE DONNEES) ---
$identifier = $input['identifier'] ?? '';
$password = $input['password'] ?? '';

if (empty($identifier) || empty($password)) {
    echo json_encode(['success' => false, 'message' => 'Champs manquants']);
    exit;
}

// Recherche de l'utilisateur
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? OR minecraft_name = ?");
$stmt->execute([$identifier, $identifier]);
$user = $stmt->fetch();

if (!$user) {
    echo json_encode(['success' => false, 'message' => 'Utilisateur inconnu.']);
    exit;
}

// Vérification du mot de passe
if (password_verify($password, $user['password_hash'])) {
    // Succès ! On renvoie les infos (sans le mot de passe bien sûr)
    echo json_encode([
        'success' => true, 
        'user' => [
            'id' => $user['id'],
            'username' => $user['minecraft_name'],
            'uuid' => $user['minecraft_uuid'],
            'email' => $user['email'],
            'role' => $user['role'],
            'refreshToken' => $user['microsoft_refresh_token'],
            'type' => 'microsoft'
        ]
    ]);
} else {
    echo json_encode(['success' => false, 'message' => 'Mot de passe incorrect.']);
}
?>