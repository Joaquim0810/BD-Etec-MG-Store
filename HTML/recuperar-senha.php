<?php
require_once __DIR__ . "/conexao.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: recuperar-senha.html");
    exit;
}

$email = trim($_POST["email"] ?? "");
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    exit("E-mail inválido. <a href=\"recuperar-senha.html\">Voltar</a>");
}

$mensagem = "Se esse e-mail estiver cadastrado, a solicitação de recuperação foi processada.";
$linkLocalTeste = "";

try {
    $stmt = $conexao->prepare("SELECT id FROM usuarios WHERE email = ? LIMIT 1");
    if (!$stmt) {
        throw new RuntimeException("Falha ao preparar consulta de usuário.");
    }
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $resultado = $stmt->get_result();
    $usuario = $resultado->fetch_assoc();
    $stmt->close();

    if ($usuario) {
        $usuarioId = (int) $usuario["id"];
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash("sha256", $token);
        $expiraEm = date("Y-m-d H:i:s", time() + 3600);

        $del = $conexao->prepare("DELETE FROM recuperacao_senhas WHERE usuario_id = ?");
        if (!$del) {
            throw new RuntimeException("Falha ao preparar limpeza de tokens.");
        }
        $del->bind_param("i", $usuarioId);
        $del->execute();
        $del->close();

        $ins = $conexao->prepare(
            "INSERT INTO recuperacao_senhas (usuario_id, token_hash, expira_em) VALUES (?, ?, ?)"
        );
        if (!$ins) {
            throw new RuntimeException("Falha ao preparar gravação do token.");
        }
        $ins->bind_param("iss", $usuarioId, $tokenHash, $expiraEm);
        $ins->execute();
        $ins->close();

        $https = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off");
        $protocolo = $https ? "https" : "http";
        $diretorio = rtrim(str_replace("\\", "/", dirname($_SERVER["SCRIPT_NAME"])), "/");
        $urlBase = $protocolo . "://" . $_SERVER["HTTP_HOST"] . $diretorio;
        $link = $urlBase . "/redefinir-senha.php?token=" . urlencode($token);

        $assunto = "Recuperacao de senha - MG Store";
        $corpo = "Olá!\n\nUse o link abaixo para redefinir sua senha. Ele expira em 1 hora:\n\n" . $link . "\n\nSe você não pediu a recuperação, ignore esta mensagem.";
        $cabecalhos = "From: MG Store <nao-responda@localhost>\r\n";
        $enviado = @mail($email, $assunto, $corpo, $cabecalhos);

        // Ajuda a testar no XAMPP local, onde o envio de e-mail normalmente não está configurado.
        // Nunca disponibilize este link de teste em um site público.
        $host = strtolower($_SERVER["HTTP_HOST"] ?? "");
        if (!$enviado && in_array($host, ["localhost", "127.0.0.1", "localhost:80", "127.0.0.1:80"], true)) {
            $linkLocalTeste = $link;
        }
    }
} catch (Throwable $e) {
    error_log("Erro na recuperação de senha: " . $e->getMessage());
    $mensagem = "Não foi possível processar a solicitação agora. Confira a configuração do banco de dados e tente novamente.";
}

if (isset($conexao) && $conexao instanceof mysqli) {
    $conexao->close();
}
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solicitação de recuperação - MG Store</title>
    <link rel="stylesheet" href="paginas.css">
</head>
<body>
    <main>
        <section class="conteudo">
            <h1>Recuperação de senha</h1>
            <p><?= htmlspecialchars($mensagem, ENT_QUOTES, "UTF-8") ?></p>
            <?php if ($linkLocalTeste !== ""): ?>
                <p><strong>Modo de teste local:</strong> o XAMPP não enviou o e-mail. Abra este link para testar a redefinição:</p>
                <p><a href="<?= htmlspecialchars($linkLocalTeste, ENT_QUOTES, "UTF-8") ?>">Abrir redefinição de senha</a></p>
                <p>Esse link de teste só aparece em localhost. Não use esse recurso em um site público.</p>
            <?php endif; ?>
            <p><a href="login.html">Voltar ao login</a></p>
        </section>
    </main>
</body>
</html>
