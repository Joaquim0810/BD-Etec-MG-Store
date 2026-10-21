<?php
require_once __DIR__ . "/conexao.php";

$token = $_POST["token"] ?? $_GET["token"] ?? "";
if (!is_string($token) || !preg_match('/\A[a-f0-9]{64}\z/', $token)) {
    $token = "";
}

$erro = "";
$sucesso = false;
$tokenValido = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $senha = $_POST["senha"] ?? "";
    $confirmar = $_POST["confirmar_senha"] ?? "";

    if (!is_string($senha) || strlen($senha) < 8) {
        $erro = "A senha deve ter pelo menos 8 caracteres.";
    } elseif ($senha !== $confirmar) {
        $erro = "As senhas não coincidem.";
    } elseif ($token === "") {
        $erro = "O link é inválido ou expirou. Solicite outro.";
    } else {
        $tokenHash = hash("sha256", $token);
        $stmt = $conexao->prepare("SELECT usuario_id FROM recuperacao_senhas WHERE token_hash = ? AND expira_em > NOW() LIMIT 1");
        $stmt->bind_param("s", $tokenHash);
        $stmt->execute();
        $registro = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$registro) {
            $erro = "O link é inválido ou expirou. Solicite outro.";
        } else {
            $usuarioId = (int) $registro["usuario_id"];
            $senhaHash = password_hash($senha, PASSWORD_DEFAULT);
            $stmt = $conexao->prepare("UPDATE usuarios SET senha = ? WHERE id = ?");
            $stmt->bind_param("si", $senhaHash, $usuarioId);
            if ($stmt->execute() && $stmt->affected_rows === 1) {
                $stmt->close();
                $del = $conexao->prepare("DELETE FROM recuperacao_senhas WHERE usuario_id = ?");
                $del->bind_param("i", $usuarioId);
                $del->execute();
                $del->close();
                $sucesso = true;
            } else {
                $erro = "Não foi possível alterar a senha. Tente novamente.";
                $stmt->close();
            }
        }
    }
} elseif ($token !== "") {
    $tokenHash = hash("sha256", $token);
    $stmt = $conexao->prepare("SELECT id FROM recuperacao_senhas WHERE token_hash = ? AND expira_em > NOW() LIMIT 1");
    $stmt->bind_param("s", $tokenHash);
    $stmt->execute();
    $tokenValido = (bool) $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

$conexao->close();
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redefinir senha - MG Store</title>
    <link rel="stylesheet" href="paginas.css">
</head>
<body>
    <main>
        <section class="conteudo">
            <?php if ($sucesso): ?>
                <h1>Senha alterada!</h1>
                <p>Sua senha foi redefinida com sucesso.</p>
                <p><a href="login.html">Fazer login</a></p>
            <?php elseif ($erro !== ""): ?>
                <h1>Não foi possível redefinir a senha</h1>
                <p><?= htmlspecialchars($erro, ENT_QUOTES, "UTF-8") ?></p>
                <p><a href="recuperar-senha.html">Solicitar novo link</a></p>
            <?php elseif ($tokenValido): ?>
                <h1>Crie uma nova senha</h1>
                <form action="redefinir-senha.php" method="POST">
                    <input type="hidden" name="token" value="<?= htmlspecialchars($token, ENT_QUOTES, "UTF-8") ?>">
                    <label for="senha">Nova senha (mínimo 8 caracteres)</label>
                    <input type="password" id="senha" name="senha" minlength="8" autocomplete="new-password" required>
                    <label for="confirmar_senha">Confirmar nova senha</label>
                    <input type="password" id="confirmar_senha" name="confirmar_senha" minlength="8" autocomplete="new-password" required>
                    <button class="botao" type="submit">Salvar nova senha</button>
                </form>
            <?php else: ?>
                <h1>Link inválido ou expirado</h1>
                <p>Solicite um novo link para redefinir sua senha.</p>
                <p><a href="recuperar-senha.html">Recuperar senha</a></p>
            <?php endif; ?>
        </section>
    </main>
</body>
</html>
