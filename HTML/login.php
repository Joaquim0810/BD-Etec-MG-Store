<?php

session_start();

require_once "conexao.php";

$email = $_POST["email"];
$senha = $_POST["senha"];

$sql = "SELECT id, nome, email, senha
        FROM usuarios
        WHERE email = ?";

$stmt = $conexao->prepare($sql);

$stmt->bind_param("s", $email);

$stmt->execute();

$resultado = $stmt->get_result();

if ($resultado->num_rows === 1) {

    $usuario = $resultado->fetch_assoc();

    if (password_verify($senha, $usuario["senha"])) {

        $_SESSION["usuario_id"] = $usuario["id"];
        $_SESSION["usuario_nome"] = $usuario["nome"];
        $_SESSION["usuario_email"] = $usuario["email"];

        echo "Login realizado com sucesso!";
        echo "<br>Bem-vindo, " . htmlspecialchars($usuario["nome"]) . "!";

    } else {

        echo "E-mail ou senha incorretos.";

    }

} else {

    echo "E-mail ou senha incorretos.";

}

$stmt->close();
$conexao->close();

?>