<?php

require_once "conexao.php";

$nome = $_POST["nome"];
$email = $_POST["email"];
$senha = $_POST["senha"];
$confirmar_senha = $_POST["confirmar_senha"];

if ($senha !== $confirmar_senha) {
    die("As senhas não são iguais.");
}

$senha_hash = password_hash($senha, PASSWORD_DEFAULT);

$sql = "INSERT INTO usuarios (nome, email, senha)
        VALUES (?, ?, ?)";

$stmt = $conexao->prepare($sql);

$stmt->bind_param("sss", $nome, $email, $senha_hash);

if ($stmt->execute()) {

    echo "Cadastro realizado com sucesso!";

    echo "<br><a href='login.html'>Ir para o login</a>";

} else {

    if ($conexao->errno == 1062) {
        echo "Este e-mail já está cadastrado.";
    } else {
        echo "Erro ao realizar o cadastro.";
    }
}

$stmt->close();
$conexao->close();

?>