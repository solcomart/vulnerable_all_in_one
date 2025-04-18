<?php


// [SQL Injection][Easy]
$conn = new mysqli("localhost", "root", "", "test");
$id = $_GET['id'];
$result = $conn->query("SELECT * FROM users WHERE id = '$id'");


// [SQL Injection][Medium]
$id = $_GET['id'];
$query = sprintf("SELECT * FROM users WHERE id = '%s'", $id);
$result = mysqli_query($conn, $query);


// [SQL Injection][Hard]
function getUserById($id)
{
	global $conn;
	$query = "SELECT * FROM users WHERE id = '" . addslashes($id) . "'";
	return mysqli_query($conn, $query);
}

getUserById($_GET['id']);

// [SQL Injection][Mikhail]
// это уязвимость
// строку, прочитанную из Redis, нужно санировать перед запросом в БД
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$name = $redis->get('name');
$email = $redis->get('email');
$result = mysqli_query($conn, "INSERT INTO users (id, name, email)
VALUES ('$id', '$name', '$email');");


// [SQL Injection][Mikhail][Safe]
// на такой код анализатор реагировать по идее не должен
// если реагирует, это можно считать ложным срабатыванием
// из строки удаляются все управляющие символы
function getUserByIdCustom($id)
{
	global $conn;
	$id = preg_replace('/[^a-zA-Z0-9]/', '', $id);
	$query = "SELECT * FROM users WHERE id = '" . addslashes($id) . "'";
	return mysqli_query($conn, $query);
}

getUserByIdCustom($_GET['id']);


// [XSS][Easy]
echo "Welcome " . $_GET['name'];


// [XSS][Medium]
$name = htmlspecialchars($_POST['name'], ENT_NOQUOTES); // quotes still injectable
echo $name;


// [XSS][Hard]
$name = $_POST['name'];
echo "<script>var user = '$name';</script>";


// [XSS][Mikhail]
function render($data)
{
	return $data;
}

echo render($_GET['msg']);


// [XSS][Mikhail]
// строку, прочитанную из Redis, тоже надо санировать перед выводом
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$value = $redis->get('123');
echo $value;


// [XSS][Mikhail]
// addslashes это не средство от XSS
function escapeJs($input)
{
	return addslashes($input);
}

$js = $_GET['js'];
echo "<script>var msg = '" . escapeJs($js) . "';</script>";


// [RCE][Easy]
eval($_GET['cmd']);


// [RCE][Medium]
$func = $_GET['func'];
$args = $_GET['arg'];
call_user_func($func, $args);


// [RCE][Hard]
// просто для информации: у нас на многих серверах отключены такие команды как system, exec, shell_exec, eval
// проверять такой код всё равно надо
$cmd = $_POST['cmd'];
if (preg_match('/^[a-z]+$/', $cmd)) {
	system($cmd);
}


// [Insecure Deserialization][Easy]
$data = unserialize($_GET['data']);


// [Insecure Deserialization][Medium]
$cookie = $_COOKIE['auth'];
$user = unserialize(base64_decode($cookie));


// [Insecure Deserialization][Hard]
$raw = file_get_contents("php://input");
$obj = unserialize($raw);


// [File Upload][Easy]
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']);


// [File Upload][Medium]
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (in_array($ext, ['jpg', 'png', 'gif'])) {
	move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']);
}


// [Open Redirect][Easy]
header("Location: " . $_GET['redirect']);


// [Open Redirect][Medium]
$url = $_GET['url'];
if (strpos($url, "http") === 0) {
	header("Location: $url");
}


// [CORS Misconfiguration][High]
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Credentials: true");


// [Sensitive Data Exposure][Easy]
file_put_contents("log.txt", $_POST['password']);


// [Sensitive Data Exposure][Medium]
error_log("Password: " . $_POST['password']);


// [Missing Security Headers][Medium]
echo "No security headers set intentionally.";


// [Path Traversal][Easy]
include("uploads/" . $_GET['page']);


// [Path Traversal][Medium]
$file = $_GET['f'];
$content = file_get_contents("uploads/" . $file);
echo $content;


// [SSRF][Easy]
$url = $_GET['url'];
echo file_get_contents($url);


// [SSRF][Medium]
$host = $_POST['host'];
$response = curl_init("http://" . $host);
curl_exec($response);


// [SSRF][Mikhail][Safe]
// код безопасный - не должно быть срабатывания
$host = $_POST['host'];
if (!in_array($host, ['tilda.by', 'tilda.cc'])) {
	die('Wrong host');
}
$response = curl_init("http://" . $host);
curl_exec($response);


// [Insecure Crypto][Easy]
echo md5($_POST['password']);


// [Insecure Crypto][Medium]
$key = "123456";
$encrypted = openssl_encrypt($_POST['data'], 'aes128', $key);


// [Mass Assignment][Easy]
foreach ($_POST as $k => $v) {
	$user->$k = $v;
}


// [Mass Assignment][Medium]
$allowed = ['name', 'email'];
foreach ($_POST as $k => $v) {
	if (in_array($k, $allowed)) {
		$user->$k = $v;
	}
}
?>
