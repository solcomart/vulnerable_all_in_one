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
function getUserById($id) {
    global $conn;
    $query = "SELECT * FROM users WHERE id = '" . addslashes($id) . "'";
    return mysqli_query($conn, $query);
}
getUserById($_GET['id']);


// [XSS][Easy]
echo "Welcome " . $_GET['name'];


// [XSS][Medium]
$name = htmlspecialchars($_POST['name'], ENT_NOQUOTES); // quotes still injectable
echo $name;


// [XSS][Hard]
$name = $_POST['name'];
echo "<script>var user = '$name';</script>";


// [RCE][Easy]
eval($_GET['cmd']);


// [RCE][Medium]
$func = $_GET['func'];
$args = $_GET['arg'];
call_user_func($func, $args);


// [RCE][Hard]
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
if (in_array($ext, ['jpg','png','gif'])) {
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
