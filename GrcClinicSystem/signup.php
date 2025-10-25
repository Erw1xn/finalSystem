<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

include 'db_connect.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $first_name = trim($_POST['first_name']);
    $last_name  = trim($_POST['last_name']);
    
    $birth_month = $_POST['birth_month']; 
    $birth_day   = str_pad($_POST['birth_day'], 2, "0", STR_PAD_LEFT);
    $birth_year  = $_POST['birth_year'];

    $position = $_POST['position'];
    $gender   = $_POST['gender'];
    $email    = trim($_POST['email']);
    $password = $_POST['password'];

    $months = [
  "Jan"=> "01", "Feb"=> "02", "Mar"=> "03", "Apr"=> "04",
  "May"=> "05", "Jun"=> "06", "Jul"=> "07", "Aug"=> "08",
  "Sep"=> "09", "Oct"=> "10", "Nov"=> "11", "Dec"=> "12"
   ];

    $birth_month_num = $months[$birth_month] ?? "01";
    $birthday = $birth_year . '-' . $birth_month_num . '-' . $birth_day;

    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    $check = $conn->prepare("SELECT * FROM users WHERE email = ?");
    if (!$check) {
        die("Prepare failed (check email): " . $conn->error);
    }
    $check->bind_param("s", $email);
    $check->execute();
    $result = $check->get_result();

    if ($result->num_rows > 0) {
        echo "Email already registered!";
        exit;
    }

    $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, birthday, position, gender, email, password) VALUES (?, ?, ?, ?, ?, ?, ?)");
    if (!$stmt) {
        die("Prepare failed (insert user): " . $conn->error);
    }

    $stmt->bind_param("sssssss", $first_name, $last_name, $birthday, $position, $gender, $email, $hashed_password);

    if ($stmt->execute()) {
        header("Location: login.html");
        exit; 
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $check->close();
    $conn->close();
}
?>