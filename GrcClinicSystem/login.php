<?php
session_start();
include 'db_connect.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $email = trim($_POST['email']);
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();

        if (password_verify($password, $user['password'])) {

            // Set session variables
            $_SESSION['user_id'] = $user['user_id'];
            $_SESSION['full_name'] = $user['first_name'] . ' ' . $user['last_name'];
            $_SESSION['position'] = $user['position'];

            // Redirect based on position
            if ($user['position'] === 'Staff') {
                header("Location: index.html");
                exit;
            } elseif ($user['position'] === 'Doctor') {
                header("Location: dashboardfordoctor.html");
                exit;
            } else {
                // Unauthorized position
                header("Location: login.html?error=" . urlencode("You do not have access to the dashboard."));
                exit;
            }

        } else {
            header("Location: login.html?error=" . urlencode("Email or password is incorrect."));
            exit;
        }

    } else {
        header("Location: login.html?error=" . urlencode("No account found with this email."));
        exit;
    }

    $stmt->close();
    $conn->close();
}
?>
