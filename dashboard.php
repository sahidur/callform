<?php
session_start();
require 'db.php';
require 'csrf.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$message = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['check'])) {
    if (!verifyCsrfToken($_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $input = htmlspecialchars($_POST['input']);

    // Check if input email or phone exists
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? OR user_phone = ?");
    $stmt->execute([$input, $input]);
    if ($stmt->rowCount() > 0) {
        $message = 'User found!';
    } else {
        $message = 'User not found!';
    }
}

// Handle CSV upload
$csv_message = '';
$csv_results = [];
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['csv_file'])) {
    if (!verifyCsrfToken($_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $file = $_FILES['csv_file']['tmp_name'];

    if (($handle = fopen($file, 'r')) !== false) {
        while (($data = fgetcsv($handle, 1000, ',')) !== false) {
            $email = filter_var($data[0], FILTER_SANITIZE_EMAIL);
            $phone = htmlspecialchars($data[1]);

            $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? OR user_phone = ?");
            $stmt->execute([$email, $phone]);
            $exists = $stmt->rowCount() > 0 ? 'Exists' : 'Does not exist';

            $csv_results[] = ['email' => $email, 'phone' => $phone, 'status' => $exists];
        }
        fclose($handle);
    } else {
        $csv_message = 'Error opening the file.';
    }
}

$csrf_token = generateCsrfToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h2>Welcome, <?= htmlspecialchars($_SESSION['user_email']) ?></h2>
        <p><a href="logout.php" class="btn btn-danger">Logout</a></p>

        <!-- Check Email/Phone Form -->
        <h3>Check User by Email/Phone</h3>
        <?php if ($message): ?>
            <div class="alert alert-info"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
            <div class="form-group">
                <label for="input">Email or Phone:</label>
                <input type="text" class="form-control" name="input" required>
            </div>
            <button type="submit" name="check" class="btn btn-primary">Check</button>
        </form>

        <!-- CSV Upload Form -->
        <h3>Upload CSV File</h3>
        <?php if ($csv_message): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($csv_message) ?></div>
        <?php endif; ?>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
            <div class="form-group">
                <label for="csv_file">CSV File:</label>
                <input type="file" class="form-control" name="csv_file" accept=".csv" required>
            </div>
            <button type="submit" class="btn btn-primary">Upload and Check</button>
        </form>

        <!-- CSV Results Table -->
        <?php if (!empty($csv_results)): ?>
            <h4>CSV Check Results</h4>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($csv_results as $result): ?>
                        <tr>
                            <td><?= htmlspecialchars($result['email']) ?></td>
                            <td><?= htmlspecialchars($result['phone']) ?></td>
                            <td><?= $result['status'] ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</body>
</html>
