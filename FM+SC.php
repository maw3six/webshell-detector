<?php
/**
 * Secure File Manager & Malware Scanner v2.0
 * @version 2.0
 * @author maw3six t.me/maw3six
 * @description Complete integrated system for secure file management and malware detection
 */

declare(strict_types=1);
error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);

session_start();

// =============================================================================
// CONFIGURATION
// =============================================================================

final class SystemConfig
{
    public const SECURITY = [
        'password_hash' => '$2a$12$HSxU5hnuvNJw1q4CFerjE.bEHeFWfCr6qJNTDvlhvFLbZqpgttrf6',
        'session_timeout' => 3600,
        'access_key' => 'maw3six',
        'csrf_token_length' => 32,
        'rate_limit_delay' => 2,
    ];

    public const FILESYSTEM = [
        'max_file_size' => 10485760,
        'max_upload_size' => 50485760,
        'max_depth' => 10,
        'timeout' => 300,
        'scan_extensions' => ['php', 'phtml', 'shtml', 'php7', 'phar', 'asp', 'aspx', 'js'],
        'editable_extensions' => ['php', 'html', 'css', 'js', 'txt', 'md', 'json', 'xml', 'yml', 'yaml', 'htaccess', 'conf'],
        'image_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'],
        'allowed_upload_types' => ['php', 'html', 'css', 'js', 'txt', 'md', 'json', 'xml', 'jpg', 'png', 'gif', 'pdf', 'zip'],
        'protected_paths' => ['/etc', '/bin', '/sbin', '/usr/bin', '/root', '/boot'],
    ];

    public const UI = [
        'theme' => 'dark',
        'language' => 'en',
        'pagination_limit' => 50,
        'max_preview_lines' => 50,
    ];

    public const SCANNER = [
        'max_patterns_per_file' => 100,
        'heuristic_threshold' => 5,
    ];

    public static function getAll(): array
    {
        return [
            'security' => self::SECURITY,
            'filesystem' => self::FILESYSTEM,
            'ui' => self::UI,
            'scanner' => self::SCANNER,
        ];
    }
}

// =============================================================================
// SECURITY COMPONENTS
// =============================================================================

final class SecurityManager
{
    private array $config;
    private array $errors = [];

    public function __construct(array $config)
    {
        $this->config = $config['security'];
    }

    public function authenticate(): bool
    {
        return $this->isAuthenticated() && $this->updateSessionActivity();
    }

    public function processLogin(string $password): bool
    {
        if (password_verify($password, $this->config['password_hash'])) {
            $this->startSecureSession();
            return true;
        }

        $this->errors[] = 'Invalid password';
        $this->rateLimitDelay();
        return false;
    }

    public function generateCSRFToken(): string
    {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes($this->config['csrf_token_length']));
        }
        return $_SESSION['csrf_token'];
    }

    public function verifyCsrfToken(?string $token): bool
    {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token ?? '');
    }

    public function logout(): void
    {
        session_destroy();
        session_start();
        $_SESSION['message'] = 'Successfully logged out';
    }

    public function getErrors(): array
    {
        return $this->errors;
    }

    public function requireAuthentication(): void
    {
        if (!$this->authenticate()) {
            $this->showLoginForm();
            exit;
        }
    }

    private function showLoginForm(): void
    {
        $errors = $this->getErrors();
        $csrfToken = $this->generateCSRFToken();

        echo $this->renderLoginTemplate($errors, $csrfToken);
    }

    private function renderLoginTemplate(array $errors, string $csrfToken): string
    {
        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure File Manager - Login</title>
        <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        .login-header { margin-bottom: 30px; }
        .login-header h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        .login-header p { color: #666; font-size: 14px; }
        .input-group { margin-bottom: 20px; position: relative; }
        .input-group input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .input-group input:focus { outline: none; border-color: #667eea; }
        .login-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .login-btn:hover { transform: translateY(-2px); }
        .error {
            color: #e74c3c;
            margin-bottom: 15px;
            padding: 10px;
            background: #fdf2f2;
            border-radius: 5px;
            border-left: 4px solid #e74c3c;
        }
        .show-password {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #666;
            user-select: none;
        }
        </style>
        </head>
        <body>
        <div class="login-container">
        <div class="login-header">
        <h1>🔐 Secure Access</h1>
        <p>File Manager & Security Scanner</p>
        </div>

        <?php if (!empty($errors)): ?>
        <?php foreach ($errors as $error): ?>
        <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endforeach; ?>
        <?php endif; ?>

        <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
        <div class="input-group">
        <input type="password" id="password" name="login_password" placeholder="Enter password" required>
        <span class="show-password" onclick="togglePassword()">👁️</span>
        </div>
        <button type="submit" class="login-btn">Login</button>
        </form>
        </div>

        <script>
        function togglePassword() {
            const passwordField = document.getElementById("password");
            const type = passwordField.getAttribute("type") === "password" ? "text" : "password";
            passwordField.setAttribute("type", type);
        }
        document.getElementById("password").focus();
        </script>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    private function isAuthenticated(): bool
    {
        if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
            return false;
        }

        if (isset($_SESSION['last_activity']) &&
            (time() - $_SESSION['last_activity']) > $this->config['session_timeout']) {
            $this->destroySession();
        return false;
            }

            if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
                $this->destroySession();
                return false;
            }

            return true;
    }

    private function startSecureSession(): void
    {
        $_SESSION['authenticated'] = true;
        $_SESSION['last_activity'] = time();
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['login_time'] = time();
    }

    private function updateSessionActivity(): bool
    {
        if (isset($_SESSION['last_activity'])) {
            $_SESSION['last_activity'] = time();
            return true;
        }
        return false;
    }

    private function destroySession(): void
    {
        session_destroy();
    }

    private function rateLimitDelay(): void
    {
        sleep($this->config['rate_limit_delay']);
    }
}

final class UrlEncryption
{
    private string $key;

    public function __construct()
    {
        $this->key = hash('sha256', SystemConfig::SECURITY['password_hash']);
    }

    public function encrypt(string $value): string
    {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($value, 'AES-256-CBC', $this->key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    public function decrypt(string $encryptedValue, string $default = ''): string
    {
        try {
            $data = base64_decode($encryptedValue);
            if ($data === false || strlen($data) < 16) {
                return $default;
            }

            $iv = substr($data, 0, 16);
            $encrypted = substr($data, 16);
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->key, 0, $iv);

            return $decrypted !== false ? $decrypted : $default;
        } catch (Exception $e) {
            error_log("URL decryption error: " . $e->getMessage());
            return $default;
        }
    }

    public function generateSecureUrl(string $baseUrl, array $params = []): string
    {
        $encryptedParams = [];
        foreach ($params as $key => $value) {
            $encryptedParams[$key] = $this->encrypt($value);
        }

        if (!empty($encryptedParams)) {
            $baseUrl .= '?' . http_build_query($encryptedParams);
        }

        return $baseUrl;
    }
}

// =============================================================================
// FILE SYSTEM OPERATIONS
// =============================================================================

final class FileSystemManager
{
    private array $config;
    private string $currentPath;
    private array $items = [];

    public function __construct(array $config, string $currentPath)
    {
        $this->config = $config['filesystem'];
        $this->currentPath = $this->sanitizePath($currentPath);
        set_time_limit($this->config['timeout']);
    }

    public function getCurrentPath(): string
    {
        return $this->currentPath;
    }

    public function getDirectoryContents(): array
    {
        $items = [];
        $files = @scandir($this->currentPath);

        if (!$files) {
            return $items;
        }

        foreach ($files as $file) {
            if ($file === '.') continue;
            if ($file === '..' && $this->currentPath === '/') continue;

            $fullPath = $this->currentPath . DIRECTORY_SEPARATOR . $file;
            $isDir = is_dir($fullPath);
            $extension = $isDir ? '' : strtolower(pathinfo($file, PATHINFO_EXTENSION));

            $item = [
                'name' => $file,
                'path' => $fullPath,
                'relative_path' => $file,
                'is_directory' => $isDir,
                'extension' => $extension,
                'size' => $isDir ? 0 : filesize($fullPath),
                'modified' => filemtime($fullPath),
                'permissions' => substr(sprintf('%o', fileperms($fullPath)), -4),
                'is_readable' => is_readable($fullPath),
                'is_writable' => is_writable($fullPath),
                'icon' => $this->getFileIcon($file, $isDir, $extension),
                'is_scannable' => !$isDir && in_array($extension, $this->config['scan_extensions']),
                'is_editable' => !$isDir && in_array($extension, $this->config['editable_extensions']),
                'is_image' => !$isDir && in_array($extension, $this->config['image_extensions'])
            ];

            // Quick scan for scannable files
            if ($item['is_scannable']) {
                $scanner = new MalwareScanner(SystemConfig::getAll());
                $scanResult = $scanner->quickScanFile($fullPath);
                if ($scanResult) {
                    $item['threat_level'] = $scanResult['threat_level'];
                    $item['is_threat'] = $scanResult['is_threat'];
                    $item['risk_score'] = $scanResult['risk_score'];
                }
            }

            $items[] = $item;
        }

        // Sort items: directories first, then alphabetical
        usort($items, function($a, $b) {
            if ($a['name'] === '..') return -1;
            if ($b['name'] === '..') return 1;
            if ($a['is_directory'] && !$b['is_directory']) return -1;
            if (!$a['is_directory'] && $b['is_directory']) return 1;
            return strcasecmp($a['name'], $b['name']);
        });

        return $items;
    }

    public function handleFileUpload(): array
    {
        if (!isset($_FILES['upload_file'])) {
            return ['success' => false, 'error' => 'No file uploaded'];
        }

        $file = $_FILES['upload_file'];
        $targetPath = $this->currentPath . DIRECTORY_SEPARATOR . basename($file['name']);
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

        // Validation
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'error' => 'Upload error: ' . $file['error']];
        }

        if ($file['size'] > $this->config['max_upload_size']) {
            return ['success' => false, 'error' => 'File too large'];
        }

        if (!in_array($extension, $this->config['allowed_upload_types'])) {
            return ['success' => false, 'error' => 'File type not allowed'];
        }

        if (file_exists($targetPath)) {
            return ['success' => false, 'error' => 'File already exists'];
        }

        if (!move_uploaded_file($file['tmp_name'], $targetPath)) {
            return ['success' => false, 'error' => 'Failed to move uploaded file'];
        }

        // Scan uploaded file
        $scanResult = null;
        if (in_array($extension, $this->config['scan_extensions'])) {
            $scanner = new MalwareScanner(SystemConfig::getAll());
            $scanResult = $scanner->quickScanFile($targetPath);
        }

        return [
            'success' => true,
            'message' => 'File uploaded successfully',
            'filename' => basename($file['name']),
            'scan_result' => $scanResult
        ];
    }

    public function createDirectory(string $name): array
    {
        $dirPath = $this->currentPath . DIRECTORY_SEPARATOR . $name;

        if (file_exists($dirPath)) {
            return ['success' => false, 'error' => 'Directory already exists'];
        }

        if (mkdir($dirPath, 0755)) {
            return ['success' => true, 'message' => 'Directory created successfully'];
        }

        return ['success' => false, 'error' => 'Failed to create directory'];
    }

    public function deleteItem(string $path): array
    {
        $fullPath = realpath($path);

        if (!$fullPath || !file_exists($fullPath)) {
            return ['success' => false, 'error' => 'File not found'];
        }

        // Protect system paths
        foreach ($this->config['protected_paths'] as $protected) {
            if (strpos($fullPath, $protected) === 0) {
                return ['success' => false, 'error' => 'Cannot delete protected path'];
            }
        }

        if (is_dir($fullPath)) {
            return rmdir($fullPath)
            ? ['success' => true, 'message' => 'Directory deleted successfully']
            : ['success' => false, 'error' => 'Failed to delete directory (not empty?)'];
        }

        return unlink($fullPath)
        ? ['success' => true, 'message' => 'File deleted successfully']
        : ['success' => false, 'error' => 'Failed to delete file'];
    }

    public function renameItem(string $oldPath, string $newName): array
    {
        $oldFullPath = realpath($oldPath);
        $newFullPath = dirname($oldFullPath) . DIRECTORY_SEPARATOR . $newName;

        if (!$oldFullPath || !file_exists($oldFullPath)) {
            return ['success' => false, 'error' => 'File not found'];
        }

        if (file_exists($newFullPath)) {
            return ['success' => false, 'error' => 'Target name already exists'];
        }

        return rename($oldFullPath, $newFullPath)
        ? ['success' => true, 'message' => 'Item renamed successfully']
        : ['success' => false, 'error' => 'Failed to rename item'];
    }

    public function getFileContent(string $filePath): array
    {
        $realPath = realpath($filePath);

        if (!$realPath || !is_file($realPath)) {
            return ['success' => false, 'error' => 'File not found'];
        }

        $extension = strtolower(pathinfo($realPath, PATHINFO_EXTENSION));
        if (!in_array($extension, $this->config['editable_extensions'])) {
            return ['success' => false, 'error' => 'File type not editable'];
        }

        $content = @file_get_contents($realPath);
        if ($content === false) {
            return ['success' => false, 'error' => 'Cannot read file'];
        }

        return [
            'success' => true,
            'content' => $content,
            'size' => filesize($realPath),
            'modified' => filemtime($realPath),
            'extension' => $extension,
            'filename' => basename($realPath)
        ];
    }

    public function saveFileContent(string $filePath, string $content): array
    {
        $realPath = realpath($filePath);

        if (!$realPath || !is_file($realPath)) {
            return ['success' => false, 'error' => 'File not found'];
        }

        if (!is_writable($realPath)) {
            return ['success' => false, 'error' => 'File not writable'];
        }

        $extension = strtolower(pathinfo($realPath, PATHINFO_EXTENSION));
        if (!in_array($extension, $this->config['editable_extensions'])) {
            return ['success' => false, 'error' => 'File type not editable'];
        }

        // Create backup
        $backupPath = $realPath . '.backup.' . time();
        copy($realPath, $backupPath);

        if (file_put_contents($realPath, $content) !== false) {
            $scanResult = null;
            if (in_array($extension, $this->config['scan_extensions'])) {
                $scanner = new MalwareScanner(SystemConfig::getAll());
                $scanResult = $scanner->quickScanFile($realPath);
            }

            return [
                'success' => true,
                'message' => 'File saved successfully',
                'backup_created' => $backupPath,
                'scan_result' => $scanResult
            ];
        }

        return ['success' => false, 'error' => 'Failed to save file'];
    }

    public function createFile(string $fileName, string $content = ''): array
    {
        $fileName = preg_replace('/[^a-zA-Z0-9._-]/', '', $fileName);
        if (empty($fileName)) {
            return ['success' => false, 'error' => 'Invalid filename'];
        }

        $filePath = $this->currentPath . DIRECTORY_SEPARATOR . $fileName;

        if (file_exists($filePath)) {
            return ['success' => false, 'error' => 'File already exists'];
        }

        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        if (!in_array($extension, $this->config['editable_extensions'])) {
            return ['success' => false, 'error' => 'File type not allowed'];
        }

        if (file_put_contents($filePath, $content) !== false) {
            chmod($filePath, 0644);

            $scanResult = null;
            if (in_array($extension, $this->config['scan_extensions'])) {
                $scanner = new MalwareScanner(SystemConfig::getAll());
                $scanResult = $scanner->quickScanFile($filePath);
            }

            return [
                'success' => true,
                'message' => 'File created successfully',
                'filename' => $fileName,
                'scan_result' => $scanResult
            ];
        }

        return ['success' => false, 'error' => 'Failed to create file'];
    }

    public function changeFilePermissions(string $filePath, string $permissions): array
    {
        $realPath = realpath($filePath);

        if (!$realPath || !file_exists($realPath)) {
            return ['success' => false, 'error' => 'File not found'];
        }

        foreach ($this->config['protected_paths'] as $protected) {
            if (strpos($realPath, $protected) === 0) {
                return ['success' => false, 'error' => 'Cannot modify permissions of protected path'];
            }
        }

        if (!preg_match('/^[0-7]{3,4}$/', $permissions)) {
            return ['success' => false, 'error' => 'Invalid permissions format'];
        }

        $octalPermissions = octdec($permissions);

        return chmod($realPath, $octalPermissions)
        ? ['success' => true, 'message' => 'Permissions changed successfully']
        : ['success' => false, 'error' => 'Failed to change permissions'];
    }

    public function getFilePermissions(string $filePath): array
    {
        $realPath = realpath($filePath);

        if (!$realPath || !file_exists($realPath)) {
            return ['success' => false, 'error' => 'File not found'];
        }

        $permissions = fileperms($realPath);
        $octal = substr(sprintf('%o', $permissions), -4);

        return [
            'success' => true,
            'permissions' => $octal,
            'readable' => is_readable($realPath),
            'writable' => is_writable($realPath),
            'executable' => is_executable($realPath)
        ];
    }

    public function getBreadcrumb(): array
    {
        $parts = explode(DIRECTORY_SEPARATOR, trim($this->currentPath, DIRECTORY_SEPARATOR));
        $breadcrumb = [];
        $currentPath = '';

        foreach ($parts as $index => $part) {
            if (empty($part)) continue;

            $currentPath .= ($index === 0 ? '' : DIRECTORY_SEPARATOR) . $part;
            $breadcrumb[] = [
                'name' => $part,
                'path' => $currentPath,
                'is_current' => $index === count($parts) - 1
            ];
        }

        return $breadcrumb;
    }

    public function getDirectorySuggestions(): array
    {
        $currentPath = dirname($_SERVER['SCRIPT_FILENAME']);
        $suggestions = [$currentPath];

        // Add parent directories
        $pathParts = explode(DIRECTORY_SEPARATOR, trim($currentPath, DIRECTORY_SEPARATOR));
        $builtPath = '';

        foreach ($pathParts as $part) {
            if (!empty($part)) {
                $builtPath .= DIRECTORY_SEPARATOR . $part;
                if (is_dir($builtPath) && !in_array($builtPath, $suggestions)) {
                    $suggestions[] = $builtPath;
                }
            }
        }

        // Add common web directories
        $commonDirs = [
            $_SERVER['DOCUMENT_ROOT'],
            '/var/www',
            '/var/www/html',
            '/home',
            '/usr/local/www'
        ];

        foreach ($commonDirs as $dir) {
            if (is_dir($dir) && !in_array($dir, $suggestions)) {
                $suggestions[] = $dir;
            }
        }

        return array_unique($suggestions);
    }

    private function sanitizePath(string $path): string
    {
        // Try encrypted path first
        $encryption = new UrlEncryption();
        $sanitizedPath = $encryption->decrypt($path);

        if (empty($sanitizedPath) && !empty($_GET['path'])) {
            $sanitizedPath = $_GET['path']; // Fallback
        }

        if (empty($sanitizedPath)) {
            $sanitizedPath = dirname($_SERVER['SCRIPT_FILENAME']);
        }

        $realPath = realpath($sanitizedPath);
        if (!$realPath || !is_dir($realPath)) {
            return dirname($_SERVER['SCRIPT_FILENAME']);
        }

        // Protect system paths
        foreach ($this->config['protected_paths'] as $protected) {
            if (strpos($realPath, $protected) === 0) {
                return dirname($_SERVER['SCRIPT_FILENAME']);
            }
        }

        return $realPath;
    }

    private function getFileIcon(string $filename, bool $isDir, string $extension): string
    {
        if ($isDir) {
            return $filename === '..' ? 'fas fa-arrow-left' : 'fas fa-folder';
        }

        $iconMap = [
            'php' => 'fab fa-php',
            'html' => 'fab fa-html5',
            'css' => 'fab fa-css3-alt',
            'js' => 'fab fa-js-square',
            'json' => 'fas fa-code',
            'xml' => 'fas fa-code',
            'txt' => 'fas fa-file-alt',
            'md' => 'fab fa-markdown',
            'jpg' => 'fas fa-image',
            'jpeg' => 'fas fa-image',
            'png' => 'fas fa-image',
            'gif' => 'fas fa-image',
            'zip' => 'fas fa-file-archive',
            'pdf' => 'fas fa-file-pdf',
            'htaccess' => 'fas fa-cog',
            'conf' => 'fas fa-cogs',
        ];

        return $iconMap[$extension] ?? 'fas fa-file';
    }
}

// =============================================================================
// MALWARE SCANNER
// =============================================================================

final class MalwareScanner
{
    private array $config;
    private array $patterns;
    private array $results = [];
    private array $errors = [];

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->patterns = $this->loadMalwarePatterns();
    }

    public function scanDirectory(string $directory, int $depth = 0): void
    {
        if ($depth > $this->config['filesystem']['max_depth']) {
            return;
        }

        $validPath = $this->validatePath($directory);
        if (!$validPath) {
            return;
        }

        $files = @scandir($validPath);
        if (!$files) {
            $this->errors[] = "Cannot read directory: $directory";
            return;
        }

        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;

            $fullPath = $validPath . DIRECTORY_SEPARATOR . $file;

            if (is_dir($fullPath)) {
                $this->scanDirectory($fullPath, $depth + 1);
            } elseif (is_file($fullPath)) {
                $this->scanFile($fullPath);
            }
        }
    }

    public function quickScanFile(string $filePath): ?array
    {
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $fileSize = filesize($filePath);

        if ($fileSize > $this->config['filesystem']['max_file_size']) {
            return null;
        }

        if (!in_array($extension, $this->config['filesystem']['scan_extensions'])) {
            return null;
        }

        $content = @file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        $detectedPatterns = [];
        $riskScore = 0;

        foreach ($this->patterns as $pattern) {
            if (stripos($content, $pattern) !== false) {
                $detectedPatterns[] = $pattern;
                $riskScore += $this->calculatePatternRisk($pattern);
            }
        }

        $heuristicResults = $this->performHeuristicAnalysis($content);
        if (!empty($heuristicResults['patterns'])) {
            $detectedPatterns = array_merge($detectedPatterns, $heuristicResults['patterns']);
            $riskScore += $heuristicResults['risk_score'];
        }

        if (empty($detectedPatterns)) {
            return null;
        }

        return [
            'path' => $filePath,
            'size' => $fileSize,
            'extension' => $extension,
            'modified' => filemtime($filePath),
            'patterns' => $detectedPatterns,
            'risk_score' => $riskScore,
            'threat_level' => $this->calculateThreatLevel($riskScore, count($detectedPatterns)),
            'hash' => hash('sha256', $content),
            'is_threat' => true
        ];
    }

    public function getResults(): array
    {
        return $this->results;
    }

    public function filterResultsByThreatLevel(array $results, string $threatLevel): array
    {
        if (empty($threatLevel) || $threatLevel === 'all') {
            return $results;
        }

        return array_filter($results, function($result) use ($threatLevel) {
            return strtolower($result['threat_level']) === strtolower($threatLevel);
        });
    }

    public function getUniqueThreatLevels(array $results): array
    {
        $levels = array_unique(array_map(fn($result) => $result['threat_level'], $results));
        $priority = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

        usort($levels, fn($a, $b) => array_search($a, $priority) <=> array_search($b, $priority));
        return $levels;
    }

    private function loadMalwarePatterns(): array
    {
        return [
            // High-risk execution patterns
            'eval($_POST', 'eval($_GET', 'eval($_REQUEST', 'eval($_COOKIE',
            'system($_POST', 'system($_GET', 'system($_REQUEST', 'system($_COOKIE',
            'exec($_POST', 'exec($_GET', 'exec($_REQUEST', 'exec($_COOKIE',
            'shell_exec($_POST', 'shell_exec($_GET', 'shell_exec($_REQUEST', 'shell_exec($_COOKIE',
            'passthru($_POST', 'passthru($_GET', 'passthru($_REQUEST', 'passthru($_COOKIE',
            'assert($_POST', 'assert($_GET', 'assert($_REQUEST', 'assert($_COOKIE',

            // Regex execution vulnerabilities
            'preg_replace("/.*/e', 'preg_replace("/.*/e', '/e\s*\)', 'preg_replace\([^,]*\s*e\s*[,]',
            'preg_replace\([^,]*["\']\s*\.\s*["\']\s*e\s*[,]', 'preg_replace\([^,]*\`\s*\`\s*e\s*[,]',

            // Dynamic function creation and execution
            'create_function(', 'call_user_func(', 'call_user_func_array(',
            'array_map(\s*["\']assert["\']', 'array_map(\s*["\']eval["\']',
            'array_filter(\s*["\']assert["\']', 'array_filter(\s*["\']eval["\']',
            'usort(\s*["\']assert["\']', 'uasort(\s*["\']assert["\']',

            // Encoding/Decoding functions (obfuscation)
            'base64_decode(', 'gzinflate(', 'gzuncompress(', 'str_rot13(', 'gzdecode(',
            'convert_uudecode(', 'hex2bin(', 'urldecode(', 'rawurldecode(', 'strrev(',
            'base64_decode\s*\(\s*base64_decode', 'strrev\s*\(\s*base64_decode',
            'str_rot13\s*\(\s*base64_decode', 'gzinflate\s*\(\s*base64_decode',
            'gzuncompress\s*\(\s*base64_decode', 'gzdecode\s*\(\s*base64_decode',

            // File manipulation with user input
            'file_get_contents($_GET', 'file_get_contents($_POST', 'file_get_contents($_REQUEST',
            'file_put_contents($_GET', 'file_put_contents($_POST', 'file_put_contents($_REQUEST',
            'fopen($_GET', 'fopen($_POST', 'fopen($_REQUEST',
            'fwrite($_GET', 'fwrite($_POST', 'fwrite($_REQUEST',
            'unlink($_GET', 'unlink($_POST', 'unlink($_REQUEST',
            'include($_GET', 'include($_POST', 'include($_REQUEST', 'include_once($_GET',
            'require($_GET', 'require($_POST', 'require($_REQUEST', 'require_once($_GET',
            'move_uploaded_file($_GET', 'move_uploaded_file($_POST', 'move_uploaded_file($_REQUEST',

            // Dangerous file operations
            'fsockopen(', 'pfsockopen(', 'stream_socket_client(', 'socket_create(',
            'mail(\s*[,][^,]*\s*[,][^,]*\s*[,][^,]*\s*-O', 'mail(\s*[,][^,]*\s*[,][^,]*\s*[,][^,]*\s*-C',
            'symlink(', 'link(', 'readlink(', 'lchgrp(', 'lchown(',

            // Session manipulation
            'session_start(\s*\)\s*;', '$_SESSION\s*\[', 'session_destroy(',
            'setcookie(\s*[^,]*\s*[,]\s*[^,]*\s*[,]\s*0\s*[,]\s*["\']\s*\)',

            // SQL injection patterns
            'mysql_query\s*\(\s*\$_(GET|POST|REQUEST)', 'mysqli_query\s*\(\s*[^,]*\s*,\s*\$_(GET|POST|REQUEST)',
            'pg_query\s*\(\s*\$_(GET|POST|REQUEST)', 'sqlite_query\s*\(\s*\$_(GET|POST|REQUEST)',

            // Obfuscation techniques
            'chr\s*\(\s*\d+\s*\)\s*\.', 'chr\s*\(\s*\d+\s*\)\s*\.\s*chr', '\$_\w+\s*\[\s*["\']\w+["\']\s*\]\s*\(\s*\$_\w+',
            'eval\s*\(\s*gzinflate\s*\(\s*base64_decode', 'eval\s*\(\s*strrev\s*\(\s*base64_decode',
            'eval\s*\(\s*str_rot13\s*\(\s*base64_decode', 'eval\s*\(\s*gzuncompress\s*\(\s*base64_decode',
            'eval\s*\(\s*gzdecode\s*\(\s*base64_decode', '@assert\s*\(\s*\$_', '@eval\s*\(\s*\$_',
            '@system\s*\(\s*\$_', '@exec\s*\(\s*\$_', 'assert\s*\(\s*base64_decode',

            // PHP configuration manipulation
            'ini_set\s*\(\s*["\']disable_functions["\']', 'ini_restore\s*\(', 'dl\s*\(',
            'set_time_limit\s*\(\s*0\s*\)', 'ignore_user_abort\s*\(\s*true\s*\)',
            'ini_set\s*\(\s*["\']open_basedir["\']',

            // Suspicious string concatenation
            '\$_\w+\s*\.\s*\$_\w+', '\$_\w+\s*\[\s*\$_\w+', '\$_\w+\s*\{\s*\$_\w+',

            // Malicious header manipulation
            'header\s*\(\s*["\']Location:\s*http', 'header\s*\(\s*["\']Content-Type:\s*text/html\s*;',

            // Cryptocurrency mining
            'coinhive', 'cryptoloot', 'authedmine', 'jsecoin', 'minero', 'webminer',

            // Additional dangerous functions
            'pcntl_exec(', 'proc_open(', 'popen(', 'escapeshellcmd(', 'escapeshellarg(',
            'stream_socket_server(', 'socket_connect(', 'socket_bind(', 'socket_listen(',
            'socket_accept(', 'socket_read(', 'socket_write(',

            // File upload vulnerabilities
            '\$_FILES\[', 'move_uploaded_file\s*\(', 'is_uploaded_file\s*\(',

            // Database connection strings
            'mysql_connect\s*\(', 'mysqli_connect\s*\(', 'pg_connect\s*\(', 'sqlite_open\s*\(',

            // Network functions
            'curl_exec\s*\(', 'curl_init\s*\(', 'file_get_contents\s*\(\s*["\']http',
            'fsockopen\s*\(', 'pfsockopen\s*\(',

            // Known webshell signatures and names from Shell-Strings.txt
            'WSO', 'WSO 2.5', 'WSO 2.6', 'WSO 4.2.5', 'WSO 4.2.6', 'WSO 5.0.0', 'WSO 5.1.4',
            'WSO YANZ ENC BYPASS', 'WSOX ENC', 'b374k', 'b374k 2.8', 'c99', 'c99shell',
            'r57shell', 'alfa', 'alfa-v4', 'ALFA TEaM Shell', 'IndoXploit', 'IndoXploit Shell',
            'Mini Shell', 'minishell', 'File manager', 'Tryag File Manager', 'B Ge Team File Manager',
            'FoxWSO', 'FoxWSO v1.2', 'Negat1ve Shell', 'WebShellOrb', 'WebShellOrb 2.6',
            'Yanz Webshell', 'X-Sec Shell', 'X_Shell', 'marijuana', 'MARIJuANA', 'Fuxxer',
            'Leaf PHPMailer', 'xleet', 'xleetshell', 'Dr HeX', 'H3X', 'izocin', 'Mr.Combet',
            'Psych0.WorM', 'Mister Spy', 'MisterSpyv7up', 'Raiz0WorM', 'RevoLutioN Namesis',
            'AnonGhost', 'GhostSec', '0byte', '0byt3m1n1', 'Gel4y Mini Shell', 'gel4y',
            'Lambo', 'LAMBO', 'Pr1v8 Upl0ader', 'Priv8 Uploader', 'Priv8 WebShell',
            'Priv8 Home Root Uploader', 'RxR', 'RxR HaCkEr', 'Walkers404', 'FierzaXploit',
            'KCT MINI SHELL', 'Sym403', 'Shell Bypass 403', 'Bypass Sh3ll', '403WebShell',
            'Mini Shell By Black_Shadow', 'Sh3ll', 'Webshell', 'PHU Mini Shell', 'Tiny File Manager',
            'Simple File Manage', 'Upload files', 'Vuln!! patch it Now!', 'xAttacker',
            'Andela1C3', 'Evil Twin', 'Jijle3', 'aDriv4', 'AnonymousFox', 'UnknownSec',
            'United Bangladeshi Hackers', 'United Tunsian Scammers', 'One Hat Cyber Team',
            'Kelelawar Cyber Team', 'Indramayu Cyber', 'Haxor Clan', 'Hunter Neel',
            'Graybyt3', 'Dr.D3m0', 'Franz Private Shell', 'Ninja Shell', 'DeathShop',
            'MarukoChan', 'SOQOR Shell', 'BlackDragon', 'TripleDNN', 'God4m', 'Con7ext',
            'JEMBOETS', 'Madstore', 'SEA-GHOST', 'WHY MINI SHELL', 'SIMPEL BANGET',
            'MatteKudasai', 'R@DIK@L', 'F0x', 'Shal Shell', 'King RxR', 'AlkantarClan',
            'Modified By #No_Identity', 'WIBUHAX0R1337', 'UBHTeam', 'Nopebee7', 'X7-ROOT',
            'D3xterR00t', 'Cod3d By', 'Team-0ROOT', 'SuramSh3ll', 'TheAlmightyZeus',
            'Cassano Bypass', 'F4st~03', 'Gelişmiş Dosya Yöneticisi', 'ABC Manager',
            'FileManager Version 0.2', 'CCAEF Uploader', 'ajout nouvelle actualité',
            'Leafmail3', 'alexusMailer', 'xLeet PHPMailer', 'FierzaXploit {Mini Shell }',
            'KCT MINI SHELL 403', 'FoxCyberSecurity', 'Minipriv', 'Smoker Backdoor',
            'V4Mp', 'wp-wso', 'wpindex', 'new-index', 'old-index', 'qindex', 'jindex',
            'Dr HeX', 'H3NING_MAL4M', 'CHips L Pro', '0x5a455553.github.io/MARIJUANA',
            'RansomWeb', 'Black Bot', 'Avaa Bypassed', 'LIER SHELL', 'MINI MO Shell',
            'MSQ_403', 'admin403', 'omest403', 'lock360', 'sym403', 'shellbypass',
            'p0wny@shell:~#', 'U7TiM4T3_H4x0R', 'Fighter Kamrul Plugin', 'Upl04d3r',
            'Upl0od Your T0ols', 'adriv4-Priv8 TOOL', 'cong', 'cot', 'jadow', 'mrjn',
            'tonant', 'sunda', 'sundaxploit', 'trenggalek6etar', 'bondowoso', 'blacksec',
            'gecko', 'load', 'local', 'pref', 'sys', 'vuln', 'ineSec Team Shell',
            'PHP Upload By Haxgeno7', 'kill_the_net', 'nopebee7', 'skullxploit', 'xichang1',
            'xforce', 'xdmah', 'kliverz1337', 'iCloud1337 private shell', 'walex says Fuck Off Kids:',
            'TINY SHELL', 'MINI SH3LL BYPASS', 'm1n1 5h3ll', 'm1n1 Shell', 'Sh3ll By Anons79',
            'Get S.H.E.L.L.en', 'Leaf PHP Mailer by [orvx.pw]', '- FierzaXploit -',
            'Leaf PHPMailer</title>', 'xleet-shell', 'yanz', 'Yanz Webshell!',
            'PRIV8 WEB SHELL ORB YANZ BYPASS!', 'Dr HeX', 'H3X', 'izocin', 'Mr.Combet WebShell',
            'Psych0.WorM', 'Mister Spy', 'MisterSpyv7up', 'Raiz0WorM', 'RevoLutioN Namesis'
        ];
    }

    private function validatePath(string $path): ?string
    {
        $realPath = realpath($path);

        if (!$realPath || !is_dir($realPath)) {
            return null;
        }

        foreach ($this->config['filesystem']['protected_paths'] as $protected) {
            if (strpos($realPath, $protected) === 0) {
                $this->errors[] = "Access denied to protected path: $protected";
                return null;
            }
        }

        return $realPath;
    }

    private function scanFile(string $filePath): void
    {
        $scanResult = $this->quickScanFile($filePath);
        if ($scanResult) {
            $this->results[] = array_merge($scanResult, [
                'preview' => $this->getFilePreview(file_get_contents($filePath))
            ]);
        }
    }

    private function calculatePatternRisk(string $pattern): int
    {
        $highRisk = ['eval(', 'system(', 'exec(', 'shell_exec(', 'passthru('];
        $mediumRisk = ['base64_decode(', 'gzinflate(', 'include(', 'require('];

        foreach ($highRisk as $hr) {
            if (stripos($pattern, $hr) !== false) return 10;
        }

        foreach ($mediumRisk as $mr) {
            if (stripos($pattern, $mr) !== false) return 5;
        }

        return 2;
    }

    private function performHeuristicAnalysis(string $content): array
    {
        $patterns = [];
        $riskScore = 0;

        // Obfuscation detection
        $obfuscationPatterns = [
            '/\$[a-zA-Z_]\w*\s*=\s*["\'][a-zA-Z0-9+\/=]{20,}["\'];/',
            '/chr\(\d+\)\.chr\(\d+\)/',
            '/eval\s*\(\s*\$\w+\s*\.\s*\$\w+\s*\)/'
        ];

        $obfuscationCount = 0;
        foreach ($obfuscationPatterns as $pattern) {
            $obfuscationCount += preg_match_all($pattern, $content, $matches);
        }

        if ($obfuscationCount > 5) {
            $patterns[] = 'Heavy obfuscation detected';
            $riskScore += 8;
        } elseif ($obfuscationCount > 2) {
            $patterns[] = 'Moderate obfuscation detected';
            $riskScore += 4;
        }

        // Encoding layers detection
        $encodings = ['base64_decode', 'gzinflate', 'str_rot13', 'hex2bin'];
        $encodingLayers = 0;
        foreach ($encodings as $encoding) {
            if (stripos($content, $encoding) !== false) $encodingLayers++;
        }

        if ($encodingLayers >= 3) {
            $patterns[] = 'Multiple encoding layers';
            $riskScore += 6;
        }

        // Error suppression
        $errorSuppressionCount = substr_count($content, '@');
        if ($errorSuppressionCount > 5) {
            $patterns[] = 'Excessive error suppression';
            $riskScore += 4;
        }

        return ['patterns' => $patterns, 'risk_score' => $riskScore];
    }

    private function calculateThreatLevel(int $riskScore, int $patternCount): string
    {
        if ($riskScore >= 20 || $patternCount >= 8) return 'CRITICAL';
        if ($riskScore >= 10 || $patternCount >= 5) return 'HIGH';
        if ($riskScore >= 5 || $patternCount >= 3) return 'MEDIUM';
        return 'LOW';
    }

    private function getFilePreview(string $content, int $maxLines = 5): string
    {
        $lines = explode("\n", $content);
        $preview = array_slice($lines, 0, $maxLines);
        return htmlspecialchars(implode("\n", $preview));
    }
}

// =============================================================================
// UI RENDERER
// =============================================================================

final class UIRenderer
{
    private array $config;
    private string $mode;
    private string $currentPath;
    private array $items;
    private array $scanResults;
    private array $breadcrumb;
    private array $directorySuggestions;

    public function __construct(
        array $config,
        string $mode,
        string $currentPath,
        array $items,
        array $scanResults = [],
        array $breadcrumb = [],
        array $directorySuggestions = []
    ) {
        $this->config = $config;
        $this->mode = $mode;
        $this->currentPath = $currentPath;
        $this->items = $items;
        $this->scanResults = $scanResults;
        $this->breadcrumb = $breadcrumb;
        $this->directorySuggestions = $directorySuggestions;
    }

    public function render(): string
    {
        return $this->mode === 'scanner'
        ? $this->renderScannerInterface()
        : $this->renderFileManagerInterface();
    }

    private function renderFileManagerInterface(): string
    {
        ob_start();
        $csrfToken = (new SecurityManager($this->config))->generateCSRFToken();
        $encryption = new UrlEncryption();
        ?>
        <!DOCTYPE html>
        <html lang="en" class="dark">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure File Manager & Scanner</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.23.4/ace.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.23.4/mode-php.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.23.4/theme-monokai.min.js"></script>
        <style>
        body { background-color: #0f172a; color: #e2e8f0; }
        .dark .card { background-color: #1e293b; border-color: #334155; }
        .dark .modal-content { background-color: #1e293b; }
        .dark .form-control {
            background-color: #1e293b !important;
            border-color: #334155 !important;
            color: #e2e8f0 !important;
        }
        .dark .form-control:focus {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 0.2rem rgba(59, 130, 246, 0.25) !important;
            color: #e2e8f0 !important;
        }
        .file-item:hover { background-color: #374151; }
        .threat-critical { border-left: 4px solid #ef4444; }
        .threat-high { border-left: 4px solid #f97316; }
        .threat-medium { border-left: 4px solid #eab308; }
        .threat-low { border-left: 4px solid #22c55e; }
        #editor { border: 1px solid #334155; height: 500px; }
        .modal-overlay { background-color: rgba(0, 0, 0, 0.75); }
        .form-control::placeholder { color: #9ca3af !important; }
        .form-select { background-color: #1e293b !important; border: 1px solid #334155 !important; color: #e2e8f0 !important; }
        .form-select option { background-color: #1e293b !important; color: #e2e8f0 !important; }
        .form-select:focus { border-color: #3b82f6 !important; box-shadow: 0 0 0 0.2rem rgba(59, 130, 246, 0.25) !important; }
        </style>
        </head>
        <body class="bg-gray-900 text-gray-200">
        <div class="container mx-auto px-4 py-6">
        <!-- Header -->
        <header class="mb-6">
        <div class="flex items-center justify-between">
        <div>
        <h1 class="text-3xl font-bold text-white flex items-center">
        <i class="fas fa-shield-alt mr-3 text-blue-500"></i>
        Secure File Manager
        </h1>
        <p class="text-gray-400 mt-2">Advanced file management with real-time security scanning</p>
        </div>
        <div class="flex items-center space-x-3">
        <span class="text-sm text-gray-400">Mode:</span>
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'filemanager', 'path' => $this->currentPath]) ?>"
        class="px-4 py-2 rounded bg-blue-600 text-white <?= $this->mode === 'filemanager' ? '' : 'bg-gray-600' ?>">
        <i class="fas fa-folder mr-2"></i>File Manager
        </a>
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'scanner', 'scan_dir' => $this->currentPath]) ?>"
        class="px-4 py-2 rounded bg-gray-600 text-white <?= $this->mode === 'scanner' ? 'bg-blue-600' : '' ?>">
        <i class="fas fa-search mr-2"></i>Security Scanner
        </a>
        <a href="?logout=1" class="px-4 py-2 rounded bg-red-600 text-white" onclick="return confirm('Logout?')">
        <i class="fas fa-sign-out-alt mr-2"></i>Logout
        </a>
        </div>
        </div>
        </header>

        <!-- Breadcrumb & Actions -->
        <div class="card rounded-lg shadow-lg mb-6">
        <div class="p-4">
        <div class="flex flex-wrap items-center justify-between gap-4">
        <!-- Breadcrumb -->
        <nav class="flex items-center space-x-2 text-sm">
        <i class="fas fa-home text-blue-400"></i>
        <?php foreach ($this->breadcrumb as $crumb): ?>
        <i class="fas fa-chevron-right text-gray-500"></i>
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'filemanager', 'path' => $crumb['path']]) ?>"
        class="text-blue-400 hover:text-blue-300">
        <?= htmlspecialchars($crumb['name']) ?>
        </a>
        <?php endforeach; ?>
        </nav>

        <!-- Action Buttons -->
        <div class="flex items-center space-x-2">
        <button onclick="showUploadModal()" class="px-4 py-2 bg-blue-600 text-white rounded flex items-center hover:bg-blue-700">
        <i class="fas fa-upload mr-2"></i>Upload
        </button>
        <button onclick="showCreateFolderModal()" class="px-4 py-2 bg-gray-600 text-white rounded flex items-center hover:bg-gray-500">
        <i class="fas fa-folder-plus mr-2"></i>New Folder
        </button>
        <button onclick="showCreateFileModal()" class="px-4 py-2 bg-green-600 text-white rounded flex items-center hover:bg-green-700">
        <i class="fas fa-file-plus mr-2"></i>New File
        </button>
        <button onclick="bulkScanSelected()" class="px-4 py-2 bg-yellow-600 text-white rounded flex items-center hover:bg-yellow-700">
        <i class="fas fa-search mr-2"></i>Scan Selected
        </button>
        <button onclick="location.reload()" class="px-4 py-2 bg-gray-600 text-white rounded flex items-center hover:bg-gray-500">
        <i class="fas fa-sync mr-2"></i>Refresh
        </button>
        </div>
        </div>
        </div>
        </div>

        <!-- File List -->
        <div class="card rounded-lg shadow-lg">
        <div class="p-4 border-b border-gray-700">
        <h2 class="text-xl font-semibold flex items-center">
        <i class="fas fa-folder-open mr-2 text-blue-400"></i>
        Directory Contents (<?= count($this->items) ?> items)
        </h2>
        </div>

        <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-700">
        <thead class="bg-gray-800">
        <tr>
        <th class="px-6 py-3 text-left"><input type="checkbox" id="selectAll" class="rounded"></th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase">Name</th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase">Size</th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase">Modified</th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase">Permissions</th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase">Security</th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase">Actions</th>
        </tr>
        </thead>
        <tbody class="divide-y divide-gray-700">
        <?php foreach ($this->items as $item): ?>
        <tr class="file-item hover:bg-gray-800 <?= isset($item['threat_level']) ? 'threat-' . strtolower($item['threat_level']) : '' ?>"
        data-path="<?= htmlspecialchars($item['path']) ?>">
        <td class="px-6 py-4">
        <?php if ($item['name'] !== '..'): ?>
        <input type="checkbox" class="file-checkbox rounded" value="<?= htmlspecialchars($item['path']) ?>">
        <?php endif; ?>
        </td>
        <td class="px-6 py-4">
        <div class="flex items-center">
        <i class="<?= $item['icon'] ?> mr-3 text-blue-400"></i>
        <?php if ($item['is_directory']): ?>
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'filemanager', 'path' => $item['path']]) ?>"
        class="text-blue-400 hover:text-blue-300 font-medium">
        <?= htmlspecialchars($item['name']) ?>/
        </a>
        <?php else: ?>
        <span class="font-medium"><?= htmlspecialchars($item['name']) ?></span>
        <?php if (isset($item['is_threat']) && $item['is_threat']): ?>
        <i class="fas fa-exclamation-triangle text-red-500 ml-2" title="Potential threat"></i>
        <?php endif; ?>
        <?php endif; ?>
        </div>
        </td>
        <td class="px-6 py-4 text-sm"><?= $item['is_directory'] ? '-' : $this->formatBytes($item['size']) ?></td>
        <td class="px-6 py-4 text-sm"><?= date('Y-m-d H:i', $item['modified']) ?></td>
        <td class="px-6 py-4 text-sm">
        <span class="font-mono"><?= $item['permissions'] ?></span>
        <?php if (!$item['is_readable']): ?>
        <i class="fas fa-lock text-red-500 ml-1" title="Not readable"></i>
        <?php endif; ?>
        </td>
        <td class="px-6 py-4 text-sm">
        <?php if (isset($item['threat_level'])): ?>
        <span class="px-2 py-1 rounded text-xs font-medium
        <?= $item['threat_level'] === 'CRITICAL' ? 'bg-red-600' :
        ($item['threat_level'] === 'HIGH' ? 'bg-orange-600' :
        ($item['threat_level'] === 'MEDIUM' ? 'bg-yellow-600' : 'bg-green-600')) ?>">
        <?= $item['threat_level'] ?>
        </span>
        <?php elseif ($item['is_scannable']): ?>
        <button onclick="scanSingleFile('<?= htmlspecialchars($item['path']) ?>')"
        class="px-2 py-1 bg-gray-600 text-white rounded text-xs">
        <i class="fas fa-search"></i> Scan
        </button>
        <?php else: ?>
        <span class="text-gray-500 text-xs">N/A</span>
        <?php endif; ?>
        </td>
        <td class="px-6 py-4">
        <div class="flex items-center space-x-1">
        <?php if (!$item['is_directory']): ?>
        <?php if ($item['is_editable']): ?>
        <button onclick="editFilePopup('<?= htmlspecialchars($item['path']) ?>')"
        class="px-2 py-1 bg-green-600 text-white rounded text-xs hover:bg-green-700" title="Edit">
        <i class="fas fa-edit"></i>
        </button>
        <?php endif; ?>
        <?php if ($item['is_image']): ?>
        <button onclick="viewImage('<?= htmlspecialchars($item['path']) ?>')"
        class="px-2 py-1 bg-gray-600 text-white rounded text-xs hover:bg-gray-500" title="View">
        <i class="fas fa-eye"></i>
        </button>
        <?php endif; ?>
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['action' => 'download', 'file' => $item['path']]) ?>"
        class="px-2 py-1 bg-gray-600 text-white rounded text-xs hover:bg-gray-500" title="Download">
        <i class="fas fa-download"></i>
        </a>
        <?php endif; ?>
        <?php if ($item['name'] !== '..'): ?>
        <button onclick="renameItem('<?= htmlspecialchars($item['path']) ?>', '<?= htmlspecialchars($item['name']) ?>')"
        class="px-2 py-1 bg-yellow-600 text-white rounded text-xs hover:bg-yellow-700" title="Rename">
        <i class="fas fa-pen"></i>
        </button>
        <button onclick="showChmodModal('<?= htmlspecialchars($item['path']) ?>', '<?= htmlspecialchars($item['name']) ?>')"
        class="px-2 py-1 bg-blue-600 text-white rounded text-xs hover:bg-blue-700" title="Permissions">
        <i class="fas fa-lock"></i>
        </button>
        <button onclick="deleteItem('<?= htmlspecialchars($item['path']) ?>')"
        class="px-2 py-1 bg-red-600 text-white rounded text-xs hover:bg-red-700" title="Delete">
        <i class="fas fa-trash"></i>
        </button>
        <?php endif; ?>
        </div>
        </td>
        </tr>
        <?php endforeach; ?>

        <?php if (empty($this->items)): ?>
        <tr>
        <td colspan="7" class="px-6 py-8 text-center text-gray-500">
        <i class="fas fa-folder-open text-4xl mb-3"></i>
        <p>Directory is empty</p>
        </td>
        </tr>
        <?php endif; ?>
        </tbody>
        </table>
        </div>
        </div>

        <!-- Security Alert -->
        <?php
        $threats = array_filter($this->items, fn($item) => isset($item['is_threat']) && $item['is_threat']);
        if (!empty($threats)):
            ?>
            <div class="alert bg-yellow-900 border-l-4 border-yellow-500 rounded-lg p-4 mt-6">
            <h3 class="font-semibold flex items-center mb-2">
            <i class="fas fa-exclamation-triangle mr-2 text-yellow-400"></i>
            Security Alert
            </h3>
            <p>Found <?= count($threats) ?> potentially malicious file(s). Please review immediately.</p>
            </div>
            <?php endif; ?>

            <!-- Modals -->
            <?= $this->renderModals($csrfToken, $encryption) ?>

            <!-- JavaScript for File Manager -->
            <script>
            const CSRF_TOKEN = '<?= $csrfToken ?>';
            let editor = null;
            let currentEditFile = null;

            // Initialize editor
            function initEditor() {
                editor = ace.edit("editor");
                editor.setTheme("ace/theme/monokai");
                editor.setOptions({
                    fontSize: "14px",
                    showPrintMargin: false,
                    wrap: true
                });
            }

            // Modal functions
            function showModal(modalId) { document.getElementById(modalId).classList.remove('hidden'); }
            function closeModal(modalId) {
                if (modalId === 'editorModal' && editor && editor.getSession().getLength() > 0) {
                    if (!confirm('Unsaved changes will be lost. Continue?')) return;
                }
                document.getElementById(modalId).classList.add('hidden');
            }

            // File operations
            async function editFilePopup(filePath) {
                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=get_content&file=${encodeURIComponent(filePath)}&csrf_token=${CSRF_TOKEN}`
                    });
                    const result = await response.json();

                    if (result.success) {
                        currentEditFile = filePath;
                        document.getElementById('editorTitle').textContent = `Edit: ${result.filename}`;

                        if (!editor) initEditor();
                        editor.setValue(result.content);
                        editor.clearSelection();
                        showModal('editorModal');
                        editor.focus();
                    } else {
                        alert('Error: ' + result.error);
                    }
                } catch (error) {
                    alert('Failed to load file: ' + error.message);
                }
            }

            async function saveFile() {
                if (!currentEditFile || !editor) return;

                const content = editor.getValue();
                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=save_content&file=${encodeURIComponent(currentEditFile)}&content=${encodeURIComponent(content)}&csrf_token=${CSRF_TOKEN}`
                    });
                    const result = await response.json();

                    if (result.success) {
                        alert('File saved successfully!');
                        if (result.scan_result?.is_threat) {
                            alert(`Warning: File flagged as ${result.scan_result.threat_level} threat!`);
                        }
                    } else {
                        alert('Error: ' + result.error);
                    }
                } catch (error) {
                    alert('Save failed: ' + error.message);
                }
            }

            // Bulk operations
            async function bulkScanSelected() {
                const checkboxes = document.querySelectorAll('.file-checkbox:checked');
                if (checkboxes.length === 0) {
                    alert('Please select files to scan');
                    return;
                }

                const files = Array.from(checkboxes).map(cb => cb.value);
                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=bulk_scan&files=${encodeURIComponent(JSON.stringify(files))}&csrf_token=${CSRF_TOKEN}`
                    });
                    const result = await response.json();

                    if (result.success) {
                        alert(`Scanned ${result.scanned} files, found ${result.threats} threats`);
                        location.reload();
                    }
                } catch (error) {
                    alert('Bulk scan failed: ' + error.message);
                }
            }

            async function deleteItem(path) {
                if (!confirm('Are you sure you want to delete this item?')) return;

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=delete&file=${encodeURIComponent(path)}&csrf_token=${CSRF_TOKEN}`
                    });
                    const result = await response.json();

                    if (result.success) {
                        alert(result.message);
                        location.reload();
                    } else {
                        alert('Error: ' + result.error);
                    }
                } catch (error) {
                    alert('Delete failed: ' + error.message);
                }
            }

            // Form handlers
            document.addEventListener('DOMContentLoaded', function() {
                // Select all checkbox
                document.getElementById('selectAll').addEventListener('change', function() {
                    document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = this.checked);
                });

                // Form submissions
                document.getElementById('uploadForm')?.addEventListener('submit', handleFormSubmit);
                document.getElementById('createFolderForm')?.addEventListener('submit', handleFormSubmit);
                document.getElementById('createFileForm')?.addEventListener('submit', handleFormSubmit);
                document.getElementById('chmodForm')?.addEventListener('submit', handleFormSubmit);

                // Keyboard shortcuts
                document.addEventListener('keydown', function(e) {
                    if (e.ctrlKey || e.metaKey) {
                        if (e.key === 's' && document.getElementById('editorModal')?.classList.contains('hidden') === false) {
                            e.preventDefault();
                            saveFile();
                        }
                    }
                    if (e.key === 'Escape') {
                        ['uploadModal', 'createFolderModal', 'createFileModal', 'chmodModal', 'editorModal'].forEach(id => {
                            if (!document.getElementById(id)?.classList.contains('hidden')) {
                                closeModal(id);
                            }
                        });
                    }
                });
            });

            async function handleFormSubmit(e) {
                e.preventDefault();
                const formData = new FormData(e.target);
                formData.append('csrf_token', CSRF_TOKEN);

                try {
                    const response = await fetch(window.location.href, { method: 'POST', body: formData });
                    const result = await response.json();

                    if (result.success) {
                        alert(result.message);
                        closeModal(e.target.closest('.fixed').id);
                        if (result.scan_result?.is_threat) {
                            alert(`Warning: ${result.scan_result.threat_level} threat detected!`);
                        }
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        alert('Error: ' + result.error);
                    }
                } catch (error) {
                    alert('Operation failed: ' + error.message);
                }
            }

            function formatBytes(bytes) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            // Modal show functions
            function showUploadModal() { showModal('uploadModal'); }
            function showCreateFolderModal() { showModal('createFolderModal'); }
            function showCreateFileModal() { showModal('createFileModal'); }

            async function showChmodModal(filePath, fileName) {
                document.getElementById('chmodFilePath').value = filePath;
                document.getElementById('chmodFileName').value = fileName;

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=get_permissions&file=${encodeURIComponent(filePath)}&csrf_token=${CSRF_TOKEN}`
                    });
                    const result = await response.json();

                    if (result.success) {
                        document.getElementById('currentPermissions').value = result.permissions;
                        document.getElementById('newPermissions').value = result.permissions;
                        showModal('chmodModal');
                    }
                } catch (error) {
                    alert('Failed to load permissions: ' + error.message);
                }
            }

            function viewImage(filePath) {
                window.open(`?action=view_image&file=${encodeURIComponent(filePath)}`, '_blank');
            }

            async function scanSingleFile(filePath) {
                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=scan_file&file=${encodeURIComponent(filePath)}&csrf_token=${CSRF_TOKEN}`
                    });
                    const result = await response.json();

                    if (result.success && result.scan_result) {
                        if (result.scan_result.is_threat) {
                            alert(`Threat detected: ${result.scan_result.threat_level} (Score: ${result.scan_result.risk_score})`);
                        } else {
                            alert('File appears to be clean');
                        }
                        location.reload();
                    } else {
                        alert('Scan failed: ' + (result.error || 'Unknown error'));
                    }
                } catch (error) {
                    alert('Scan failed: ' + error.message);
                }
            }
            </script>
            </div>

            <!-- Upload Modal -->
            <div id="uploadModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
            <div class="flex items-center justify-center min-h-screen px-4">
            <div class="fixed inset-0 modal-overlay" onclick="closeModal('uploadModal')"></div>
            <div class="modal-content relative bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
            <h3 class="text-lg font-semibold mb-4">Upload File</h3>
            <form id="uploadForm" enctype="multipart/form-data">
            <input type="hidden" name="action" value="upload">
            <input type="hidden" name="path" value="<?= htmlspecialchars($this->currentPath) ?>">

            <div class="mb-4">
            <label class="block text-sm font-medium mb-2">Select File</label>
            <input type="file" name="upload_file" class="form-control w-full p-2 rounded border" required>
            <p class="text-xs text-gray-400 mt-1">
            Max: <?= $this->formatBytes(SystemConfig::FILESYSTEM['max_upload_size']) ?>
            </p>
            </div>

            <div class="flex justify-end space-x-3">
            <button type="button" onclick="closeModal('uploadModal')" class="px-4 py-2 bg-gray-600 text-white rounded">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded">Upload</button>
            </div>
            </form>
            </div>
            </div>
            </div>

            <!-- Create Folder Modal -->
            <div id="createFolderModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
            <div class="flex items-center justify-center min-h-screen px-4">
            <div class="fixed inset-0 modal-overlay" onclick="closeModal('createFolderModal')"></div>
            <div class="modal-content relative bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
            <h3 class="text-lg font-semibold mb-4">Create New Folder</h3>
            <form id="createFolderForm">
            <input type="hidden" name="action" value="create_folder">
            <input type="hidden" name="path" value="<?= htmlspecialchars($this->currentPath) ?>">

            <div class="mb-4">
            <label class="block text-sm font-medium mb-2">Folder Name</label>
            <input type="text" name="folder_name" class="form-control w-full px-3 py-2 rounded border" placeholder="New Folder" required>
            </div>

            <div class="flex justify-end space-x-3">
            <button type="button" onclick="closeModal('createFolderModal')" class="px-4 py-2 bg-gray-600 text-white rounded">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded">Create</button>
            </div>
            </form>
            </div>
            </div>
            </div>

            <!-- Create File Modal -->
            <div id="createFileModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
            <div class="flex items-center justify-center min-h-screen px-4">
            <div class="fixed inset-0 modal-overlay" onclick="closeModal('createFileModal')"></div>
            <div class="modal-content relative bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
            <h3 class="text-lg font-semibold mb-4">Create New File</h3>
            <form id="createFileForm">
            <input type="hidden" name="action" value="create_file">

            <div class="mb-4">
            <label class="block text-sm font-medium mb-2">File Name</label>
            <input type="text" name="filename" class="form-control w-full px-3 py-2 rounded border" placeholder="example.php" required>
            </div>

            <div class="mb-4">
            <label class="block text-sm font-medium mb-2">Initial Content</label>
            <textarea name="content" rows="4" class="form-control w-full px-3 py-2 rounded border" placeholder="Enter initial content..."></textarea>
            </div>

            <div class="flex justify-end space-x-3">
            <button type="button" onclick="closeModal('createFileModal')" class="px-4 py-2 bg-gray-600 text-white rounded">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-green-600 text-white rounded">Create</button>
            </div>
            </form>
            </div>
            </div>
            </div>

            <!-- Chmod Modal -->
            <div id="chmodModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
            <div class="flex items-center justify-center min-h-screen px-4">
            <div class="fixed inset-0 modal-overlay" onclick="closeModal('chmodModal')"></div>
            <div class="modal-content relative bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
            <h3 class="text-lg font-semibold mb-4">Change Permissions</h3>
            <form id="chmodForm">
            <input type="hidden" name="action" value="chmod">
            <input type="hidden" name="file" id="chmodFilePath">

            <div class="mb-4">
            <label class="block text-sm font-medium mb-2">File</label>
            <input type="text" id="chmodFileName" class="form-control w-full px-3 py-2 rounded border bg-gray-700" readonly>
            </div>

            <div class="mb-4">
            <label class="block text-sm font-medium mb-2">Current</label>
            <input type="text" id="currentPermissions" class="form-control w-full px-3 py-2 rounded border bg-gray-700" readonly>
            </div>

            <div class="mb-4">
            <label class="block text-sm font-medium mb-2">New Permissions</label>
            <input type="text" name="permissions" id="newPermissions" class="form-control w-full px-3 py-2 rounded border" placeholder="644" required>
            <small class="text-gray-400">Use octal format (644, 755, 777)</small>
            </div>

            <div class="flex justify-end space-x-3">
            <button type="button" onclick="closeModal('chmodModal')" class="px-4 py-2 bg-gray-600 text-white rounded">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded">Change</button>
            </div>
            </form>
            </div>
            </div>
            </div>

            <!-- Editor Modal -->
            <div id="editorModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
            <div class="flex items-center justify-center min-h-screen px-4">
            <div class="fixed inset-0 modal-overlay" onclick="closeModal('editorModal')"></div>
            <div class="modal-content relative bg-gray-800 rounded-lg shadow-xl w-11/12 h-11/12 flex flex-col max-w-6xl">
            <div class="p-4 border-b border-gray-700 flex justify-between items-center">
            <div class="flex items-center space-x-4">
            <h3 class="text-lg font-semibold" id="editorTitle">Edit File</h3>
            </div>
            <div class="flex space-x-2">
            <button onclick="saveFile()" class="px-4 py-2 bg-green-600 text-white rounded flex items-center hover:bg-green-700">
            <i class="fas fa-save mr-2"></i>Save
            </button>
            <button onclick="closeModal('editorModal')" class="px-4 py-2 bg-gray-600 text-white rounded flex items-center hover:bg-gray-500">
            <i class="fas fa-times mr-2"></i>Close
            </button>
            </div>
            </div>
            <div class="flex-1 p-4">
            <div id="editor"></div>
            </div>
            </div>
            </div>
            </div>
            </body>
            </html>
            <?php
            return ob_get_clean();
    }

    private function renderScannerInterface(): string
    {
        $filterLevel = $_GET['threat_level'] ?? 'all';
        $filteredResults = (new MalwareScanner($this->config))->filterResultsByThreatLevel($this->scanResults, $filterLevel);
        $threatLevels = (new MalwareScanner($this->config))->getUniqueThreatLevels($this->scanResults);
        $encryption = new UrlEncryption();
        $csrfToken = (new SecurityManager($this->config))->generateCSRFToken();

        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en" class="dark">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scanner - Malware Detection</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
        body { background-color: #0f172a; color: #e2e8f0; }
        .dark .card { background-color: #1e293b; border-color: #334155; }
        .badge-critical { background-color: #ef4444; }
        .badge-high { background-color: #f97316; }
        .badge-medium { background-color: #eab308; }
        .badge-low { background-color: #22c55e; }
        .pre-content {
            background-color: #0f172a;
            border: 1px solid #334155;
            color: #e2e8f0;
            max-height: 400px;
            overflow-y: auto;
        }

        /* Form Controls for Dark Mode */
        .form-control {
            background-color: #1e293b !important;
            border: 1px solid #334155 !important;
            color: #e2e8f0 !important;
            transition: all 0.2s ease;
        }

        .form-control:focus {
            background-color: #1e293b !important;
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 0.2rem rgba(59, 130, 246, 0.25) !important;
            color: #e2e8f0 !important;
        }

        .form-control::placeholder {
            color: #9ca3af !important;
        }

        .form-select {
            background-color: #1e293b !important;
            border: 1px solid #334155 !important;
            color: #e2e8f0 !important;
        }

        .form-select option {
            background-color: #1e293b !important;
            color: #e2e8f0 !important;
            padding: 8px;
        }

        .form-select:focus {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 0.2rem rgba(59, 130, 246, 0.25) !important;
        }

        /* Label styling */
        .text-gray-300 {
            color: #d1d5db !important;
        }
        </style>
        </head>
        <body class="bg-gray-900 text-gray-200 min-h-screen">
        <div class="container mx-auto px-4 py-8">
        <!-- Header -->
        <header class="mb-8">
        <div class="flex items-center justify-between">
        <div>
        <h1 class="text-3xl font-bold text-white flex items-center">
        <i class="fas fa-shield-alt mr-3 text-red-500"></i>
        Security Scanner
        </h1>
        <p class="text-gray-400 mt-2">Advanced malware detection for web servers</p>
        </div>
        <div class="flex items-center space-x-3">
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'filemanager', 'path' => $this->currentPath]) ?>"
        class="px-4 py-2 rounded bg-gray-600 text-white hover:bg-gray-500">
        <i class="fas fa-folder mr-2"></i>File Manager
        </a>
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'scanner', 'scan_dir' => $this->currentPath]) ?>"
        class="px-4 py-2 rounded bg-red-600 text-white hover:bg-red-700">
        <i class="fas fa-search mr-2"></i>Security Scanner
        </a>
        <a href="?logout=1" class="px-4 py-2 rounded bg-red-600 text-white hover:bg-red-700" onclick="return confirm('Logout?')">
        <i class="fas fa-sign-out-alt mr-2"></i>Logout
        </a>
        </div>
        </div>
        </header>

        <!-- Scan Form -->
        <div class="card rounded-lg shadow-lg mb-8">
        <div class="p-6">
        <h2 class="text-xl font-semibold mb-4 flex items-center">
        <i class="fas fa-folder-open mr-2 text-blue-400"></i>
        Scan Directory
        </h2>
        <form method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="md:col-span-3">
        <label class="block text-sm font-medium mb-2 text-gray-300">Directory Path</label>
        <div class="relative">
        <select class="form-control w-full px-3 py-2 rounded border mb-2 bg-gray-700 border-gray-600 text-white focus:bg-gray-600 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50"
        onchange="updatePath(this.value)">
        <option value="" class="bg-gray-700 text-white">-- Select Directory --</option>
        <?php foreach ($this->directorySuggestions as $dir): ?>
        <option value="<?= htmlspecialchars($dir) ?>" class="bg-gray-700 text-white"><?= htmlspecialchars($dir) ?></option>
        <?php endforeach; ?>
        <option value="custom" class="bg-gray-700 text-white">Custom Path...</option>
        </select>
        <input type="text" name="scan_dir"
        class="form-control w-full px-3 py-2 rounded border bg-gray-700 border-gray-600 text-white placeholder-gray-400 focus:bg-gray-600 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50"
        placeholder="/var/www/html or . (current directory)"
        value="<?= htmlspecialchars($this->currentPath) ?>"
        required>
        </div>
        </div>
        <div class="flex items-end">
        <button type="submit" class="w-full py-2 px-4 bg-red-600 hover:bg-red-700 text-white rounded transition-colors flex items-center justify-center">
        <i class="fas fa-search mr-2"></i>Start Scan
        </button>
        </div>
        </form>
        </div>
        </div>

        <!-- Stats -->
        <?php if (!empty($this->scanResults)): ?>
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div class="card p-6">
        <h3 class="text-gray-400 text-sm mb-1">Files Scanned</h3>
        <p class="text-3xl font-bold text-blue-400"><?= number_format(count($this->scanResults)) ?></p>
        </div>
        <div class="card p-6">
        <h3 class="text-gray-400 text-sm mb-1">Threats Found</h3>
        <p class="text-3xl font-bold text-red-500">
        <?= number_format(count(array_filter($this->scanResults, fn($r) => !empty($r['patterns'])))) ?>
        </p>
        </div>
        <div class="card p-6">
        <h3 class="text-gray-400 text-sm mb-1">Critical</h3>
        <p class="text-xl font-bold text-red-400">
        <?= number_format(count(array_filter($this->scanResults, fn($r) => $r['threat_level'] === 'CRITICAL'))) ?>
        </p>
        </div>
        <div class="card p-6">
        <h3 class="text-gray-400 text-sm mb-1">Clean Files</h3>
        <p class="text-xl font-bold text-green-400">
        <?= number_format(count($this->scanResults) - count(array_filter($this->scanResults, fn($r) => !empty($r['patterns'])))) ?>
        </p>
        </div>
        </div>
        <?php endif; ?>

        <!-- Results Table -->
        <?php if (!empty($this->scanResults)): ?>
        <div class="card rounded-lg shadow-lg mb-6">
        <div class="p-4 border-b border-gray-700 flex justify-between items-center">
        <h2 class="text-xl font-semibold flex items-center">
        <i class="fas fa-bug mr-2 text-red-400"></i>
        Scan Results
        </h2>
        <div class="flex items-center space-x-4 text-sm">
        <span class="text-gray-400">
        Showing: <strong class="text-white"><?= count($filteredResults) ?></strong>
        / <?= count($this->scanResults) ?> files
        </span>
        <?php if ($filterLevel !== 'all'): ?>
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'scanner', 'scan_dir' => $this->currentPath]) ?>"
        class="text-blue-400 hover:text-blue-300 flex items-center">
        <i class="fas fa-times mr-1"></i> Clear Filter
        </a>
        <?php endif; ?>
        </div>
        </div>

        <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-700">
        <thead class="bg-gray-800">
        <tr>
        <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">
        <input type="checkbox" id="selectAllResults" class="rounded border-gray-600">
        </th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">File Path</th>
        <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">Size</th>
        <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">Modified</th>
        <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">Threat Level</th>
        <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">Risk Score</th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">Patterns</th>
        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">Actions</th>
        </tr>
        </thead>
        <tbody class="divide-y divide-gray-700 bg-gray-800">
        <?php if (empty($filteredResults)): ?>
        <tr>
        <td colspan="8" class="px-6 py-12 text-center">
        <div class="text-gray-400">
        <i class="fas fa-search text-4xl mb-3 block"></i>
        <p class="text-lg">No files match the current filter</p>
        <p class="text-sm mt-1">
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'scanner', 'scan_dir' => $this->currentPath]) ?>"
        class="text-blue-400 hover:text-blue-300">
        Click here to view all results
        </a>
        </p>
        </div>
        </td>
        </tr>
        <?php else: ?>
        <?php foreach ($filteredResults as $index => $result):
        $threatColor = match(strtolower($result['threat_level'])) {
            'critical' => 'text-red-400 bg-red-900/20 border-red-500/30',
            'high' => 'text-orange-400 bg-orange-900/20 border-orange-500/30',
            'medium' => 'text-yellow-400 bg-yellow-900/20 border-yellow-500/30',
            'low' => 'text-green-400 bg-green-900/20 border-green-500/30',
            default => 'text-gray-400 bg-gray-900 border-gray-500/30'
        };
        ?>
        <tr class="hover:bg-gray-700/50 transition-colors group"
        data-threat="<?= strtolower($result['threat_level']) ?>"
        data-file-path="<?= htmlspecialchars($result['path']) ?>">

        <!-- Select Checkbox -->
        <td class="px-4 py-4 whitespace-nowrap">
        <input type="checkbox"
        class="threat-checkbox rounded border-gray-600 text-blue-500 focus:ring-blue-500 w-4 h-4"
        name="selected_files[]"
        value="<?= base64_encode($result['path']) ?>">
        </td>

        <!-- File Path -->
        <td class="px-6 py-4 max-w-xs">
        <div class="flex items-center space-x-3">
        <div class="w-2 h-2 rounded-full <?= $threatColor ?> animate-pulse"></div>
        <code class="text-sm font-mono break-all text-gray-200 truncate max-w-[200px] group-hover:max-w-none group-hover:truncate-0 transition-all">
        <?= htmlspecialchars($result['path']) ?>
        </code>
        <?php if (strlen($result['path']) > 50): ?>
        <span class="text-xs text-gray-500 ml-2">(long path)</span>
        <?php endif; ?>
        </div>
        </td>

        <!-- File Size -->
        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-400">
        <?= $this->formatBytes($result['size']) ?>
        </td>

        <!-- Modified Date -->
        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-400">
        <?= date('M j, Y g:i A', $result['modified']) ?>
        </td>

        <!-- Threat Level -->
        <td class="px-4 py-4 whitespace-nowrap">
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ring-1 ring-inset <?= $threatColor ?> capitalize">
        <i class="fas <?= match(strtolower($result['threat_level'])) {
            'critical' => 'fa-skull-crossbones',
            'high' => 'fa-exclamation-triangle',
            'medium' => 'fa-exclamation-circle',
            'low' => 'fa-info-circle',
            default => 'fa-question-circle'
        } ?> mr-1"></i>
        <?= $result['threat_level'] ?>
        </span>
        </td>

        <!-- Risk Score -->
        <td class="px-4 py-4 whitespace-nowrap">
        <div class="flex items-center space-x-2">
        <span class="text-sm font-mono text-gray-300"><?= $result['risk_score'] ?></span>
        <div class="flex space-x-0.5">
        <?php for ($i = 1; $i <= 5; $i++): ?>
        <i class="fas fa-fire text-xs <?= $i <= ($result['risk_score'] / 4) ? 'text-red-400' : 'text-gray-600' ?>"></i>
        <?php endfor; ?>
        </div>
        </div>
        </td>

        <!-- Detected Patterns -->
        <td class="px-6 py-4">
        <?php if (!empty($result['patterns'])): ?>
        <div class="flex flex-wrap gap-1 max-w-xs">
        <?php foreach (array_slice($result['patterns'], 0, 3) as $pattern): ?>
        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs bg-red-900/50 border border-red-500/30 text-red-200 truncate max-w-[120px]">
        <i class="fas fa-code mr-1 text-red-400"></i>
        <?= htmlspecialchars(substr($pattern, 0, 15)) . (strlen($pattern) > 15 ? '...' : '') ?>
        </span>
        <?php endforeach; ?>
        <?php if (count($result['patterns']) > 3): ?>
        <span class="text-gray-500 text-xs font-medium">+<?= count($result['patterns']) - 3 ?> more</span>
        <?php endif; ?>
        </div>
        <?php else: ?>
        <span class="px-2 py-1 bg-green-900/30 border border-green-500/30 rounded text-xs text-green-400">
        <i class="fas fa-check mr-1"></i>Clean
        </span>
        <?php endif; ?>
        </td>

        <!-- Actions -->
        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
        <div class="flex items-center space-x-2">
        <!-- View Button -->
        <button onclick="viewFileDetails('<?= base64_encode($result['path']) ?>', '<?= $result['threat_level'] ?>')"
        class="inline-flex items-center px-3 py-2 border border-blue-500/50 bg-blue-900/20 hover:bg-blue-900/30 text-blue-400 hover:text-blue-300 rounded-md text-sm font-medium transition-all duration-200 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50"
        title="View file details and analysis">
        <i class="fas fa-eye mr-1"></i>
        <span class="hidden sm:inline">View</span>
        </button>

        <!-- Quick Actions Dropdown -->
        <div class="relative">
        <button onclick="toggleActions('action-menu-<?= $index ?>')"
        class="inline-flex items-center px-2 py-2 border border-gray-600/50 bg-gray-800/50 hover:bg-gray-700/50 text-gray-400 hover:text-gray-300 rounded-md text-sm transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-opacity-50"
        title="More actions">
        <i class="fas fa-ellipsis-v"></i>
        </button>

        <!-- Dropdown Menu -->
        <div id="action-menu-<?= $index ?>" class="absolute right-0 mt-2 w-48 bg-gray-800 border border-gray-600/50 rounded-md shadow-lg opacity-0 invisible z-50 group-hover:opacity-100 group-hover:visible transition-all duration-200"
        style="display: none;">
        <div class="py-1">
        <!-- Download -->
        <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['action' => 'download', 'file' => $result['path']]) ?>"
        class="block px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 hover:text-white flex items-center transition-colors"
        title="Download file">
        <i class="fas fa-download mr-3 text-blue-400 w-4"></i>
        Download
        </a>

        <!-- Edit (if editable) -->
        <?php $extension = strtolower(pathinfo($result['path'], PATHINFO_EXTENSION));
        if (in_array($extension, SystemConfig::FILESYSTEM['editable_extensions'])): ?>
            <button onclick="editFileFromScanner('<?= htmlspecialchars($result['path']) ?>')"
            class="w-full text-left px-4 py-2 text-sm text-gray-200 hover:bg-green-700/50 hover:text-green-200 flex items-center transition-colors"
            title="Edit file content">
            <i class="fas fa-edit mr-3 text-green-400 w-4"></i>
            Edit
            </button>
            <?php endif; ?>

            <!-- View in File Manager -->
            <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'filemanager', 'path' => dirname($result['path'])]) ?>"
            class="block px-4 py-2 text-sm text-gray-200 hover:bg-blue-700/50 hover:text-blue-200 flex items-center transition-colors"
            title="Open containing folder">
            <i class="fas fa-folder mr-3 text-blue-400 w-4"></i>
            Open Folder
            </a>

            <!-- Copy Path -->
            <button onclick="copyFilePath('<?= htmlspecialchars($result['path']) ?>')"
            class="w-full text-left px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 hover:text-white flex items-center transition-colors"
            title="Copy file path to clipboard">
            <i class="fas fa-copy mr-3 text-gray-400 w-4"></i>
            Copy Path
            </button>

            <!-- Divider -->
            <div class="border-t border-gray-600/30 my-1"></div>

            <!-- Delete -->
            <button onclick="confirmDeleteFile('<?= htmlspecialchars($result['path']) ?>', '<?= htmlspecialchars(basename($result['path'])) ?>')"
            class="w-full text-left px-4 py-2 text-sm text-red-200 hover:bg-red-700/50 hover:text-red-100 flex items-center transition-colors"
            title="Delete this file">
            <i class="fas fa-trash-alt mr-3 text-red-400 w-4"></i>
            Delete File
            </button>
            </div>
            </div>
            </div>
            </div>
            </td>
            </tr>
            <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
            </table>
            </div>

            <!-- Bulk Actions -->
            <?php if (!empty($filteredResults)): ?>
            <div class="p-4 border-t border-gray-700 bg-gray-900/50">
            <div class="flex items-center justify-between flex-wrap gap-4">
            <div class="flex items-center space-x-4">
            <span class="text-sm text-gray-400">
            <strong class="text-white"><?= count($filteredResults) ?></strong>
            file<?= count($filteredResults) !== 1 ? 's' : '' ?> selected
            </span>

            <!-- Bulk Actions -->
            <div class="flex items-center space-x-2">
            <!-- Bulk Delete -->
            <button onclick="bulkDeleteSelected()"
            class="inline-flex items-center px-4 py-2 border border-red-500/50 bg-red-900/20 hover:bg-red-900/30 text-red-400 hover:text-red-300 rounded-md text-sm font-medium transition-all duration-200 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-opacity-50"
            title="Delete all selected files">
            <i class="fas fa-trash mr-2"></i>
            <span>Delete Selected (<?= count($filteredResults) ?>)</span>
            </button>

            <!-- Export Results -->
            <button onclick="exportResults()"
            class="inline-flex items-center px-4 py-2 border border-green-500/50 bg-green-900/20 hover:bg-green-900/30 text-green-400 hover:text-green-300 rounded-md text-sm font-medium transition-all duration-200"
            title="Export scan results">
            <i class="fas fa-download mr-2"></i>
            Export
            </button>
            </div>
            </div>

            <!-- Filter by Threat Level -->
            <div class="flex items-center space-x-2">
            <span class="text-sm text-gray-400">Filter:</span>
            <select onchange="filterByThreat(this.value)"
            class="px-3 py-1 rounded border border-gray-600 bg-gray-700 text-white text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500">
            <option value="all" <?= $filterLevel === 'all' ? 'selected' : '' ?>>All Levels</option>
            <option value="critical" <?= $filterLevel === 'critical' ? 'selected' : '' ?>>Critical</option>
            <option value="high" <?= $filterLevel === 'high' ? 'selected' : '' ?>>High</option>
            <option value="medium" <?= $filterLevel === 'medium' ? 'selected' : '' ?>>Medium</option>
            <option value="low" <?= $filterLevel === 'low' ? 'selected' : '' ?>>Low</option>
            </select>
            </div>
            </div>
            </div>
            <?php endif; ?>
            </div>
            <?php else: ?>
            <!-- No Results State -->
            <div class="text-center py-16 bg-gray-800 rounded-lg border border-gray-700">
            <div class="max-w-md mx-auto">
            <?php if (empty($_POST['scan_dir'] ?? '')): ?>
            <i class="fas fa-search text-6xl text-gray-500 mb-6"></i>
            <h3 class="text-2xl font-semibold text-gray-300 mb-2">Ready to Scan</h3>
            <p class="text-gray-400 mb-6">Select a directory above to begin scanning for malware and security threats</p>
            <div class="flex justify-center space-x-3 text-sm">
            <span class="text-gray-500">Scans for:</span>
            <span class="text-blue-400">• Webshells</span>
            <span class="text-orange-400">• Backdoors</span>
            <span class="text-red-400">• Exploits</span>
            </div>
            <?php else: ?>
            <i class="fas fa-check-circle text-6xl text-green-500 mb-6"></i>
            <h3 class="text-2xl font-semibold text-gray-300 mb-2">Scan Complete!</h3>
            <p class="text-gray-400 mb-6">No threats detected in the scanned directory. Your system appears clean! 🎉</p>
            <div class="flex justify-center space-x-4">
            <button onclick="location.reload()"
            class="px-6 py-2 bg-green-600 hover:bg-green-700 text-white rounded-md transition-colors">
            Scan Again
            </button>
            <a href="<?= $encryption->generateSecureUrl($_SERVER['PHP_SELF'], ['mode' => 'filemanager', 'path' => $this->currentPath]) ?>"
            class="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors">
            Open File Manager
            </a>
            </div>
            <?php endif; ?>
            </div>
            </div>
            <?php endif; ?>

            <!-- File Viewer Modal -->
            <div id="fileViewerModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
            <div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20">
            <div class="fixed inset-0 bg-gray-900 bg-opacity-75 transition-opacity" onclick="document.getElementById('fileViewerModal').classList.add('hidden')"></div>
            <div class="relative bg-gray-800 rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] overflow-hidden transform transition-all">
            <div class="flex flex-col h-full">
            <!-- Header -->
            <div class="p-6 border-b border-gray-700 flex justify-between items-center bg-gray-900/50">
            <div class="flex items-center space-x-4">
            <button onclick="document.getElementById('fileViewerModal').classList.add('hidden')"
            class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition-colors">
            <i class="fas fa-arrow-left text-xl"></i>
            </button>
            <h3 class="text-xl font-semibold text-white flex items-center">
            <i class="fas fa-file-alt mr-2 text-blue-400"></i>
            File Security Analysis
            </h3>
            </div>
            <div class="flex items-center space-x-2">
            <button onclick="toggleContentWrap()" class="px-3 py-1 text-sm text-gray-400 hover:text-white bg-gray-700 rounded transition-colors">
            Wrap Text
            </button>
            <button onclick="copyFilePath(document.getElementById('currentFilePath')?.textContent)"
            class="px-3 py-1 text-sm text-gray-400 hover:text-white bg-gray-700 rounded transition-colors">
            <i class="fas fa-copy"></i>
            </button>
            </div>
            </div>

            <!-- Content Area -->
            <div id="fileViewerContent" class="flex-1 overflow-y-auto p-0">
            <!-- Content will be loaded here -->
            </div>
            </div>
            </div>
            </div>
            </div>

            <script>
            const CSRF_TOKEN = '<?= $csrfToken ?>';

            // Enhanced View File Function
            async function viewFileDetails(encodedPath, threatLevel) {
                const modal = document.getElementById('fileViewerModal');
                const contentArea = document.getElementById('fileViewerContent');
                const loadingSpinner = document.createElement('div');

                // Create loading state
                loadingSpinner.innerHTML = `
                <div class="flex flex-col items-center justify-center py-12">
                <div class="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 mb-4"></div>
                <p class="text-gray-400">Analyzing file security...</p>
                </div>
                `;
                contentArea.innerHTML = '';
                contentArea.appendChild(loadingSpinner);
                modal.classList.remove('hidden');

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=get_file_content&file_path=${encodedPath}&csrf_token=${CSRF_TOKEN}`
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }

                    const data = await response.json();

                    if (data.success) {
                        renderFileDetails(data, threatLevel);
                    } else {
                        throw new Error(data.error || 'Failed to load file');
                    }
                } catch (error) {
                    contentArea.innerHTML = `
                    <div class="p-6 bg-red-900/20 border border-red-500/30 rounded-lg">
                    <div class="flex items-center text-red-400 mb-3">
                    <i class="fas fa-exclamation-triangle mr-3 text-xl"></i>
                    <h3 class="text-lg font-semibold">Error Loading File</h3>
                    </div>
                    <p class="text-red-300">${error.message}</p>
                    </div>
                    `;
                }
            }

            function renderFileDetails(data, threatLevel) {
                const contentArea = document.getElementById('fileViewerContent');
                const threatColors = {
                    'CRITICAL': 'text-red-400 bg-red-900/20 border-red-500/30',
                    'HIGH': 'text-orange-400 bg-orange-900/20 border-orange-500/30',
                    'MEDIUM': 'text-yellow-400 bg-yellow-900/20 border-yellow-500/30',
                    'LOW': 'text-green-400 bg-green-900/20 border-green-500/30',
                    'CLEAN': 'text-green-400 bg-green-900/20 border-green-500/30'
                };

                const threatClass = threatColors[threatLevel] || threatColors['CLEAN'];

                // File header with metadata
                const header = `
                <div class="mb-6 p-4 bg-gray-900/50 border border-gray-700 rounded-lg">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                <div>
                <label class="text-xs font-medium text-gray-400 block mb-1">File Path</label>
                <code class="text-sm font-mono break-all text-white" id="currentFilePath">${escapeHtml(data.path)}</code>
                </div>
                <div>
                <label class="text-xs font-medium text-gray-400 block mb-1">File Name</label>
                <code class="text-sm font-mono text-blue-400">${escapeHtml(data.filename)}</code>
                </div>
                <div>
                <label class="text-xs font-medium text-gray-400 block mb-1">Size</label>
                <span class="text-sm text-gray-300">${formatBytes(data.size)}</span>
                </div>
                <div>
                <label class="text-xs font-medium text-gray-400 block mb-1">Modified</label>
                <span class="text-sm text-gray-300">${data.modified}</span>
                </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 border-t border-gray-700">
                <div class="flex items-center">
                <span class="text-sm font-medium text-gray-400 mr-2">Threat Level:</span>
                <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ring-1 ring-inset ${threatClass}">
                <i class="fas fa-${threatLevel === 'CRITICAL' ? 'skull-crossbones' : threatLevel === 'HIGH' ? 'exclamation-triangle' : threatLevel === 'MEDIUM' ? 'exclamation-circle' : threatLevel === 'LOW' ? 'info-circle' : 'check-circle'} mr-1"></i>
                ${threatLevel}
                </span>
                </div>

                <div class="flex items-center">
                <span class="text-sm font-medium text-gray-400 mr-2">Risk Score:</span>
                <span class="text-sm font-mono text-white">${data.risk_score}</span>
                <div class="flex ml-2">
                ${[...Array(5)].map((_, i) => `<i class="fas fa-fire text-xs ${i < Math.ceil(data.risk_score / 4) ? 'text-red-400' : 'text-gray-600'}"></i>`).join('')}
                </div>
                </div>

                <div class="flex items-center justify-end">
                <button onclick="copyFilePath('${escapeHtml(data.path)}')"
                class="inline-flex items-center px-3 py-1 border border-gray-600 bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white rounded-md text-sm transition-colors mr-2">
                <i class="fas fa-copy mr-1"></i>Copy Path
                </button>
                <a href="?action=download&file=${btoa(data.path)}"
                class="inline-flex items-center px-3 py-1 border border-blue-600 bg-blue-900/20 hover:bg-blue-900/30 text-blue-400 hover:text-blue-300 rounded-md text-sm transition-colors">
                <i class="fas fa-download mr-1"></i>Download
                </a>
                </div>
                </div>
                </div>
                `;

                // Patterns section
                let patternsSection = '';
                if (data.patterns && data.patterns.length > 0) {
                    patternsSection = `
                    <div class="mb-6">
                    <h4 class="text-lg font-semibold text-gray-200 mb-3 flex items-center">
                    <i class="fas fa-code mr-2 text-red-400"></i>Detected Patterns
                    </h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-48 overflow-y-auto">
                    ${data.patterns.map(pattern => `
                        <div class="p-3 bg-red-900/20 border border-red-500/30 rounded-lg">
                        <div class="flex items-start space-x-3">
                        <div class="flex-shrink-0">
                        <i class="fas fa-bug text-red-400 mt-0.5"></i>
                        </div>
                        <div class="flex-1 min-w-0">
                        <p class="text-sm font-mono text-red-200 break-all">${escapeHtml(pattern)}</p>
                        <p class="text-xs text-red-400 mt-1">${getPatternRisk(pattern)}</p>
                        </div>
                        </div>
                        </div>
                        `).join('')}
                        </div>
                        </div>
                        `;
                }

                // File content preview
                const contentPreview = data.content ?
                `<div class="mt-6">
                <div class="flex items-center justify-between mb-3">
                <h4 class="text-lg font-semibold text-gray-200 flex items-center">
                <i class="fas fa-file-code mr-2 text-blue-400"></i>File Content Preview
                </h4>
                <div class="flex items-center space-x-2 text-sm">
                <button onclick="toggleContentWrap()" class="text-gray-400 hover:text-gray-200">
                <i class="fas fa-align-left ${isContentWrapped ? 'hidden' : ''}"></i>
                <i class="fas fa-align-justify ${!isContentWrapped ? 'hidden' : ''}"></i>
                </button>
                <span class="text-gray-500">First 100 lines shown</span>
                </div>
                </div>
                <div class="pre-content border rounded-lg p-4 max-h-96 overflow-y-auto font-mono text-sm ${isContentWrapped ? 'whitespace-pre-wrap' : 'whitespace-pre'}">
                ${escapeHtml(data.content.split('\n').slice(0, 100).join('\n'))}
                ${data.content.split('\n').length > 100 ? '<div class="text-center text-gray-500 mt-2 pt-2 border-t border-gray-700">... (showing first 100 lines of ' + data.content.split('\n').length + ' total)</div>' : ''}
                </div>
                </div>` :
                '<div class="text-center py-12 text-gray-500"><i class="fas fa-file text-4xl mb-3 opacity-50"></i><p class="text-lg">No content available</p></div>';

                contentArea.innerHTML = header + patternsSection + contentPreview;
            }

            // Enhanced Delete Function
            async function confirmDeleteFile(filePath, fileName) {
                const threatLevel = document.querySelector(`tr[data-file-path="${escapeHtml(filePath)}"]`)?.dataset.threat;
                const isCritical = threatLevel === 'critical' || threatLevel === 'high';

                let message = `Are you sure you want to delete:\n\n"${fileName}"\n${filePath}\n\n`;
                if (isCritical) {
                    message += `⚠️  WARNING: This file has a ${threatLevel.toUpperCase()} threat level.\n`;
                }
                message += `This action cannot be undone!`;

                if (!confirm(message)) return;

                // Show loading state
                const row = document.querySelector(`tr[data-file-path="${escapeHtml(filePath)}"]`);
                const originalActions = row.querySelector('td:last-child').innerHTML;
                row.querySelector('td:last-child').innerHTML = `
                <div class="flex items-center justify-center py-2">
                <div class="animate-spin rounded-full h-5 w-5 border-t-2 border-b-2 border-red-500 mr-2"></div>
                <span class="text-red-400 text-sm">Deleting...</span>
                </div>
                `;

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=delete_single_file&file_path=${encodeURIComponent(filePath)}&csrf_token=${CSRF_TOKEN}`
                    });

                    const result = await response.json();

                    if (result.success) {
                        // Animate row removal
                        row.style.transition = 'all 0.3s ease';
                        row.style.opacity = '0';
                        row.style.transform = 'translateX(-20px)';
                        setTimeout(() => {
                            row.remove();
                            updateSelectionCount();
                            showToast(`✅ File "${fileName}" deleted successfully`, 'success');
                        }, 300);
                    } else {
                        throw new Error(result.error || 'Delete failed');
                    }
                } catch (error) {
                    // Restore original actions
                    row.querySelector('td:last-child').innerHTML = originalActions;
                    showToast(`❌ Failed to delete "${fileName}": ${error.message}`, 'error');
                }
            }

            // Bulk Delete Function
            async function bulkDeleteSelected() {
                const checkboxes = document.querySelectorAll('.threat-checkbox:checked');
                if (checkboxes.length === 0) {
                    showToast('Please select files to delete', 'warning');
                    return;
                }

                const filesToDelete = Array.from(checkboxes).map(cb => ({
                    path: cb.value ? atob(cb.value) : '',
                                                                        name: document.querySelector(`tr:has(input[value="${cb.value}"])`).querySelector('code').textContent
                }));

                const confirmMessage = `Delete ${filesToDelete.length} selected file${filesToDelete.length !== 1 ? 's' : ''}?\n\n` +
                filesToDelete.slice(0, 3).map(f => `• ${f.name}`).join('\n') +
                (filesToDelete.length > 3 ? `\n... and ${filesToDelete.length - 3} more` : '') +
                `\n\nThis action cannot be undone!`;

                if (!confirm(confirmMessage)) return;

                const deletedCount = 0;
                const failedCount = 0;

                // Process deletions
                for (const file of filesToDelete) {
                    try {
                        const response = await fetch(window.location.href, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: `action=delete_single_file&file_path=${encodeURIComponent(file.path)}&csrf_token=${CSRF_TOKEN}`
                        });

                        const result = await response.json();
                        if (result.success) deletedCount++;
                        else failedCount++;
                    } catch (error) {
                        failedCount++;
                    }
                }

                // Update UI
                document.querySelectorAll('.threat-checkbox:checked').forEach(cb => {
                    const row = cb.closest('tr');
                    if (deletedCount > 0) {
                        row.style.transition = 'all 0.3s ease';
                row.style.opacity = '0';
                row.style.transform = 'translateX(-20px)';
                setTimeout(() => row.remove(), 300);
                    }
                });

                setTimeout(() => {
                    if (deletedCount > 0) {
                        showToast(`✅ Successfully deleted ${deletedCount} file${deletedCount !== 1 ? 's' : ''}${failedCount > 0 ? `, ${failedCount} failed` : ''}`, 'success');
                    } else {
                        showToast(`❌ Failed to delete files`, 'error');
                    }
                    updateSelectionCount();
                    if (document.querySelectorAll('tbody tr').length === 1) {
                        location.reload(); // Reload if no more rows
                    }
                }, 350);
            }

            // Edit from Scanner
            async function editFileFromScanner(filePath) {
                // Switch to file manager mode and open editor
                const url = new URL(window.location.href);
                url.searchParams.set('mode', 'filemanager');
                url.searchParams.set('path', encodeURIComponent(dirname(filePath)));

                // Store file path in session for auto-open
                localStorage.setItem('autoEditFile', filePath);
                window.location.href = url.toString();
            }

            // Copy file path to clipboard
            function copyFilePath(filePath) {
                navigator.clipboard.writeText(filePath).then(() => {
                    showToast('📋 File path copied to clipboard', 'success');
                }).catch(() => {
                    // Fallback for older browsers
                    const textArea = document.createElement('textarea');
                    textArea.value = filePath;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    showToast('📋 File path copied to clipboard', 'success');
                });
            }

            // Toggle content wrap
            let isContentWrapped = false;
            function toggleContentWrap() {
                isContentWrapped = !isContentWrapped;
                const pre = document.querySelector('.pre-content');
                if (pre) {
                    pre.classList.toggle('whitespace-pre-wrap', isContentWrapped);
                    pre.classList.toggle('whitespace-pre', !isContentWrapped);
                }
            }

            // Filter by threat level
            function filterByThreat(level) {
                const rows = document.querySelectorAll('tbody tr[data-threat]');
                let visibleCount = 0;

                rows.forEach(row => {
                    if (level === 'all' || row.dataset.threat === level) {
                        row.style.display = '';
                visibleCount++;
                    } else {
                        row.style.display = 'none';
                    }
                });

                // Update counter
                const counter = document.querySelector('.text-white');
                if (counter) {
                    counter.textContent = visibleCount;
                }

                showToast(`${visibleCount} files match "${level}" filter`, 'info');
            }

            // Export results
            function exportResults() {
                const results = Array.from(document.querySelectorAll('tbody tr[data-threat]')).map(row => ({
                    path: row.dataset.filePath,
                    threat: row.dataset.threat,
                    size: row.querySelector('td:nth-child(3)')?.textContent || '',
                    modified: row.querySelector('td:nth-child(4)')?.textContent || '',
                    risk: row.querySelector('td:nth-child(6)')?.textContent || ''
                }));

                const csvContent = [
                    ['File Path', 'Threat Level', 'Size', 'Modified', 'Risk Score'],
                    ...results.map(r => [r.path, r.threat, r.size, r.modified, r.risk])
                ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

                const blob = new Blob([csvContent], { type: 'text/csv' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `security-scan-${new Date().toISOString().split('T')[0]}.csv`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);

                showToast('📊 Scan results exported as CSV', 'success');
            }

            // Action menu toggle
            function toggleActions(menuId) {
                const menu = document.getElementById(menuId);
                const isVisible = menu.style.display === 'block';

                // Hide all other menus
                document.querySelectorAll('[id^="action-menu-"]').forEach(m => {
                    m.style.display = 'none';
                m.classList.remove('opacity-100', 'visible');
                });

                if (!isVisible) {
                    menu.style.display = 'block';
                    menu.classList.add('opacity-100', 'visible');
                }
            }

            // Toast notifications
            function showToast(message, type = 'info') {
                // Remove existing toasts
                document.querySelectorAll('.toast-notification').forEach(toast => toast.remove());

                const toast = document.createElement('div');
                toast.className = `toast-notification fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg transform translate-x-full transition-transform duration-300 ${
                    type === 'success' ? 'bg-green-600 text-white' :
                    type === 'error' ? 'bg-red-600 text-white' :
                    type === 'warning' ? 'bg-yellow-600 text-white' : 'bg-blue-600 text-white'
                }`;

                toast.innerHTML = `
                <div class="flex items-center">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'} mr-3"></i>
                <span class="flex-1">${escapeHtml(message)}</span>
                <button onclick="this.closest('.toast-notification').remove()" class="ml-3 text-white hover:text-gray-200">
                <i class="fas fa-times"></i>
                </button>
                </div>
                `;

                document.body.appendChild(toast);

                // Animate in
                setTimeout(() => toast.classList.remove('translate-x-full'), 100);

                // Auto remove
                setTimeout(() => {
                    toast.classList.add('translate-x-full');
                    setTimeout(() => toast.remove(), 300);
                }, 5000);
            }

            // Update selection count
            function updateSelectionCount() {
                const checkboxes = document.querySelectorAll('.threat-checkbox:checked');
                const counter = document.querySelector('.text-white');
                if (counter) {
                    counter.textContent = checkboxes.length;
                }
            }

            // Select all functionality
            document.addEventListener('DOMContentLoaded', function() {
                const selectAll = document.getElementById('selectAllResults');
                if (selectAll) {
                    selectAll.addEventListener('change', function() {
                        document.querySelectorAll('.threat-checkbox').forEach(cb => {
                            cb.checked = this.checked;
                        });
                        updateSelectionCount();
                    });
                }

                // Checkbox change listener
                document.addEventListener('change', function(e) {
                    if (e.target.classList.contains('threat-checkbox')) {
                        updateSelectionCount();

                        // Update select all state
                        const selectAll = document.getElementById('selectAllResults');
                        const allCheckboxes = document.querySelectorAll('.threat-checkbox');
                        const checkedCount = document.querySelectorAll('.threat-checkbox:checked').length;

                        if (checkedCount === 0) {
                            selectAll.indeterminate = false;
                            selectAll.checked = false;
                        } else if (checkedCount === allCheckboxes.length) {
                            selectAll.indeterminate = false;
                            selectAll.checked = true;
                        } else {
                            selectAll.indeterminate = true;
                            selectAll.checked = false;
                        }
                    }
                });

                // Close modals on escape
                document.addEventListener('keydown', function(e) {
                    if (e.key === 'Escape') {
                        document.getElementById('fileViewerModal')?.classList.add('hidden');
                        document.querySelectorAll('[id^="action-menu-"]').forEach(menu => {
                            menu.style.display = 'none';
                        });
                    }
                });

                // Hide dropdowns on outside click
                document.addEventListener('click', function(e) {
                    if (!e.target.closest('button[onclick*="toggleActions"]')) {
                        document.querySelectorAll('[id^="action-menu-"]').forEach(menu => {
                            menu.style.display = 'none';
                        menu.classList.remove('opacity-100', 'visible');
                        });
                    }
                });
            });

            // Utility functions
            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }

            function formatBytes(bytes) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            function dirname(path) {
                return path.replace(/\/[^\/]*$/, '');
            }

            function getPatternRisk(pattern) {
                const highRisk = ['eval', 'system', 'exec', 'shell_exec', 'passthru'];
                const mediumRisk = ['base64_decode', 'gzinflate', 'include', 'require'];

                for (const risk of highRisk) {
                    if (pattern.includes(risk)) return 'High Risk - Code Execution';
                }
                for (const risk of mediumRisk) {
                    if (pattern.includes(risk)) return 'Medium Risk - File Include';
                }
                return 'Low Risk - Suspicious Pattern';
            }

            function updatePath(value) {
                const input = document.querySelector('input[name="scan_dir"]');
                if (value === 'custom') {
                    input.value = '';
                    input.focus();
                } else {
                    input.value = value;
                }
            }
            </script>
            </div>
            </body>
            </html>
            <?php
            return ob_get_clean();
    }

    private function formatBytes(int $bytes): string
    {
        if ($bytes === 0) return '0 Bytes';
        $k = 1024;
        $sizes = ['Bytes', 'KB', 'MB', 'GB'];
        $i = floor(log($bytes) / log($k));
        return round($bytes / pow($k, $i), 2) . ' ' . $sizes[$i];
    }

    private function renderModals(string $csrfToken, UrlEncryption $encryption): string
    {
        // Modal HTML templates would go here - already included in the file manager render
        return '';
    }
}

// =============================================================================
// MAIN APPLICATION
// =============================================================================

final class SecureFileSystem
{
    private SecurityManager $security;
    private UrlEncryption $encryption;
    private FileSystemManager $fileManager;
    private MalwareScanner $scanner;
    private UIRenderer $renderer;
    private string $mode = 'filemanager';
    private array $config;

    public function __construct()
    {
        $this->config = SystemConfig::getAll();
        $this->security = new SecurityManager($this->config);
        $this->encryption = new UrlEncryption();
        $this->handleAuthentication();

        $currentPath = $_GET['path'] ?? dirname($_SERVER['SCRIPT_FILENAME']);
        $this->fileManager = new FileSystemManager($this->config, $currentPath);
        $this->scanner = new MalwareScanner($this->config);

        $this->mode = $_POST['mode'] ?? $this->encryption->decrypt($_GET['mode'] ?? '', 'filemanager');

        $items = $this->fileManager->getDirectoryContents();
        $breadcrumb = $this->fileManager->getBreadcrumb();
        $directorySuggestions = $this->fileManager->getDirectorySuggestions();

        $scanResults = [];
        if ($this->mode === 'scanner' && !empty($_POST['scan_dir'])) {
            $this->scanner->scanDirectory($_POST['scan_dir']);
            $scanResults = $this->scanner->getResults();
        }

        $this->renderer = new UIRenderer(
            $this->config,
            $this->mode,
            $this->fileManager->getCurrentPath(),
                                         $items,
                                         $scanResults,
                                         $breadcrumb,
                                         $directorySuggestions
        );
    }

    public function run(): void
    {
        if (isset($_GET['logout'])) {
            $this->security->logout();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        }

        echo $this->renderer->render();
    }

    private function handleAuthentication(): void
    {
        if (isset($_POST['login_password'])) {
            if (!$this->security->processLogin($_POST['login_password'])) {
                $this->security->requireAuthentication();
            }
        } else {
            $this->security->requireAuthentication();
        }
    }

    // API Endpoints
    public static function handleApiRequest(): void
    {
        header('Content-Type: application/json');

        try {
            $config = SystemConfig::getAll();
            $security = new SecurityManager($config);

            if (!isset($_POST['csrf_token']) || !$security->verifyCsrfToken($_POST['csrf_token'])) {
                http_response_code(403);
                echo json_encode(['success' => false, 'error' => 'Invalid security token']);
                exit;
            }

            $action = $_POST['action'] ?? '';
            $currentPath = $_GET['path'] ?? dirname($_SERVER['SCRIPT_FILENAME']);
            $fileManager = new FileSystemManager($config, $currentPath);

            switch ($action) {
                case 'upload':
                    echo json_encode($fileManager->handleFileUpload());
                    break;

                case 'create_folder':
                    echo json_encode($fileManager->createDirectory($_POST['folder_name'] ?? ''));
                    break;

                case 'delete':
                    echo json_encode($fileManager->deleteItem($_POST['file'] ?? ''));
                    break;

                case 'rename':
                    echo json_encode($fileManager->renameItem($_POST['file'] ?? '', $_POST['new_name'] ?? ''));
                    break;

                case 'get_content':
                    echo json_encode($fileManager->getFileContent($_POST['file'] ?? ''));
                    break;

                case 'save_content':
                    echo json_encode($fileManager->saveFileContent($_POST['file'] ?? '', $_POST['content'] ?? ''));
                    break;

                case 'create_file':
                    echo json_encode($fileManager->createFile($_POST['filename'] ?? '', $_POST['content'] ?? ''));
                    break;

                case 'chmod':
                    echo json_encode($fileManager->changeFilePermissions($_POST['file'] ?? '', $_POST['permissions'] ?? ''));
                    break;

                case 'get_permissions':
                    echo json_encode($fileManager->getFilePermissions($_POST['file'] ?? ''));
                    break;

                case 'scan_file':
                    $scanner = new MalwareScanner($config);
                    $result = $scanner->quickScanFile($_POST['file'] ?? '');
                    echo json_encode(['success' => true, 'scan_result' => $result]);
                    break;

                case 'bulk_scan':
                    $files = json_decode($_POST['files'] ?? '[]', true);
                    $scanner = new MalwareScanner($config);
                    $scanned = 0;
                    $threats = 0;

                    foreach ($files as $file) {
                        if (is_file($file)) {
                            $result = $scanner->quickScanFile($file);
                            $scanned++;
                            if ($result && $result['is_threat']) $threats++;
                        }
                    }

                    echo json_encode(['success' => true, 'scanned' => $scanned, 'threats' => $threats]);
                    break;

                case 'get_file_content':
                    $filePath = base64_decode($_POST['file_path'] ?? '');
                    $scanner = new MalwareScanner($config);

                    if (!is_file($filePath)) {
                        echo json_encode(['success' => false, 'error' => 'File not found']);
                        exit;
                    }

                    $content = file_get_contents($filePath);
                    $scanResult = $scanner->quickScanFile($filePath) ?: [
                        'threat_level' => 'CLEAN',
                        'patterns' => [],
                        'risk_score' => 0
                    ];

                    echo json_encode([
                        'success' => true,
                        'content' => $content,
                        'path' => $filePath,
                        'filename' => basename($filePath),
                                     'size' => filesize($filePath),
                                     'modified' => date('Y-m-d H:i:s', filemtime($filePath)),
                                     'threat_level' => $scanResult['threat_level'],
                                     'patterns' => $scanResult['patterns'],
                                     'risk_score' => $scanResult['risk_score']
                    ]);
                    break;

                case 'delete_single_file':
                    $filePath = $_POST['file_path'] ?? '';
                    $fileManager = new FileSystemManager($config, dirname($filePath));
                    echo json_encode($fileManager->deleteItem($filePath));
                    break;

                default:
                    echo json_encode(['success' => false, 'error' => 'Invalid action']);
            }
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage()]);
        }
        exit;
    }

    // Download handler
    public static function handleDownload(): void
    {
        if (!isset($_GET['action']) || $_GET['action'] !== 'download' || !isset($_GET['file'])) {
            http_response_code(404);
            exit('Not found');
        }

        $encryption = new UrlEncryption();
        $filePath = $encryption->decrypt($_GET['file']);

        if (!is_file($filePath)) {
            http_response_code(404);
            exit('File not found');
        }

        // Security check
        $realPath = realpath($filePath);
        $protectedPaths = SystemConfig::FILESYSTEM['protected_paths'];
        foreach ($protectedPaths as $protected) {
            if (strpos($realPath, $protected) === 0) {
                http_response_code(403);
                exit('Access denied');
            }
        }

        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    }

    // Image viewer
    public static function handleImageView(): void
    {
        if (!isset($_GET['action']) || $_GET['action'] !== 'view_image' || !isset($_GET['file'])) {
            http_response_code(404);
            exit;
        }

        $encryption = new UrlEncryption();
        $filePath = $encryption->decrypt($_GET['file']);

        if (!is_file($filePath)) {
            http_response_code(404);
            exit;
        }

        $realPath = realpath($filePath);
        $protectedPaths = SystemConfig::FILESYSTEM['protected_paths'];
        foreach ($protectedPaths as $protected) {
            if (strpos($realPath, $protected) === 0) {
                http_response_code(403);
                exit('Access denied');
            }
        }

        $mimeType = mime_content_type($filePath);
        header('Content-Type: ' . $mimeType);
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    }
}

// =============================================================================
// ROUTING & EXECUTION
// =============================================================================

// Handle API requests
if (isset($_POST['action']) && !empty($_POST['action'])) {
    SecureFileSystem::handleApiRequest();
}

// Handle downloads
if (isset($_GET['action']) && $_GET['action'] === 'download') {
    SecureFileSystem::handleDownload();
}

// Handle image viewing
if (isset($_GET['action']) && $_GET['action'] === 'view_image') {
    SecureFileSystem::handleImageView();
}

// Handle bulk delete
if (isset($_POST['delete_selected']) && isset($_POST['delete_files'])) {
    if (!isset($_POST['key']) || $_POST['key'] !== SystemConfig::SECURITY['access_key']) {
        http_response_code(403);
        exit;
    }

    $config = SystemConfig::getAll();
    $fileManager = new FileSystemManager($config, dirname($_POST['delete_files'][0] ?? ''));

    $deleted = 0;
    foreach ($_POST['delete_files'] as $encodedPath) {
        $filePath = base64_decode($encodedPath);
        if ($fileManager->deleteItem($filePath)['success']) {
            $deleted++;
        }
    }

    if ($deleted > 0) {
        echo '<div class="alert alert-success">Successfully deleted ' . $deleted . ' files</div>';
    }
}

// Main application
$app = new SecureFileSystem();
$app->run();
?>
