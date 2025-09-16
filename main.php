<?php
/**
 * A secure tool for scanning and detecting malicious files on web servers
 * @version 2.0
 * @maw3six t.me/maw3six
 */

session_start();

class WebSecurityScanner {
    private $config;
    private $results = [];
    private $errors = [];

    public function __construct() {
        $this->config = [
            'access_key' => 'maw3six',
            'max_file_size' => 10485760, // 10MB
            'scan_extensions' => ['php', 'phtml', 'shtml', 'php7', 'phar', 'asp', 'aspx', 'js'],
            'protected_paths' => ['/etc', '/bin', '/sbin', '/usr/bin', '/root', '/boot'],
            'max_depth' => 10,
            'timeout' => 300
        ];

        set_time_limit($this->config['timeout']);
    }

    /**
     * Verify access authorization
     */
    private function verifyAccess() {
        if (!isset($_GET['key']) || $_GET['key'] !== $this->config['access_key']) {
            http_response_code(404);
            include $_SERVER['DOCUMENT_ROOT'] . "/404.php";
            exit;
        }
    }

    /**
     * Get malware detection patterns
     */
    private function getMalwarePatterns() {
        return [
            // Common execution functions with user input
            'eval($_POST', 'eval($_GET', 'eval($_REQUEST', 'eval($_COOKIE',
            'system($_POST', 'system($_GET', 'system($_REQUEST',
            'exec($_POST', 'exec($_GET', 'exec($_REQUEST',
            'shell_exec($_POST', 'shell_exec($_GET', 'shell_exec($_REQUEST',
            'passthru($_POST', 'passthru($_GET', 'passthru($_REQUEST',
            'assert($_POST', 'assert($_GET', 'assert($_REQUEST',
            'popen($_POST', 'popen($_GET', 'proc_open($_POST', 'proc_open($_GET',

            // Regex execution vulnerabilities
            'preg_replace("/.*/"e', 'preg_replace("/.*/e', 'preg_replace(\'/.*\/e\'',
            'preg_replace_callback(', 'preg_filter(',

            // Dynamic function creation
            'create_function(', 'ReflectionFunction', 'call_user_func(',
            'call_user_func_array(', 'forward_static_call(', 'forward_static_call_array(',

            // Encoding/Decoding functions
            'base64_decode(', 'base64_encode(', 'gzinflate(', 'gzdeflate(',
            'gzcompress(', 'gzuncompress(', 'str_rot13(', 'convert_uuencode(',
            'convert_uudecode(', 'hex2bin(', 'bin2hex(', 'pack(', 'unpack(',

            // File manipulation with user input
            'file_get_contents($_GET', 'file_get_contents($_POST', 'file_get_contents($_REQUEST',
            'file_put_contents($_GET', 'file_put_contents($_POST', 'file_put_contents($_REQUEST',
            'include($_GET', 'include($_POST', 'include($_REQUEST', 'require($_POST', 'require($_GET',
            'require($_REQUEST', 'include_once($_GET', 'require_once($_POST', 'fopen($_POST',
            'fopen($_GET', 'fwrite($_POST', 'fwrite($_GET', 'fputs($_POST', 'fputs($_GET',
            'move_uploaded_file', 'copy($_POST', 'copy($_GET', 'rename($_POST', 'rename($_GET',
            'unlink($_POST', 'unlink($_GET', 'mkdir($_POST', 'mkdir($_GET', 'rmdir($_POST', 'rmdir($_GET',

            // Known webshell names and titles
            'WSO SHELL', 'WSO 2.', 'c99shell', 'c99 shell', 'c100 shell', 'r57shell', 'r57 shell',
            'r99 shell', 'b374k', 'b374k shell', 'antichat', 'Antichat Shell', 'DxShell', 'Crystal',
            'Liz0ziM', 'Ayyildiz Tim', 'Gecko Shell', 'PHP Shell', 'Mini Shell', 'FilesMan',
            'Safe Mode Bypass', 'Bypass 403', 'Private-i3lue', 'AK-74 Security Team', 'JspSpy',
            'JspWebshell', 'Laudanum', 'WeBaCoo', 'China Chopper', 'webadmin', 'phpremoteview',
            'directmail', 'JaheeM Shell', 'GFS web-shell', 'Predator', 'tryag', 'Romanian Shell',
            'Dx', 'Moroccan Spamers', 'Matamu', 'Behinder', 'Godzilla', 'AntSword', 'WebShellOrb'
        ];
    }

    /**
     * Get directory suggestions based on current script location
     */
    public function getDirectorySuggestions() {
        $currentPath = dirname($_SERVER['SCRIPT_FILENAME']);
        $suggestions = [];

        $suggestions[] = $currentPath;

        $pathParts = explode('/', trim($currentPath, '/'));
        $currentDir = '';

        foreach ($pathParts as $part) {
            if (!empty($part)) {
                $currentDir .= '/' . $part;
                if (is_dir($currentDir) && !in_array($currentDir, $suggestions)) {
                    $suggestions[] = $currentDir;
                }
            }
        }

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

        $suggestions = array_unique($suggestions);
        sort($suggestions);

        return $suggestions;
    }

    /**
     * Scan directory for malicious files
     */
    public function scanDirectory($directory, $depth = 0) {
        if ($depth > $this->config['max_depth']) {
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

    /**
     * Validate and sanitize directory path
     */
    private function validatePath($path) {
        $realPath = realpath($path);

        if (!$realPath || !is_dir($realPath)) {
            return false;
        }

        foreach ($this->config['protected_paths'] as $protected) {
            if (strpos($realPath, $protected) === 0) {
                $this->errors[] = "Access denied to protected path: $protected";
                return false;
            }
        }

        return $realPath;
    }

    /**
     * Scan individual file for malicious content
     */
    private function scanFile($filePath) {
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $fileSize = filesize($filePath);

        if ($fileSize > $this->config['max_file_size']) {
            return;
        }

        if (!in_array($extension, $this->config['scan_extensions'])) {
            return;
        }

        $content = @file_get_contents($filePath);
        if ($content === false) {
            return;
        }

        $patterns = $this->getMalwarePatterns();
        $detectedPatterns = [];
        $riskScore = 0;

        foreach ($patterns as $pattern) {
            if (stripos($content, $pattern) !== false) {
                $detectedPatterns[] = $pattern;
                $riskScore += $this->calculatePatternRisk($pattern);
            }
        }

        $heuristicResults = $this->performHeuristicAnalysis($content);
        if (!empty($heuristicResults)) {
            $detectedPatterns = array_merge($detectedPatterns, $heuristicResults['patterns']);
            $riskScore += $heuristicResults['risk_score'];
        }

        if (!empty($detectedPatterns)) {
            $this->results[] = [
                'path' => $filePath,
                'size' => $fileSize,
                'extension' => $extension,
                'modified' => filemtime($filePath),
                'patterns' => $detectedPatterns,
                'risk_score' => $riskScore,
                'threat_level' => $this->calculateThreatLevel($riskScore, count($detectedPatterns)),
                'preview' => $this->getFilePreview($content),
                'hash' => hash('sha256', $content)
            ];
        }
    }

    /**
     * Calculate risk score for individual patterns
     */
    private function calculatePatternRisk($pattern) {
        $highRiskPatterns = [
            'eval($_POST', 'eval($_GET', 'eval($_REQUEST',
            'system($_POST', 'system($_GET', 'exec($_POST', 'exec($_GET',
            'shell_exec($_POST', 'shell_exec($_GET', 'passthru($_POST', 'passthru($_GET',
            'assert($_POST', 'assert($_GET', 'create_function(',
            'preg_replace("/.*/"e', 'preg_replace("/.*/e'
        ];

        $mediumRiskPatterns = [
            'base64_decode(', 'gzinflate(', 'str_rot13(',
            'file_get_contents($_GET', 'file_get_contents($_POST',
            'include($_GET', 'include($_POST', 'require($_POST', 'require($_GET',
            'fopen($_POST', 'fopen($_GET', 'move_uploaded_file'
        ];

        if (in_array($pattern, $highRiskPatterns)) {
            return 10;
        } elseif (in_array($pattern, $mediumRiskPatterns)) {
            return 5;
        } else {
            return 2;
        }
    }

    /**
     * Perform heuristic analysis for advanced threat detection
     */
    private function performHeuristicAnalysis($content) {
        $patterns = [];
        $riskScore = 0;

        $obfuscationCount = 0;
        $obfuscationPatterns = [
            '/\$[a-zA-Z_]\w*\s*=\s*["\'][a-zA-Z0-9+\/=]{20,}["\'];/',
            '/chr\(\d+\)\.chr\(\d+\)/',
            '/\$\w+\[\d+\]\.\$\w+\[\d+\]/',
            '/eval\s*\(\s*\$\w+\s*\.\s*\$\w+\s*\)/',
            '/\$\{[^}]+\}/',
        ];

        foreach ($obfuscationPatterns as $pattern) {
            if (preg_match_all($pattern, $content, $matches)) {
                $obfuscationCount += count($matches[0]);
            }
        }

        if ($obfuscationCount > 5) {
            $patterns[] = 'Heavy obfuscation detected';
            $riskScore += 8;
        } elseif ($obfuscationCount > 2) {
            $patterns[] = 'Moderate obfuscation detected';
            $riskScore += 4;
        }

        if (preg_match('/\$[_]{2,}|\$[a-zA-Z]{1,2}\b/', $content)) {
            $patterns[] = 'Suspicious variable naming';
            $riskScore += 3;
        }

        $encodingLayers = 0;
        if (stripos($content, 'base64_decode') !== false) $encodingLayers++;
        if (stripos($content, 'gzinflate') !== false) $encodingLayers++;
        if (stripos($content, 'str_rot13') !== false) $encodingLayers++;
        if (stripos($content, 'hex2bin') !== false) $encodingLayers++;

        if ($encodingLayers >= 3) {
            $patterns[] = 'Multiple encoding layers';
            $riskScore += 6;
        }

        $contentLength = strlen($content);
        $codeLength = strlen(preg_replace('/\s+/', '', $content));
        if ($contentLength > 1000 && ($codeLength / $contentLength) > 0.8) {
            $patterns[] = 'High code density (minimal whitespace)';
            $riskScore += 3;
        }

        $errorSuppressionCount = substr_count($content, '@');
        if ($errorSuppressionCount > 5) {
            $patterns[] = 'Excessive error suppression';
            $riskScore += 4;
        }

        return ['patterns' => $patterns, 'risk_score' => $riskScore];
    }

    /**
     * Calculate overall threat level
     */
    private function calculateThreatLevel($riskScore, $patternCount) {
        if ($riskScore >= 20 || $patternCount >= 8) {
            return 'CRITICAL';
        } elseif ($riskScore >= 10 || $patternCount >= 5) {
            return 'HIGH';
        } elseif ($riskScore >= 5 || $patternCount >= 3) {
            return 'MEDIUM';
        } else {
            return 'LOW';
        }
    }

    /**
     * Get safe preview of file content
     */
    private function getFilePreview($content, $maxLines = 5) {
        $contentLines = explode("\n", $content);
        $preview = array_slice($contentLines, 0, $maxLines);
        return htmlspecialchars(implode("\n", $preview));
    }

    /**
     * Safely delete files with verification
     */
    public function deleteFiles($filePaths) {
        $deleted = [];

        if (!is_array($filePaths)) {
            return $deleted;
        }

        foreach ($filePaths as $filePath) {
            $filePath = trim($filePath);

            if (!file_exists($filePath) || !is_file($filePath)) {
                continue;
            }

            $realPath = realpath($filePath);
            if (!$realPath) {
                continue;
            }

            if (unlink($realPath)) {
                $deleted[] = $filePath;
            }
        }

        return $deleted;
    }

    /**
     * Get results (for AJAX use)
     */
    public function getResults() {
        return $this->results;
    }

    /**
     * Filter results by threat level
     */
    public function filterResultsByThreatLevel($results, $threatLevel) {
        if (empty($threatLevel) || $threatLevel === 'all') {
            return $results;
        }

        return array_filter($results, function($result) use ($threatLevel) {
            return strtolower($result['threat_level']) === strtolower($threatLevel);
        });
    }

    /**
     * Get unique threat levels from results
     */
    public function getUniqueThreatLevels($results) {
        $levels = array_unique(array_map(function($result) {
            return $result['threat_level'];
        }, $results));

        $priority = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        usort($levels, function($a, $b) use ($priority) {
            $posA = array_search($a, $priority);
            $posB = array_search($b, $priority);
            return $posA <=> $posB;
        });

        return $levels;
    }

    /**
     * Generate HTML report
     */
    public function generateReport($scanDirectory = '', $filterLevel = 'all') {
        $results = $this->getResults();
        if (empty($results) && isset($_SESSION['scan_results'])) {
            $results = $_SESSION['scan_results'];
        }

        $filteredResults = $this->filterResultsByThreatLevel($results, $filterLevel);

        $threatLevels = $this->getUniqueThreatLevels($results);

        $directorySuggestions = $this->getDirectorySuggestions();

        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en" class="dark">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Malware Detection and Cleanup Tool</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <script>
                tailwind.config = {
                    darkMode: 'class',
                    theme: {
                        extend: {
                            colors: {
                                dark: {
                                    900: '#0f172a',
                                    800: '#1e293b',
                                    700: '#334155',
                                    600: '#475569',
                                    500: '#64748b',
                                    400: '#94a3b8',
                                    300: '#cbd5e1',
                                    200: '#e2e8f0',
                                    100: '#f1f5f9'
                                }
                            }
                        }
                    }
                }
            </script>
            <style>
                body { background-color: #0f172a; color: #e2e8f0; }
                .dark .card { background-color: #1e293b; }
                .dark .table-dark { background-color: #334155; }
                .dark .table-striped tbody tr:nth-of-type(odd) { background-color: #1e293b; }
                .dark .table-hover tbody tr:hover { background-color: #334155; }
                .dark .modal-content { background-color: #1e293b; }
                .dark .modal-header { border-bottom: 1px solid #334155; }
                .dark .modal-footer { border-top: 1px solid #334155; }
                .dark .badge-critical { background-color: #ef4444; }
                .dark .badge-high { background-color: #f97316; }
                .dark .badge-medium { background-color: #eab308; }
                .dark .badge-low { background-color: #22c55e; }
                .dark .badge-secondary { background-color: #64748b; }
                .dark .badge-danger { background-color: #ef4444; }
                .dark .badge-info { background-color: #0ea5e9; }
                .dark .badge-warning { background-color: #f97316; }
                .dark .badge-success { background-color: #22c55e; }
                .dark .form-control, .dark .form-select {
                    background-color: #1e293b;
                    border-color: #334155;
                    color: #e2e8f0;
                }
                .dark .form-control:focus {
                    background-color: #1e293b;
                    border-color: #3b82f6;
                    color: #e2e8f0;
                    box-shadow: 0 0 0 0.2rem rgba(59, 130, 246, 0.25);
                }
                .dark .btn-primary {
                    background-color: #3b82f6;
                    border-color: #3b82f6;
                }
                .dark .btn-primary:hover {
                    background-color: #2563eb;
                    border-color: #2563eb;
                }
                .dark .btn-danger {
                    background-color: #ef4444;
                    border-color: #ef4444;
                }
                .dark .btn-danger:hover {
                    background-color: #dc2626;
                    border-color: #dc2626;
                }
                .dark .btn-secondary {
                    background-color: #64748b;
                    border-color: #64748b;
                }
                .dark .btn-secondary:hover {
                    background-color: #475569;
                    border-color: #475569;
                }
                .dark .alert-danger {
                    background-color: #7f1d1d;
                    border-color: #7f1d1d;
                    color: #fecaca;
                }
                .dark .alert-info {
                    background-color: #1e3a8a;
                    border-color: #1e3a8a;
                    color: #bfdbfe;
                }
                .dark .alert-warning {
                    background-color: #78350f;
                    border-color: #78350f;
                    color: #fed7aa;
                }
                .dark .alert-success {
                    background-color: #14532d;
                    border-color: #14532d;
                    color: #bbf7d0;
                }
                .dark .toast-success {
                    background-color: #14532d;
                }
                .dark .toast-error {
                    background-color: #7f1d1d;
                }
                .dark .pre-content {
                    background-color: #0f172a;
                    border-color: #334155;
                    color: #e2e8f0;
                }
                .dark .select-all:hover {
                    background-color: #334155;
                }
            </style>
        </head>
        <body class="bg-dark-900 text-dark-200 min-h-screen">
            <div class="container mx-auto px-4 py-8">
                <header class="mb-8">
                    <h1 class="text-3xl font-bold text-white flex items-center">
                        <i class="fas fa-shield-alt mr-3 text-blue-500"></i>
                        Malware Detection and Cleanup Tool
                    </h1>
                    <p class="text-dark-400 mt-2">Maw3six security scanner for web servers</p>
                </header>

                <main>
                    <div class="card rounded-lg shadow-lg mb-8 border border-dark-700">
                        <div class="card-header p-4 border-b border-dark-700">
                            <h2 class="text-xl font-semibold flex items-center">
                                <i class="fas fa-folder-open mr-2 text-blue-400"></i>
                                Scan Directory
                            </h2>
                        </div>
                        <div class="card-body p-6">
                            <form method="GET" class="grid grid-cols-1 md:grid-cols-4 gap-4">
                                <input type="hidden" name="key" value="<?php echo htmlspecialchars($this->config['access_key']); ?>">
                                <div class="md:col-span-3">
                                    <label for="scan_dir" class="block text-sm font-medium mb-2">Select or enter directory path to scan</label>
                                    <div class="relative">
                                        <select
                                            id="scan_dir_select"
                                            class="form-select w-full px-4 py-2 rounded border focus:outline-none focus:ring-2 focus:ring-blue-500 mb-2"
                                            onchange="updateDirectoryInput(this.value)"
                                        >
                                            <option value="">-- Choose a directory --</option>
                                            <?php foreach ($directorySuggestions as $dir): ?>
                                                <option value="<?php echo htmlspecialchars($dir); ?>" <?php echo ($scanDirectory === $dir) ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($dir); ?>
                                                </option>
                                            <?php endforeach; ?>
                                            <option value="custom">-- Custom Directory --</option>
                                        </select>
                                        <input
                                            type="text"
                                            class="form-control w-full px-4 py-2 rounded border focus:outline-none focus:ring-2 focus:ring-blue-500"
                                            id="scan_dir"
                                            name="scan_dir"
                                            value="<?php echo htmlspecialchars($scanDirectory); ?>"
                                            placeholder="e.g., /var/www/html or . (current directory)"
                                            required
                                        >
                                    </div>
                                </div>
                                <div class="flex items-end">
                                    <button type="submit" class="btn btn-primary w-full py-2 px-4 rounded flex items-center justify-center">
                                        <i class="fas fa-search mr-2"></i>Start Scan
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>

                    <?php if (!empty($scanDirectory)): ?>
                        <div class="mb-6 p-4 bg-dark-800 rounded-lg border border-dark-700">
                            <p class="text-lg">
                                Scan directory: <code class="bg-dark-700 px-2 py-1 rounded text-sm"><?php echo htmlspecialchars($scanDirectory); ?></code>
                            </p>
                        </div>
                    <?php endif; ?>

                    <?php if (!empty($this->errors)): ?>
                        <div class="alert alert-danger rounded-lg p-4 mb-6">
                            <?php echo implode('<br>', array_map('htmlspecialchars', $this->errors)); ?>
                        </div>
                    <?php endif; ?>

                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                        <div class="card rounded-lg shadow-lg p-6 border border-dark-700">
                            <h3 class="text-dark-400 text-sm font-medium mb-1">Files Scanned</h3>
                            <p class="text-3xl font-bold text-blue-400"><?php echo number_format(count($results)); ?></p>
                        </div>
                        <div class="card rounded-lg shadow-lg p-6 border border-dark-700">
                            <h3 class="text-dark-400 text-sm font-medium mb-1">Threats Found</h3>
                            <p class="text-3xl font-bold text-red-500">
                                <?php echo number_format(count(array_filter($results, function($r) { return !empty($r['patterns']); }))); ?>
                            </p>
                        </div>
                        <div class="card rounded-lg shadow-lg p-6 border border-dark-700">
                            <h3 class="text-dark-400 text-sm font-medium mb-1">Extensions Checked</h3>
                            <p class="text-lg font-medium text-yellow-400">
                                <?php echo implode(', ', array_slice($this->config['scan_extensions'], 0, 3)); ?>
                                <?php if (count($this->config['scan_extensions']) > 3): ?>
                                    <span class="text-dark-500">+<?php echo count($this->config['scan_extensions']) - 3; ?> more</span>
                                <?php endif; ?>
                            </p>
                        </div>
                        <div class="card rounded-lg shadow-lg p-6 border border-dark-700">
                            <h3 class="text-dark-400 text-sm font-medium mb-1">Max File Size</h3>
                            <p class="text-3xl font-bold text-green-400">
                                <?php echo round($this->config['max_file_size'] / 1024 / 1024, 1); ?> MB
                            </p>
                        </div>
                    </div>

                    <?php if (!empty($results)): ?>
                        <div class="card rounded-lg shadow-lg mb-6 border border-dark-700">
                            <div class="card-header p-4 border-b border-dark-700">
                                <h3 class="text-lg font-semibold flex items-center">
                                    <i class="fas fa-filter mr-2 text-blue-400"></i>
                                    Filter Results
                                </h3>
                            </div>
                            <div class="card-body p-4">
                                <form method="GET" class="flex flex-wrap items-center gap-4">
                                    <input type="hidden" name="key" value="<?php echo htmlspecialchars($this->config['access_key']); ?>">
                                    <input type="hidden" name="scan_dir" value="<?php echo htmlspecialchars($scanDirectory); ?>">

                                    <div class="flex items-center">
                                        <label for="threat_level" class="mr-2 text-sm">Threat Level:</label>
                                        <select
                                            id="threat_level"
                                            name="threat_level"
                                            class="form-select px-3 py-1 rounded border focus:outline-none focus:ring-2 focus:ring-blue-500"
                                            onchange="this.form.submit()"
                                        >
                                            <option value="all" <?php echo ($filterLevel === 'all') ? 'selected' : ''; ?>>All Levels</option>
                                            <?php foreach ($threatLevels as $level): ?>
                                                <option value="<?php echo strtolower($level); ?>" <?php echo ($filterLevel === strtolower($level)) ? 'selected' : ''; ?>>
                                                    <?php echo $level; ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>

                                    <div class="flex items-center">
                                        <span class="mr-2 text-sm">Showing:</span>
                                        <span class="font-semibold"><?php echo count($filteredResults); ?></span>
                                        <span class="mx-1">/</span>
                                        <span><?php echo count($results); ?></span>
                                        <span class="ml-1 text-sm">files</span>
                                    </div>

                                    <?php if ($filterLevel !== 'all'): ?>
                                        <a href="?key=<?php echo $this->config['access_key']; ?>&scan_dir=<?php echo urlencode($scanDirectory); ?>" class="text-blue-400 hover:text-blue-300 text-sm flex items-center">
                                            <i class="fas fa-times-circle mr-1"></i>Clear Filter
                                        </a>
                                    <?php endif; ?>
                                </form>
                            </div>
                        </div>

                        <!-- Results Table -->
                        <div class="card rounded-lg shadow-lg border border-dark-700 overflow-hidden">
                            <div class="card-header p-4 border-b border-dark-700">
                                <h2 class="text-xl font-semibold">
                                    Scan Results
                                    <?php if ($filterLevel !== 'all'): ?>
                                        <span class="text-sm font-normal text-dark-400">(Filtered by <?php echo strtoupper($filterLevel); ?>)</span>
                                    <?php endif; ?>
                                </h2>
                            </div>
                            <div class="overflow-x-auto">
                                <table class="min-w-full divide-y divide-dark-700">
                                    <thead class="table-dark">
                                        <tr>
                                            <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">
                                                <input type="checkbox" id="selectAll" class="rounded text-blue-500">
                                            </th>
                                            <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">File Path</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Size</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Modified</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Threat Level</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Risk Score</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Patterns</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-dark-700">
                                        <?php if (empty($filteredResults)): ?>
                                            <tr>
                                                <td colspan="8" class="px-6 py-4 text-center text-dark-500">
                                                    No files found with <?php echo strtoupper($filterLevel); ?> threat level.
                                                    <a href="?key=<?php echo $this->config['access_key']; ?>&scan_dir=<?php echo urlencode($scanDirectory); ?>" class="text-blue-400 hover:text-blue-300 ml-2">
                                                        Clear filter to see all results
                                                    </a>
                                                </td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach ($filteredResults as $result): ?>
                                                <tr class="hover:bg-dark-800">
                                                    <td class="px-6 py-4 whitespace-nowrap">
                                                        <input type="checkbox" class="file-checkbox rounded text-blue-500" name="delete_files[]" value="<?php echo base64_encode($result['path']); ?>">
                                                    </td>
                                                    <td class="px-6 py-4">
                                                        <code class="text-sm break-all"><?php echo htmlspecialchars($result['path']); ?></code>
                                                    </td>
                                                    <td class="px-6 py-4 whitespace-nowrap">
                                                        <?php echo $this->formatBytes($result['size']); ?>
                                                    </td>
                                                    <td class="px-6 py-4 whitespace-nowrap">
                                                        <?php echo date('Y-m-d H:i:s', $result['modified']); ?>
                                                    </td>
                                                    <td class="px-6 py-4 whitespace-nowrap">
                                                        <span class="badge badge-<?php echo strtolower($result['threat_level']); ?> px-2 py-1 rounded-full text-xs font-medium">
                                                            <?php echo $result['threat_level']; ?>
                                                        </span>
                                                    </td>
                                                    <td class="px-6 py-4 whitespace-nowrap">
                                                        <?php echo $result['risk_score']; ?>
                                                    </td>
                                                    <td class="px-6 py-4">
                                                        <?php if (!empty($result['patterns'])): ?>
                                                            <div class="flex flex-wrap gap-1">
                                                                <?php foreach (array_slice($result['patterns'], 0, 3) as $pattern): ?>
                                                                    <span class="badge badge-danger px-2 py-1 rounded text-xs">
                                                                        <?php echo htmlspecialchars($pattern); ?>
                                                                    </span>
                                                                <?php endforeach; ?>
                                                                <?php if (count($result['patterns']) > 3): ?>
                                                                    <span class="text-dark-500 text-xs">+<?php echo count($result['patterns']) - 3; ?> more</span>
                                                                <?php endif; ?>
                                                            </div>
                                                        <?php else: ?>
                                                            <span class="badge badge-secondary px-2 py-1 rounded text-xs">None</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td class="px-6 py-4 whitespace-nowrap">
                                                        <button
                                                            class="btn btn-secondary text-xs py-1 px-3 rounded flex items-center"
                                                            onclick="viewFile('<?php echo base64_encode($result['path']); ?>')"
                                                        >
                                                            <i class="fas fa-eye mr-1"></i>View
                                                        </button>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                            <?php if (!empty($filteredResults)): ?>
                                <div class="card-footer p-4 border-t border-dark-700">
                                    <form method="post">
                                        <button type="submit" name="delete_selected" class="btn btn-danger py-2 px-4 rounded flex items-center">
                                            <i class="fas fa-trash mr-2"></i>Delete Selected Files
                                        </button>
                                    </form>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php else: ?>
                        <?php if (!empty($scanDirectory)): ?>
                            <div class="alert alert-info rounded-lg p-6 text-center">
                                <i class="fas fa-check-circle text-green-500 text-4xl mb-3"></i>
                                <h3 class="text-xl font-semibold mb-2">No threats found!</h3>
                                <p>Your system appears to be clean. Good job! 🎉</p>
                            </div>
                        <?php else: ?>
                            <div class="alert alert-info rounded-lg p-6 text-center">
                                <i class="fas fa-info-circle text-blue-500 text-4xl mb-3"></i>
                                <h3 class="text-xl font-semibold mb-2">Ready to scan</h3>
                                <p>Select a directory from the dropdown or enter a custom path above and click "Start Scan" to begin.</p>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>

                    <div class="alert alert-warning rounded-lg p-6 mt-8 border border-yellow-700">
                        <h3 class="text-lg font-semibold flex items-center mb-3">
                            <i class="fas fa-exclamation-triangle mr-2 text-yellow-500"></i>
                            Important Security Notes
                        </h3>
                        <ul class="list-disc pl-5 space-y-2">
                            <li>Always backup your files before deletion</li>
                            <li>Review detected files manually before deleting</li>
                            <li>Remove this scanner after use for security</li>
                            <li>Backups are stored in scanner_backups/ directory</li>
                        </ul>
                    </div>
                </main>
            </div>

            <div id="fileViewerModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
                <div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
                    <div class="fixed inset-0 transition-opacity" aria-hidden="true">
                        <div class="absolute inset-0 bg-dark-900 opacity-75"></div>
                    </div>
                    <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
                    <div class="inline-block align-bottom rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-6xl sm:w-full">
                        <div class="modal-content bg-dark-800 border border-dark-700 rounded-lg">
                            <div class="modal-header px-6 py-4 border-b border-dark-700 flex justify-between items-center">
                                <h3 class="text-xl font-semibold flex items-center">
                                    <i class="fas fa-file-code mr-2 text-blue-400"></i>
                                    File Content Viewer (First 50 Lines)
                                </h3>
                                <button type="button" class="text-dark-400 hover:text-white" onclick="closeModal()">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                            <div class="modal-body p-6">
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                                    <div>
                                        <strong class="block text-dark-400 mb-1">File Path:</strong>
                                        <code id="modal-file-path" class="break-all bg-dark-700 px-2 py-1 rounded"></code>
                                    </div>
                                    <div>
                                        <strong class="block text-dark-400 mb-1">File Size:</strong>
                                        <span id="modal-file-size"></span>
                                    </div>
                                    <div>
                                        <strong class="block text-dark-400 mb-1">Last Modified:</strong>
                                        <span id="modal-file-modified"></span>
                                    </div>
                                    <div>
                                        <strong class="block text-dark-400 mb-1">Threat Level:</strong>
                                        <span id="modal-threat-level"></span>
                                    </div>
                                </div>
                                <div class="mb-6">
                                    <strong class="block text-dark-400 mb-2">Risk Score:</strong>
                                    <span id="modal-risk-score" class="badge badge-secondary px-2 py-1 rounded"></span>
                                </div>
                                <div class="mb-6">
                                    <strong class="block text-dark-400 mb-2">Detected Patterns:</strong>
                                    <div id="modal-patterns" class="flex flex-wrap gap-1"></div>
                                </div>
                                <div class="flex justify-between items-center mb-3">
                                    <strong class="text-dark-400">File Content:</strong>
                                    <div class="flex space-x-2">
                                        <button type="button" class="btn btn-secondary text-xs py-1 px-3 rounded flex items-center" onclick="copyToClipboard()">
                                            <i class="fas fa-copy mr-1"></i>Copy
                                        </button>
                                        <button type="button" class="btn btn-secondary text-xs py-1 px-3 rounded flex items-center" onclick="downloadFile()">
                                            <i class="fas fa-download mr-1"></i>Download
                                        </button>
                                        <button type="button" class="btn btn-secondary text-xs py-1 px-3 rounded flex items-center" onclick="toggleLineNumbers()">
                                            <i class="fas fa-list-ol mr-1"></i>Line Numbers
                                        </button>
                                    </div>
                                </div>
                                <div class="relative">
                                    <pre id="modal-file-content" class="pre-content border rounded p-4 max-h-96 overflow-y-auto text-sm"></pre>
                                    <div id="loading-spinner" class="absolute inset-0 flex items-center justify-center hidden">
                                        <div class="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
                                    </div>
                                </div>
                            </div>
                            <div class="modal-footer px-6 py-4 border-t border-dark-700 flex justify-between">
                                <button type="button" class="btn btn-secondary py-2 px-4 rounded flex items-center" onclick="closeModal()">
                                    <i class="fas fa-times mr-2"></i>Close
                                </button>
                                <button type="button" class="btn btn-danger py-2 px-4 rounded flex items-center" onclick="confirmDeleteFile()" id="delete-file-btn">
                                    <i class="fas fa-trash mr-2"></i>Delete This File
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="toast-container" class="fixed top-4 right-4 z-50 space-y-2"></div>

            <script>
                function updateDirectoryInput(value) {
                    const input = document.getElementById('scan_dir');
                    if (value === 'custom') {
                        input.value = '';
                        input.focus();
                        input.placeholder = 'Enter custom directory path...';
                    } else if (value) {
                        input.value = value;
                    }
                }

                document.addEventListener('DOMContentLoaded', function() {
                    const select = document.getElementById('scan_dir_select');
                    const input = document.getElementById('scan_dir');

                    if (input.value) {
                        let found = false;
                        for (let option of select.options) {
                            if (option.value === input.value) {
                                option.selected = true;
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            select.value = 'custom';
                        }
                    }
                });

                let currentFileData = null;
                let showLineNumbers = false;

                function viewFile(encodedPath) {
                    const modal = document.getElementById('fileViewerModal');
                    const loadingSpinner = document.getElementById('loading-spinner');
                    const contentElement = document.getElementById('modal-file-content');

                    loadingSpinner.classList.remove('hidden');
                    contentElement.innerHTML = '';
                    modal.classList.remove('hidden');

                    fetch(window.location.href, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: 'action=get_file_content&file_path=' + encodeURIComponent(encodedPath) +
                        '&key=' + encodeURIComponent('<?php echo $this->config['access_key']; ?>')
                    })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Network response was not ok');
                        }
                        return response.json();
                    })
                    .then(data => {
                        loadingSpinner.classList.add('hidden');

                        if (data.success) {
                            currentFileData = data;
                            populateModal(data);
                        } else {
                            contentElement.innerHTML = '<div class="alert alert-danger p-3 rounded">Error: ' + htmlspecialchars(data.error) + '</div>';
                        }
                    })
                    .catch(error => {
                        loadingSpinner.classList.add('hidden');
                        contentElement.innerHTML = '<div class="alert alert-danger p-3 rounded">Error fetching file content: ' + htmlspecialchars(error.message) + '</div>';
                    });
                }

                function populateModal(data) {
                    document.getElementById('modal-file-path').textContent = data.path;
                    document.getElementById('modal-file-size').textContent = formatBytes(data.size);
                    document.getElementById('modal-file-modified').textContent = data.modified;

                    const threatLevel = document.getElementById('modal-threat-level');
                    const threatClass = data.threat_level === 'CRITICAL' ? 'critical' :
                                      (data.threat_level === 'HIGH' ? 'high' :
                                      (data.threat_level === 'MEDIUM' ? 'medium' : 'low'));
                    threatLevel.innerHTML = '<span class="badge badge-' + threatClass + ' px-2 py-1 rounded-full text-xs font-medium">' + data.threat_level + '</span>';

                    document.getElementById('modal-risk-score').textContent = data.risk_score;

                    const patternsDiv = document.getElementById('modal-patterns');
                    patternsDiv.innerHTML = '';
                    if (data.patterns && data.patterns.length > 0) {
                        data.patterns.forEach(pattern => {
                            const badge = document.createElement('span');
                            badge.className = 'badge badge-danger px-2 py-1 rounded text-xs';
                            badge.textContent = pattern;
                            patternsDiv.appendChild(badge);
                        });
                    } else {
                        patternsDiv.textContent = 'No patterns detected';
                    }

                    displayFileContent(data.content || 'No content available');
                }

                function displayFileContent(content) {
                    const contentElement = document.getElementById('modal-file-content');
                    if (showLineNumbers && content) {
                        const lines = content.split('\n');
                        const limitedLines = lines.slice(0, 50);
                        const numberedContent = limitedLines.map((line, index) => {
                            const lineNumber = (index + 1).toString().padStart(4, ' ');
                            return lineNumber + ' | ' + (line || '');
                        }).join('\n');
                        contentElement.textContent = numberedContent || 'Empty file (showing first 50 lines)';
                    } else {
                        const lines = content.split('\n');
                        const limitedLines = lines.slice(0, 50);
                        contentElement.textContent = limitedLines.join('\n') || 'No content available (showing first 50 lines)';
                    }
                }

                function toggleLineNumbers() {
                    showLineNumbers = !showLineNumbers;
                    if (currentFileData) {
                        displayFileContent(currentFileData.content);
                    }
                }

                function copyToClipboard() {
                    if (currentFileData) {
                        navigator.clipboard.writeText(currentFileData.content).then(() => {
                            showToast('Content copied to clipboard!', 'success');
                        }).catch(() => {
                            showToast('Failed to copy content', 'error');
                        });
                    }
                }

                function downloadFile() {
                    if (currentFileData) {
                        const blob = new Blob([currentFileData.content], { type: 'text/plain' });
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = currentFileData.filename || 'suspicious_file.txt';
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                        showToast('File downloaded!', 'success');
                    }
                }

                function confirmDeleteFile() {
                    if (currentFileData && confirm('Are you sure you want to delete this file?\n\nFile: ' + currentFileData.path + '\n\nThis action cannot be undone!')) {
                        deleteFile(currentFileData.path);
                    }
                }

                function deleteFile(filePath) {
                    fetch(window.location.href, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: 'action=delete_single_file&file_path=' + encodeURIComponent(filePath) +
                        '&key=' + encodeURIComponent('<?php echo $this->config['access_key']; ?>')
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showToast('File deleted successfully!', 'success');
                            closeModal();
                            setTimeout(() => {
                                location.reload();
                            }, 1500);
                        } else {
                            showToast('Error deleting file: ' + data.error, 'error');
                        }
                    })
                    .catch(error => {
                        showToast('Error: ' + error.message, 'error');
                    });
                }

                function closeModal() {
                    document.getElementById('fileViewerModal').classList.add('hidden');
                }

                function formatBytes(bytes) {
                    if (bytes === 0) return '0 Bytes';
                    const k = 1024;
                    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                }

                function showToast(message, type) {
                    const toastContainer = document.getElementById('toast-container');
                    const toast = document.createElement('div');
                    toast.className = 'toast rounded-lg p-4 text-white max-w-md ' + (type === 'success' ? 'toast-success bg-green-700' : 'toast-error bg-red-700');
                    toast.innerHTML = `
                        <div class="flex items-start">
                            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'} mr-2 mt-1"></i>
                            <div>${message}</div>
                            <button class="ml-auto" onclick="this.parentElement.parentElement.remove()">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    `;
                    toastContainer.appendChild(toast);

                    setTimeout(() => {
                        if (toast.parentElement) {
                            toast.remove();
                        }
                    }, 5000);
                }

                function selectAllFiles() {
                    const checkboxes = document.querySelectorAll('.file-checkbox');
                    const selectAll = document.getElementById('selectAll');

                    checkboxes.forEach(checkbox => {
                        checkbox.checked = selectAll.checked;
                    });
                }

                document.getElementById('selectAll').addEventListener('change', selectAllFiles);

                if (window.history.replaceState) {
                    window.history.replaceState(null, null, window.location.href);
                }

                function htmlspecialchars(string) {
                    return string
                        .replace(/&/g, "&amp;")
                        .replace(/"/g, "&quot;")
                        .replace(/'/g, "&#039;")
                        .replace(/</g, "<")
                        .replace(/>/g, ">");
                }

                document.getElementById('fileViewerModal').addEventListener('click', function(e) {
                    if (e.target === this) {
                        closeModal();
                    }
                });
            </script>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    /**
     * Helper function for bytes formatting (static-like)
     */
    private function formatBytes($bytes) {
        if ($bytes === 0) return '0 Bytes';
        $k = 1024;
        $sizes = ['Bytes', 'KB', 'MB', 'GB'];
        $i = floor(log($bytes) / log($k));
        return round($bytes / pow($k, $i), 2) . ' ' . $sizes[$i];
    }
}

if (isset($_POST['action'])) {
    header('Content-Type: application/json');
    $scanner = new WebSecurityScanner(); // Re-init for AJAX

    if ($_POST['action'] === 'get_file_content') {
        if (!isset($_POST['key']) || $_POST['key'] !== 'maw3six') {
            echo json_encode(['success' => false, 'error' => 'Unauthorized access']);
            exit;
        }

        $filePath = base64_decode($_POST['file_path']);

        if (!file_exists($filePath) || !is_file($filePath)) {
            echo json_encode(['success' => false, 'error' => 'File not found']);
            exit;
        }

        $realPath = realpath($filePath);
        $protectedPaths = ['/etc', '/bin', '/sbin', '/usr/bin', '/root', '/boot'];
        foreach ($protectedPaths as $protected) {
            if (strpos($realPath, $protected) === 0) {
                echo json_encode(['success' => false, 'error' => 'Access denied to protected path']);
                exit;
            }
        }

        $content = @file_get_contents($filePath);
        if ($content === false) {
            error_log("Failed to read file: $filePath");
            echo json_encode(['success' => false, 'error' => 'Cannot read file (permission or corruption issue)']);
            exit;
        }

        $fileInfo = null;
        if (isset($_SESSION['scan_results'])) {
            foreach ($_SESSION['scan_results'] as $result) {
                if ($result['path'] === $filePath) {
                    $fileInfo = $result;
                    break;
                }
            }
        }

        if (!$fileInfo) {
            $fileInfo = [
                'path' => $filePath,
                'size' => filesize($filePath),
                'modified' => filemtime($filePath),
                'patterns' => [],
                'risk_score' => 0,
                'threat_level' => 'UNKNOWN'
            ];
        }

        echo json_encode([
            'success' => true,
            'content' => $content,
            'path' => $filePath,
            'filename' => basename($filePath),
                         'size' => $fileInfo['size'],
                         'modified' => date('Y-m-d H:i:s', $fileInfo['modified']),
                         'patterns' => $fileInfo['patterns'],
                         'risk_score' => $fileInfo['risk_score'],
                         'threat_level' => $fileInfo['threat_level']
        ]);
        exit;
    }

    if ($_POST['action'] === 'delete_single_file') {
        if (!isset($_POST['key']) || $_POST['key'] !== 'maw3six') {
            echo json_encode(['success' => false, 'error' => 'Unauthorized access']);
            exit;
        }

        $filePath = trim($_POST['file_path']);
        $deletedFiles = $scanner->deleteFiles([$filePath]);

        if (!empty($deletedFiles)) {
            echo json_encode(['success' => true, 'message' => 'File deleted successfully']);
        } else {
            echo json_encode(['success' => false, 'error' => 'Failed to delete file']);
        }
        exit;
    }
}

$scanner = new WebSecurityScanner();

if (!isset($_GET['key']) || $_GET['key'] !== 'maw3six') {
    http_response_code(404);
    if (file_exists($_SERVER['DOCUMENT_ROOT'] . "/404.php")) {
        include $_SERVER['DOCUMENT_ROOT'] . "/404.php";
    } else {
        echo "404 Not Found";
    }
    exit;
}

if (isset($_POST['delete_selected']) && isset($_POST['delete_files'])) {
    $deletedFiles = $scanner->deleteFiles($_POST['delete_files']);
    if (!empty($deletedFiles)) {
        echo '<div class="alert alert-success rounded-lg p-4 mb-6">Successfully deleted ' . count($deletedFiles) . ' files.</div>';
    }
}

$scanDirectory = '';
$filterLevel = 'all';

if (isset($_GET['scan_dir']) && !empty(trim($_GET['scan_dir']))) {
    $scanDirectory = trim($_GET['scan_dir']);
    $scanner->scanDirectory($scanDirectory);

    $_SESSION['scan_results'] = $scanner->getResults();
}

if (isset($_GET['threat_level'])) {
    $filterLevel = strtolower($_GET['threat_level']);
}

echo $scanner->generateReport($scanDirectory, $filterLevel);
?>
