#!/bin/bash
# FINAL Rebuilt: security-v3.sh
# Custom Security Middleware Installer for Pterodactyl (v3) + Web UI Toggle + Activity Log (Indonesia format)
# Usage: sudo bash security-v3.sh
set -euo pipefail

# -----------------------
# Colors & helpers
# -----------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
info()   { echo -e "${BLUE}[MENU]${NC} $*"; }

# -----------------------
# Paths
# -----------------------
APP_DIR="/var/www/pterodactyl"
MW_FILE="$APP_DIR/app/Http/Middleware/CustomSecurityCheck.php"
KERNEL="$APP_DIR/app/Http/Kernel.php"
API_CLIENT="$APP_DIR/routes/api-client.php"
ADMIN_ROUTES="$APP_DIR/routes/admin.php"
LAYOUT_FILE="$APP_DIR/resources/views/layouts/admin.blade.php"
ACTIVITY_LOG="$APP_DIR/storage/logs/activity.log"

# -----------------------
# Small helpers
# -----------------------
STAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_DIR="/root/pterodactyl-customsecurity-backup-$STAMP"
mkdir -p "$BACKUP_DIR"

bk() { [ -f "$1" ] && cp -a "$1" "$BACKUP_DIR/$(basename "$1").bak.$STAMP" && echo "  backup: $1 -> $BACKUP_DIR"; }

ensure_app_dir() {
    if [ ! -d "$APP_DIR" ]; then
        error "Pterodactyl directory not found: $APP_DIR"
    fi
}

# -----------------------
# Show menu
# -----------------------
show_menu() {
    echo
    info "=========================================="
    info "    PROTECT PANEL VERSION 3 BY OZZY      "
    info "=========================================="
    echo
    info "Pilihan yang tersedia:"
    info "1. Install Security Middleware + Web UI Interaktif + Activity Log"
    info "2. Ganti Nama Credit di Middleware"
    info "3. Keluar"
    echo
}

replace_credit_name() {
    echo
    info "GANTI NAMA CREDIT"
    info "================="
    echo
    read -p "Masukkan nama baru untuk mengganti '@thezzyxopois': " new_name

    if [ -z "$new_name" ]; then
        error "Nama tidak boleh kosong!"
    fi

    new_name=$(echo "$new_name" | sed 's/^@//')

    if [ ! -f "$MW_FILE" ]; then
        error "Middleware belum diinstall! Silakan install terlebih dahulu."
    fi

    bk "$MW_FILE"
    sed -i "s/@thezzyxopois/@$new_name/g" "$MW_FILE"

    log "✅ Nama berhasil diganti menjadi '@$new_name'"

    cd "$APP_DIR"
    sudo -u www-data php artisan config:clear || true
    sudo -u www-data php artisan route:clear || true
    sudo -u www-data php artisan cache:clear || true

    log "🎉 Nama credit berhasil diubah!"
    log "💬 Credit sekarang: @$new_name"
}

install_full_security_v3() {
    # Must be root
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo)."
    fi

    ensure_app_dir

    log "🚀 Starting Custom Security Middleware Full Installation v3..."
    echo "App: $APP_DIR"
    echo "Backup: $BACKUP_DIR"

    # --- 1) Create middleware file (with toggle and logging embedded) ---
    log "📝 Creating CustomSecurityCheck middleware..."
    mkdir -p "$(dirname "$MW_FILE")"
    bk "$MW_FILE"

    cat > "$MW_FILE" <<'PHP'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Pterodactyl\Models\Server;
use Pterodactyl\Models\User;
use Illuminate\Support\Facades\Log;

class CustomSecurityCheck
{
    private function monthName($n) {
        $m = [
            1=>'Januari',2=>'Februari',3=>'Maret',4=>'April',5=>'Mei',6=>'Juni',
            7=>'Juli',8=>'Agustus',9=>'September',10=>'Oktober',11=>'November',12=>'Desember'
        ];
        return $m[(int)$n] ?? $n;
    }

    private function writeActivityLog($user, $role, $action)
    {
        try {
            $d = new \DateTime();
            $day = $d->format('j');
            $month = $this->monthName($d->format('n'));
            $year = $d->format('Y');
            $time = $d->format('H:i:s');
            $username = $user->username ?? $user->name ?? $user->email ?? 'id:'.$user->id;
            $line = sprintf("[%d/%s/%s] (%s) Pengguna %s sebagai role %s %s", $day, $month, $year, $time, $username, $role, $action);
            $logPath = storage_path('logs/activity.log');
            @file_put_contents($logPath, $line.PHP_EOL, FILE_APPEND | LOCK_EX);
        } catch (\Throwable $e) {
            Log::warning('ActivityLog write failed: ' . $e->getMessage());
        }
    }

    public function handle(Request $request, Closure $next)
    {
        // === Toggle check: read /storage/security-toggle.json
        try {
            $configFile = storage_path('security-toggle.json');
            if (file_exists($configFile)) {
                $cfg = json_decode(file_get_contents($configFile), true);
                if (isset($cfg['enabled']) && !$cfg['enabled']) {
                    // Security toggle is OFF -> skip checks & logging for middleware (blade hook still may log views)
                    return $next($request);
                }
            }
        } catch (\Throwable $e) {
            Log::warning('CustomSecurityCheck: toggle read failed: ' . $e->getMessage());
        }

        $user   = $request->user();
        $path   = strtolower($request->path());
        $method = strtoupper($request->method());
        $server = $request->route('server');

        // === Middleware logs: NON-GET admin actions and sensitive API actions ===
        if ($user && str_contains($path, 'admin') && $method !== 'GET') {
            $role = $user->root_admin ? 'Admin' : 'User';
            // Friendly action mapping
            if (str_contains($path, 'admin/servers') && $method === 'POST') {
                $srvName = $request->input('name') ?? 'tanpa_nama';
                $this->writeActivityLog($user, $role, "membuat server bernama ".$srvName);
            } elseif (str_contains($path, 'admin/servers') && in_array($method, ['PUT','PATCH'])) {
                $this->writeActivityLog($user, $role, "mengupdate server (".$path.")");
            } elseif (str_contains($path, 'admin/servers') && $method === 'DELETE') {
                $this->writeActivityLog($user, $role, "menghapus server (".$path.")");
            } elseif (str_contains($path, 'admin/users') && in_array($method, ['POST','PUT','PATCH','DELETE'])) {
                $this->writeActivityLog($user, $role, "modifikasi user pada ".$path);
            } else {
                $this->writeActivityLog($user, $role, "melakukan aksi ".$method." pada ".$path);
            }
        }

        Log::debug('CustomSecurityCheck: incoming request', [
            'user_id'     => $user->id ?? null,
            'root_admin'  => $user->root_admin ?? false,
            'path'        => $path,
            'method'      => $method,
            'server_id'   => $server instanceof Server ? $server->id : null,
            'auth_header' => $request->hasHeader('Authorization'),
        ]);

        if (!$user) {
            return $next($request);
        }

        if ($server instanceof Server) {
            if ($user->id === $server->owner_id) {
                Log::info('Owner bypass', ['user_id' => $user->id, 'server_id' => $server->id]);
                return $next($request);
            }

            if ($this->isFilesListRoute($path, $method)) {
                return $next($request);
            }

            if ($this->isRestrictedFileAction($path, $method, $request)) {
                Log::warning('Blocked non-owner file action', [
                    'user_id'   => $user->id,
                    'server_id' => $server->id,
                    'path'      => $path,
                ]);
                $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "mencoba aksi file terlarang pada server ".$server->id);
                return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
            }
        }

        if ($this->isAdminDeletingUser($path, $method)) {
            $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "mencoba menghapus user");
            return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
        }

        if ($this->isAdminUpdatingUser($request, $path, $method)) {
            $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "mencoba mengupdate user");
            return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
        }

        if ($this->isAdminDeletingServer($path, $method)) {
            $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "mencoba menghapus server");
            return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
        }

        if ($this->isAdminModifyingNode($path, $method)) {
            $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "mencoba memodifikasi node");
            return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
        }

        if ($request->hasHeader('Authorization') && $this->isRestrictedFileAction($path, $method, $request) && $server instanceof Server && $user->id !== $server->owner_id) {
            Log::warning('Blocked admin API key file action', [
                'user_id'   => $user->id,
                'server_id' => $server->id ?? null,
                'path'      => $path,
            ]);
            $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "mencoba aksi file menggunakan API key pada server ".$server->id);
            return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
        }

        if (str_contains($path, 'admin/settings')) {
            $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "membuka bagian Settings");
            return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
        }

        if (!$user->root_admin) {
            $targetUser = $request->route('user');

            if ($targetUser instanceof User && $user->id !== $targetUser->id) {
                $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "mencoba mengakses data user lain");
                return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
            }

            if ($this->isAccessingRestrictedList($path, $method, $targetUser)) {
                $this->writeActivityLog($user, $user->root_admin ? 'Admin' : 'User', "mencoba mengakses daftar terbatas ".$path);
                return $this->deny($request, 'Mau ngapain lu? - @thezzyxopois');
            }
        }

        return $next($request);
    }

    private function deny(Request $request, string $message)
    {
        if ($request->is('api/*') || $request->expectsJson()) {
            return response()->json(['error' => $message], 403);
        }
        if ($request->hasSession()) {
            $request->session()->flash('error', $message);
        }
        return redirect()->back();
    }

    private function isFilesListRoute(string $path, string $method): bool
    {
        return (
            preg_match('#^server/[^/]+/files$#', $path) && $method === 'GET'
        ) || (
            (str_contains($path, 'application/servers/') || str_contains($path, 'api/servers/'))
            && str_contains($path, '/files')
            && $method === 'GET'
        );
    }

    private function isRestrictedFileAction(string $path, string $method, Request $request): bool
    {
        $restricted = ['download','archive','compress','decompress','delete','chmod','upload'];
        foreach ($restricted as $kw) {
            if (str_contains($path, $kw)) {
                return true;
            }
        }

        if ((str_contains($path, 'application/servers/') || str_contains($path, 'api/servers/')) && str_contains($path, '/files') && $method === 'GET') {
            $q = strtolower($request->getQueryString() ?? '');
            return str_contains($q, 'download') || str_contains($q, 'file=');
        }

        return false;
    }

    private function isAdminDeletingUser(string $path, string $method): bool
    {
        return ($method === 'DELETE' && str_contains($path, 'admin/users'))
            || ($method === 'POST' && str_contains($path, 'admin/users') && str_contains($path, 'delete'));
    }

    private function isAdminUpdatingUser(Request $request, string $path, string $method): bool
    {
        if (in_array($method, ['PUT','PATCH']) && str_contains($path, 'admin/users')) {
            return true;
        }

        $override = strtoupper($request->input('_method', ''));
        if ($method === 'POST' && in_array($override, ['PUT','PATCH']) && str_contains($path, 'admin/users')) {
            return true;
        }

        return $method === 'POST' && preg_match('/admin\/users\/\d+$/', $path);
    }

    private function isAdminDeletingServer(string $path, string $method): bool
    {
        return ($method === 'DELETE' && str_contains($path, 'admin/servers'))
            || ($method === 'POST' && str_contains($path, 'admin/servers') && str_contains($path, 'delete'));
    }

    private function isAdminModifyingNode(string $path, string $method): bool
    {
        return str_contains($path, 'admin/nodes') && in_array($method, ['POST','PUT','PATCH','DELETE']);
    }

    private function isAccessingRestrictedList(string $path, string $method, $user): bool
    {
        if ($method !== 'GET' || $user) {
            return false;
        }
        foreach (['admin/users','admin/servers','admin/nodes'] as $restricted) {
            if (str_contains($path, $restricted)) {
                return true;
            }
        }
        return false;
    }
}
?>
PHP

    log "✅ Custom middleware created"

    # --- 2) Register middleware in Kernel ---
    log "📝 Registering middleware in Kernel..."
    if [ -f "$KERNEL" ]; then
        bk "$KERNEL"
        php <<'PHP'
<?php
$f = '/var/www/pterodactyl/app/Http/Kernel.php';
$s = file_get_contents($f);
$alias = "'custom.security' => \\Pterodactyl\\Http\\Middleware\\CustomSecurityCheck::class,";
if (strpos($s, "'custom.security'") !== false) {
    echo "Kernel alias already present\n";
    exit;
}

$patterns = [
    '/(\$middlewareAliases\s*=\s*\[)([\s\S]*?)(\n\s*\];)/',
    '/(\$routeMiddleware\s*=\s*\[)([\s\S]*?)(\n\s*\];)/',
];
$done = false;
foreach ($patterns as $p) {
    $s2 = preg_replace_callback($p, function($m) use ($alias){
        $body = rtrim($m[2]);
        if ($body !== '' && substr(trim($body), -1) !== ',') $body .= ',';
        $body .= "\n        " . $alias;
        return $m[1] . $body . $m[3];
    }, $s, 1, $cnt);
    if ($cnt > 0) { $s = $s2; $done = true; break; }
}
if (!$done) {
    fwrite(STDERR, "ERROR: \$middlewareAliases / \$routeMiddleware not found\n");
    exit(1);
}
file_put_contents($f, $s);
echo "Kernel alias inserted\n";
?>
PHP
        log "✅ Middleware registered in Kernel"
    else
        warn "⚠️ Kernel.php not found, skipped"
    fi

    # --- 3) Patch api-client.php ---
    log "🔧 Patching api-client.php..."
    if [ -f "$API_CLIENT" ]; then
        bk "$API_CLIENT"
        php <<'PHP'
<?php
$f = '/var/www/pterodactyl/routes/api-client.php';
$s = file_get_contents($f);
if (stripos($s, "custom.security") !== false) {
    echo "api-client.php already has custom.security\n";
    exit;
}

$changed = false;
$s = preg_replace_callback('/(middleware\s*=>\s*\[)([\s\S]*?)(\])/i', function($m) use (&$changed) {
    $body = $m[2];
    if (stripos($body, 'AuthenticateServerAccess::class') !== false) {
        if (stripos($body, 'custom.security') === false) {
            $b = rtrim($body);
            if ($b !== '' && substr(trim($b), -1) !== ',') $b .= ',';
            $b .= "\n        'custom.security'";
            $changed = true;
            return $m[1] . $b . $m[3];
        }
    }
    return $m[0];
}, $s, -1);

if ($changed) {
    file_put_contents($f, $s);
    echo "api-client.php patched\n";
} else {
    echo "NOTE: middleware array w/ AuthenticateServerAccess::class not found — no change\n";
}
?>
PHP
        log "✅ api-client.php patched"
    else
        warn "⚠️ api-client.php not found, skipped"
    fi

    # --- 4) Patch admin.php ---
    log "🔧 Patching admin.php..."
    if [ -f "$ADMIN_ROUTES" ]; then
        bk "$ADMIN_ROUTES"
        php <<'PHP'
<?php
$f = '/var/www/pterodactyl/routes/admin.php';
$s = file_get_contents($f);

/* 4a) Group 'users' & 'servers' */
$prefixes = ["'users'", "'servers'"];
foreach ($prefixes as $pfx) {
    $s = preg_replace_callback(
        '/Route::group\s*\(\s*\[([^\]]*prefix\s*=>\s*'.$pfx.'[^\]]*)\]\s*,\s*function\s*\(\)\s*\{/is',
        function($m){
            $head = $m[1];
            if (stripos($head, 'middleware') === false) {
                return str_replace($m[1], $head . ", 'middleware' => ['custom.security']", $m[0]);
            }
            $head2 = preg_replace_callback('/(middleware\s*=>\s*\[)([\s\S]*?)(\])/i', function($mm){
                if (stripos($mm[2], 'custom.security') !== false) return $mm[0];
                $b = rtrim($mm[2]);
                if ($b !== '' && substr(trim($b), -1) !== ',') $b .= ',';
                $b .= "\n        'custom.security'";
                return $mm[1] . $b . $mm[3];
            }, $head, 1);
            return str_replace($m[1], $head2, $m[0]);
        },
        $s
    );
}

/* 4b) Node routes: tambah ->middleware(['custom.security']) kalau belum ada */
$controllers = [
    'Admin\\\\NodesController::class',
    'Admin\\\\NodeAutoDeployController::class',
];
foreach ($controllers as $ctrl) {
    $s = preg_replace_callback(
        '/(Route::(post|patch|delete)\s*\([^;]*?\[\s*'.$ctrl.'[^\]]*\][^;]*)(;)/i',
        function($m){
            $chain = $m[1];
            if (stripos($chain, '->middleware([') !== false) return $m[0];
            // sisip sebelum ->name(...) jika ada, else sebelum ';'
            $chain2 = preg_replace('/(->name\([^)]*\))/', "->middleware(['custom.security'])$1", $chain, 1, $cnt);
            if ($cnt === 0) $chain2 .= "->middleware(['custom.security'])";
            return $chain2 . $m[3];
        },
        $s
    );
}

file_put_contents($f, $s);
echo "admin.php patched\n";
?>
PHP
        log "✅ admin.php patched"
    else
        warn "⚠️ admin.php not found, skipped"
    fi

    # --- 5) Additional patch for api-client server groups ---
    log "🔧 Applying additional patches..."
    if [ -f "$API_CLIENT" ]; then
        bk "$API_CLIENT"
        php <<'PHP'
<?php
$f = '/var/www/pterodactyl/routes/api-client.php';
$s = file_get_contents($f);
if (stripos($s, "custom.security") !== false) { exit; }

$groupRx = '/Route::group\s*\(\s*\[([\s\S]*?)\]\s*,\s*function\s*\(\)\s*\{\s*[\s\S]*?\}\s*\);/i';

$changed = false;
$s = preg_replace_callback($groupRx, function($m) use (&$changed) {
    $header = $m[1];
    $hLow = strtolower($header);
    $isServersGroup =
        strpos($hLow, "prefix") !== false &&
        (strpos($hLow, "servers/{server}") !== false ||
         strpos($hLow, "/servers/{server}") !== false);

    if (!$isServersGroup) {
        return $m[0];
    }

    if (!preg_match('/middleware\s*=>\s*\[/i', $header)) {
        $newHeader = rtrim($header);
        if ($newHeader !== '' && substr(trim($newHeader), -1) !== ',') {
            $newHeader .= ',';
        }
        $newHeader .= " 'middleware' => ['custom.security']";
        $changed = true;
        return str_replace($header, $newHeader, $m[0]);
    }

    $newHeader = preg_replace_callback('/(middleware\s*=>\s*\[)([\s\S]*?)(\])/i', function($mm) use (&$changed) {
        $body = $mm[2];
        if (stripos($body, 'custom.security') !== false) {
            return $mm[0];
        }
        $b = rtrim($body);
        if ($b !== '' && substr(trim($b), -1) !== ',') $b .= ',';
        $b .= "\n        'custom.security'";
        $changed = true;
        return $mm[1] . $b . $mm[3];
    }, $header, 1);

    return str_replace($header, $newHeader, $m[0]);
}, $s, -1);

if ($changed) {
    file_put_contents($f, $s);
    echo "api-client.php additional patch applied\n";
}
?>
PHP
    fi

    # --- 6) Install Web UI Toggle (controllers, view, routes, config, sidebar, log viewer) ---
    log "🌐 Installing Web UI Security Toggle (Owner ID = 1) + Activity Log UI..."

    CTRL_DIR="$APP_DIR/app/Http/Controllers/Admin"
    VIEW_DIR="$APP_DIR/resources/views/admin"
    ROUTE_FILE="$APP_DIR/routes/admin.php"
    CONFIG_FILE="$APP_DIR/storage/security-toggle.json"

    # create activity log file (ensure folder exists)
    mkdir -p "$(dirname "$ACTIVITY_LOG")"
    touch "$ACTIVITY_LOG"
    chmod 644 "$ACTIVITY_LOG"
    bk "$ACTIVITY_LOG"

    # 6.1 create config (only if missing)
    if [ ! -f "$CONFIG_FILE" ]; then
        log "📝 Creating toggle config..."
        mkdir -p "$(dirname "$CONFIG_FILE")"
        cat > "$CONFIG_FILE" <<EOF
{
    "enabled": true
}
EOF
        chmod 644 "$CONFIG_FILE"
    else
        log "🔎 Toggle config already exists, skipping creation."
        bk "$CONFIG_FILE"
    fi

    # 6.2 controller (with log reading)
    log "📦 Creating SecurityToggleController..."
    mkdir -p "$CTRL_DIR"
    bk "$CTRL_DIR/SecurityToggleController.php"
    cat > "$CTRL_DIR/SecurityToggleController.php" <<'PHP'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;

class SecurityToggleController
{
    protected string $configPath;
    protected string $logPath;

    public function __construct()
    {
        $this->configPath = storage_path('security-toggle.json');
        $this->logPath = storage_path('logs/activity.log');
    }

    public function index(Request $request)
    {
        if (!$request->user() || $request->user()->id !== 1) {
            abort(404);
        }

        if (!File::exists($this->configPath)) {
            File::put($this->configPath, json_encode(['enabled' => true]));
        }

        $config = json_decode(File::get($this->configPath), true);

        // Read log (last 500 lines approximated)
        $logs = [];
        if (File::exists($this->logPath)) {
            $contents = File::get($this->logPath);
            $lines = array_filter(explode(PHP_EOL, $contents));
            $lines = array_reverse($lines);
            $logs = array_slice($lines, 0, 500);
        }

        return view('admin.security-toggle', [
            'enabled' => $config['enabled'] ?? true,
            'logs' => $logs,
        ]);
    }

    public function toggle(Request $request)
    {
        if (!$request->user() || $request->user()->id !== 1) {
            abort(404);
        }

        $newState = $request->input('enabled') === '1';

        File::put($this->configPath, json_encode(['enabled' => $newState]));

        return back()->with('success', 'Security protection updated.');
    }
}
PHP

    # 6.3 blade view (toggle + logviewer)
    log "🖼️ Creating Blade UI (toggle + log viewer)..."
    mkdir -p "$VIEW_DIR"
    bk "$VIEW_DIR/security-toggle.blade.php"
    cat > "$VIEW_DIR/security-toggle.blade.php" <<'PHP'
@extends('layouts.admin')

@section('title')
    Security Control
@endsection

@section('content-header')
    <h1>Custom Security Toggle & Activity Log</h1>
@endsection

@section('content')
<div class="row">
    <div class="col-md-6">
        <div class="box @if($enabled) box-success @else box-danger @endif">
            <div class="box-header with-border">
                <h3 class="box-title">Status Proteksi</h3>
            </div>
            <div class="box-body">
                <p>Proteksi saat ini: <strong>@if($enabled) AKTIF @else NON-AKTIF @endif</strong></p>

                <form method="POST" action="{{ route('admin.security.toggle') }}">
                    {!! csrf_field() !!}
                    <input type="hidden" name="enabled" value="{{ $enabled ? 0 : 1 }}">
                    <button class="btn btn-primary">
                        @if($enabled) Matikan Proteksi @else Aktifkan Proteksi @endif
                    </button>
                </form>
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title">Activity Log (Terbaru)</h3>
            </div>
            <div class="box-body">
                <p>Menampilkan sampai 500 entri terbaru.</p>
                <div style="max-height:420px; overflow:auto; background:#111; color:#eee; padding:10px; font-family:monospace; font-size:13px;">
                    @if(!empty($logs))
                        @foreach($logs as $line)
                            <div>{{ $line }}</div>
                        @endforeach
                    @else
                        <div>Tidak ada aktivitas tercatat.</div>
                    @endif
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
PHP

    # 6.4 append routes (if not already present)
    log "🛠️ Patching admin routes for UI..."
    if ! grep -q "Security Control UI (Owner ID=1 Only)" "$ROUTE_FILE"; then
        bk "$ROUTE_FILE"
        cat >> "$ROUTE_FILE" <<'PHP'


/* === Security Control UI (Owner ID=1 Only) === */
Route::group([
    'prefix' => 'security-control',
    'middleware' => [],
], function () {
    Route::get('/', '\Pterodactyl\Http\Controllers\Admin\SecurityToggleController@index')
        ->name('admin.security.index');

    Route::post('/toggle', '\Pterodactyl\Http\Controllers\Admin\SecurityToggleController@toggle')
        ->name('admin.security.toggle');
});
PHP
        log "✅ Routes patched."
    else
        log "🔎 Routes already patched."
    fi

    # 6.5 safe sidebar injection: insert after opening <ul class="sidebar-menu"> if exists
    if [ -f "$LAYOUT_FILE" ]; then
        log "📌 Adding sidebar menu entry (Owner only) safely..."
        bk "$LAYOUT_FILE"
        SIDEBAR_LINE='<li>@if(Auth::user() && Auth::user()->id === 1)<a href="{{ route('\''admin.security.index'\'') }}"><i class="fa fa-shield"></i> <span>Security Control</span></a></li>@endif'
        perl -0777 -pe "s/(<ul\s+class=\"sidebar-menu\"[^>]*>)/\$1\n        $SIDEBAR_LINE/s" -i "$LAYOUT_FILE" || true

        # 6.6 Blade hook for page-view logging (only GET, admin pages)
        # Insert snippet near top of <body> or after header to log page views for admins
        # We'll try to insert once after first occurrence of @section('content-header') if present,
        # otherwise after <body> tag.
        HOOK_SNIPPET='<?php if(auth()->check() && auth()->user()->id && request()->is(\"admin/*\") && request()->method() === \"GET\"): 
    try {
        $u = auth()->user();
        $role = $u->root_admin ? \"Admin\" : \"User\";
        $months = [1=>\"Januari\",2=>\"Februari\",3=>\"Maret\",4=>\"April\",5=>\"Mei\",6=>\"Juni\",7=>\"Juli\",8=>\"Agustus\",9=>\"September\",10=>\"Oktober\",11=>\"November\",12=>\"Desember\"];
        $d = new \\DateTime();
        $day = $d->format(\"j\");
        $month = $months[(int)$d->format(\"n\")] ?? $d->format(\"n\");
        $year = $d->format(\"Y\");
        $time = $d->format(\"H:i:s\");
        $username = $u->username ?? $u->name ?? $u->email ?? \"id:\".$u->id;
        $action = \"membuka bagian \" . (str_replace(\"admin/\",\"\", request()->path()));
        $line = sprintf(\"[%d/%s/%s] (%s) Pengguna %s sebagai role %s %s\", $day, $month, $year, $time, $username, $role, $action);
        @file_put_contents(storage_path(\"logs/activity.log\"), $line.PHP_EOL, FILE_APPEND | LOCK_EX);
    } catch (\\Throwable $e) { /* ignore */ }
endif; ?>'

        # Try to insert after @section('content-header')
        perl -0777 -pe "if(s/(@section\\('\\'content-header\\'\\'\\)\\s*\\{\\s*\\n)/\\1\n$HOOK_SNIPPET/){print STDOUT;} else { }" -i "$LAYOUT_FILE" || true

        # Fallback: insert after opening <body>
        perl -0777 -pe "s/(<body[^>]*>)/\$1\n$HOOK_SNIPPET/s" -i "$LAYOUT_FILE" || true
    else
        warn "⚠️ Layout file not found: $LAYOUT_FILE. Sidebar link & blade hook skipped."
    fi

    # --- 7) Clear cache and optimize (after creating controllers/views/routes) ---
    log "🧹 Clearing cache and optimizing..."
    cd "$APP_DIR"
    sudo -u www-data php artisan config:clear || true
    sudo -u www-data php artisan route:clear || true
    sudo -u www-data php artisan view:clear || true
    sudo -u www-data php artisan cache:clear || true
    sudo -u www-data php artisan optimize || true

    log "✅ Cache cleared successfully"

    # --- 8) Restart services ---
    log "🔄 Restarting services..."
    PHP_SERVICE=""
    if systemctl is-active --quiet php8.3-fpm 2>/dev/null; then
        PHP_SERVICE="php8.3-fpm"
    elif systemctl is-active --quiet php8.2-fpm 2>/dev/null; then
        PHP_SERVICE="php8.2-fpm"
    elif systemctl is-active --quiet php8.1-fpm 2>/dev/null; then
        PHP_SERVICE="php8.1-fpm"
    elif systemctl is-active --quiet php8.0-fpm 2>/dev/null; then
        PHP_SERVICE="php8.0-fpm"
    fi

    if [ -n "$PHP_SERVICE" ]; then
        systemctl restart "$PHP_SERVICE" && log "✅ $PHP_SERVICE restarted" || warn "⚠️ Failed to restart $PHP_SERVICE"
    else
        warn "⚠️ PHP-FPM service not detected, skipping restart"
    fi

    if systemctl is-active --quiet pteroq-service 2>/dev/null; then
        systemctl restart pteroq-service && log "✅ pterodactyl-service restarted" || warn "⚠️ Failed to restart pterodactyl service"
    fi

    if systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl reload nginx && log "✅ nginx reloaded" || warn "⚠️ Failed to reload nginx"
    fi

    # Final verification / notes
    log "🔍 Verifying installation..."
    echo
    log "📋 PROTECTION SUMMARY:"
    log "   ✅ Admin hanya bisa akses: Application API"
    log "   ❌ Admin DIBLOKIR dari:"
    log "      - Users, Servers, Nodes, Settings"
    log "      - Delete/Update operations"
    log "   🔒 API DELETE Operations DIBLOKIR:"
    log "      - DELETE /api/application/users/{id}"
    log "      - DELETE /api/application/servers/{id}"
    log "      - DELETE /api/application/servers/{id}/force"
    log "   🔒 Server ownership protection aktif"
    log "   🛡️ User access restriction aktif"
    echo
    log "🎉 Custom Security Middleware v3 installed successfully!"
    log "💬 Source Code Credit by - @thezzyxopois"
    echo
    log "📦 Backups saved in: $BACKUP_DIR"
    echo
    warn "⚠️ IMPORTANT: Test dengan login sebagai admin (ID=1) dan buka /admin/security-control untuk toggle & lihat activity log"
}

# -----------------------
# Main program
# -----------------------
main() {
    while true; do
        show_menu
        read -p "$(info 'Pilih opsi (1-3): ')" choice || choice=3

        case $choice in
            1) install_full_security_v3 ;;
            2) replace_credit_name ;;
            3) log "Terima kasih! Keluar dari program." ; exit 0 ;;
            *) error "Pilihan tidak valid! Silakan pilih 1, 2, atau 3." ;;
        esac

        echo
        read -p "$(info 'Tekan Enter untuk kembali ke menu...')" dummy || true
    done
}

main