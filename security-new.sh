#!/bin/bash

# Pterodactyl Security Protection
# By @thezzyxopois
# Features: Anti Delete, Anti Intip, Anti Akses Server Orang Lain

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PANEL_PATH="/var/www/pterodactyl"
BACKUP_PATH="/root/pterodactyl_backup"
SECURITY_BACKUP="$BACKUP_PATH/security_backup"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Script harus dijalankan sebagai root${NC}"
   exit 1
fi

# Function to display banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "================================================"
    echo "    Pterodactyl Security Protection Installer"
    echo "    By: @thezzyxopois"
    echo "================================================"
    echo -e "${NC}"
}

# Function to backup original files
backup_files() {
    echo -e "${YELLOW}Membuat backup file original...${NC}"
    mkdir -p "$SECURITY_BACKUP"
    
    # Backup important files
    cp "$PANEL_PATH/app/Http/Controllers/Api/Client/Servers/ServerController.php" "$SECURITY_BACKUP/" 2>/dev/null
    cp "$PANEL_PATH/app/Http/Controllers/Admin/NodesController.php" "$SECURITY_BACKUP/" 2>/dev/null
    cp "$PANEL_PATH/app/Http/Controllers/Admin/NestsController.php" "$SECURITY_BACKUP/" 2>/dev/null
    cp "$PANEL_PATH/app/Http/Controllers/Admin/LocationsController.php" "$SECURITY_BACKUP/" 2>/dev/null
    cp "$PANEL_PATH/app/Http/Controllers/Admin/ServersController.php" "$SECURITY_BACKUP/" 2>/dev/null
    cp "$PANEL_PATH/app/Http/Controllers/Admin/UsersController.php" "$SECURITY_BACKUP/" 2>/dev/null
    cp "$PANEL_PATH/app/Http/Middleware/AdminAuthenticate.php" "$SECURITY_BACKUP/" 2>/dev/null
    cp "$PANEL_PATH/app/Http/Middleware/ClientAuthenticate.php" "$SECURITY_BACKUP/" 2>/dev/null
    cp "$PANEL_PATH/app/Exceptions/Handler.php" "$SECURITY_BACKUP/" 2>/dev/null
    
    echo -e "${GREEN}Backup selesai di: $SECURITY_BACKUP${NC}"
}

# Function to restore from backup
restore_backup() {
    echo -e "${YELLOW}Memulihkan file dari backup...${NC}"
    
    if [ ! -d "$SECURITY_BACKUP" ]; then
        echo -e "${RED}Backup tidak ditemukan!${NC}"
        return 1
    fi
    
    # Restore files
    cp "$SECURITY_BACKUP/ServerController.php" "$PANEL_PATH/app/Http/Controllers/Api/Client/Servers/" 2>/dev/null
    cp "$SECURITY_BACKUP/NodesController.php" "$PANEL_PATH/app/Http/Controllers/Admin/" 2>/dev/null
    cp "$SECURITY_BACKUP/NestsController.php" "$PANEL_PATH/app/Http/Controllers/Admin/" 2>/dev/null
    cp "$SECURITY_BACKUP/LocationsController.php" "$PANEL_PATH/app/Http/Controllers/Admin/" 2>/dev/null
    cp "$SECURITY_BACKUP/ServersController.php" "$PANEL_PATH/app/Http/Controllers/Admin/" 2>/dev/null
    cp "$SECURITY_BACKUP/UsersController.php" "$PANEL_PATH/app/Http/Controllers/Admin/" 2>/dev/null
    cp "$SECURITY_BACKUP/AdminAuthenticate.php" "$PANEL_PATH/app/Http/Middleware/" 2>/dev/null
    cp "$SECURITY_BACKUP/ClientAuthenticate.php" "$PANEL_PATH/app/Http/Middleware/" 2>/dev/null
    cp "$SECURITY_BACKUP/Handler.php" "$PANEL_PATH/app/Exceptions/" 2>/dev/null
    
    echo -e "${GREEN}Restore selesai!${NC}"
}

# Function to create security middleware
create_security_middleware() {
    echo -e "${BLUE}Membuat security middleware...${NC}"
    
    # Create SecurityMiddleware
    cat > "$PANEL_PATH/app/Http/Middleware/SecurityMiddleware.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Pterodactyl\Models\Server;
use Pterodactyl\Models\User;

class SecurityMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $user = $request->user();
        $route = $request->route();
        
        // Check if user is authenticated
        if (!$user) {
            return $next($request);
        }

        // Security protection for admin pages
        if ($user->root_admin) {
            // Allow admin to access their own data
            return $next($request);
        }

        // Protection for server access - only allow access to own servers
        if ($route && $serverParam = $route->parameter('server')) {
            $server = $serverParam instanceof Server ? $serverParam : Server::find($serverParam);
            
            if ($server && $server->user_id !== $user->id) {
                if ($request->expectsJson()) {
                    return response()->json([
                        'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
                    ], 403);
                }
                
                abort(403, 'hayo mau ngapain lu ngentot? - by @thezzyxopois');
            }
        }

        // Protection for user access - only allow access to own profile
        if ($route && $userParam = $route->parameter('user')) {
            $userModel = $userParam instanceof User ? $userParam : User::find($userParam);
            
            if ($userModel && $userModel->id !== $user->id) {
                if ($request->expectsJson()) {
                    return response()->json([
                        'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
                    ], 403);
                }
                
                abort(403, 'hayo mau ngapain lu ngentot? - by @thezzyxopois');
            }
        }

        return $next($request);
    }
}
?>
EOF
}

# Function to install security protection
install_security() {
    echo -e "${YELLOW}Memulai instalasi security protection...${NC}"
    
    # Backup original files first
    backup_files
    
    # Create security middleware
    create_security_middleware

    # 1. Anti Delete Server & User Protection (Admin Only)
    echo -e "${BLUE}Menginstall Anti Delete Server & User...${NC}"
    
    # Modify ServersController.php for anti delete with better protection
    cat > "$PANEL_PATH/app/Http/Controllers/Admin/ServersController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Models\Server;
use Prologue\Alerts\AlertsMessageBag;

class ServersController extends Controller
{
    protected $alerts;

    public function __construct(AlertsMessageBag $alerts)
    {
        $this->alerts = $alerts;
    }

    public function index()
    {
        // Allow admin to see servers list
        return view('admin.servers.index', [
            'servers' => Server::with('user', 'node', 'nest')->get()
        ]);
    }

    public function view(Request $request, $id)
    {
        // Allow admin to view server details
        $server = Server::with('user', 'node', 'nest')->findOrFail($id);
        return view('admin.servers.view', ['server' => $server]);
    }

    public function delete(Request $request, $id)
    {
        // Block server deletion with custom error
        $this->alerts->danger('hayo mau ngapain lu ngentot? - by @thezzyxopois')->flash();
        return redirect()->route('admin.servers.view', $id);
    }

    public function destroy(Request $request, $id)
    {
        // Block server destruction with custom error
        $this->alerts->danger('hayo mau ngapain lu ngentot? - by @thezzyxopois')->flash();
        return redirect()->route('admin.servers.view', $id);
    }
}
?>
EOF

    # Modify UsersController.php for anti delete with better protection
    cat > "$PANEL_PATH/app/Http/Controllers/Admin/UsersController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Models\User;
use Prologue\Alerts\AlertsMessageBag;

class UsersController extends Controller
{
    protected $alerts;

    public function __construct(AlertsMessageBag $alerts)
    {
        $this->alerts = $alerts;
    }

    public function index()
    {
        // Allow admin to see users list
        return view('admin.users.index', [
            'users' => User::all()
        ]);
    }

    public function view(Request $request, $id)
    {
        // Allow admin to view user details
        $user = User::findOrFail($id);
        return view('admin.users.view', ['user' => $user]);
    }

    public function delete(Request $request, $id)
    {
        // Block user deletion with custom error
        $this->alerts->danger('hayo mau ngapain lu ngentot? - by @thezzyxopois')->flash();
        return redirect()->route('admin.users.view', $id);
    }

    public function destroy(Request $request, $id)
    {
        // Block user destruction with custom error
        $this->alerts->danger('hayo mau ngapain lu ngentot? - by @thezzyxopois')->flash();
        return redirect()->route('admin.users.view', $id);
    }
}
?>
EOF

    # 2. Anti Intip Location, Nodes, Nest (For Non-Admin Users)
    echo -e "${BLUE}Menginstall Anti Intip Location, Nodes, Nest...${NC}"
    
    # Modify NodesController.php - Allow admin, block others
    cat > "$PANEL_PATH/app/Http/Controllers/Admin/NodesController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Models\Node;
use Prologue\Alerts\AlertsMessageBag;

class NodesController extends Controller
{
    protected $alerts;

    public function __construct(AlertsMessageBag $alerts)
    {
        $this->alerts = $alerts;
    }

    public function index()
    {
        // Allow admin to see nodes list
        return view('admin.nodes.index', [
            'nodes' => Node::all()
        ]);
    }

    public function view(Request $request, $id)
    {
        // Allow admin to view node details
        $node = Node::findOrFail($id);
        return view('admin.nodes.view', ['node' => $node]);
    }
}

// Additional protection for non-admin users trying to access nodes
namespace Pterodactyl\Http\Controllers\Api\Client;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;

class NodesController extends ClientApiController
{
    public function index(Request $request)
    {
        // Block non-admin users from accessing nodes via API
        if (!$request->user() || !$request->user()->root_admin) {
            return response()->json([
                'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
            ], 403);
        }
    }
}
?>
EOF

    # Modify NestsController.php - Allow admin, block others
    cat > "$PANEL_PATH/app/Http/Controllers/Admin/NestsController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Models\Nest;
use Prologue\Alerts\AlertsMessageBag;

class NestsController extends Controller
{
    protected $alerts;

    public function __construct(AlertsMessageBag $alerts)
    {
        $this->alerts = $alerts;
    }

    public function index()
    {
        // Allow admin to see nests list
        return view('admin.nests.index', [
            'nests' => Nest::with('eggs')->get()
        ]);
    }

    public function view(Request $request, $id)
    {
        // Allow admin to view nest details
        $nest = Nest::with('eggs')->findOrFail($id);
        return view('admin.nests.view', ['nest' => $nest]);
    }
}

// Additional protection for non-admin users trying to access nests
namespace Pterodactyl\Http\Controllers\Api\Client;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;

class NestsController extends ClientApiController
{
    public function index(Request $request)
    {
        // Block non-admin users from accessing nests via API
        if (!$request->user() || !$request->user()->root_admin) {
            return response()->json([
                'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
            ], 403);
        }
    }
}
?>
EOF

    # Modify LocationsController.php - Allow admin, block others
    cat > "$PANEL_PATH/app/Http/Controllers/Admin/LocationsController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Models\Location;
use Prologue\Alerts\AlertsMessageBag;

class LocationsController extends Controller
{
    protected $alerts;

    public function __construct(AlertsMessageBag $alerts)
    {
        $this->alerts = $alerts;
    }

    public function index()
    {
        // Allow admin to see locations list
        return view('admin.locations.index', [
            'locations' => Location::with('nodes')->get()
        ]);
    }

    public function view(Request $request, $id)
    {
        // Allow admin to view location details
        $location = Location::with('nodes')->findOrFail($id);
        return view('admin.locations.view', ['location' => $location]);
    }
}

// Additional protection for non-admin users trying to access locations
namespace Pterodactyl\Http\Controllers\Api\Client;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;

class LocationsController extends ClientApiController
{
    public function index(Request $request)
    {
        // Block non-admin users from accessing locations via API
        if (!$request->user() || !$request->user()->root_admin) {
            return response()->json([
                'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
            ], 403);
        }
    }
}
?>
EOF

    # 3. Anti Akses Server Orang Lain dengan Protection Lengkap
    echo -e "${BLUE}Menginstall Anti Akses Server Orang Lain...${NC}"
    
    # Modify ServerController for client API dengan protection lengkap
    cat > "$PANEL_PATH/app/Http/Controllers/Api/Client/Servers/ServerController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Illuminate\Http\Response;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Models\Server;
use Illuminate\Http\JsonResponse;
use Prologue\Alerts\AlertsMessageBag;

class ServerController extends ClientApiController
{
    protected $alerts;

    public function __construct(AlertsMessageBag $alerts)
    {
        $this->alerts = $alerts;
    }

    public function index()
    {
        // User can only see their own servers - this is normal behavior
        return parent::index();
    }

    public function view($server)
    {
        // Enhanced protection: Check if user owns the server
        if ($server->user_id !== auth()->user()->id) {
            // Return 403 with custom error message
            if (request()->expectsJson()) {
                return new JsonResponse([
                    'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
                ], Response::HTTP_FORBIDDEN);
            }
            
            // For web requests, show error page but don't break the website
            abort(403, 'hayo mau ngapain lu ngentot? - by @thezzyxopois');
        }

        // Allow normal access if user owns the server
        return parent::view($server);
    }

    public function settings($server)
    {
        // Enhanced protection for server settings
        if ($server->user_id !== auth()->user()->id) {
            return new JsonResponse([
                'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
            ], Response::HTTP_FORBIDDEN);
        }

        return parent::settings($server);
    }

    public function databases($server)
    {
        // Enhanced protection for server databases
        if ($server->user_id !== auth()->user()->id) {
            return new JsonResponse([
                'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
            ], Response::HTTP_FORBIDDEN);
        }

        return parent::databases($server);
    }
}
?>
EOF

    # 4. Enhanced Middleware Protection dengan Custom Error
    echo -e "${BLUE}Menginstall Enhanced Middleware Protection...${NC}"
    
    # Modify AdminAuthenticate middleware
    cat > "$PANEL_PATH/app/Http/Middleware/AdminAuthenticate.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class AdminAuthenticate
{
    public function handle(Request $request, Closure $next)
    {
        if (!$request->user() || !$request->user()->root_admin) {
            if ($request->expectsJson()) {
                return new JsonResponse([
                    'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
                ], 403);
            }

            // Show error but don't break the entire website
            abort(403, 'hayo mau ngapain lu ngentot? - by @thezzyxopois');
        }

        return $next($request);
    }
}
?>
EOF

    # Modify ClientAuthenticate middleware
    cat > "$PANEL_PATH/app/Http/Middleware/ClientAuthenticate.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class ClientAuthenticate
{
    public function handle(Request $request, Closure $next)
    {
        if (!$request->user()) {
            if ($request->expectsJson()) {
                return new JsonResponse([
                    'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
                ], 401);
            }

            // Show error but don't break the entire website
            abort(401, 'hayo mau ngapain lu ngentot? - by @thezzyxopois');
        }

        return $next($request);
    }
}
?>
EOF

    # 5. Custom Error Handler dengan Pesan Kustom
    echo -e "${BLUE}Menginstall Custom Error Handler...${NC}"
    
    # Modify Exception Handler
    cat > "$PANEL_PATH/app/Exceptions/Handler.php" << 'EOF'
<?php

namespace Pterodactyl\Exceptions;

use Exception;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Prologue\Alerts\AlertsMessageBag;
use Symfony\Component\HttpKernel\Exception\HttpException;

class Handler extends ExceptionHandler
{
    protected $alerts;

    public function __construct(AlertsMessageBag $alerts)
    {
        $this->alerts = $alerts;
    }

    public function render($request, Exception $exception)
    {
        // Custom handling for 403 Forbidden errors
        if ($exception instanceof \Illuminate\Auth\Access\AuthorizationException || 
            $exception instanceof HttpException && $exception->getStatusCode() === 403) {
            
            if ($request->expectsJson()) {
                return new JsonResponse([
                    'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
                ], 403);
            }
            
            // For web requests, show error page but maintain website functionality
            $this->alerts->danger('hayo mau ngapain lu ngentot? - by @thezzyxopois')->flash();
            return redirect()->back()->withErrors(['security' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois']);
        }

        // Custom handling for 404 Not Found errors
        if ($exception instanceof \Symfony\Component\HttpKernel\Exception\NotFoundHttpException) {
            if ($request->expectsJson()) {
                return new JsonResponse([
                    'error' => 'hayo mau ngapain lu ngentot? - by @thezzyxopois'
                ], 404);
            }
            
            $this->alerts->danger('hayo mau ngapain lu ngentot? - by @thezzyxopois')->flash();
            return redirect()->route('index');
        }

        return parent::render($request, $exception);
    }
}
?>
EOF

    # Update route middleware to include security protection
    echo -e "${BLUE}Update route middleware...${NC}"
    
    # Add security middleware to web routes (if needed)
    if [ -f "$PANEL_PATH/app/Providers/RouteServiceProvider.php" ]; then
        sed -i '/protected \$middlewareGroups = \[/,/\];/{
            /web.*=>.*\[/a\
            \\\Pterodactyl\\Http\\Middleware\\SecurityMiddleware::class,
        }' "$PANEL_PATH/app/Providers/RouteServiceProvider.php" 2>/dev/null
    fi

    # Run panel optimizations
    echo -e "${YELLOW}Menjalankan optimasi panel...${NC}"
    cd "$PANEL_PATH" || exit 1
    php artisan config:cache
    php artisan view:cache
    php artisan route:cache

    # Set proper permissions
    chown -R www-data:www-data "$PANEL_PATH"
    chmod -R 755 "$PANEL_PATH"
    chmod -R 755 "$PANEL_PATH/storage"
    chmod -R 755 "$PANEL_PATH/bootstrap/cache"

    echo -e "${GREEN}Security protection berhasil diinstall!${NC}"
    echo -e "${CYAN}Fitur yang aktif:${NC}"
    echo -e "✓ Anti Delete Server & User"
    echo -e "✓ Anti Intip Location, Nodes, Nest" 
    echo -e "✓ Anti Akses Server Orang Lain"
    echo -e "✓ Custom Error Message: 'hayo mau ngapain lu ngentot? - by @thezzyxopois'"
    echo -e "✓ Admin tetap bisa akses semua fitur"
    echo -e "✓ User hanya bisa akses server sendiri"
    echo -e "${YELLOW}Panel tetap berfungsi normal, hanya menampilkan error 403 saat ada percobaan akses illegal.${NC}"
}

# Function to change error texts
change_error_texts() {
    echo -e "${YELLOW}Mengganti teks error...${NC}"
    
    # Update all files with new error message
    find "$PANEL_PATH" -name "*.php" -type f -exec sed -i 's/Ngapain sih? mau nyolong sc org? - By @thezzyxopois/hayo mau ngapain lu ngentot? - by @thezzyxopois/g' {} \; 2>/dev/null
    
    echo -e "${GREEN}Teks error berhasil diganti!${NC}"
    echo -e "${BLUE}Custom message: 'hayo mau ngapain lu ngentot? - by @thezzyxopois'${NC}"
}

# Function to uninstall security
uninstall_security() {
    echo -e "${YELLOW}Memulai uninstall security protection...${NC}"
    
    if [ ! -d "$SECURITY_BACKUP" ]; then
        echo -e "${RED}Backup tidak ditemukan! Tidak bisa melakukan uninstall.${NC}"
        return 1
    fi
    
    # Restore from backup
    restore_backup
    
    # Remove security middleware
    rm -f "$PANEL_PATH/app/Http/Middleware/SecurityMiddleware.php" 2>/dev/null
    
    # Run panel optimizations
    echo -e "${YELLOW}Menjalankan optimasi panel...${NC}"
    cd "$PANEL_PATH" || exit 1
    php artisan config:clear
    php artisan view:clear
    php artisan route:clear
    php artisan cache:clear
    
    php artisan config:cache
    php artisan view:cache
    php artisan route:cache

    echo -e "${GREEN}Security protection berhasil diuninstall!${NC}"
}

# Function to check security status
check_status() {
    echo -e "${YELLOW}Memeriksa status security...${NC}"
    
    if [ -d "$SECURITY_BACKUP" ]; then
        echo -e "${GREEN}✓ Security protection terdeteksi terinstall${NC}"
        echo -e "${BLUE}  Backup files tersedia di: $SECURITY_BACKUP${NC}"
    else
        echo -e "${RED}✗ Security protection tidak terdeteksi${NC}"
    fi
    
    # Check security features
    features=(
        "Anti Delete Server:$PANEL_PATH/app/Http/Controllers/Admin/ServersController.php"
        "Anti Delete User:$PANEL_PATH/app/Http/Controllers/Admin/UsersController.php"
        "Anti Intip Nodes:$PANEL_PATH/app/Http/Controllers/Admin/NodesController.php"
        "Anti Intip Nests:$PANEL_PATH/app/Http/Controllers/Admin/NestsController.php"
        "Anti Intip Locations:$PANEL_PATH/app/Http/Controllers/Admin/LocationsController.php"
        "Server Access Protection:$PANEL_PATH/app/Http/Controllers/Api/Client/Servers/ServerController.php"
        "Security Middleware:$PANEL_PATH/app/Http/Middleware/SecurityMiddleware.php"
    )
    
    for feature in "${features[@]}"; do
        name="${feature%%:*}"
        file="${feature##*:}"
        
        if [ -f "$file" ] && grep -q "hayo mau ngapain lu ngentot?" "$file" 2>/dev/null; then
            echo -e "${GREEN}✓ $name aktif${NC}"
        else
            echo -e "${RED}✗ $name tidak aktif${NC}"
        fi
    done
    
    echo -e "${CYAN}Error message: 'hayo mau ngapain lu ngentot? - by @thezzyxopois'${NC}"
}

# Main menu
main_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}Pilih opsi:${NC}"
        echo -e "1. Install Security Panel"
        echo -e "2. Ganti Teks Error" 
        echo -e "3. Uninstall Security Panel"
        echo -e "4. Check Status Security"
        echo -e "5. Exit Security Panel"
        echo -e ""
        read -p "Masukkan pilihan [1-5]: " choice
        
        case $choice in
            1)
                install_security
                ;;
            2)
                change_error_texts
                ;;
            3)
                uninstall_security
                ;;
            4)
                check_status
                ;;
            5)
                echo -e "${GREEN}Keluar dari Security Panel. Terima kasih!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Pilihan tidak valid!${NC}"
                ;;
        esac
        
        echo -e ""
        read -p "Tekan Enter untuk melanjutkan..."
    done
}

# Check if panel path exists
if [ ! -d "$PANEL_PATH" ]; then
    echo -e "${RED}Directory panel Pterodactyl tidak ditemukan di: $PANEL_PATH${NC}"
    echo -e "${YELLOW}Silakan edit variabel PANEL_PATH di script ini sesuai dengan path instalasi panel Anda.${NC}"
    exit 1
fi

# Start the script
main_menu
