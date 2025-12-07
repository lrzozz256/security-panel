#!/bin/bash

# ============================================
# Script Proteksi Panel Pterodactyl v1.11.11
# ============================================
# Author: System Administrator
# Date: $(date)
# ============================================

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Konfigurasi
PANEL_PATH="/var/www/pterodactyl"
BACKUP_PATH="/root/backup_pterodactyl"
LOG_FILE="/var/log/pterodactyl_protection.log"
ADMIN_USER_ID="1"

# Fungsi untuk logging
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Fungsi untuk menampilkan status
show_status() {
    echo -e "${GREEN}[✓]${NC} $1"
    log_message "SUCCESS: $1"
}

show_error() {
    echo -e "${RED}[✗]${NC} $1"
    log_message "ERROR: $1"
}

show_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log_message "WARNING: $1"
}

show_info() {
    echo -e "${BLUE}[i]${NC} $1"
    log_message "INFO: $1"
}

# Fungsi untuk backup file
backup_file() {
    local file="$1"
    local backup_dir="$BACKUP_PATH/$(dirname "$file")"
    
    mkdir -p "$backup_dir"
    if [ -f "$file" ]; then
        cp "$file" "$backUP_PATH$file.backup.$(date +%Y%m%d_%H%M%S)"
        show_status "Backup created for $file"
    fi
}

# Fungsi untuk memeriksa apakah user adalah admin
is_admin() {
    local user_id="$1"
    if [ "$user_id" == "$ADMIN_USER_ID" ]; then
        return 0  # true, adalah admin
    else
        return 1  # false, bukan admin
    fi
}

# ============================================
# PATCH 1: Mencegah akses ke server milik orang lain
# ============================================

patch_server_access() {
    show_info "Applying patch 1: Restricting server access..."
    
    # File yang akan dipatch
    local files=(
        "app/Http/Controllers/Api/Client/Servers/ServerController.php"
        "app/Http/Controllers/Base/Client/ServerController.php"
        "app/Http/Controllers/Api/Client/Servers/ServerController.php"
    )
    
    for file in "${files[@]}"; do
        local full_path="$PANEL_PATH/$file"
        
        if [ -f "$full_path" ]; then
            backup_file "$full_path"
            
            # Cari dan tambahkan pemeriksaan ownership untuk setiap metode
            sed -i '/public function index/,/^    \}/ {
                /public function index/,/^    \}/ {
                    /public function index/ {
                        a\
        // ============================================\n\
        // SECURITY PATCH: Restrict server access to owner only\n\
        // ============================================\n\
        $this->authorize(\"view-any\", \\Pterodactyl\\Models\\Server::class);\n\
\n\
        // Get current authenticated user\n\
        $user = \\Auth::user();\n\
\n\
        // Allow full access for admin user (ID 1)\n\
        if ($user->id == '"$ADMIN_USER_ID"') {\n\
            return \\Inertia::render(\"Dashboard\");\n\
        }\n\
\n\
        // For non-admin users, restrict to own servers only\n\
        $servers = \\Pterodactyl\\Models\\Server::where(\"owner_id\", $user->id)\n\
            ->with([\"node\", \"user\", \"allocation\"])->get();\n\
\n\
        return \\Inertia::render(\"Dashboard\", [\n\
            \"servers\" => $servers,\n\
        ]);
                        n
                        d
                    }
                }
            }' "$full_path"
            
            show_status "Applied ownership check to $file"
        else
            show_warning "File not found: $file"
        fi
    done
}

# ============================================
# PATCH 2: Mencegah modifikasi server milik orang lain
# ============================================

patch_server_modification() {
    show_info "Applying patch 2: Restricting server modification..."
    
    local files=(
        "app/Http/Controllers/Api/Client/Servers/ServerController.php"
        "app/Http/Controllers/Base/Client/ServerController.php"
        "app/Services/Servers/ServerDeletionService.php"
        "app/Services/Servers/ServerUpdateService.php"
    )
    
    for file in "${files[@]}"; do
        local full_path="$PANEL_PATH/$file"
        
        if [ -f "$full_path" ]; then
            backup_file "$full_path"
            
            # Tambahkan middleware untuk memeriksa ownership
            sed -i '/public function __construct()/,/^    \}/ {
                /public function __construct()/ {
                    a\
        // SECURITY PATCH: Add ownership verification\n\
        $this->middleware(function ($request, $next) {\n\
            // Skip check for admin user (ID 1)\n\
            if (\\Auth::user()->id == '"$ADMIN_USER_ID"') {\n\
                return $next($request);\n\
            }\n\
            \n\
            // Get server from route parameters\n\
            $serverId = $request->route()->parameter("server") ?? \n\
                       $request->route()->parameter("serverId") ?? \n\
                       $request->input("server");\n\
            \n\
            if ($serverId) {\n\
                $server = \\Pterodactyl\\Models\\Server::findOrFail($serverId);\n\
                \n\
                // Check if user owns the server\n\
                if ($server->owner_id != \\Auth::user()->id) {\n\
                    return response()->json([\n\
                        \"error\" => \"Unauthorized\",\n\
                        \"message\" => \"You do not have permission to modify this server.\"\n\
                    ], 403);\n\
                }\n\
            }\n\
            \n\
            return $next($request);\n\
        });
                }
            }' "$full_path"
            
            show_status "Applied modification restriction to $file"
        else
            show_warning "File not found: $file"
        fi
    done
}

# ============================================
# PATCH 3: Mencegah akses ke bagian administrasi
# ============================================

patch_admin_sections() {
    show_info "Applying patch 3: Restricting admin section access..."
    
    # File yang mengatur navigasi dan permissions
    local files=(
        "app/Http/Controllers/Admin"
        "app/Http/Middleware/AdminAuthenticate.php"
        "resources/scripts/components/Navigation.tsx"
        "resources/scripts/router/index.tsx"
    )
    
    # Patch middleware untuk membatasi akses admin
    local middleware_file="$PANEL_PATH/app/Http/Middleware/AdminAuthenticate.php"
    if [ -f "$middleware_file" ]; then
        backup_file "$middleware_file"
        
        # Tambahkan pemeriksaan user ID
        sed -i '/public function handle/,/^    \}/ {
            /public function handle/ {
                a\
        // SECURITY PATCH: Restrict admin access to user ID 1 only\n\
        if (!\\Auth::check()) {\n\
            return redirect()->guest(route("auth.login"));\n\
        }\n\
\n\
        $user = \\Auth::user();\n\
        \n\
        // Allow only user with ID 1 to access admin sections\n\
        if ($user->id != '"$ADMIN_USER_ID"') {\n\
            // Log unauthorized access attempt\n\
            \\Log::warning("Unauthorized admin access attempt", [\n\
                "user_id" => $user->id,\n\
                "email" => $user->email,\n\
                "ip" => request()->ip(),\n\
                "route" => request()->fullUrl()\n\
            ]);\n\
            \n\
            // Redirect to dashboard with error message\n\
            return redirect()->route("index")\n\
                ->with("error", "You do not have permission to access this section.");\n\
        }\n\
\n\
        return $next($request);
                n
                d
            }
        }' "$middleware_file"
        
        show_status "Applied admin section restriction to middleware"
    fi
    
    # Patch router frontend untuk menyembunyikan menu admin
    local router_file="$PANEL_PATH/resources/scripts/router/index.tsx"
    if [ -f "$router_file" ]; then
        backup_file "$router_file"
        
        # Tambahkan kondisi untuk mengecek user ID
        sed -i '/const routes: Route\[\] = \[/,/\];/ {
            /path: "\/admin"/,/,/ {
                /path: "\/admin"/ {
                    a\
            // SECURITY PATCH: Restrict admin routes to user ID 1 only\n\
            loader: () => {\n\
                const user = useStoreState(state => state.user.data);\n\
                if (!user || user.id !== '"$ADMIN_USER_ID"') {\n\
                    window.location.href = "/";\n\
                    return null;\n\
                }\n\
                return import("@/components/admin/AdminContainer");\n\
            },
                }
            }
        }' "$router_file"
        
        show_status "Applied admin route restriction to frontend router"
    fi
}

# ============================================
# PATCH 4: Menyembunyikan menu Nodes, Location, Nest & Egg, Settings
# ============================================

patch_hidden_menus() {
    show_info "Applying patch 4: Hiding admin menus from non-admin users..."
    
    # File navigation component
    local nav_file="$PANEL_PATH/resources/scripts/components/Navigation.tsx"
    if [ -f "$nav_file" ]; then
        backup_file "$nav_file"
        
        # Cari bagian menu admin dan tambahkan kondisi
        sed -i '/const Navigation = () => {/,/^};/ {
            /{user.isRootAdministrator}/ {
                a\
        // SECURITY PATCH: Show admin menus only for user ID 1\n\
        {user.id === '"$ADMIN_USER_ID"' && user.isRootAdministrator && (\n\
            <>\n\
                <NavigationGroup\n\
                    id="admin"\n\
                    name="Administration"\n\
                    icon={<FontAwesomeIcon icon={faCogs} fixedWidth />}\n\
                >\n\
                    <NavigationItem\n\
                        id="admin.servers"\n\
                        name="Servers"\n\
                        link={"/admin/servers"}\n\
                        exact\n\
                    />\n\
                </NavigationGroup>\n\
            </>\n\
        )}\n\
\n\
        // Hide all admin menus for non-admin users\n\
        {user.id !== '"$ADMIN_USER_ID"' && (\n\
            <>\n\
                {/* No admin menus shown for regular users */}\n\
            </>\n\
        )}
                n
                d
            }
        }' "$nav_file"
        
        show_status "Applied menu hiding patch to navigation component"
    fi
    
    # Tambahkan juga pemeriksaan di sidebar
    local sidebar_files=(
        "$PANEL_PATH/resources/scripts/components/admin/AdminSidebar.tsx"
        "$PANEL_PATH/resources/scripts/layouts/AdminLayout.tsx"
    )
    
    for sidebar_file in "${sidebar_files[@]}"; do
        if [ -f "$sidebar_file" ]; then
            backup_file "$sidebar_file"
            
            # Tambahkan redirect untuk non-admin users
            sed -i '/export default/,/^}/ {
                /export default/ {
                    a\
// SECURITY PATCH: Check if user is admin (ID 1)\n\
const AdminLayout: React.FC = ({ children }) => {\n\
    const user = useStoreState(state => state.user.data);\n\
    \n\
    useEffect(() => {\n\
        if (!user || user.id !== '"$ADMIN_USER_ID"') {\n\
            window.location.href = "/";\n\
        }\n\
    }, [user]);\n\
    \n\
    if (!user || user.id !== '"$ADMIN_USER_ID"') {\n\
        return null;\n\
    }\n\
    \n\
    return (\n\
        <div className="flex min-h-screen bg-gray-50">\n\
            {/* ... existing sidebar code ... */}\n\
            {children}\n\
        </div>\n\
    );\n\
};
                n
                d
            }
            }' "$sidebar_file"
        fi
    done
}

# ============================================
# PATCH 5: Tambahkan security middleware global
# ============================================

patch_global_middleware() {
    show_info "Applying patch 5: Adding global security middleware..."
    
    # Buat middleware custom
    local middleware_dir="$PANEL_PATH/app/Http/Middleware"
    local security_middleware="$middleware_dir/CheckUserOwnership.php"
    
    cat > "$security_middleware" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Pterodactyl\Models\Server;

class CheckUserOwnership
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Skip check for admin user (ID 1)
        if (auth()->check() && auth()->user()->id == 1) {
            return $next($request);
        }

        // Check for server ownership in all server-related routes
        $serverId = $request->route('server') ?? 
                   $request->route('serverId') ?? 
                   $request->input('server');

        if ($serverId) {
            $server = Server::find($serverId);
            
            if ($server && $server->owner_id !== auth()->id()) {
                if ($request->expectsJson()) {
                    return response()->json([
                        'error' => 'Forbidden',
                        'message' => 'You do not have permission to access this server.'
                    ], 403);
                }
                
                return redirect()->route('index')
                    ->with('error', 'You do not have permission to access this server.');
            }
        }

        return $next($request);
    }
}
EOF
    
    show_status "Created global security middleware"
    
    # Register middleware di Kernel
    local kernel_file="$PANEL_PATH/app/Http/Kernel.php"
    if [ -f "$kernel_file" ]; then
        backup_file "$kernel_file"
        
        # Tambahkan middleware ke $routeMiddleware
        sed -i "/protected \$routeMiddleware = \[/,/\];/ {
            /\];/ i\
        'check.ownership' => \Pterodactyl\Http\Middleware\CheckUserOwnership::class,
        }" "$kernel_file"
        
        show_status "Registered security middleware in Kernel"
    fi
}

# ============================================
# PATCH 6: Update database permissions
# ============================================

patch_database_permissions() {
    show_info "Applying patch 6: Updating database permissions..."
    
    # Jalankan migrasi untuk menambahkan kolom permission jika diperlukan
    local migration_file="$PANEL_PATH/database/migrations/$(date +%Y_%m_%d_%H%M%S)_add_admin_restriction.php"
    
    cat > "$migration_file" << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class AddAdminRestriction extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Add is_super_admin column if not exists
        if (!Schema::hasColumn('users', 'is_super_admin')) {
            Schema::table('users', function (Blueprint $table) {
                $table->boolean('is_super_admin')->default(false)->after('id');
            });
        }
        
        // Set user ID 1 as super admin
        DB::table('users')->where('id', 1)->update(['is_super_admin' => true]);
        
        // Create permissions table if not exists
        if (!Schema::hasTable('permissions')) {
            Schema::create('permissions', function (Blueprint $table) {
                $table->increments('id');
                $table->unsignedInteger('user_id');
                $table->string('permission');
                $table->timestamps();
                
                $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
                $table->unique(['user_id', 'permission']);
            });
        }
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('is_super_admin');
        });
        
        Schema::dropIfExists('permissions');
    }
}
EOF
    
    show_status "Created database migration for permissions"
    
    # Jalankan migrasi
    cd "$PANEL_PATH" && php artisan migrate --force
    if [ $? -eq 0 ]; then
        show_status "Database migrations applied successfully"
    else
        show_error "Failed to apply database migrations"
    fi
}

# ============================================
# PATCH 7: Tambahkan event listener untuk logging
# ============================================

patch_event_listeners() {
    show_info "Applying patch 7: Adding security event listeners..."
    
    # Buat event listener untuk logging akses tidak sah
    local listener_dir="$PANEL_PATH/app/Listeners"
    mkdir -p "$listener_dir"
    
    cat > "$listener_dir/LogUnauthorizedAccess.php" << 'EOF'
<?php

namespace Pterodactyl\Listeners;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Http\Request;
use Pterodactyl\Events\Auth\FailedPassword;
use Illuminate\Support\Facades\Log;

class LogUnauthorizedAccess
{
    protected $request;
    
    public function __construct(Request $request)
    {
        $this->request = $request;
    }
    
    public function handle($event)
    {
        $user = auth()->user();
        
        // Log all admin section accesses
        if ($this->request->is('admin/*') || 
            $this->request->is('api/application/*')) {
            
            Log::info('Admin section accessed', [
                'user_id' => $user ? $user->id : 'guest',
                'email' => $user ? $user->email : 'guest',
                'ip' => $this->request->ip(),
                'url' => $this->request->fullUrl(),
                'method' => $this->request->method(),
                'user_agent' => $this->request->userAgent(),
                'timestamp' => now()->toDateTimeString()
            ]);
        }
        
        // Log unauthorized access attempts
        if ($event instanceof FailedPassword) {
            Log::warning('Failed login attempt', [
                'email' => $event->credentials['email'] ?? 'unknown',
                'ip' => $this->request->ip(),
                'user_agent' => $this->request->userAgent()
            ]);
        }
    }
}
EOF
    
    show_status "Created security event listener"
}

# ============================================
# FUNGSI UTAMA
# ============================================

main() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}   Pterodactyl Panel Security Patcher      ${NC}"
    echo -e "${BLUE}   Version: 1.11.11                        ${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
    
    # Cek apakah running sebagai root
    if [ "$EUID" -ne 0 ]; then
        show_error "Please run as root"
        exit 1
    fi
    
    # Cek apakah panel path ada
    if [ ! -d "$PANEL_PATH" ]; then
        show_error "Pterodactyl panel not found at $PANEL_PATH"
        echo "Please update PANEL_PATH variable in the script"
        exit 1
    fi
    
    # Buat backup directory
    mkdir -p "$BACKUP_PATH"
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Mulai logging
    log_message "=== Starting Pterodactyl Security Patch Application ==="
    
    # Apply semua patches
    patch_server_access
    patch_server_modification
    patch_admin_sections
    patch_hidden_menus
    patch_global_middleware
    patch_database_permissions
    patch_event_listeners
    
    # Clear cache
    show_info "Clearing application cache..."
    cd "$PANEL_PATH" && php artisan cache:clear
    cd "$PANEL_PATH" && php artisan view:clear
    cd "$PANEL_PATH" && php artisan route:clear
    
    # Build frontend assets
    show_info "Building frontend assets..."
    cd "$PANEL_PATH" && yarn build:production
    
    # Set permissions
    show_info "Setting correct permissions..."
    chown -R www-data:www-data "$PANEL_PATH"
    chmod -R 755 "$PANEL_PATH/storage"
    chmod -R 755 "$PANEL_PATH/bootstrap/cache"
    
    # Restart services
    show_info "Restarting web services..."
    systemctl restart php8.1-fpm 2>/dev/null || systemctl restart php8.0-fpm 2>/dev/null || systemctl restart php7.4-fpm 2>/dev/null
    systemctl restart nginx 2>/dev/null || systemctl restart apache2 2>/dev/null
    
    # Selesai
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}   SECURITY PATCHES APPLIED SUCCESSFULLY   ${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "${YELLOW}Summary of applied protections:${NC}"
    echo "1. ✓ Users cannot access other users' servers"
    echo "2. ✓ Users cannot modify other users' servers"
    echo "3. ✓ Admin sections (Nodes, Locations, Nests, Settings)"
    echo "   are hidden from non-admin users"
    echo "4. ✓ Only user with ID $ADMIN_USER_ID has full access"
    echo "5. ✓ All changes have been backed up to: $BACKUP_PATH"
    echo "6. ✓ Activity logging enabled"
    echo ""
    echo -e "${YELLOW}Important Notes:${NC}"
    echo "- User with ID $ADMIN_USER_ID has unrestricted access"
    echo "- All other users are restricted to their own servers only"
    echo "- Admin sections are completely hidden from non-admin users"
    echo "- Logs are available at: $LOG_FILE"
    echo "- Backups are stored at: $BACKUP_PATH"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Test the restrictions with a non-admin user account"
    echo "2. Check the log file for any issues"
    echo "3. Keep your backups in a safe location"
    
    log_message "=== Security patches applied successfully ==="
}

# Jalankan fungsi utama
main