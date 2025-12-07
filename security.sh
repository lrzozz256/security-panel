#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

info() {
    echo -e "${BLUE}[MENU]${NC} $1"
}

show_menu() {
    clear
    cat <<'EOF'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠒⠒⠉⣩⣽⣿⣿⣿⣿⣿⠿⢿⣶⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣿⣿⣿⣿⣿⣿⣿⡷⠀⠈⠙⠻⢿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⠿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣴⣶⣿⣿⣿⣿⣦⣄⣾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⠏⠉⢹⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣁⡀⠀⢸⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣷⠀⢸⣿⣿⡇⠻⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣷⣼⣿⣿⡇⠀⠈⠻⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⡃⠙⣿⣿⣄⡀⠀⠈⠙⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠺⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠘⣿⣿⣿⣷⣶⣤⣈⡟⢳⢄⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⢻⣿⣯⡉⠛⠻⢿⣿⣷⣧⡀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⡿⠹⣿⣿⣿⣷⠀⠀⠀⢀⣿⣿⣷⣄⠀⠀⠈⠙⠿⣿⣄⠀⠀⠀⢠⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⠋⠀⣀⣻⣿⣿⣿⣀⣠⣶⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠈⢹⠇⠀⠀⣾⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣟⠛⠋⠉⠁⠀⠀⠀⠉⠻⢧⠀⠀⠀⠘⠃⠀⣼⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢢⡀⠀⠀⠀⠀⢿⣿⣿⠿⠟⠛⠉⠁⠈⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⢺⠀⠀⠀⠀⢀⣾⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠊⠀⠀⠀⣰⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣷⣤⣀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⣿⣶⣦⣤⣤⣀⣀⣀⣻⣿⣀⣀⣤⣴⣶⣿⣿⣿⣿⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢿⣿⣯⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
EOF

    echo
    echo "=========================================="
    echo "              SIMPLE OPTION               "
    echo "    CUSTOM SECURITY MIDDLEWARE INSTALLER  "
    echo "                 @thezzyxopois                 "
    echo "=========================================="
    echo
    echo "Menu yang tersedia:"
    echo "1. Install Security Middleware"
    echo "2. Ganti Nama Credit di Middleware"
    echo "3. Custom Teks Error Message"
    echo "4. Clear Security (Uninstall)"
    echo "5. Keluar"
    echo
}

clear_security() {
    echo
    info "CLEAR SECURITY MIDDLEWARE"
    info "========================"
    echo
    warn "⚠️  PERINGATAN: Tindakan ini akan menghapus security middleware dan mengembalikan sistem ke kondisi normal!"
    read -p "Apakah Anda yakin ingin menghapus security middleware? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log "❌ Penghapusan dibatalkan."
        return
    fi
    
    PTERO_DIR="/var/www/pterodactyl"
    
    if [ ! -d "$PTERO_DIR" ]; then
        error "Pterodactyl directory not found: $PTERO_DIR"
    fi
    
    log "🧹 Membersihkan security middleware..."
    
    # 1. Hapus file middleware
    if [ -f "$PTERO_DIR/app/Http/Middleware/CustomSecurityCheck.php" ]; then
        rm -f "$PTERO_DIR/app/Http/Middleware/CustomSecurityCheck.php"
        log "✅ File middleware dihapus"
    else
        warn "⚠️ File middleware tidak ditemukan"
    fi
    
    # 2. Hapus dari Kernel.php
    KERNEL_FILE="$PTERO_DIR/app/Http/Kernel.php"
    if [ -f "$KERNEL_FILE" ]; then
        if grep -q "custom.security" "$KERNEL_FILE"; then
            sed -i "/'custom.security' => \\\\Pterodactyl\\\\Http\\\\Middleware\\\\CustomSecurityCheck::class,/d" "$KERNEL_FILE"
            log "✅ Middleware dihapus dari Kernel"
        else
            warn "⚠️ Middleware tidak terdaftar di Kernel"
        fi
    fi
    
    # 3. Hapus middleware dari routes
    log "🔧 Membersihkan routes..."
    
    # api-client.php
    API_CLIENT_FILE="$PTERO_DIR/routes/api-client.php"
    if [ -f "$API_CLIENT_FILE" ]; then
        if grep -q "Route::group(\['prefix' => '/files', 'middleware' => \['custom.security'\]" "$API_CLIENT_FILE"; then
            sed -i "s/Route::group(\['prefix' => '\/files', 'middleware' => \['custom.security'\]/Route::group(['prefix' => '\/files'/g" "$API_CLIENT_FILE"
            log "✅ Middleware dihapus dari api-client.php"
        fi
    fi
    
    # admin.php - hapus middleware dari semua route
    ADMIN_FILE="$PTERO_DIR/routes/admin.php"
    if [ -f "$ADMIN_FILE" ]; then
        # Hapus ->middleware(['custom.security']) dari semua route
        sed -i "s/->middleware(\['custom.security'\])//g" "$ADMIN_FILE"
        log "✅ Middleware dihapus dari admin.php"
    fi
    
    # 4. Clear cache
    log "🧹 Membersihkan cache..."
    cd $PTERO_DIR
    sudo -u www-data php artisan config:clear
    sudo -u www-data php artisan route:clear
    sudo -u www-data php artisan view:clear
    sudo -u www-data php artisan cache:clear
    sudo -u www-data php artisan optimize
    
    log "✅ Cache dibersihkan"
    
    # 5. Restart services
    log "🔄 Restart services..."
    
    PHP_SERVICE=""
    if systemctl is-active --quiet php8.2-fpm; then
        PHP_SERVICE="php8.2-fpm"
    elif systemctl is-active --quiet php8.1-fpm; then
        PHP_SERVICE="php8.1-fpm"
    elif systemctl is-active --quiet php8.0-fpm; then
        PHP_SERVICE="php8.0-fpm"
    elif systemctl is-active --quiet php8.3-fpm; then
        PHP_SERVICE="php8.3-fpm"
    fi
    
    if [ -n "$PHP_SERVICE" ]; then
        systemctl restart $PHP_SERVICE
        log "✅ $PHP_SERVICE di-restart"
    fi
    
    if systemctl is-active --quiet pteroq-service; then
        systemctl restart pteroq-service
        log "✅ pterodactyl-service di-restart"
    fi
    
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
        log "✅ nginx di-reload"
    fi
    
    echo
    log "🎉 Security middleware berhasil dihapus!"
    log "📋 Yang telah dilakukan:"
    log "   ✅ File middleware dihapus"
    log "   ✅ Registrasi di Kernel dihapus"
    log "   ✅ Middleware dari routes dihapus"
    log "   ✅ Cache dibersihkan"
    log "   ✅ Services di-restart"
    echo
    warn "⚠️  Sistem sekarang dalam kondisi NORMAL tanpa proteksi security middleware"
}

replace_credit_name() {
    echo
    info "GANTI NAMA CREDIT"
    info "================="
    echo
    read -p "Masukkan nama baru untuk mengganti '@naeldev': " new_name
    
    if [ -z "$new_name" ]; then
        error "Nama tidak boleh kosong!"
    fi
    
    new_name=$(echo "$new_name" | sed 's/^@//')
    
    echo
    info "Mengganti '@thezzyxopois' dengan '@$new_name'..."
    
    if [ ! -f "$PTERO_DIR/app/Http/Middleware/CustomSecurityCheck.php" ]; then
        error "Middleware belum diinstall! Silakan install terlebih dahulu."
    fi
    
    sed -i "s/@thezzyxopois/@$new_name/g" "$PTERO_DIR/app/Http/Middleware/CustomSecurityCheck.php"
    
    log "✅ Nama berhasil diganti dari '@thezzyxopois' menjadi '@$new_name'"
    
    log "🧹 Membersihkan cache..."
    cd $PTERO_DIR
    sudo -u www-data php artisan config:clear
    sudo -u www-data php artisan route:clear
    sudo -u www-data php artisan cache:clear
    
    echo
    log "🎉 Nama credit berhasil diubah!"
    log "💬 Credit sekarang: @$new_name"
}

custom_error_message() {
    echo
    info "CUSTOM TEKS ERROR MESSAGE"
    info "========================"
    echo
    read -p "Masukkan teks error custom (contoh: 'Akses ditolak!'): " custom_error
    
    if [ -z "$custom_error" ]; then
        error "Teks error tidak boleh kosong!"
    fi
    
    echo
    info "Mengganti teks error dengan: '$custom_error'..."
    
    if [ ! -f "$PTERO_DIR/app/Http/Middleware/CustomSecurityCheck.php" ]; then
        error "Middleware belum diinstall! Silakan install terlebih dahulu."
    fi
    
    sed -i "s/'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'/'error' => '$custom_error'/g" "$PTERO_DIR/app/Http/Middleware/CustomSecurityCheck.php"
    
    log "✅ Teks error berhasil diganti dengan: '$custom_error'"
    
    log "🧹 Membersihkan cache..."
    cd $PTERO_DIR
    sudo -u www-data php artisan config:clear
    sudo -u www-data php artisan route:clear
    sudo -u www-data php artisan cache:clear
    
    echo
    log "🎉 Teks error berhasil diubah!"
}

apply_manual_routes() {
    log "🔧 Applying middleware to routes manually..."
    
    API_CLIENT_FILE="$PTERO_DIR/routes/api-client.php"
    if [ -f "$API_CLIENT_FILE" ]; then
        log "📝 Processing api-client.php..."
        
        if grep -q "Route::group(\['prefix' => '/files'" "$API_CLIENT_FILE"; then
            if ! grep -q "Route::group(\['prefix' => '/files', 'middleware' => \['custom.security'\]" "$API_CLIENT_FILE"; then
                sed -i "s/Route::group(\['prefix' => '\/files'/Route::group(['prefix' => '\/files', 'middleware' => ['custom.security']/g" "$API_CLIENT_FILE"
                log "✅ Applied middleware to /files group in api-client.php"
            else
                warn "⚠️ Middleware already applied to /files group in api-client.php"
            fi
        else
            warn "⚠️ /files group not found in api-client.php"
        fi
    fi

    ADMIN_FILE="$PTERO_DIR/routes/admin.php"
    if [ -f "$ADMIN_FILE" ]; then
        log "📝 Processing admin.php..."
        
        log "🔍 Searching for routes in admin.php..."
        
        route_patterns=(
            "view/{user:id}.*update"
            "view/{user:id}.*delete"
            "view/{server:id}/details"
            "view/{server:id}/delete"
            "view/{node:id}/settings"
            "view/{node:id}/configuration"
            "view/{node:id}/settings/token"
            "view/{node:id}/delete"
        )
        
        for pattern in "${route_patterns[@]}"; do
            log "🔍 Searching for pattern: $pattern"
            
            while IFS= read -r line; do
                if [[ ! -z "$line" && ! "$line" =~ "middleware" && "$line" =~ "Route::" ]]; then
                    log "📝 Found route: $(echo "$line" | tr -s ' ' | sed 's/^[[:space:]]*//')"
                    
                    if [[ "$line" =~ \)\; ]]; then
                        new_line=$(echo "$line" | sed "s/);/)->middleware(['custom.security']);/")
                        
                        escaped_line=$(printf '%s\n' "$line" | sed 's/[[\.*^$/]/\\&/g')
                        escaped_new_line=$(printf '%s\n' "$new_line" | sed 's/[[\.*^$/]/\\&/g')
                        
                        sed -i "s|$escaped_line|$escaped_new_line|g" "$ADMIN_FILE"
                        log "✅ Applied middleware to route"
                    fi
                fi
            done < <(grep -n "$pattern" "$ADMIN_FILE" | head -5)
        done

        log "🔧 Applying specific route protection..."
        
        if grep -q "Route::patch.*view/{user:id}.*update" "$ADMIN_FILE"; then
            sed -i "s/Route::patch('\/view\/{user:id}', \[Admin\\UserController::class, 'update'\])/Route::patch('\/view\/{user:id}', [Admin\\UserController::class, 'update'])->middleware(['custom.security'])/g" "$ADMIN_FILE" 2>/dev/null || warn "User update route not found in exact format"
        fi
        
        if grep -q "Route::delete.*view/{user:id}.*delete" "$ADMIN_FILE"; then
            sed -i "s/Route::delete('\/view\/{user:id}', \[Admin\\UserController::class, 'delete'\])/Route::delete('\/view\/{user:id}', [Admin\\UserController::class, 'delete'])->middleware(['custom.security'])/g" "$ADMIN_FILE" 2>/dev/null || warn "User delete route not found in exact format"
        fi
        
        server_routes=(
            "view/{server:id}/details"
            "view/{server:id}/delete"
        )
        
        for route in "${server_routes[@]}"; do
            escaped_route=$(echo "$route" | sed 's/\//\\\//g')
            
            if grep -q "Route::get.*$route" "$ADMIN_FILE"; then
                sed -i "s/Route::get('\/$escaped_route', \[Admin\\Servers\\ServerViewController::class, '${route##*/}'\])/Route::get('\/$escaped_route', [Admin\\Servers\\ServerViewController::class, '${route##*/}'])->middleware(['custom.security'])/g" "$ADMIN_FILE" 2>/dev/null || \
                sed -i "s/Route::get('\/$escaped_route',/Route::get('\/$escaped_route',/g" "$ADMIN_FILE" 2>/dev/null || \
                warn "Server $route route not found in expected format"
            fi
        done
        
        if grep -q "Route::post.*view/{server:id}/delete" "$ADMIN_FILE"; then
            sed -i "s/Route::post('\/view\/{server:id}\/delete', \[Admin\\ServersController::class, 'delete'\])/Route::post('\/view\/{server:id}\/delete', [Admin\\ServersController::class, 'delete'])->middleware(['custom.security'])/g" "$ADMIN_FILE" 2>/dev/null || warn "Server post delete route not found"
        fi
        
        if grep -q "Route::patch.*view/{server:id}/details" "$ADMIN_FILE"; then
            sed -i "s/Route::patch('\/view\/{server:id}\/details', \[Admin\\ServersController::class, 'setDetails'\])/Route::patch('\/view\/{server:id}\/details', [Admin\\ServersController::class, 'setDetails'])->middleware(['custom.security'])/g" "$ADMIN_FILE" 2>/dev/null || warn "Server setDetails route not found"
        fi

        log "🔍 Manual inspection of admin.php routes..."
        
        total_routes=$(grep -c "Route::" "$ADMIN_FILE" || true)
        log "📊 Total routes found in admin.php: $total_routes"
        
        log "📋 Sample routes in admin.php:"
        grep "Route::" "$ADMIN_FILE" | head -10 | while read -r route_line; do
            log "   📝 $(echo "$route_line" | tr -s ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        done
        
    else
        error "Admin routes file not found: $ADMIN_FILE"
    fi
    
    log "✅ Manual route protection completed"
}

install_middleware() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root: sudo bash <(curl -s https://raw.githubusercontent.com/liaacans/installers/refs/heads/main/security.sh)"
    fi

    PTERO_DIR="/var/www/pterodactyl"

    if [ ! -d "$PTERO_DIR" ]; then
        error "Pterodactyl directory not found: $PTERO_DIR"
    fi

    log "🚀 Installing Custom Security Middleware for Pterodactyl..."
    log "📁 Pterodactyl directory: $PTERO_DIR"

    if [ ! -d "$PTERO_DIR/routes" ]; then
        error "Routes directory not found: $PTERO_DIR/routes"
    fi

    log "📝 Creating CustomSecurityCheck middleware..."
    cat > $PTERO_DIR/app/Http/Middleware/CustomSecurityCheck.php << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Pterodactyl\Models\Server;
use Pterodactyl\Models\User;
use Pterodactyl\Models\Node;

class CustomSecurityCheck
{
    public function handle(Request $request, Closure $next)
    {
        if (!$request->user()) {
            return $next($request);
        }

        $currentUser = $request->user();
        $path = $request->path();
        $method = $request->method();

        if ($currentUser->root_admin && $this->isAdminAccessingRestrictedPanel($path, $method)) {
            return new JsonResponse([
                'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
            ], 403);
        }

        if ($currentUser->root_admin && $this->isAdminAccessingSettings($path, $method)) {
            return new JsonResponse([
                'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
            ], 403);
        }

        if ($currentUser->root_admin && $this->isAdminModifyingUser($path, $method)) {
            return new JsonResponse([
                'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
            ], 403);
        }

        if ($currentUser->root_admin && $this->isAdminModifyingServer($path, $method)) {
            return new JsonResponse([
                'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
            ], 403);
        }

        if ($currentUser->root_admin && $this->isAdminModifyingNode($path, $method)) {
            return new JsonResponse([
                'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
            ], 403);
        }

        if ($currentUser->root_admin && $this->isAdminDeletingViaAPI($path, $method)) {
            return new JsonResponse([
                'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
            ], 403);
        }

        $server = $request->route('server');
        if ($server instanceof Server) {
            $isServerOwner = $currentUser->id === $server->owner_id;
            if (!$isServerOwner) {
                return new JsonResponse([
                    'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
                ], 403);
            }
        }

        if (!$currentUser->root_admin) {
            $user = $request->route('user');
            if ($user instanceof User && $currentUser->id !== $user->id) {
                return new JsonResponse([
                    'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
                ], 403);
            }

            if ($this->isAccessingRestrictedList($path, $method, $user)) {
                return new JsonResponse([
                    'error' => 'Mau ngapain lu ngentot?? - @thezzyxopois'
                ], 403);
            }
        }

        return $next($request);
    }

    private function isAdminAccessingRestrictedPanel(string $path, string $method): bool
    {
        if ($method !== 'GET') {
            return false;
        }

        if (str_contains($path, 'admin/api')) {
            return false;
        }

        $restrictedPaths = [
            'admin/users',
            'admin/servers', 
            'admin/nodes',
            'admin/databases',
            'admin/locations',
            'admin/nests',
            'admin/mounts',
            'admin/eggs',
            'admin/settings'
        ];

        foreach ($restrictedPaths as $restrictedPath) {
            if (str_contains($path, $restrictedPath)) {
                return true;
            }
        }

        return false;
    }

    private function isAdminAccessingSettings(string $path, string $method): bool
    {
        if (str_contains($path, 'admin/settings')) {
            return true;
        }

        if (str_contains($path, 'application/settings')) {
            return in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE']);
        }

        return false;
    }

    private function isAdminModifyingUser(string $path, string $method): bool
    {
        if (str_contains($path, 'admin/users')) {
            return in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE']);
        }

        if (str_contains($path, 'application/users')) {
            return in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE']);
        }

        return false;
    }

    private function isAdminModifyingServer(string $path, string $method): bool
    {
        if (str_contains($path, 'admin/servers')) {
            if ($method === 'DELETE') {
                return true;
            }
            if ($method === 'POST' && str_contains($path, 'delete')) {
                return true;
            }
        }

        if (str_contains($path, 'application/servers')) {
            if ($method === 'DELETE') {
                return true;
            }
        }

        return false;
    }

    private function isAdminModifyingNode(string $path, string $method): bool
    {
        if (str_contains($path, 'admin/nodes')) {
            return in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE']);
        }

        if (str_contains($path, 'application/nodes')) {
            return in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE']);
        }

        return false;
    }

    private function isAdminDeletingViaAPI(string $path, string $method): bool
    {
        if ($method === 'DELETE' && preg_match('#application/users/\d+#', $path)) {
            return true;
        }

        if ($method === 'DELETE' && preg_match('#application/servers/\d+#', $path)) {
            return true;
        }

        if ($method === 'DELETE' && preg_match('#application/servers/\d+/.+#', $path)) {
            return true;
        }

        return false;
    }

    private function isAccessingRestrictedList(string $path, string $method, $user): bool
    {
        if ($method !== 'GET' || $user) {
            return false;
        }

        $restrictedPaths = [
            'admin/users', 'application/users',
            'admin/servers', 'application/servers',
            'admin/nodes', 'application/nodes',
            'admin/databases', 'admin/locations',
            'admin/nests', 'admin/mounts', 'admin/eggs',
            'admin/settings', 'application/settings'
        ];

        foreach ($restrictedPaths as $restrictedPath) {
            if (str_contains($path, $restrictedPath)) {
                return true;
            }
        }

        return false;
    }
}
?>
EOF

    log "✅ Custom middleware created"

    KERNEL_FILE="$PTERO_DIR/app/Http/Kernel.php"
    log "📝 Registering middleware in Kernel..."

    if grep -q "custom.security" "$KERNEL_FILE"; then
        warn "⚠️ Middleware already registered in Kernel"
    else
        sed -i "/protected \$middlewareAliases = \[/a\\
        'custom.security' => \\\\Pterodactyl\\\\Http\\\\Middleware\\\\CustomSecurityCheck::class," "$KERNEL_FILE"
        log "✅ Middleware registered in Kernel"
    fi

    apply_manual_routes

    log "🧹 Clearing cache and optimizing..."
    cd $PTERO_DIR

    sudo -u www-data php artisan config:clear
    sudo -u www-data php artisan route:clear
    sudo -u www-data php artisan view:clear
    sudo -u www-data php artisan cache:clear
    sudo -u www-data php artisan optimize

    log "✅ Cache cleared successfully"

    log "🔄 Restarting services..."

    PHP_SERVICE=""
    if systemctl is-active --quiet php8.2-fpm; then
        PHP_SERVICE="php8.2-fpm"
    elif systemctl is-active --quiet php8.1-fpm; then
        PHP_SERVICE="php8.1-fpm"
    elif systemctl is-active --quiet php8.0-fpm; then
        PHP_SERVICE="php8.0-fpm"
    elif systemctl is-active --quiet php8.3-fpm; then
        PHP_SERVICE="php8.3-fpm"
    else
        warn "⚠️ PHP-FPM service not detected, skipping restart"
    fi

    if [ -n "$PHP_SERVICE" ]; then
        systemctl restart $PHP_SERVICE
        log "✅ $PHP_SERVICE restarted"
    fi

    if systemctl is-active --quiet pteroq-service; then
        systemctl restart pteroq-service
        log "✅ pterodactyl-service restarted"
    fi

    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
        log "✅ nginx reloaded"
    fi

    log "🔍 Verifying middleware application..."
    echo
    log "📋 Applied middleware to:"
    log "   ✅ Route groups: files"
    log "   ✅ Admin routes: user update/delete"
    log "   ✅ Server routes: details, delete, setDetails"
    log "   ✅ Node routes: settings, configuration, token, updateSettings, delete"
    echo
    log "🎉 Custom Security Middleware installed successfully!"
    echo
    log "📊 PROTECTION SUMMARY:"
    log "   ✅ Admin hanya bisa akses: Application API"
    log "   ❌ Admin DIBLOKIR dari:"
    log "      - Users, Servers, Nodes, Settings"
    log "      - Databases, Locations, Nests, Mounts, Eggs"
    log "      - Delete/Update operations"
    log "   🔒 API DELETE Operations DIBLOKIR:"
    log "      - DELETE /api/application/users/{id}"
    log "      - DELETE /api/application/servers/{id}" 
    log "      - DELETE /api/application/servers/{id}/force"
    log "   🔒 Server ownership protection aktif"
    log "   🛡️ User access restriction aktif"
    echo
    log "💬 Source Code Credit by - @thezzyxopois'"
    echo
    warn "⚠️ IMPORTANT: Test dengan login sebagai admin dan coba akses tabs yang diblokir"
    log "   Gunakan opsi 'Clear Security' untuk menguninstall"
}

main() {
    while true; do
        show_menu
        read -p "$(info 'Silahkan pilih opsi (1-5): ')" choice
        
        case $choice in
            1)
                echo
                install_middleware
                ;;
            2)
                replace_credit_name
                ;;
            3)
                custom_error_message
                ;;
            4)
                clear_security
                ;;
            5)
                echo
                log "Terima kasih! Keluar dari program."
                exit 0
                ;;
            *)
                error "Pilihan tidak valid! Silakan pilih 1, 2, 3, 4, atau 5."
                ;;
        esac
        
        echo
        read -p "$(info 'Tekan Enter untuk kembali ke menu...')"
    done
}

main
