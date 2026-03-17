#!/bin/bash

# 1. Restore Apache DocumentRoot
sudo sed -i 's|DocumentRoot /home/jeycee/Documents/WORKSPACE/wavs2026/public|DocumentRoot /var/www/html|' /etc/apache2/sites-enabled/000-default.conf

# Remove the Directory block we added
sudo sed -i '/<Directory \/home\/jeycee\/Documents\/WORKSPACE\/wavs2026\/public>/,/<\/Directory>/d' /etc/apache2/sites-enabled/000-default.conf

# Restart Apache
sudo systemctl restart apache2

# 2. Restore directory permissions
chmod o-x /home/jeycee
chmod o-x /home/jeycee/Documents
chmod o-x /home/jeycee/Documents/WORKSPACE
chmod o-x /home/jeycee/Documents/WORKSPACE/wavs2026

# 3. Restore Laravel file ownership
cd /home/jeycee/Documents/WORKSPACE/wavs2026
sudo chown -R jeycee:jeycee storage bootstrap/cache

# 4. Restore .env
sed -i 's/APP_ENV=local/APP_ENV=production/' .env
sed -i 's/APP_DEBUG=true/APP_DEBUG=false/' .env
sed -i 's|APP_URL=http://localhost$|APP_URL=http://localhost:8000|' .env

# 5. Remove test files
rm -f resources/views/test_vulns.blade.php
rm -f app/Http/Middleware/BypassSecurityHeaders.php

# 6. Remove test routes from web.php
# This removes everything from the test vulns comment to end of file
sed -i '/# TEST VULNS\|test-vulns\|test_vulns/d' routes/web.php

# 7. Clear all caches
php artisan config:clear
php artisan route:clear
php artisan cache:clear
php artisan view:clear

echo "Done! Everything reverted."
