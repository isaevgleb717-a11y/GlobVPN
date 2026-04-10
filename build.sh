#!/bin/bash

echo "🔨 Сборка GlobVPN..."

mkdir -p build
cd build
cmake ..
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

if [ $? -eq 0 ]; then
    echo "✅ Сборка завершена успешно!"
    echo ""
    echo "Запуск: ./globvpn"
    echo "Убедитесь, что geoip.dat находится в той же директории"
else
    echo "❌ Ошибка сборки"
    exit 1
fi