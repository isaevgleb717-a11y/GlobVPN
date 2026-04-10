#!/bin/bash

echo "🔨 Сборка GlobVPN..."

# Создание директории для сборки
mkdir -p build
cd build

# CMake конфигурация
cmake ..

# Компиляция
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

if [ $? -eq 0 ]; then
    echo "✅ Сборка завершена успешно!"
    echo ""
    echo "Запуск: ./globvpn"
    echo "Или: ./globvpn /path/to/config.json"
else
    echo "❌ Ошибка сборки"
    exit 1
fi
#Нужно для библиотеки