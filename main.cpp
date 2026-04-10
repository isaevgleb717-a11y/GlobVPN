#include "globvpn.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <signal.h>
#include <atomic>

using namespace GlobVPN;

std::atomic<bool> running(true);

void signalHandler(int signum) {
    std::cout << "\n[!] Получен сигнал " << signum << std::endl;
    running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "╔══════════════════════════════════════════╗" << std::endl;
    std::cout << "║     🌍 GlobVPN - Netherlands Company     ║" << std::endl;
    std::cout << "║     Protocol: VLESS + Reality (Xray)     ║" << std::endl;
    std::cout << "║     Version: 2.1.0 (with GeoIP)          ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    GlobVPNClient vpn;
    vpn.setLogLevel(LogLevel::INFO);
    
    std::string config_file = "config.json";
    if (argc > 1) config_file = argv[1];
    
    if (!vpn.loadConfig(config_file)) {
        std::cerr << "Ошибка загрузки конфигурации. Используются настройки по умолчанию." << std::endl;
        vpn.configure("123e4567-e89b-12d3-a456-426614174000", "nl_reality_pub_1a2b3c4d5e6f7g8h9i0j", "deadbeef");
    }
    
    // Инициализация GeoIP
    if (vpn.initGeoIP("geoip.dat")) {
        std::cout << "[✓] GeoIP загружен успешно" << std::endl;
        std::cout << "[✓] Пример: 8.8.8.8 → " << vpn.getRouting()->getRoute("8.8.8.8") << std::endl;
        std::cout << "[✓] Пример: 77.88.55.66 → " << vpn.getRouting()->getRoute("77.88.55.66") << std::endl;
    } else {
        std::cout << "[!] GeoIP не загружен (файл geoip.dat не найден)" << std::endl;
    }
    
    vpn.onConnecting([](const std::string& server, int port) {
        std::cout << "\n[🔄] Подключение к " << server << ":" << port << std::endl;
    });
    
    vpn.onConnected([](const std::string& server, const std::string& protocol) {
        std::cout << "\n[✅] ПОДКЛЮЧЕНО!" << std::endl;
        std::cout << "    Сервер: " << server << std::endl;
        std::cout << "    Протокол: " << protocol << std::endl;
        std::cout << "    Страна: Нидерланды 🇳🇱" << std::endl;
    });
    
    vpn.onDisconnected([]() {
        std::cout << "\n[🔌] ОТКЛЮЧЕНО" << std::endl;
    });
    
    vpn.onError([](const std::string& error) {
        std::cout << "\n[❌] Ошибка: " << error << std::endl;
    });
    
    auto servers = vpn.getServers();
    std::cout << "\n📡 Доступные серверы GlobVPN:" << std::endl;
    for (size_t i = 0; i < servers.size(); i++) {
        std::cout << "  " << (i + 1) << ". " << servers[i].name << ":" << servers[i].port
                  << " (" << servers[i].location << ") - нагрузка: " << servers[i].load << "%" << std::endl;
    }
    std::cout << "  " << (servers.size() + 1) << ". Автовыбор (лучший сервер)" << std::endl;
    std::cout << "  " << (servers.size() + 2) << ". Выход" << std::endl;
    std::cout << "\n➡️  Выберите сервер: ";
    
    int choice;
    std::cin >> choice;
    
    if (choice == static_cast<int>(servers.size()) + 2) {
        std::cout << "Выход." << std::endl;
        return 0;
    }
    
    bool connected = false;
    if (choice == static_cast<int>(servers.size()) + 1) {
        connected = vpn.connectToBestServer();
    } else if (choice >= 1 && choice <= static_cast<int>(servers.size())) {
        const auto& srv = servers[choice - 1];
        connected = vpn.connect(srv.name, srv.port);
    } else {
        std::cout << "Неверный выбор. Используется сервер по умолчанию." << std::endl;
        connected = vpn.connectToBestServer();
    }
    
    if (!connected) {
        std::cout << "Не удалось подключиться." << std::endl;
        return 1;
    }
    
    std::cout << "\n════════════════════════════════════════════" << std::endl;
    std::cout << "VPN активен. Команды:" << std::endl;
    std::cout << "  s - статус" << std::endl;
    std::cout << "  r - маршрутизация IP" << std::endl;
    std::cout << "  d - отключиться" << std::endl;
    std::cout << "  q - выход" << std::endl;
    std::cout << "════════════════════════════════════════════" << std::endl;
    
    std::thread stats_thread([&vpn, &running]() {
        while (running && vpn.isConnected()) {
            auto stats = vpn.getStats();
            if (stats.state == ConnectionState::ESTABLISHED) {
                auto now = std::chrono::steady_clock::now();
                auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - stats.connected_since).count();
                std::cout << "\r🔒 Активно: " << uptime << "с | 📤 " << stats.tx_bytes / 1024 
                          << "KB | 📥 " << stats.rx_bytes / 1024 << "KB | ⚡ " 
                          << stats.latency_ms << "ms   " << std::flush;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        std::cout << std::endl;
    });
    
    std::string cmd;
    while (running && vpn.isConnected()) {
        std::cout << "\n> ";
        std::cin >> cmd;
        
        if (cmd == "s" || cmd == "status") {
            std::cout << vpn.getStatus() << std::endl;
        } else if (cmd == "r" || cmd == "route") {
            std::string ip;
            std::cout << "Введите IP: ";
            std::cin >> ip;
            std::cout << "Маршрут для " << ip << ": " << vpn.getRouting()->getRoute(ip) << std::endl;
        } else if (cmd == "d" || cmd == "disconnect") {
            vpn.disconnect();
            break;
        } else if (cmd == "q" || cmd == "quit") {
            break;
        } else {
            std::cout << "Неизвестная команда. Доступно: s, r, d, q" << std::endl;
        }
    }
    
    vpn.disconnect();
    running = false;
    if (stats_thread.joinable()) stats_thread.join();
    
    std::cout << "\nGlobVPN завершил работу. Спасибо!" << std::endl;
    return 0;
}