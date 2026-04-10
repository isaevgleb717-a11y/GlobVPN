#ifndef GLOBVPN_HPP
#define GLOBVPN_HPP

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>
#include <mutex>
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <cstring>
#include <ctime>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
#endif

namespace GlobVPN {

enum class ConnectionState {
    DISCONNECTED,
    HANDSHAKE,
    ESTABLISHED,
    ERROR,
    RECONNECTING
};

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

struct RealityConfig {
    std::string public_key;
    std::string short_id;
    std::string fingerprint = "chrome";
    std::string server_name = "www.microsoft.com";
    std::string spider_x = "";
};

struct VLESSConfig {
    std::string uuid;
    std::string flow = "xtls-rprx-vision";
    std::string encryption = "none";
    int level = 0;
};

struct ServerInfo {
    std::string name;
    int port;
    std::string public_key;
    std::string short_id;
    std::string location;
    int load;
};

struct ConnectionStats {
    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;
    int latency_ms = 0;
    ConnectionState state = ConnectionState::DISCONNECTED;
    std::chrono::steady_clock::time_point connected_since;
};

// GeoIP структуры
#pragma pack(push, 1)
struct GeoIPRecordV4 {
    uint32_t from_ip;
    uint32_t to_ip;
    char country_code[2];
};
#pragma pack(pop)

struct GeoIPDatabase {
    std::vector<GeoIPRecordV4> records;
    std::string version;
    bool is_loaded;
    GeoIPDatabase() : is_loaded(false) {}
};

// Классы
class RealityHandshake {
private:
    RealityConfig config_;
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
public:
    explicit RealityHandshake(const RealityConfig& config);
    std::vector<uint8_t> buildClientHello();
    bool verifyServerResponse(const std::vector<uint8_t>& response);
};

class VLESSTunnel {
private:
    VLESSConfig vless_config_;
    RealityHandshake reality_;
    int socket_fd_;
    ConnectionState state_;
    uint64_t tx_bytes_;
    uint64_t rx_bytes_;
    int latency_ms_;
    std::mutex mutex_;
    std::chrono::steady_clock::time_point connected_since_;
    std::vector<uint8_t> buildVLESSHeader();
    void measureLatency();
public:
    VLESSTunnel(const VLESSConfig& vless, const RealityConfig& reality);
    ~VLESSTunnel();
    bool connect(const std::string& server, int port, int timeout = 10);
    void disconnect();
    ssize_t send(const std::vector<uint8_t>& data);
    std::vector<uint8_t> recv(size_t buffer_size = 8192);
    ConnectionStats getStats();
    bool isConnected() const { return state_ == ConnectionState::ESTABLISHED; }
};

class GeoIP {
private:
    GeoIPDatabase db_;
    std::mutex mutex_;
    std::string db_path_;
    uint32_t ipToUint(const std::string& ip);
    bool loadFromBinaryFile(const std::string& path);
public:
    GeoIP();
    ~GeoIP();
    bool init(const std::string& db_path);
    std::string lookupCountry(const std::string& ip);
    std::string lookupCountry(uint32_t ip_addr);
    bool isLoaded() const { return db_.is_loaded; }
    size_t getRecordCount() const { return db_.records.size(); }
};

class RoutingEngine {
private:
    std::shared_ptr<GeoIP> geoip_;
    std::vector<std::string> bypass_countries_;
    std::vector<std::string> proxy_countries_;
    bool bypass_lan_;
    std::string default_action_;
    bool isPrivateIP(uint32_t ip);
public:
    RoutingEngine();
    void init(std::shared_ptr<GeoIP> geoip);
    void setBypassCountries(const std::vector<std::string>& countries);
    void setProxyCountries(const std::vector<std::string>& countries);
    void setBypassLan(bool enable);
    std::string getRoute(const std::string& dest_ip);
    bool shouldBypass(const std::string& dest_ip);
    bool shouldProxy(const std::string& dest_ip);
};

class GlobVPNClient {
private:
    std::unique_ptr<VLESSTunnel> tunnel_;
    std::unique_ptr<RoutingEngine> routing_;
    std::shared_ptr<GeoIP> geoip_;
    std::string connected_server_;
    VLESSConfig vless_config_;
    RealityConfig reality_config_;
    std::vector<ServerInfo> servers_;
    bool auto_reconnect_;
    int reconnect_delay_;
    int timeout_;
    LogLevel log_level_;
    std::function<void(const std::string&, int)> on_connecting_;
    std::function<void(const std::string&, const std::string&)> on_connected_;
    std::function<void()> on_disconnected_;
    std::function<void(const std::string&)> on_error_;
    std::function<void(const ConnectionStats&)> on_stats_;
    void log(LogLevel level, const std::string& message);
    bool parseConfig(const std::string& config_file);
    std::string readFile(const std::string& filename);
    std::string parseJSON(const std::string& json, const std::string& key);
public:
    GlobVPNClient();
    ~GlobVPNClient();
    bool loadConfig(const std::string& config_file);
    bool initGeoIP(const std::string& geoip_path);
    void configure(const std::string& uuid, const std::string& public_key, const std::string& short_id);
    bool connect(const std::string& server = "", int port = 0);
    bool connectToBestServer();
    void disconnect();
    void reconnect();
    bool isConnected() const;
    std::string getStatus() const;
    ConnectionStats getStats() const;
    std::vector<ServerInfo> getServers() const { return servers_; }
    ssize_t sendData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> receiveData(size_t size = 8192);
    void onConnecting(std::function<void(const std::string&, int)> callback);
    void onConnected(std::function<void(const std::string&, const std::string&)> callback);
    void onDisconnected(std::function<void()> callback);
    void onError(std::function<void(const std::string&)> callback);
    void onStats(std::function<void(const ConnectionStats&)> callback);
    void setLogLevel(LogLevel level) { log_level_ = level; }
    RoutingEngine* getRouting() { return routing_.get(); }
};

// Вспомогательные функции
std::vector<uint8_t> hexToBytes(const std::string& hex);
std::string bytesToHex(const std::vector<uint8_t>& bytes);
std::string generateUUID();

} // namespace GlobVPN

#endif // GLOBVPN_HPP