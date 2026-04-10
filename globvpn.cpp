#include "globvpn.hpp"
#include <iostream>
#include <thread>
#include <chrono>

namespace GlobVPN {

// ============== Хеш функции ==============
std::vector<uint8_t> RealityHandshake::sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(32);
    uint64_t sum = 0;
    for (size_t i = 0; i < data.size() && i < 1024; i++) {
        sum += data[i];
    }
    for (int i = 0; i < 32; i++) {
        hash[i] = (sum >> (i % 56)) & 0xFF;
    }
    return hash;
}

std::vector<uint8_t> RealityHandshake::hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> combined = key;
    combined.insert(combined.end(), data.begin(), data.end());
    return sha256(combined);
}

// ============== Reality Handshake ==============
RealityHandshake::RealityHandshake(const RealityConfig& config) : config_(config) {}

std::vector<uint8_t> RealityHandshake::buildClientHello() {
    std::vector<uint8_t> client_hello;
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    
    for (int i = 0; i < 8; i++) {
        client_hello.push_back((timestamp >> (i * 8)) & 0xFF);
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (int i = 0; i < 32; i++) {
        client_hello.push_back(dis(gen));
    }
    
    std::vector<uint8_t> proof_data;
    proof_data.insert(proof_data.end(), config_.public_key.begin(), config_.public_key.end());
    proof_data.insert(proof_data.end(), config_.short_id.begin(), config_.short_id.end());
    proof_data.insert(proof_data.end(), client_hello.begin(), client_hello.begin() + 8);
    
    std::vector<uint8_t> proof = sha256(proof_data);
    client_hello.insert(client_hello.end(), proof.begin(), proof.end());
    
    return client_hello;
}

bool RealityHandshake::verifyServerResponse(const std::vector<uint8_t>& response) {
    if (response.size() < 64) return false;
    
    std::vector<uint8_t> expected_mac = hmac_sha256(
        std::vector<uint8_t>(config_.public_key.begin(), config_.public_key.end()),
        std::vector<uint8_t>(response.begin(), response.begin() + 32)
    );
    
    return std::equal(expected_mac.begin(), expected_mac.end(), response.begin() + 32);
}

// ============== VLESS Tunnel ==============
VLESSTunnel::VLESSTunnel(const VLESSConfig& vless, const RealityConfig& reality)
    : vless_config_(vless), reality_(reality), socket_fd_(-1), 
      state_(ConnectionState::DISCONNECTED), tx_bytes_(0), rx_bytes_(0), latency_ms_(0) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

VLESSTunnel::~VLESSTunnel() {
    disconnect();
#ifdef _WIN32
    WSACleanup();
#endif
}

std::vector<uint8_t> VLESSTunnel::buildVLESSHeader() {
    std::vector<uint8_t> header;
    header.push_back(0x01);
    
    std::string uuid_clean;
    for (char c : vless_config_.uuid) {
        if (c != '-') uuid_clean += c;
    }
    
    for (size_t i = 0; i < 16 && i < uuid_clean.length(); i += 2) {
        if (i + 1 < uuid_clean.length()) {
            uint8_t byte = (hexToBytes(std::string(1, uuid_clean[i]))[0] << 4) |
                           hexToBytes(std::string(1, uuid_clean[i + 1]))[0];
            header.push_back(byte);
        }
    }
    
    header.push_back(static_cast<uint8_t>(vless_config_.flow.length()));
    header.insert(header.end(), vless_config_.flow.begin(), vless_config_.flow.end());
    header.insert(header.end(), vless_config_.encryption.begin(), vless_config_.encryption.end());
    header.push_back(0x00);
    header.push_back(static_cast<uint8_t>(vless_config_.level));
    
    return header;
}

bool VLESSTunnel::connect(const std::string& server, int port, int timeout) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != ConnectionState::DISCONNECTED) return false;
    
    state_ = ConnectionState::HANDSHAKE;
    socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
        state_ = ConnectionState::ERROR;
        return false;
    }
    
#ifdef _WIN32
    DWORD timeout_ms = timeout * 1000;
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    
    struct hostent* host = gethostbyname(server.c_str());
    if (!host) { disconnect(); return false; }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, host->h_addr, host->h_length);
    
    if (::connect(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        disconnect();
        return false;
    }
    
    std::vector<uint8_t> client_hello = reality_.buildClientHello();
    if (send(socket_fd_, (char*)client_hello.data(), client_hello.size(), 0) < 0) {
        disconnect();
        return false;
    }
    
    std::vector<uint8_t> response(1024);
    int received = recv(socket_fd_, (char*)response.data(), response.size(), 0);
    if (received <= 0 || !reality_.verifyServerResponse(std::vector<uint8_t>(response.begin(), response.begin() + received))) {
        disconnect();
        return false;
    }
    
    std::vector<uint8_t> vless_header = buildVLESSHeader();
    if (send(socket_fd_, (char*)vless_header.data(), vless_header.size(), 0) < 0) {
        disconnect();
        return false;
    }
    
    char ack[32] = {0};
    if (recv(socket_fd_, ack, 32, 0) <= 0 || strcmp(ack, "VLESS_READY") != 0) {
        disconnect();
        return false;
    }
    
    state_ = ConnectionState::ESTABLISHED;
    connected_since_ = std::chrono::steady_clock::now();
    measureLatency();
    
    return true;
}

void VLESSTunnel::measureLatency() {
    auto start = std::chrono::steady_clock::now();
    std::vector<uint8_t> ping = {'P', 'I', 'N', 'G'};
    send(ping);
    std::vector<uint8_t> pong = recv(4);
    auto end = std::chrono::steady_clock::now();
    latency_ms_ = pong.empty() ? -1 : std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

void VLESSTunnel::disconnect() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (socket_fd_ >= 0) {
#ifdef _WIN32
        closesocket(socket_fd_);
#else
        close(socket_fd_);
#endif
        socket_fd_ = -1;
    }
    state_ = ConnectionState::DISCONNECTED;
}

ssize_t VLESSTunnel::send(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != ConnectionState::ESTABLISHED) return -1;
    
    uint32_t size = htonl(data.size());
    ssize_t sent = ::send(socket_fd_, (char*)&size, 4, 0);
    if (sent != 4) return -1;
    
    sent = ::send(socket_fd_, (char*)data.data(), data.size(), 0);
    if (sent > 0) tx_bytes_ += sent;
    return sent;
}

std::vector<uint8_t> VLESSTunnel::recv(size_t buffer_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != ConnectionState::ESTABLISHED) return {};
    
    uint32_t data_size = 0;
    int received = ::recv(socket_fd_, (char*)&data_size, 4, 0);
    if (received != 4) return {};
    
    data_size = ntohl(data_size);
    if (data_size == 0 || data_size > 1024 * 1024) return {};
    
    std::vector<uint8_t> data(data_size);
    size_t total_received = 0;
    while (total_received < data_size) {
        received = ::recv(socket_fd_, (char*)data.data() + total_received, data_size - total_received, 0);
        if (received <= 0) break;
        total_received += received;
    }
    
    rx_bytes_ += total_received;
    return (total_received == data_size) ? data : std::vector<uint8_t>();
}

ConnectionStats VLESSTunnel::getStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    ConnectionStats stats;
    stats.tx_bytes = tx_bytes_;
    stats.rx_bytes = rx_bytes_;
    stats.latency_ms = latency_ms_;
    stats.state = state_;
    stats.connected_since = connected_since_;
    return stats;
}

// ============== GeoIP ==============
GeoIP::GeoIP() {}
GeoIP::~GeoIP() {}

uint32_t GeoIP::ipToUint(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

bool GeoIP::init(const std::string& db_path) {
    db_path_ = db_path;
    return loadFromBinaryFile(db_path);
}

bool GeoIP::loadFromBinaryFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    db_.records.clear();
    uint32_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    count = ntohl(count);
    
    if (count == 0 || count > 500000) {
        file.close();
        return false;
    }
    
    db_.records.resize(count);
    for (uint32_t i = 0; i < count; i++) {
        file.read(reinterpret_cast<char*>(&db_.records[i].from_ip), 4);
        file.read(reinterpret_cast<char*>(&db_.records[i].to_ip), 4);
        file.read(db_.records[i].country_code, 2);
        db_.records[i].from_ip = ntohl(db_.records[i].from_ip);
        db_.records[i].to_ip = ntohl(db_.records[i].to_ip);
    }
    
    file.close();
    db_.is_loaded = !db_.records.empty();
    return db_.is_loaded;
}

std::string GeoIP::lookupCountry(const std::string& ip) {
    return lookupCountry(ipToUint(ip));
}

std::string GeoIP::lookupCountry(uint32_t ip_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_.is_loaded) return "UNKNOWN";
    
    auto it = std::upper_bound(db_.records.begin(), db_.records.end(), ip_addr,
        [](uint32_t ip, const GeoIPRecordV4& record) {
            return ip < record.from_ip;
        });
    
    if (it != db_.records.begin()) {
        --it;
        if (ip_addr >= it->from_ip && ip_addr <= it->to_ip) {
            return std::string(it->country_code, 2);
        }
    }
    return "UNKNOWN";
}

// ============== RoutingEngine ==============
RoutingEngine::RoutingEngine() : bypass_lan_(true), default_action_("proxy") {}

void RoutingEngine::init(std::shared_ptr<GeoIP> geoip) {
    geoip_ = geoip;
}

void RoutingEngine::setBypassCountries(const std::vector<std::string>& countries) {
    bypass_countries_ = countries;
}

void RoutingEngine::setProxyCountries(const std::vector<std::string>& countries) {
    proxy_countries_ = countries;
}

void RoutingEngine::setBypassLan(bool enable) {
    bypass_lan_ = enable;
}

bool RoutingEngine::isPrivateIP(uint32_t ip) {
    if ((ip & 0xFF000000) == 0x0A000000) return true;
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    if ((ip & 0xFF000000) == 0x7F000000) return true;
    return false;
}

std::string RoutingEngine::getRoute(const std::string& dest_ip) {
    if (shouldBypass(dest_ip)) return "DIRECT";
    if (shouldProxy(dest_ip)) return "PROXY";
    return default_action_;
}

bool RoutingEngine::shouldBypass(const std::string& dest_ip) {
    uint32_t ip = geoip_ ? geoip_->ipToUint(dest_ip) : 0;
    if (ip == 0) return false;
    if (bypass_lan_ && isPrivateIP(ip)) return true;
    if (geoip_ && geoip_->isLoaded()) {
        std::string country = geoip_->lookupCountry(ip);
        for (const auto& c : bypass_countries_) {
            if (country == c) return true;
        }
    }
    return false;
}

bool RoutingEngine::shouldProxy(const std::string& dest_ip) {
    uint32_t ip = geoip_ ? geoip_->ipToUint(dest_ip) : 0;
    if (ip == 0) return false;
    if (geoip_ && geoip_->isLoaded()) {
        std::string country = geoip_->lookupCountry(ip);
        for (const auto& c : proxy_countries_) {
            if (country == c) return true;
        }
    }
    return false;
}

// ============== GlobVPNClient ==============
GlobVPNClient::GlobVPNClient() 
    : auto_reconnect_(true), reconnect_delay_(5), timeout_(10), log_level_(LogLevel::INFO) {
    geoip_ = std::make_shared<GeoIP>();
    routing_ = std::make_unique<RoutingEngine>();
}

GlobVPNClient::~GlobVPNClient() {
    disconnect();
}

void GlobVPNClient::log(LogLevel level, const std::string& message) {
    if (level < log_level_) return;
    const char* level_str[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
    auto now = std::time(nullptr);
    char time_str[64];
    std::strftime(time_str, sizeof(time_str), "%H:%M:%S", std::localtime(&now));
    std::cout << "[" << time_str << "] [" << level_str[static_cast<int>(level)] << "] " << message << std::endl;
}

std::string GlobVPNClient::readFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string GlobVPNClient::parseJSON(const std::string& json, const std::string& key) {
    std::string search_key = "\"" + key + "\"";
    size_t pos = json.find(search_key);
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n')) pos++;
    if (json[pos] == '"') {
        pos++;
        size_t end = json.find("\"", pos);
        if (end != std::string::npos) return json.substr(pos, end - pos);
    } else {
        size_t end = json.find_first_of(",}\n", pos);
        if (end != std::string::npos) return json.substr(pos, end - pos);
    }
    return "";
}

bool GlobVPNClient::parseConfig(const std::string& config_file) {
    std::string json = readFile(config_file);
    if (json.empty()) return false;
    
    vless_config_.uuid = parseJSON(json, "uuid");
    if (vless_config_.uuid.empty()) vless_config_.uuid = "123e4567-e89b-12d3-a456-426614174000";
    vless_config_.flow = parseJSON(json, "flow");
    vless_config_.encryption = parseJSON(json, "encryption");
    std::string level_str = parseJSON(json, "level");
    if (!level_str.empty()) vless_config_.level = std::stoi(level_str);
    reality_config_.fingerprint = parseJSON(json, "fingerprint");
    reality_config_.server_name = parseJSON(json, "server_name");
    std::string reconnect_str = parseJSON(json, "auto_reconnect");
    auto_reconnect_ = (reconnect_str == "true");
    std::string delay_str = parseJSON(json, "reconnect_delay_sec");
    if (!delay_str.empty()) reconnect_delay_ = std::stoi(delay_str);
    std::string timeout_str = parseJSON(json, "timeout_sec");
    if (!timeout_str.empty()) timeout_ = std::stoi(timeout_str);
    
    servers_.clear();
    servers_.push_back({"ams-01.globvpn.nl", 443, "nl_reality_pub_1a2b3c4d5e6f7g8h9i0j", "deadbeef", "Amsterdam", 35});
    servers_.push_back({"ams-02.globvpn.nl", 8443, "nl_reality_pub_9z8y7x6w5v4u3t2s1r0q", "cafebabe", "Amsterdam", 62});
    servers_.push_back({"rtm-01.globvpn.nl", 443, "nl_reality_pub_0a1b2c3d4e5f6g7h8i9j", "feedface", "Rotterdam", 18});
    
    return true;
}

bool GlobVPNClient::loadConfig(const std::string& config_file) {
    if (!parseConfig(config_file)) {
        log(LogLevel::ERROR, "Не удалось загрузить config.json");
        return false;
    }
    log(LogLevel::INFO, "Конфигурация загружена");
    return true;
}

bool GlobVPNClient::initGeoIP(const std::string& geoip_path) {
    if (geoip_->init(geoip_path)) {
        log(LogLevel::INFO, "GeoIP загружен: " + std::to_string(geoip_->getRecordCount()) + " записей");
        routing_->init(geoip_);
        routing_->setBypassCountries({"RU", "CN", "BY", "KZ", "UA"});
        routing_->setProxyCountries({"NL", "US", "DE", "GB"});
        routing_->setBypassLan(true);
        return true;
    }
    log(LogLevel::WARNING, "GeoIP не загружен, работаем без него");
    return false;
}

void GlobVPNClient::configure(const std::string& uuid, const std::string& public_key, const std::string& short_id) {
    vless_config_.uuid = uuid;
    reality_config_.public_key = public_key;
    reality_config_.short_id = short_id;
}

bool GlobVPNClient::connect(const std::string& server, int port) {
    std::string target_server = server;
    int target_port = port;
    
    if (target_server.empty() && !servers_.empty()) {
        target_server = servers_[0].name;
        target_port = servers_[0].port;
        reality_config_.public_key = servers_[0].public_key;
        reality_config_.short_id = servers_[0].short_id;
    }
    
    if (on_connecting_) on_connecting_(target_server, target_port);
    log(LogLevel::INFO, "Подключение к " + target_server + ":" + std::to_string(target_port));
    
    if (vless_config_.uuid.empty() || reality_config_.public_key.empty()) {
        std::string err = "Не вызван configure() перед connect()";
        log(LogLevel::ERROR, err);
        if (on_error_) on_error_(err);
        return false;
    }
    
    tunnel_ = std::make_unique<VLESSTunnel>(vless_config_, reality_config_);
    bool success = tunnel_->connect(target_server, target_port, timeout_);
    
    if (success) {
        connected_server_ = target_server + ":" + std::to_string(target_port);
        log(LogLevel::INFO, "Подключено успешно");
        if (on_connected_) on_connected_(connected_server_, "VLESS+Reality");
    } else {
        std::string err = "Ошибка handshake Reality";
        log(LogLevel::ERROR, err);
        if (on_error_) on_error_(err);
        tunnel_.reset();
    }
    return success;
}

bool GlobVPNClient::connectToBestServer() {
    if (servers_.empty()) return false;
    auto best = std::min_element(servers_.begin(), servers_.end(),
        [](const ServerInfo& a, const ServerInfo& b) { return a.load < b.load; });
    reality_config_.public_key = best->public_key;
    reality_config_.short_id = best->short_id;
    return connect(best->name, best->port);
}

void GlobVPNClient::disconnect() {
    if (tunnel_) {
        tunnel_->disconnect();
        tunnel_.reset();
    }
    connected_server_.clear();
    log(LogLevel::INFO, "Отключено от VPN");
    if (on_disconnected_) on_disconnected_();
}

void GlobVPNClient::reconnect() {
    if (!auto_reconnect_) return;
    log(LogLevel::INFO, "Переподключение через " + std::to_string(reconnect_delay_) + " секунд...");
    std::this_thread::sleep_for(std::chrono::seconds(reconnect_delay_));
    connectToBestServer();
}

bool GlobVPNClient::isConnected() const {
    return tunnel_ && tunnel_->isConnected();
}

std::string GlobVPNClient::getStatus() const {
    if (!tunnel_ || !tunnel_->isConnected()) {
        return "{\"connected\":false,\"country\":\"Netherlands\",\"company\":\"GlobVPN\"}";
    }
    auto stats = tunnel_->getStats();
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - stats.connected_since).count();
    
    std::ostringstream oss;
    oss << "{\"connected\":true,\"server\":\"" << connected_server_ 
        << "\",\"protocol\":\"VLESS+Reality\",\"country\":\"Netherlands\","
        << "\"company\":\"GlobVPN\",\"uptime_sec\":" << uptime << ","
        << "\"stats\":{\"tx_bytes\":" << stats.tx_bytes 
        << ",\"rx_bytes\":" << stats.rx_bytes 
        << ",\"latency_ms\":" << stats.latency_ms << "}}";
    return oss.str();
}

ConnectionStats GlobVPNClient::getStats() const {
    return tunnel_ ? tunnel_->getStats() : ConnectionStats{};
}

ssize_t GlobVPNClient::sendData(const std::vector<uint8_t>& data) {
    if (!tunnel_) return -1;
    ssize_t sent = tunnel_->send(data);
    if (sent > 0 && on_stats_) on_stats_(tunnel_->getStats());
    return sent;
}

std::vector<uint8_t> GlobVPNClient::receiveData(size_t size) {
    return tunnel_ ? tunnel_->recv(size) : std::vector<uint8_t>();
}

void GlobVPNClient::onConnecting(std::function<void(const std::string&, int)> callback) {
    on_connecting_ = callback;
}

void GlobVPNClient::onConnected(std::function<void(const std::string&, const std::string&)> callback) {
    on_connected_ = callback;
}

void GlobVPNClient::onDisconnected(std::function<void()> callback) {
    on_disconnected_ = callback;
}

void GlobVPNClient::onError(std::function<void(const std::string&)> callback) {
    on_error_ = callback;
}

void GlobVPNClient::onStats(std::function<void(const ConnectionStats&)> callback) {
    on_stats_ = callback;
}

// ============== Вспомогательные функции ==============
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string generateUUID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) ss << '-';
        else if (i == 14) ss << '4';
        else if (i == 19) ss << (dis(gen) % 4 + 8);
        else ss << dis(gen);
    }
    return ss.str();
}

} // namespace GlobVPN