#include "networkmanager.h"

#include <memory>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <queue>

// Deep dip includes
#include <sstream>
#include <iomanip>

#include <SFML/Network.hpp>

static FILE *g_logFile;

static void file_log(std::string str) {
    if (g_logFile) {
        time_t now = time(NULL);
        char buf[sizeof "2000-01-01T00:00:00Z"];
        strftime(buf, sizeof buf, "%FT%TZ", gmtime(&now));
        fprintf(g_logFile, "[%s] %s\n", buf, str.c_str());
        fflush(g_logFile);
    }
}

#ifdef GHOST_GUI
#include <QVector>
#define GHOST_LOG(x) (file_log(x), emit this->OnNewEvent(QString::fromStdString(x)))
#else
#include <stdio.h>
#define GHOST_LOG(x) (file_log(x), printf("[LOG] %s\n", std::string(x).c_str()))
#endif

#define HEARTBEAT_RATE 5000
#define HEARTBEAT_RATE_UDP 1000 // We don't actually respond to these, they're just to keep the connection alive
#define CONNECT_TIMEOUT 1500
#define WEB_RECONNECT_INTERVAL 10000  // Try to reconnect every 10 seconds
#define CONNECTION_TEST_INTERVAL 30000
#define MAX_WEB_RECONNECT_ATTEMPTS 0  // 0 = infinite attempts

static std::chrono::time_point<std::chrono::steady_clock> lastHeartbeat;
static std::chrono::time_point<std::chrono::steady_clock> lastHeartbeatUdp;
static std::chrono::time_point<std::chrono::steady_clock> lastUpdate;

// Deep Dip Vars
static std::chrono::time_point<std::chrono::steady_clock> lastHeightUpdate;
#define HEIGHT_UPDATE_RATE 30000 // update every 30 seconds
#define TOWER_BOTTOM_Z -13103.97f
#define TOWER_TOP_Z 9632.03f
#define TOWER_TOTAL_HEIGHT (TOWER_TOP_Z - TOWER_BOTTOM_Z)
#define TOWER_MAP_NAME "bhop_deep_dip_c_bp1" // replace with real bsp name later

// Helper function to convert world Z to tower height
static float WorldZToTowerHeight(float worldZ) {
    worldZ += 64; // For some reason z-pos is 64 units below what is expected, so adding it arbitrarily to compensate for now

    if (worldZ < TOWER_BOTTOM_Z) return 0.0f; 
    if (worldZ > TOWER_TOP_Z) return TOWER_TOTAL_HEIGHT;
    return worldZ - TOWER_BOTTOM_Z;
}

static bool IsTowerMap(const std::string& mapName) {
    return mapName.find(TOWER_MAP_NAME) != std::string::npos;
}

// Helper function to check if position is at origin (spawn position)
static bool IsAtOrigin(const Vector& position) {
    const float ORIGIN_THRESHOLD = 512.0f;
    return (position.x >= -ORIGIN_THRESHOLD && position.x <= ORIGIN_THRESHOLD &&
            position.y >= -ORIGIN_THRESHOLD && position.y <= ORIGIN_THRESHOLD &&
            position.z >= -ORIGIN_THRESHOLD && position.z <= ORIGIN_THRESHOLD);
}

//DataGhost

sf::Packet& operator>>(sf::Packet& packet, Vector& vec)
{
    return packet >> vec.x >> vec.y >> vec.z;
}

sf::Packet& operator<<(sf::Packet& packet, const Vector& vec)
{
    return packet << vec.x << vec.y << vec.z;
}

sf::Packet& operator>>(sf::Packet& packet, DataGhost& dataGhost)
{
    uint8_t data;
    auto &ret = packet >> dataGhost.position >> dataGhost.view_angle >> data;
    dataGhost.view_offset = (float)(data & 0x7F);
    dataGhost.grounded = (data & 0x80) != 0;
    return ret;
}
sf::Packet& operator<<(sf::Packet& packet, const DataGhost& dataGhost)
{
    uint8_t data = ((int)dataGhost.view_offset & 0x7F) | (dataGhost.grounded ? 0x80 : 0x00);
    return packet << dataGhost.position << dataGhost.view_angle << data;
}

//HEADER

sf::Packet& operator>>(sf::Packet& packet, HEADER& header)
{
    sf::Uint8 tmp;
    packet >> tmp;
    header = static_cast<HEADER>(tmp);
    return packet;
}

sf::Packet& operator<<(sf::Packet& packet, const HEADER& header)
{
    return packet << static_cast<sf::Uint8>(header);
}

// Color

sf::Packet& operator>>(sf::Packet& packet, Color &col)
{
    return packet >> col.r >> col.g >> col.b;
}

sf::Packet& operator<<(sf::Packet& packet, const Color &col)
{
    return packet << col.r << col.g << col.b;
}

NetworkManager::NetworkManager(const char *logfile)
    : isRunning(false)
    , serverPort(53000)
    , serverIP("localhost")
    , lastID(1) //0 == server
    , webServerConnected(false)
    , enableWebHeightUpdates(false)
    , webReconnectAttempts(0)
    , shouldAttemptWebReconnect(false)
{
    g_logFile = logfile ? fopen(logfile, "w") : NULL;
    lastWebReconnectAttempt = std::chrono::steady_clock::now();
}

NetworkManager::~NetworkManager() {
    if (g_logFile) fclose(g_logFile);
}

static std::mutex g_server_queue_mutex;
static std::vector<std::function<void()>> g_server_queue;

void NetworkManager::ScheduleServerThread(std::function<void()> func) {
    g_server_queue_mutex.lock();
    g_server_queue.push_back(func);
    g_server_queue_mutex.unlock();
}

Client* NetworkManager::GetClientByID(sf::Uint32 ID)
{
    for (auto& client : this->clients) {
        if (client.ID == ID) {
            return &client;
        }
    }

    return nullptr;
}

bool NetworkManager::StartServer(const int port)
{
    if (this->udpSocket.bind(port) != sf::Socket::Done) {
        this->udpSocket.unbind();
        this->listener.close();
        return false;
    }

    if (this->listener.listen(port) != sf::Socket::Done) {
        this->udpSocket.unbind();
        this->listener.close();
        return false;
    }

    this->serverPort = port;
    this->udpSocket.setBlocking(false);

    this->selector.add(this->listener);

    this->serverThread = std::thread(&NetworkManager::RunServer, this);
    this->serverThread.detach();

    GHOST_LOG("Server started on " + this->serverIP.toString() + " (public IP: " + sf::IpAddress::getPublicAddress().toString() + ") on port " + std::to_string(this->serverPort));

    return true;
}

void NetworkManager::StopServer()
{
    if (this->isRunning) {
        this->isRunning = false;
        return;
    }

    while (this->clients.size() > 0) {
        this->DisconnectPlayer(this->clients.back(), "server stopped");
    }

    this->isRunning = false;
    this->clients.clear();

    GHOST_LOG("Server stopped!");
}

void NetworkManager::DisconnectPlayer(Client& c, const char *reason)
{
    sf::Packet packet;
    packet << HEADER::DISCONNECT << c.ID;
    
    // Capture client data BEFORE any modifications
    bool shouldNotifyWebServer = !c.spectator;
    sf::Uint32 clientID = c.ID;
    std::string clientName = c.name;
    float clientMaxHeight = c.maxHeight;
    Vector clientPosition = c.data.position;
    std::string clientMap = c.currentMap;
    
    int id = 0;
    int toErase = -1;
    for (; id < this->clients.size(); ++id) {
        if (this->clients[id].IP != c.IP) {
            this->clients[id].tcpSocket->send(packet);
        } else {
            GHOST_LOG("Player " + this->clients[id].name + " has disconnected! Reason: " + reason);
            this->selector.remove(*this->clients[id].tcpSocket);
            this->clients[id].tcpSocket->disconnect();
            toErase = id;
        }
    }

    if (toErase != -1) {
        this->clients.erase(this->clients.begin() + toErase);
    }
    
    // Send web server notification using the captured data
    if (shouldNotifyWebServer) {
        this->SendPlayerDisconnectToWebServer(clientID, clientName, clientMaxHeight, 
                                            clientPosition, clientMap, reason);
    }
}

std::vector<Client *> NetworkManager::GetPlayerByName(std::string name)
{
    std::vector<Client *> matches;
    for (auto &client : this->clients) {
        if (client.name == name) {
            matches.push_back(&client);
        }
    }

    return matches;
}

void NetworkManager::StartCountdown(const std::string preCommands, const std::string postCommands, const int duration)
{
    sf::Packet packet;
    packet << HEADER::COUNTDOWN << sf::Uint32(0) << sf::Uint8(0) << sf::Uint32(duration) << preCommands << postCommands;
    for (auto& client : this->clients) {
        client.tcpSocket->send(packet);
    }
    this->acceptingPlayers = false;
}

bool NetworkManager::ShouldBlockConnection(const sf::IpAddress& ip)
{
    if (std::find_if(this->clients.begin(), this->clients.end(), [&ip](const Client& c) { return ip == c.IP; }) != this->clients.end()) {
        return true;
    }

    for (auto banned : this->bannedIps) {
        if (ip == banned) return true;
    }

    return false;
}

void NetworkManager::CheckConnection()
{
    Client client;
    client.tcpSocket = std::make_unique<sf::TcpSocket>();

    if (this->listener.accept(*client.tcpSocket) != sf::Socket::Done) {
        return;
    }

    if (this->ShouldBlockConnection(client.tcpSocket->getRemoteAddress())) {
        return;
    }

    sf::Packet connection_packet;
    sf::SocketSelector conn_selector;
    conn_selector.add(*client.tcpSocket);
    if (!conn_selector.wait(sf::milliseconds(CONNECT_TIMEOUT))) {
        return;
    }

    client.tcpSocket->receive(connection_packet);

    HEADER header;
    unsigned short int port;
    std::string name;
    DataGhost data;
    std::string model_name;
    std::string level_name;
    bool TCP_only;
    Color col;
    bool spectator;

    connection_packet >> header >> port >> name >> data >> model_name >> level_name >> TCP_only >> col >> spectator;

    if (!(spectator ? this->acceptingSpectators : this->acceptingPlayers)) {
        // Refuse connection, since we're not currently accepting this type
        return;
    }

    client.ID = this->lastID++;
    client.IP = client.tcpSocket->getRemoteAddress();
    client.port = port;
    client.name = name;
    client.data = data;
    client.modelName = model_name;
    client.currentMap = level_name;
    client.TCP_only = TCP_only;
    client.color = col;
    client.returnedHeartbeat = true; // Make sure they don't get immediately disconnected; their heartbeat starts on next beat
    client.missedLastHeartbeat = false;
    client.spectator = spectator; //People can break the run when joining in the middle of a run

    this->selector.add(*client.tcpSocket);

    sf::Packet packet_new_client;

    packet_new_client << client.ID; //Send Client's ID
    packet_new_client << sf::Uint32(this->clients.size()); //Send every players informations
    for (auto& c : this->clients) {
        packet_new_client << c.ID << c.name.c_str() << c.data << c.modelName.c_str() << c.currentMap.c_str() << c.color << c.spectator;
    }

    client.tcpSocket->send(packet_new_client);

    sf::Packet packet_notify_all; // Notify every players of a new connection
    packet_notify_all << HEADER::CONNECT << client.ID << client.name.c_str() << client.data << client.modelName.c_str() << client.currentMap.c_str() << client.color << client.spectator;

    for (auto& c : this->clients) {
        c.tcpSocket->send(packet_notify_all);
    }

    GHOST_LOG("New player: " + client.name + " (" + (client.spectator ? "spectator" : "player") + ") @ " + client.IP.toString() + ":" + std::to_string(client.port));

    this->clients.push_back(std::move(client));

    if (!client.spectator) {
        this->SendPlayerConnectToWebServer(this->clients.back());
    }
}

void NetworkManager::ReceiveUDPUpdates(std::vector<std::pair<unsigned short, sf::Packet>>& buffer)
{
    sf::Socket::Status status;
    do {
        sf::Packet packet;
        sf::IpAddress ip;
        unsigned short int port;
        status = this->udpSocket.receive(packet, ip, port);
        if (status == sf::Socket::Done) {
            buffer.push_back({ port, packet });
        }
    } while (status == sf::Socket::Done);
}

void NetworkManager::Treat(sf::Packet& packet, unsigned short udp_port)
{
    HEADER header;
    sf::Uint32 ID;
    packet >> header >> ID;

    if (udp_port != 0) {
        auto client = this->GetClientByID(ID);
        if (client) client->port = udp_port;
    }

    switch (header) {
    case HEADER::NONE:
        break;
    case HEADER::PING: {
        sf::Packet ping_packet;
        ping_packet << HEADER::PING;
        auto client = this->GetClientByID(ID);
        if (client) {
            client->tcpSocket->send(ping_packet);
        }
    }
        break;
    case HEADER::DISCONNECT: {
        auto client = this->GetClientByID(ID);
        if (client) {
            this->DisconnectPlayer(*client, "requested");
        }
        break;
    }

    // case HEADER::STOP_SERVER:
    //     this->StopServer();
    //     break;

    case HEADER::MAP_CHANGE: {
        for (auto& client : this->clients) {
            if (client.ID != ID) {
                client.tcpSocket->send(packet);
            }
        }
        auto client = this->GetClientByID(ID);
        if (client) {
            std::string map;
            packet >> map;
            client->currentMap = map;
            GHOST_LOG(client->name + " is now on " + map);
        }

        break;
    }
    case HEADER::HEART_BEAT: {
        auto client = this->GetClientByID(ID);
        if (client) {
            uint32_t token;
            packet >> token;
            if (token == client->heartbeatToken) {
                // Good heartbeat!
                client->returnedHeartbeat = true;
            }
            break;
        }
    }
    case HEADER::MESSAGE: {
        auto client = this->GetClientByID(ID);
        if (client) {
            std::string message;
            packet >> message;
            GHOST_LOG("[message] " + client->name + ": " + message);
            for (auto& other : this->clients) {
                other.tcpSocket->send(packet);
            }
        }
        break;
    }
    case HEADER::COUNTDOWN: {
        sf::Packet packet_confirm;
        packet_confirm << HEADER::COUNTDOWN << sf::Uint32(0) << sf::Uint8(1);
        auto client = this->GetClientByID(ID);
        if (client) {
            client->tcpSocket->send(packet_confirm);
        }
        break;
    }
    case HEADER::SPEEDRUN_FINISH: {
        for (auto& client : this->clients) {
            client.tcpSocket->send(packet);
        }
        break;
    }
    case HEADER::MODEL_CHANGE: {
        std::string modelName;
        packet >> modelName;
        auto client = this->GetClientByID(ID);
        if (client) {
            client->modelName = modelName;
            for (auto& other : this->clients) {
                other.tcpSocket->send(packet);
            }
        }
        break;
    }
    case HEADER::COLOR_CHANGE: {
        Color col;
        packet >> col;
        auto client = this->GetClientByID(ID);
        if (client) {
            client->color = col;
            for (auto& other : this->clients) {
                other.tcpSocket->send(packet);
            }
        }
        break;
    }
    case HEADER::UPDATE: {
        DataGhost data;
        packet >> data;
        auto client = this->GetClientByID(ID);
        if (client) {
            client->data = data;

            // Only track height for non-spectators on tower map, and not when they're at the origin
            if (!client->spectator && IsTowerMap(client->currentMap) && !IsAtOrigin(data.position)) {
                float towerHeight = WorldZToTowerHeight(data.position.z);
                float heightDelta = towerHeight - client->lastHeight;
                if (towerHeight > client->maxHeight && heightDelta <= 300.0f && heightDelta != 0.0f) {
                    client->maxHeight = towerHeight;
                }
                client->lastHeight = towerHeight;
            }
        }
        break;
    }

    case HEADER::HEIGHT_UPDATE: {
        break;
        // For receiving height updates from clients if needed
        // Will just track server-side for now
    }
    default:
        break;
    }
}

// DEEP DIP METHOD TO TRACK HEIGHT
void NetworkManager::SendHeightUpdates() {
    // Find players with changes
    std::vector<Client*> playersOnTower;
    for (auto& client : this->clients) {
        if (!client.spectator && IsTowerMap(client.currentMap)) {
            playersOnTower.push_back(&client);
        }
    }
    if (playersOnTower.empty()) return;

    this->SendHeightJsonDataToWebServer(playersOnTower);

    // Log height updates for testing
    for (auto* client : playersOnTower) {
        float currentHeight = IsAtOrigin(client->data.position) ? 0.0f : WorldZToTowerHeight(client->data.position.z); 
        float heightDelta = currentHeight - client->lastHeightUpdate;
        if (heightDelta <= 2000 && heightDelta != 0) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(2);
            float maxPercentage = (client->maxHeight / TOWER_TOTAL_HEIGHT) * 100.0f;
            float currentPercentage = (currentHeight / TOWER_TOTAL_HEIGHT) * 100.0f;
            oss << "HEIGHT_UPDATE " << client->name << " (ID:" << client->ID 
                << ") max: " << client->maxHeight << " units (" << maxPercentage << "%) "
                << "current: " << currentHeight << " units (" << currentPercentage << "%)";
            GHOST_LOG(oss.str());
        }
        client->lastHeightUpdate = currentHeight;
    }
}

void NetworkManager::BanClientIP(Client &cl) {
    this->bannedIps.push_back(cl.IP);
    this->DisconnectPlayer(cl, "banned");
}

void NetworkManager::ServerMessage(const char *msg) {
    GHOST_LOG(std::string("[server message] ") + msg);
    sf::Packet packet;
    packet << HEADER::MESSAGE << sf::Uint32(0) << msg;
    for (auto &client : this->clients) {
        client.tcpSocket->send(packet);
    }
}

//Threaded function
void NetworkManager::RunServer()
{
    this->isRunning = true;
    this->clock.restart();

    // Initialize the height update timer
    lastHeightUpdate = std::chrono::steady_clock::now();
    this->webServerConnected = false;
    this->enableWebHeightUpdates = false;

    while (this->isRunning) {
        auto now = std::chrono::steady_clock::now();
        if (now > lastHeartbeat + std::chrono::milliseconds(HEARTBEAT_RATE)) {
            this->DoHeartbeats();
            lastHeartbeat = now;
        }

        if (now > lastHeartbeatUdp + std::chrono::milliseconds(HEARTBEAT_RATE_UDP)) {
            for (auto &client : this->clients) {
                if (!client.TCP_only) {
                    sf::Packet packet;
                    packet << HEADER::HEART_BEAT << sf::Uint32(client.ID) << sf::Uint32(0);
                    this->udpSocket.send(packet, client.IP, client.port);
                }
            }
            lastHeartbeatUdp = now;
        }

        // Deep Dip Height Updates, every 5 seconds
        if (now > lastHeightUpdate + std::chrono::milliseconds(HEIGHT_UPDATE_RATE)) {
            this->SendHeightUpdates();
            lastHeightUpdate = now;
        }

        // Web server reconnection
        if (!this->webServerConnected && this->shouldAttemptWebReconnect) {
            this->AttemptWebReconnection();
        }

        // Periodically test connection health
        static std::chrono::time_point<std::chrono::steady_clock> lastConnectionTest = std::chrono::steady_clock::now();
        if (now > lastConnectionTest + std::chrono::milliseconds(CONNECTION_TEST_INTERVAL)) {
            if (this->webServerConnected) {
                // Only test if we actually have clients that might generate data
                bool hasActiveClients = false;
                for (auto& client : this->clients) {
                    if (!client.spectator && IsTowerMap(client.currentMap)) {
                        hasActiveClients = true;
                        break;
                    }
                }
                
                if (hasActiveClients && !this->TestWebServerConnection()) {
                    GHOST_LOG("Web server connection lost - will attempt to reconnect");
                    this->shouldAttemptWebReconnect = true;
                }
            }
            lastConnectionTest = now;
        }

        if (now > lastUpdate + std::chrono::milliseconds(50)) {
            // Send bulk update packet
            sf::Packet packet;
            packet << HEADER::UPDATE << sf::Uint32(0) << sf::Uint32(this->clients.size());
            for (auto &client : this->clients) {
                packet << sf::Uint32(client.ID) << client.data;
            }
            for (auto &client : this->clients) {
                if (client.TCP_only) {
                    client.tcpSocket->send(packet);
                } else {
                    this->udpSocket.send(packet, client.IP, client.port);
                }
            }
            lastUpdate = now;
        }

        //UDP
        std::vector<std::pair<unsigned short, sf::Packet>> buffer;
        this->ReceiveUDPUpdates(buffer);
        for (auto [port, packet] : buffer) {
            this->Treat(packet, port);
        }

        if (this->selector.wait(sf::milliseconds(50))) { // If a packet is received
            if (this->selector.isReady(this->listener)) {
                this->CheckConnection(); //A player wants to connect
            } else {
                for (int i = 0; i < this->clients.size(); ++i) {
                    if (this->selector.isReady(*this->clients[i].tcpSocket)) {
                        sf::Packet packet;
                        sf::Socket::Status status = this->clients[i].tcpSocket->receive(packet);
                        if (status == sf::Socket::Disconnected) {
                            this->DisconnectPlayer(this->clients[i], "socket died");
                            --i;
                            continue;
                        }
                        this->Treat(packet, 0);
                    }
                }
            }
        }

        g_server_queue_mutex.lock();
        for (auto &f : g_server_queue) {
            f();
        }
        g_server_queue.clear();
        g_server_queue_mutex.unlock();
    }

    this->StopServer();
}

void NetworkManager::DoHeartbeats()
{
    // We don't disconnect clients in the loop; else, the loop will have
    // UB
    for (size_t i = 0; i < this->clients.size(); ++i) {
        auto &client = this->clients[i];
        if (!client.returnedHeartbeat && client.missedLastHeartbeat) {
            // Client didn't return heartbeat in time; sever connection
            this->DisconnectPlayer(client, "missed two heartbeats");
            --i;
        } else {
            // Send a heartbeat
            client.heartbeatToken = rand();
            client.missedLastHeartbeat = !client.returnedHeartbeat;
            client.returnedHeartbeat = false;
            sf::Packet packet;
            packet << HEADER::HEART_BEAT << sf::Uint32(client.ID) << sf::Uint32(client.heartbeatToken);
            if (client.tcpSocket->send(packet) == sf::Socket::Disconnected) {
                this->DisconnectPlayer(client, "socket died");
                --i;
            }
        }
    }
}

bool NetworkManager::ConnectToWebServer(const std::string& ip, unsigned short port) {
    this->webServerIP = sf::IpAddress(ip);
    this->webServerPort = port;
    this->webReconnectAttempts = 0;
    this->shouldAttemptWebReconnect = true;
    this->lastWebReconnectAttempt = std::chrono::steady_clock::now();
    
    if (this->webSocket.connect(this->webServerIP, this->webServerPort, sf::seconds(5)) == sf::Socket::Done) {
        this->webServerConnected = true;
        this->shouldAttemptWebReconnect = false; // Stop trying since we're connected
        GHOST_LOG("Connected to Deep Dip Web Server: " + ip + ":" + std::to_string(port));
        return true;
    }
    
    this->webServerConnected = false;
    GHOST_LOG("Failed to connect to Deep Dip Web Server: " + ip + ":" + std::to_string(port) + " - will retry automatically");
    return false;
}

void NetworkManager::DisconnectFromWebServer() {
    if (this->webServerConnected) {
        this->webSocket.disconnect();
        this->webServerConnected = false;
        GHOST_LOG("Disconnected from Deep Dip Web Server");
    }
}

bool NetworkManager::TestWebServerConnection() {
    if (!this->webServerConnected) {
        return false;
    }
    
    sf::Socket::Status status = this->webSocket.getLocalPort() != 0 ? sf::Socket::Done : sf::Socket::Disconnected;
    
    if (status == sf::Socket::Disconnected) {
        this->webServerConnected = false;
        return false;
    }
    
    return true;
}

void NetworkManager::SendServerStatusToWebServer() {
    if (!this->webServerConnected || !this->enableWebHeightUpdates) {
        return;
    }

    try {
        std::ostringstream json;
        json << "{\"type\":\"server_status\""
             << ",\"timestamp\":" << time(NULL)
             << ",\"server_port\":" << this->serverPort
             << ",\"connected_players\":[";

        bool first = true;
        for (const auto& client : this->clients) {
            if (!first) json << ",";
            json << "{"
                 << "\"id\":" << client.ID
                 << ",\"name\":\"" << client.name << "\""
                 << ",\"spectator\":" << (client.spectator ? "true" : "false")
                 << ",\"map\":\"" << client.currentMap << "\""
                 << "}";
            first = false;
        }

        json << "]}";

        std::string jsonStr = json.str();
        if (first) {
            // No players met the criteria, don't send empty update
            return;
        }
        sf::Uint32 dataSize = static_cast<sf::Uint32>(jsonStr.length());

        if (this->webSocket.send(&dataSize, sizeof(dataSize)) != sf::Socket::Done ||
            this->webSocket.send(jsonStr.c_str(), dataSize) != sf::Socket::Done) {
            GHOST_LOG("Failed to send server status to web server - connection lost");
            this->webServerConnected = false;
            this->shouldAttemptWebReconnect = true;
            return;
        }

        GHOST_LOG("Sent server status to web server: " + std::to_string(this->clients.size()) + " players");

    } catch (...) {
        GHOST_LOG("Exception occurred while sending server status");
        this->webServerConnected = false;
        this->shouldAttemptWebReconnect = true;
    }
}

void NetworkManager::AttemptWebReconnection() {
    auto now = std::chrono::steady_clock::now();
    
    // Don't attempt reconnection too frequently
    if (now < lastWebReconnectAttempt + std::chrono::milliseconds(WEB_RECONNECT_INTERVAL)) {
        return;
    }
    
    // Check if we've hit max attempts (if limit is set)
    if (MAX_WEB_RECONNECT_ATTEMPTS > 0 && webReconnectAttempts >= MAX_WEB_RECONNECT_ATTEMPTS) {
        GHOST_LOG("Max web server reconnection attempts reached. Giving up.");
        shouldAttemptWebReconnect = false;
        return;
    }
    
    lastWebReconnectAttempt = now;
    webReconnectAttempts++;
    
    GHOST_LOG("Attempting web server reconnection (attempt " + std::to_string(webReconnectAttempts) + ")...");
    
    // Properly disconnect and cleanup the socket
    if (this->webSocket.getLocalPort() != 0) {
        this->webSocket.disconnect();
    }
    this->webServerConnected = false;

    // Small delay to ensure socket cleanup
    sf::sleep(sf::milliseconds(100));
    
    // Attempt to reconnect
    if (this->webSocket.connect(this->webServerIP, this->webServerPort, sf::seconds(5)) == sf::Socket::Done) {
        this->webServerConnected = true;
        this->webReconnectAttempts = 0; // reset on success
        this->shouldAttemptWebReconnect = false;
        GHOST_LOG("Successfully reconnected to Deep Dip Web Server!");

        this->SendServerStatusToWebServer();
    } else {
        this->webServerConnected = false;
        GHOST_LOG("Failed to reconnect to Deep Dip Web Server (attempt " + std::to_string(webReconnectAttempts) + ")");
    }
}

void NetworkManager::SetWebHeightUpdates(bool enabled) {
    this->enableWebHeightUpdates = enabled;
}

void NetworkManager::SendHeightJsonDataToWebServer(const std::vector<Client*>& playersWithChanges) {
    if (!this->webServerConnected || !this->enableWebHeightUpdates || playersWithChanges.empty()) {
        return;
    }
    
    try {
        std::ostringstream json;
        json << "{\"timestamp\":" << time(NULL) 
             << ",\"server_port\":" << this->serverPort
             << ",\"players\":[";

        bool first = true;
        
        for (const auto* client : playersWithChanges) {
            float currentHeight = IsAtOrigin(client->data.position) ? 0.0f : WorldZToTowerHeight(client->data.position.z); 
            float heightDelta = currentHeight - client->lastHeightUpdate;
            if (heightDelta <= 2000 && heightDelta != 0) {
                if (!first) json << ",";

                json << "{\"id\":" << client->ID 
                     << ",\"name\":\"" << client->name << "\""
                     << ",\"max_height\":" << client->maxHeight
                     << ",\"current_height\":" << currentHeight
                     << ",\"max_percentage\":" << (client->maxHeight / TOWER_TOTAL_HEIGHT * 100.0f)
                     << ",\"current_percentage\":" << (currentHeight / TOWER_TOTAL_HEIGHT * 100.0f)
                     << ",\"map\":\"" << client->currentMap << "\"}";
            
                first = false;
            }
        }
        json << "]}";
        
        // Send JSON as string with length prefix
        std::string jsonStr = json.str();
        if (first) {
            // No players met the criteria, don't send empty update
            return;
        }

        sf::Uint32 dataSize = static_cast<sf::Uint32>(jsonStr.length());
        
        if (this->webSocket.send(&dataSize, sizeof(dataSize)) != sf::Socket::Done ||
            this->webSocket.send(jsonStr.c_str(), dataSize) != sf::Socket::Done) {
            GHOST_LOG("Failed to send height data to Deep Dip Web Server - connection lost");
            this->webServerConnected = false;
            this->shouldAttemptWebReconnect = true;
            return;
        }
        
        GHOST_LOG("Sent height data to Deep Dip Web Server: " + std::to_string(playersWithChanges.size()) + " players");
        
    } catch (...) {
        GHOST_LOG("Exception occurred while sending to Deep Dip Web Server");
        this->webServerConnected = false;
    }
}

void NetworkManager::SendPlayerConnectToWebServer(Client& client) {
    if (!this->webServerConnected || !this->enableWebHeightUpdates) {
        return;
    }

    try {
        std::ostringstream json;
        json << "{\"type\":\"player_connect\""
             << ",\"timestamp\":" << time(NULL)
             << ",\"server_port\":" << this->serverPort
             << ",\"player\":{"
             << "\"id\":" << client.ID
             << ",\"name\":\"" << client.name << "\""
             << ",\"ip\":\"" << client.IP.toString() << "\""
             << ",\"port\":" << client.port
             << ",\"model\":\"" << client.modelName << "\""
             << ",\"map\":\"" << client.currentMap << "\""
             << ",\"tcp_only\":" << (client.TCP_only ? "true" : "false")
             << ",\"spectator\":" << (client.spectator ? "true" : "false")
             << ",\"color\":{\"r\":" << (int)client.color.r 
             << ",\"g\":" << (int)client.color.g 
             << ",\"b\":" << (int)client.color.b << "}"
             << "}}";

        std::string jsonStr = json.str();
        sf::Uint32 dataSize = static_cast<sf::Uint32>(jsonStr.length());

        if (this->webSocket.send(&dataSize, sizeof(dataSize)) != sf::Socket::Done ||
            this->webSocket.send(jsonStr.c_str(), dataSize) != sf::Socket::Done) {
            GHOST_LOG("Failed to send connect notification to web server - connection lost");
            this->webServerConnected = false;
            this->shouldAttemptWebReconnect = true;
            return;
        }

        GHOST_LOG("Sent connect notification for " + client.name + " to web server");

    } catch (...) {
        GHOST_LOG("Exception occurred while sending connect notification");
        this->webServerConnected = false;
    }
}

void NetworkManager::SendPlayerDisconnectToWebServer(sf::Uint32 clientID, const std::string& clientName, 
                                                   float maxHeight, const Vector& position, 
                                                   const std::string& currentMap, const char* reason) {
    if (!this->webServerConnected || !this->enableWebHeightUpdates) {
        return;
    }

    try {
        std::ostringstream json;
        json << "{\"type\":\"player_disconnect\""
             << ",\"timestamp\":" << time(NULL)
             << ",\"server_port\":" << this->serverPort
             << ",\"player\":{"
             << "\"id\":" << clientID
             << ",\"name\":\"" << clientName << "\""
             << ",\"reason\":\"" << reason << "\""
             << ",\"final_max_height\":" << maxHeight;

        float currentHeight = IsAtOrigin(position) ? 0.0f : WorldZToTowerHeight(position.z);
        float maxPercentage = (maxHeight / TOWER_TOTAL_HEIGHT) * 100.0f;
        float currentPercentage = (currentHeight / TOWER_TOTAL_HEIGHT) * 100.0f;
        json << ",\"current_height\":" << currentHeight
             << ",\"max_percentage\":" << maxPercentage
             << ",\"current_percentage\":" << currentPercentage;

        json << "}}";

        std::string jsonStr = json.str();
        sf::Uint32 dataSize = static_cast<sf::Uint32>(jsonStr.length());
        
        if (this->webSocket.send(&dataSize, sizeof(dataSize)) != sf::Socket::Done ||
            this->webSocket.send(jsonStr.c_str(), dataSize) != sf::Socket::Done) {
            GHOST_LOG("Failed to send disconnect notification to web server - connection lost");
            this->webServerConnected = false;
            this->shouldAttemptWebReconnect = true;
            return;
        }

        GHOST_LOG("Sent disconnect notification for " + clientName + " to web server");

    } catch (...) {
        GHOST_LOG("Exception occurred while sending disconnect notification");
        this->webServerConnected = false;
    }
}
