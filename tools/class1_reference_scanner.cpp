// Run EIPScanner against the cpppo printer or OpENer sample.
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <numeric>
#include <string>
#include <vector>

#include "ConnectionManager.h"
#include "SessionInfo.h"
#include "cip/connectionManager/NetworkConnectionParams.h"
#include "utils/Buffer.h"

using namespace eipScanner;
constexpr int scannerUdpPort = 2223;

class LoopbackRouter : public MessageRouter {
public:
    using MessageRouter::sendRequest;

    cip::MessageRouterResponse sendRequest(
        SessionInfoIf::SPtr session, cip::CipUsint service, const cip::EPath &path,
        const std::vector<uint8_t> &data, const eip::CommonPacketItem::Vec &items) const override {
        if (service != 0x54) {
            return MessageRouter::sendRequest(session, service, path, data, items);
        }
        // Advertise a separate receive port when both stacks run on one host.
        auto addresses = items;
        utils::Buffer address;
        address << sockets::EndPoint("127.0.0.1", scannerUdpPort);
        addresses.emplace_back(eip::CommonPacketItemIds::T2O_SOCKADDR_INFO, address.data());
        return MessageRouter::sendRequest(session, service, path, data, addresses);
    }
};

int main(int argc, char **argv) {
    using namespace eipScanner::cip::connectionManager;

    if (argc != 3 || (std::string(argv[2]) != "cpppo" && std::string(argv[2]) != "opener")) {
        std::cerr << "Usage: class1-reference-scanner TCP_PORT cpppo|opener\n";
        return EXIT_FAILURE;
    }
    const bool opener = std::string(argv[2]) == "opener";
    auto session = std::make_shared<SessionInfo>("127.0.0.1", std::stoi(argv[1]));
    auto router = std::make_shared<LoopbackRouter>();
    ConnectionManager manager(router);

    std::vector<uint8_t> expected = {3, 75, 0, 0, 42, 0, 0, 0};
    if (opener) {
        expected.resize(32);
        std::iota(expected.begin(), expected.end(), 1);
        auto response = router->sendRequest(session, 0x10, cip::EPath(4, 150, 3), expected);
        if (response.getGeneralStatusCode() != cip::GeneralStatusCodes::SUCCESS) {
            std::cerr << "OpENer did not accept the sample assembly write\n";
            return EXIT_FAILURE;
        }
    }

    ConnectionParameters parameters;
    parameters.connectionPath = {0x20, 4, 0x24, 151, 0x2c, 152, 0x2c, 100};
    parameters.priorityTimeTick = 7;
    parameters.timeoutTicks = 10;
    parameters.originatorVendorId = 342;
    parameters.originatorSerialNumber = 0x123456;
    parameters.o2tRPI = parameters.t2oRPI = 50000;
    parameters.o2tNetworkConnectionParams = NetworkConnectionParams::P2P;
    parameters.t2oNetworkConnectionParams = NetworkConnectionParams::P2P | expected.size();
    parameters.transportTypeTrigger = NetworkConnectionParams::CLASS1;

    auto connection = manager.forwardOpen(session, parameters);
    auto io = connection.lock();
    if (!io) {
        return EXIT_FAILURE;
    }
    int received = 0;
    io->setReceiveDataListener([&](auto, auto, const auto &data) {
        if (data == expected) {
            ++received;
        }
    });
    io->setCloseListener([] {});

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (manager.hasOpenConnections() && received < 3 && std::chrono::steady_clock::now() < deadline) {
        manager.handleConnections(std::chrono::milliseconds(10));
    }
    if (manager.hasOpenConnections()) {
        manager.forwardClose(session, connection);
    }
    std::cout << "Received " << received << " matching Class 1 snapshots\n";
    return received >= 3 ? EXIT_SUCCESS : EXIT_FAILURE;
}
