import Foundation
import CoreBluetooth

/// GATT identifiers from ISO/IEC 18013-5 §8.3.3.1.1.
public enum AKMDocBLE {
    // mdoc peripheral server mode (mdoc = GATT server)
    public static let peripheralState = CBUUID(string: "00000001-A123-48CE-896B-4C76973373E6")
    public static let peripheralClient2Server = CBUUID(string: "00000002-A123-48CE-896B-4C76973373E6")
    public static let peripheralServer2Client = CBUUID(string: "00000003-A123-48CE-896B-4C76973373E6")
    // mdoc central client mode (reader = GATT server)
    public static let centralState = CBUUID(string: "00000005-A123-48CE-896B-4C76973373E6")
    public static let centralClient2Server = CBUUID(string: "00000006-A123-48CE-896B-4C76973373E6")
    public static let centralServer2Client = CBUUID(string: "00000007-A123-48CE-896B-4C76973373E6")
    public static let centralIdent = CBUUID(string: "00000008-A123-48CE-896B-4C76973373E6")

    public static let stateStart: UInt8 = 0x01
    public static let stateEnd: UInt8 = 0x02
}

/// Transport events.
public enum AKTransportEvent: Sendable, Equatable {
    case waiting
    case connected
    case message(Data)
    case disconnected
    case failed(String)
}

/// A message transport for an mdoc session.
public protocol AKMDocTransport: AnyObject, Sendable {
    var events: AsyncStream<AKTransportEvent> { get }
    func start()
    func send(_ message: Data)
    /// Signal end of session (State = 0x02) and tear down.
    func stop()
}

/// BLE message framing: each chunk starts with 0x01 (more follows) or 0x00 (last).
public enum AKBLEFraming {
    public static func chunks(_ message: Data, chunkSize: Int) -> [Data] {
        let size = max(1, chunkSize - 1)
        var out: [Data] = []
        var index = message.startIndex
        repeat {
            let end = min(message.endIndex, index + size)
            let last = end == message.endIndex
            out.append(Data([last ? 0x00 : 0x01]) + message[index..<end])
            index = end
        } while index < message.endIndex
        return out
    }

    public final class Reassembler: @unchecked Sendable {
        private var buffer = Data()
        private let maxSize: Int
        public init(maxSize: Int = 4 * 1024 * 1024) { self.maxSize = maxSize }

        /// Returns a complete message when the last chunk arrives.
        public func append(_ chunk: Data) throws -> Data? {
            guard let flag = chunk.first else { return nil }
            buffer.append(chunk.dropFirst())
            guard buffer.count <= maxSize else { buffer.removeAll(); throw AKPresentationError.session("BLE message too large") }
            switch flag {
            case 0x00:
                defer { buffer = Data() }
                return buffer
            case 0x01:
                return nil
            default:
                buffer.removeAll()
                throw AKPresentationError.session("invalid BLE chunk header")
            }
        }
    }
}

// MARK: - mdoc peripheral server mode

/// The mdoc advertises the engagement UUID and acts as GATT server.
public final class AKBLEPeripheralServer: NSObject, AKMDocTransport, CBPeripheralManagerDelegate, @unchecked Sendable {

    public let events: AsyncStream<AKTransportEvent>
    private let continuation: AsyncStream<AKTransportEvent>.Continuation
    private let serviceUUID: CBUUID
    private let queue = DispatchQueue(label: "ak.mdoc.ble.peripheral")
    private var manager: CBPeripheralManager?
    private var state: CBMutableCharacteristic?
    private var client2Server: CBMutableCharacteristic?
    private var server2Client: CBMutableCharacteristic?
    private var central: CBCentral?
    private var outgoing: [Data] = []
    private let reassembler = AKBLEFraming.Reassembler()

    public init(serviceUUID: UUID) {
        self.serviceUUID = CBUUID(nsuuid: serviceUUID)
        var c: AsyncStream<AKTransportEvent>.Continuation!
        self.events = AsyncStream { c = $0 }
        self.continuation = c
        super.init()
    }

    public func start() {
        queue.async {
            self.manager = CBPeripheralManager(delegate: self, queue: self.queue)
        }
    }

    public func send(_ message: Data) {
        queue.async {
            let size = self.central?.maximumUpdateValueLength ?? 20
            self.outgoing.append(contentsOf: AKBLEFraming.chunks(message, chunkSize: size))
            self.flush()
        }
    }

    public func stop() {
        queue.async {
            if let m = self.manager, let s = self.state, let c = self.central {
                _ = m.updateValue(Data([AKMDocBLE.stateEnd]), for: s, onSubscribedCentrals: [c])
            }
            self.manager?.stopAdvertising()
            self.manager?.removeAllServices()
            self.manager?.delegate = nil
            self.manager = nil
            self.continuation.yield(.disconnected)
            self.continuation.finish()
        }
    }

    private func flush() {
        guard let m = manager, let s2c = server2Client, let c = central else { return }
        while let next = outgoing.first {
            guard m.updateValue(next, for: s2c, onSubscribedCentrals: [c]) else { return } // resumes in isReady
            outgoing.removeFirst()
        }
    }

    // MARK: CBPeripheralManagerDelegate

    public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            let state = CBMutableCharacteristic(type: AKMDocBLE.peripheralState, properties: [.notify, .writeWithoutResponse],
                                                value: nil, permissions: [.writeable])
            let c2s = CBMutableCharacteristic(type: AKMDocBLE.peripheralClient2Server, properties: [.writeWithoutResponse],
                                              value: nil, permissions: [.writeable])
            let s2c = CBMutableCharacteristic(type: AKMDocBLE.peripheralServer2Client, properties: [.notify],
                                              value: nil, permissions: [.readable])
            let service = CBMutableService(type: serviceUUID, primary: true)
            service.characteristics = [state, c2s, s2c]
            self.state = state
            self.client2Server = c2s
            self.server2Client = s2c
            peripheral.add(service)
        case .unauthorized:
            continuation.yield(.failed("Bluetooth permission denied"))
        case .poweredOff:
            continuation.yield(.failed("Bluetooth is turned off"))
        case .unsupported:
            continuation.yield(.failed("Bluetooth LE is not supported"))
        default:
            break
        }
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let e = error { continuation.yield(.failed(e.localizedDescription)); return }
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [serviceUUID]])
        continuation.yield(.waiting)
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        self.central = central
        flush()
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            guard let value = request.value else { continue }
            if request.characteristic.uuid == AKMDocBLE.peripheralState {
                self.central = request.central
                if value.first == AKMDocBLE.stateStart {
                    peripheral.stopAdvertising()
                    continuation.yield(.connected)
                } else if value.first == AKMDocBLE.stateEnd {
                    continuation.yield(.disconnected)
                }
            } else if request.characteristic.uuid == AKMDocBLE.peripheralClient2Server {
                self.central = request.central
                do {
                    if let message = try reassembler.append(value) { continuation.yield(.message(message)) }
                } catch {
                    continuation.yield(.failed(error.localizedDescription))
                }
            }
        }
        if let first = requests.first, first.characteristic.properties.contains(.write) {
            peripheral.respond(to: first, withResult: .success)
        }
    }

    public func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        flush()
    }
}

// MARK: - mdoc central client mode

/// The reader advertises; the mdoc scans, connects and checks the Ident characteristic.
public final class AKBLECentralClient: NSObject, AKMDocTransport, CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {

    public let events: AsyncStream<AKTransportEvent>
    private let continuation: AsyncStream<AKTransportEvent>.Continuation
    private let serviceUUID: CBUUID
    private let expectedIdent: Data
    private let queue = DispatchQueue(label: "ak.mdoc.ble.central")
    private var manager: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var chars: [CBUUID: CBCharacteristic] = [:]
    private var outgoing: [Data] = []
    private let reassembler = AKBLEFraming.Reassembler()

    public init(serviceUUID: UUID, expectedIdent: Data) {
        self.serviceUUID = CBUUID(nsuuid: serviceUUID)
        self.expectedIdent = expectedIdent
        var c: AsyncStream<AKTransportEvent>.Continuation!
        self.events = AsyncStream { c = $0 }
        self.continuation = c
        super.init()
    }

    public func start() {
        queue.async { self.manager = CBCentralManager(delegate: self, queue: self.queue) }
    }

    public func send(_ message: Data) {
        queue.async {
            guard let p = self.peripheral else { return }
            let size = p.maximumWriteValueLength(for: .withoutResponse)
            self.outgoing.append(contentsOf: AKBLEFraming.chunks(message, chunkSize: size))
            self.flush()
        }
    }

    public func stop() {
        queue.async {
            if let p = self.peripheral, let state = self.chars[AKMDocBLE.centralState] {
                p.writeValue(Data([AKMDocBLE.stateEnd]), for: state, type: .withoutResponse)
            }
            self.manager?.stopScan()
            if let p = self.peripheral { self.manager?.cancelPeripheralConnection(p) }
            self.manager?.delegate = nil
            self.manager = nil
            self.continuation.yield(.disconnected)
            self.continuation.finish()
        }
    }

    private func flush() {
        guard let p = peripheral, let c2s = chars[AKMDocBLE.centralClient2Server] else { return }
        while let next = outgoing.first, p.canSendWriteWithoutResponse {
            p.writeValue(next, for: c2s, type: .withoutResponse)
            outgoing.removeFirst()
        }
    }

    // MARK: CBCentralManagerDelegate

    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            central.scanForPeripherals(withServices: [serviceUUID])
            continuation.yield(.waiting)
        case .unauthorized: continuation.yield(.failed("Bluetooth permission denied"))
        case .poweredOff: continuation.yield(.failed("Bluetooth is turned off"))
        case .unsupported: continuation.yield(.failed("Bluetooth LE is not supported"))
        default: break
        }
    }

    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                               advertisementData: [String: Any], rssi RSSI: NSNumber) {
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        central.connect(peripheral)
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices([serviceUUID])
    }

    public func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        continuation.yield(.failed(error?.localizedDescription ?? "connection failed"))
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        continuation.yield(.disconnected)
    }

    // MARK: CBPeripheralDelegate

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let service = peripheral.services?.first(where: { $0.uuid == serviceUUID }) else {
            continuation.yield(.failed("mdoc reader service not found")); return
        }
        peripheral.discoverCharacteristics([AKMDocBLE.centralState, AKMDocBLE.centralClient2Server,
                                            AKMDocBLE.centralServer2Client, AKMDocBLE.centralIdent], for: service)
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        for c in service.characteristics ?? [] { chars[c.uuid] = c }
        guard let ident = chars[AKMDocBLE.centralIdent] else { continuation.yield(.failed("Ident characteristic missing")); return }
        peripheral.readValue(for: ident)
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == AKMDocBLE.centralServer2Client, characteristic.isNotifying, let state = chars[AKMDocBLE.centralState] {
            peripheral.writeValue(Data([AKMDocBLE.stateStart]), for: state, type: .withoutResponse)
            continuation.yield(.connected)
        }
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let value = characteristic.value else { return }
        switch characteristic.uuid {
        case AKMDocBLE.centralIdent:
            guard value == expectedIdent else {
                continuation.yield(.failed("reader Ident does not match the engagement"))
                manager?.cancelPeripheralConnection(peripheral)
                return
            }
            if let s = chars[AKMDocBLE.centralState] { peripheral.setNotifyValue(true, for: s) }
            if let s2c = chars[AKMDocBLE.centralServer2Client] { peripheral.setNotifyValue(true, for: s2c) }
        case AKMDocBLE.centralServer2Client:
            do {
                if let message = try reassembler.append(value) { continuation.yield(.message(message)) }
            } catch {
                continuation.yield(.failed(error.localizedDescription))
            }
        case AKMDocBLE.centralState:
            if value.first == AKMDocBLE.stateEnd { continuation.yield(.disconnected) }
        default:
            break
        }
    }

    public func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        flush()
    }
}
