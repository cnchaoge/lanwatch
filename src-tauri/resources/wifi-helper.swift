// Reads Wi-Fi link quality via CoreWLAN.
// RSSI, noise, channel, and rate do not need a Location prompt.
// Usage: wifi-helper [interfaceName]

import Foundation
import CoreWLAN

func emit(_ dict: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: dict, options: []),
       let str = String(data: data, encoding: .utf8) {
        print(str)
    } else {
        print("{\"rssi\":0,\"noise\":0,\"channel\":0,\"band\":\"\",\"txRate\":0,\"rssiValid\":false}")
    }
}

let client = CWWiFiClient.shared()

var interface: CWInterface?
if CommandLine.arguments.count > 1 {
    let name = CommandLine.arguments[1]
    if let iface = client.interface(withName: name) {
        interface = iface
    }
}
if interface == nil {
    interface = client.interface()
}

guard let iface = interface else {
    emit(["rssi": 0, "noise": 0, "channel": 0, "band": "", "txRate": 0, "rssiValid": false])
    exit(0)
}

let rssi = iface.rssiValue()
let noise = iface.noiseMeasurement()
let channel = iface.wlanChannel()
let channelNumber = channel?.channelNumber ?? 0

var band = ""
if let channel = channel {
    switch channel.channelBand {
    case .band2GHz: band = "2.4GHz"
    case .band5GHz: band = "5GHz"
    case .band6GHz: band = "6GHz"
    default: band = ""
    }
}

let rssiValid = rssi != 0 && iface.interfaceMode() == .station

emit([
    "rssi": rssi,
    "noise": noise,
    "channel": channelNumber,
    "band": band,
    "txRate": Int(iface.transmitRate()),
    "rssiValid": rssiValid,
])
