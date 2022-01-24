fs = require('fs');

async function readFile(path) {
    return new Promise((resolve, reject) => {
        fs.readFile(path, 'hex', function (err, data) {
            if (err) {
                reject(err);
            }
            resolve(data);
        });
    });
}

async function PcapParser(file) {
    let pcap = await readFile(file);                                            // read file from given location

    pcap = pcap.match(/.{1,2}/g)
    // console.log(pcap)

    var current = 0                                                             // specifies the current location while parsing the hex obj

    // FileHeader
    const lenfileHeader = 24                                                    // according to specs, fileHeader is of 24 bytes
    var fileHeader = pcap.slice(current, lenfileHeader);                        // take the fileHeader out
    current += lenfileHeader                                                    // update the current location
    // console.log("fileHeader", fileHeader);

    // Packets
    // var pkid = 0
    let packets = []
    while (current < pcap.length) {
        // packetRecord
        const lenpacketRecord = 16                                              // according to specs, packetRecord is of 16 bytes
        let packetRecord = pcap.slice(current, current + lenpacketRecord);      // take the packetRecord out
        current += lenpacketRecord                                              // update the current location
        // console.log("packetRecord", pkid, packetRecord);

        let cpl = packetRecord.slice(8, 11).reverse().join('')                  // extract CPL from packetRecord as a whole hex
        cpl = parseInt(cpl, 16)                                                 // convert hex to decimal
        // console.log("Captured Packet Length", pkid, cpl);

        const lenpacketData = cpl                                               // consider packetData lenth to be CPL between CPL and OPL
        let packetData = pcap.slice(current, current + lenpacketData);          // take the packetData out
        current += lenpacketData                                                // update the current location
        // console.log("packetData", pkid, packetData);

        packets.push({ packetRecord, packetData })
        // pkid += 1
    }

    return { fileHeader, packets }
}

module.exports.PcapParser = PcapParser