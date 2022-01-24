fs = require('fs');


function PcapParser(file) {
    fs.readFile(file, 'hex', function (err, data) {
        if (err) {
            return console.log(err);
        }
        let pcap = data
        pcap = pcap.match(/.{1,2}/g)
        console.log(pcap)

        var current = 0     // specifies the current location while parsing the hex obj

        // FileHeader
        const lenfileHeader = 24    // according to specs, fileHeader is of 24 bytes
        var fileHeader = pcap.slice(current, lenfileHeader);        // take the fileHeader out
        current += lenfileHeader        // update the current location
        console.log("fileHeader", fileHeader);
    });
}

module.exports.PcapParser = PcapParser