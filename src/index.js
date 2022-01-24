fs = require('fs');


function PcapParser(file) {
    fs.readFile(file, 'hex', function (err, data) {
        if (err) {
            return console.log(err);
        }
        let pcap = data
        pcap = pcap.match(/.{1,2}/g)
        console.log(pcap)
    });
}

module.exports.PcapParser = PcapParser