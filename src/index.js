fs = require('fs');


function PcapParser(file) {
    fs.readFile(file, 'utf-8', function (err, data) {
        if (err) {
            return console.log(err);
        }
        let pcap = data
        console.log(pcap)
    });
}

module.exports.PcapParser = PcapParser