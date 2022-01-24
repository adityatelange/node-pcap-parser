const pcap = require("../src/index");


pcap.PcapParser("tests/sample_pcaps/0001.pcap").then((data) => {
    console.log(data);
})
