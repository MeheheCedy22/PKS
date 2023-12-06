#!/bin/bash

# Process eth-1.pcap to eth-9.pcap
for i in {1..9}; do
    echo "eth-${i}.pcap"
  python3 main.py "./vzorky_pcap_na_analyzu/eth-${i}.pcap"
#  sleep 5
  python3 ./validator/validator.py -s ./validator/schemas/schema-all.yaml -d output.yaml
done

# Process trace-1.pcap to trace-27.pcap
for i in {1..27}; do
  echo "eth-${i}.pcap"
  python3 main.py "./vzorky_pcap_na_analyzu/trace-${i}.pcap"
#  sleep 5
  python3 ./validator/validator.py -s ./validator/schemas/schema-all.yaml -d output.yaml
done

echo "trace_ip_nad_20_B.pcap"  
python3 main.py "./vzorky_pcap_na_analyzu/trace_ip_nad_20_B.pcap"
python3 ./validator/validator.py -s ./validator/schemas/schema-all.yaml -d output.yaml
