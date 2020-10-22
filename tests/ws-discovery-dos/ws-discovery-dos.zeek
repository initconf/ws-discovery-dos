# @TEST-EXEC: zeek -C -r $TRACES/one-scan.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

