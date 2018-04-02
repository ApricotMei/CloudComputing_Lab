#!/bin/sh

sh ovs-ofctl show s1
sh ovs-ofctl show s2
sh ovs-ofctl show s3
sh ovs-ofctl show s4
sh ovs-ofctl show s5

sh ovs-ofctl dump-flows s1
sh ovs-ofctl dump-flows s2
sh ovs-ofctl dump-flows s3
sh ovs-ofctl dump-flows s4
sh ovs-ofctl dump-flows s5
sh ovs-ofctl dump-flows s1 -o OpenFlow13
sh ovs-ofctl dump-flows s2 -o OpenFlow13
sh ovs-ofctl dump-flows s3 -o OpenFlow13
sh ovs-ofctl dump-flows s4 -o OpenFlow13
sh ovs-ofctl dump-flows s5 -o OpenFlow13

sh ovs-ofctl add-flow s1 in_port=1,actions=output:2
sh ovs-ofctl add-flow s2 in_port=1,actions=output:2
sh ovs-ofctl add-flow s4 in_port=1,actions=output:4
sh ovs-ofctl add-flow s1 priority=500, in_port=1,dl_type=0x0800,nw_proto=6,actions=output:2
sh ovs-ofctl add-flow s2 priority=500, in_port=1,dl_type=0x0800,nw_proto=6,actions=output:2
sh ovs-ofctl add-flow s4 priority=500, in_port=1,dl_type=0x0800,nw_proto=6,actions=output:4

sh ovs-ofctl add-flow s1 in_port=1,actions=output:3
sh ovs-ofctl add-flow s3 in_port=1,actions=output:3
sh ovs-ofctl add-flow s5 in_port=2,actions=output:3
sh ovs-ofctl add-flow s4 in_port=3,actions=output:4



sh ovs-ofctl add-flow s4 in_port=4,actions=output:2
sh ovs-ofctl add-flow s3 in_port=2,actions=output:1
sh ovs-ofctl add-flow s1 in_port=3,actions=output:1
sh ovs-ofctl add-flow s4 priority=500, in_port=4,dl_type=0x0800,nw_proto=6,actions=output:2
sh ovs-ofctl add-flow s3 priority=500, in_port=2,dl_type=0x0800,nw_proto=6,actions=output:1
sh ovs-ofctl add-flow s1 priority=500, in_port=3,dl_type=0x0800,nw_proto=6,actions=output:1

sh ovs-ofctl add-flow s4 in_port=4,actions=output:1
sh ovs-ofctl add-flow s2 in_port=2,actions=output:3
sh ovs-ofctl add-flow s5 in_port=1,actions=output:2
sh ovs-ofctl add-flow s3 in_port=3,actions=output:1
sh ovs-ofctl add-flow s1 in_port=3,actions=output:1