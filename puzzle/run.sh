#!/bin/bash

echo "parameter: $1"

for ((i=0;i<$1;i++))
do
	./test $i 192.168.1.218 8888 8888 pc$i.pem prikey$i.pem $i &
	sleep $[($RANDOM%50) / 1000]
done

#./test 0 192.168.1.255 8888 8800 pc0.pem prikey0.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 1 192.168.1.255 8888 8800 pc1.pem prikey1.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 2 192.168.1.255 8888 8800 pc2.pem prikey2.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 3 192.168.1.255 8888 8800 pc3.pem prikey3.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 4 192.168.1.255 8888 8800 pc4.pem prikey4.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 5 192.168.1.255 8888 8800 pc5.pem prikey5.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 6 192.168.1.255 8888 8800 pc6.pem prikey6.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 7 192.168.1.255 8888 8800 pc7.pem prikey7.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 8 192.168.1.255 8888 8800 pc8.pem prikey8.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 9 192.168.1.255 8888 8800 pc9.pem prikey9.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 10 192.168.1.255 8888 8800 pc10.pem prikey10.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 11 192.168.1.255 8888 8800 pc11.pem prikey11.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 12 192.168.1.255 8888 8800 pc12.pem prikey12.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 13 192.168.1.255 8888 8800 pc13.pem prikey13.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 14 192.168.1.255 8888 8800 pc14.pem prikey14.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 15 192.168.1.255 8888 8800 pc15.pem prikey15.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 16 192.168.1.255 8888 8800 pc16.pem prikey16.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 17 192.168.1.255 8888 8800 pc17.pem prikey17.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 18 192.168.1.255 8888 8800 pc18.pem prikey18.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 19 192.168.1.255 8888 8800 pc19.pem prikey19.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 20 192.168.1.255 8888 8800 pc20.pem prikey20.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 21 192.168.1.255 8888 8800 pc21.pem prikey21.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 22 192.168.1.255 8888 8800 pc22.pem prikey22.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 23 192.168.1.255 8888 8800 pc23.pem prikey23.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 24 192.168.1.255 8888 8800 pc24.pem prikey24.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 25 192.168.1.255 8888 8800 pc25.pem prikey25.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 26 192.168.1.255 8888 8800 pc26.pem prikey26.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 27 192.168.1.255 8888 8800 pc27.pem prikey27.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 28 192.168.1.255 8888 8800 pc28.pem prikey28.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 29 192.168.1.255 8888 8800 pc29.pem prikey29.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 30 192.168.1.255 8888 8800 pc30.pem prikey30.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 31 192.168.1.255 8888 8800 pc31.pem prikey31.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 32 192.168.1.255 8888 8800 pc32.pem prikey32.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 33 192.168.1.255 8888 8800 pc33.pem prikey33.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 34 192.168.1.255 8888 8800 pc34.pem prikey34.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 35 192.168.1.255 8888 8800 pc35.pem prikey35.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 36 192.168.1.255 8888 8800 pc36.pem prikey36.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 37 192.168.1.255 8888 8800 pc37.pem prikey37.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 38 192.168.1.255 8888 8800 pc38.pem prikey38.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 39 192.168.1.255 8888 8800 pc39.pem prikey39.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 40 192.168.1.255 8888 8800 pc40.pem prikey40.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 41 192.168.1.255 8888 8800 pc41.pem prikey41.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 42 192.168.1.255 8888 8800 pc42.pem prikey42.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 43 192.168.1.255 8888 8800 pc43.pem prikey43.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 44 192.168.1.255 8888 8800 pc44.pem prikey44.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 45 192.168.1.255 8888 8800 pc45.pem prikey45.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 46 192.168.1.255 8888 8800 pc46.pem prikey46.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 47 192.168.1.255 8888 8800 pc47.pem prikey47.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 48 192.168.1.255 8888 8800 pc48.pem prikey48.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 49 192.168.1.255 8888 8800 pc49.pem prikey49.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 50 192.168.1.255 8888 8850 pc50.pem prikey50.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 51 192.168.1.255 8888 8851 pc51.pem prikey51.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 52 192.168.1.255 8888 8852 pc52.pem prikey52.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 53 192.168.1.255 8888 8853 pc53.pem prikey53.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 54 192.168.1.255 8888 8854 pc54.pem prikey54.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 55 192.168.1.255 8888 8855 pc55.pem prikey55.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 56 192.168.1.255 8888 8856 pc56.pem prikey56.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 57 192.168.1.255 8888 8857 pc57.pem prikey57.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 58 192.168.1.255 8888 8858 pc58.pem prikey58.pem &
#sleep $[ ( $RANDOM % 50 ) / 1000 ]
#./test 59 192.168.1.255 8888 8859 pc59.pem prikey59.pem &
#./rsu &

sleep 305
ps -ef|grep test|cut -c 9-16|sudo xargs kill -9
ps -ef|grep rsu|cut -c 9-16|sudo xargs kill -9
echo "kill all"

