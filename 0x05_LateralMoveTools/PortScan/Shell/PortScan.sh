#!/bin/bash
#use telnet scan port

IP=$1
threeIP=$(echo $IP |awk -F. '{print $1"."$2"."$3"."}') 
endIP=$(echo $IP | awk -F. '{print $4}')
if [ $1 ]
then
  if [ $2 ]
    then
    if [ $endIP -eq 0 ]
    then
      for ((i=1;i<=254;i++))
      do
        (sleep 1;)|telnet $threeIP$i $2 2>&1 |grep "Connected to $threeIP$i">/dev/null 
        if [ $? -eq 0 ]
        then
          echo "host $threeIP$i $2 port is open!"
        else
          echo "host $threeIP$i $2 port is close!"         
        fi
      done
    else
      (sleep 1;)|telnet $1 $2 2>&1 |grep "Connected to $1">/dev/null
       if [ $? -eq 0 ]
       then
         echo "host $1 $2 port is open！"
       else
         echo "host $1 $2 port is close!"      
       fi
    fi  
  else
    if [ $endIP -eq 0 ]
    then
      for ((i=1;i<=254;i++))
      do
        for port in `seq 1 65535`
        do
          (sleep 1;)|telnet $threeIP$i $port 2>&1 |grep "Connected to $threeIP$i">/dev/null
          if [ $? -eq 0 ]
          then
            echo "host $threeIP$i $port port is open!"
          else
            echo "host $threeIP$i $port port is close!"          
          fi
        done
      done
    else
      for i in `seq 1 65535`
      do
        (sleep 1;)|telnet $1 $i 2>&1 |grep "Connected to $1">/dev/null
        if [ $? -eq 0 ]
        then
          echo "host $1 $i port is open!"
        else
          echo "host $1 $iport is close!"        
        fi
      done
    fi
  fi       
else
  echo "******************************************* 
  use help:  
  $0 192.168.1.1(scan a IP all port )
  $0 192.168.1.1 portx(scan a IP port select port)
  $0 192.168.1.0(scan a IP tree all port)
  $0 192.168.1.0 portx(scan a IP tree port select port) 
******************************************** "  
fi
