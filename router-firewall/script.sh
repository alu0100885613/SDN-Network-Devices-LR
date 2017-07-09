#!/bin/bash


func(){

for((i=0; i<= 10; i++))
do
  hping3 -s 443 -p 443 -c 1 10.0.2.2
done
}

func2(){
for((i=0; i<=5; i++))
do
  hping3 -s 500 -p 500 -c 1 10.0.3.2
done
}
script(){
$(func)
$(func2)
}



script
