#!/bin/sh
export LD_LIBRARY_PATH=$(pwd)/Lib:/mnt/jffs2/app/cplugin/cplugin1/MyPlugin/Lib/:$LD_LIBRARY_PATH

chmod +x $(pwd)/bin/*
cd $(pwd)/bin
echo "start eaiapp!"
trap 'killall -9 eaiapp; exit 1;' 15
while true ; do
  NUM=`ps | grep eaiapp | grep -v grep |wc -l`
  if [[ "${NUM}" -lt "1" ]]; then
        ./eaiapp &
  fi

  PID=`ps | grep eaiapp | awk -F: NR==${NUM} | awk '{print $1}' `
  USEMEM=`cat /proc/${PID}/status | grep VmRSS |  awk '{print $2}' `
  if [[ "${USEMEM}" -ge "14336" ]]; then
        killall -9 eaiapp
  fi

  sleep 8
done