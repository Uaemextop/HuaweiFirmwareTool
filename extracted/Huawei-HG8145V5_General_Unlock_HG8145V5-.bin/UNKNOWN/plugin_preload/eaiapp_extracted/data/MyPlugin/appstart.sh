#!/bin/sh
# Copyright Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

# 依赖核心插件的libplugin_agent_api.so
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)/Lib:$(pwd)/../../../MyPlugin/Lib

chmod +x $(pwd)/bin/*
cd $(pwd)/bin
echo "start eaiapp!"
trap 'killall -9 eaiapp; exit 1;' 15
while true ; do
  NUM=$(ps | grep eaiapp | grep -v grep |wc -l)
  if [[ "${NUM}" -lt "1" ]]; then
        ./eaiapp &
  fi

  PID=$(ps | grep eaiapp | awk -F: NR==${NUM} | awk '{print $1}' )
  USEMEM=$(cat /proc/${PID}/status | grep VmRSS |  awk '{print $2}' )
  if [[ "${USEMEM}" -ge "21432" ]]; then
        killall -9 eaiapp
  fi

  sleep 8
done