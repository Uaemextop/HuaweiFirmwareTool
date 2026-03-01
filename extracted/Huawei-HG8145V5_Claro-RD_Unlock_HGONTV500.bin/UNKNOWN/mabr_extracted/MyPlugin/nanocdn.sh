#!/bin/sh

START=99
STOP=99

PID_CORE_FILE=/var/run/nanocdn-core.pid
PID_RR_FILE=/var/run/nanocdn-rr.pid
NANOCDN_CONF_FILE=/mnt/jffs2/app/plugins/work/mabr/MyPlugin/nanocdn.conf

chmod +x *

LD_LIBRARY_PATH=/mnt/jffs2/app/plugins/work/mabr/MyPlugin:$LD_LIBRARY_PATH
PATH=/mnt/jffs2/app/plugins/work/mabr/MyPlugin:$PATH

# check nanocdn Broadpeak agents are available
[ -x /mnt/jffs2/app/plugins/work/mabr/MyPlugin/nanocdn-core ] || exit 0
[ -x /mnt/jffs2/app/plugins/work/mabr/MyPlugin/nanocdn-rr ] || exit 0

start()
{
	echo "nanocdn start ....."
	start-stop-daemon -S -x /mnt/jffs2/app/plugins/work/mabr/MyPlugin/nanocdn-core -- --conf $NANOCDN_CONF_FILE --pidfile $PID_CORE_FILE "$@"
	start-stop-daemon -S -x /mnt/jffs2/app/plugins/work/mabr/MyPlugin/nanocdn-rr -- --conf $NANOCDN_CONF_FILE --rr-pidfile $PID_RR_FILE "$@"
}

stop()
{
	echo "nanocdn stop ....."
	if [ -f $PID_CORE_FILE ]
	then
		PID_CORE=`cat $PID_CORE_FILE`
		start-stop-daemon -K -p $PID_CORE_FILE -s INT || rm -f $PID_CORE_FILE
		while [[ -f /proc/$PID_CORE/status ]]
		do
			sleep 1
		done
	fi

	if [ -f $PID_RR_FILE ]
	then
		PID_RR=`cat $PID_RR_FILE`
		start-stop-daemon -K -p $PID_RR_FILE -s INT || rm -f $PID_RR_FILE
		while [[ -f /proc/$PID_RR/status ]]
		do
			sleep 1
		done
	fi
}

restart() 
{
        stop
        start
}

case "$1" in
  start)
        start
        ;;
  stop)
        stop
        ;;
  restart|reload)
        restart
        ;;
  *)
        echo $"Usage: $0 {start|stop|restart}"
        exit 1
esac

echo "nanocdn end ....."

exit $?

