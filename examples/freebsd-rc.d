#!/bin/sh
#
# Deploy as a file named "fingerd" in an rc.d dir

# PROVIDE: jail-fingerd
# REQUIRE: jail

. /etc/rc.subr

name="fingerd"
desc="run fingerd inside finger jail"
rcvar=fingerd_enable

load_rc_config ${name}

: ${fingerd_enable:=NO}

jail_name="finger"
jail_fingerd="/srv/finger/bin/fingerd"
jail_runas="65534:65534"
jailed_pidfile="/log/pids/fingerd.pid"
logs_dir="/jails/${jail_name}/log"
pid_dir="${logs_dir}/pids"
pid_dir_owner="nobody"

command="${jail_fingerd}"
start_cmd="fingerd_start"
start_precmd="fingerd_prestart"
pidfile="/jails/${jail_name}${jailed_pidfile}"
JID=$(jls -j ${jail_name} jid)

fingerd_prestart() {
	mkdir -p -m 0755 "${pid_dir}"
	chown "${pid_dir_owner}" "${pid_dir}"
}

fingerd_start() {
	# "jexec -l" adds a chdir(HOME) so fails
	daemon -c jexec ${jail_name} \
		${jail_fingerd} -run-as-user ${jail_runas} -pidfile=${jailed_pidfile} \
		>>${logs_dir}/stdout 2>>${logs_dir}/stderr </dev/null
}

run_rc_command "$1"
