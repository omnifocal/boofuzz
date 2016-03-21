import os
import sys
import getopt
import signal
import time
import threading
import subprocess
import datetime

from boofuzz import pedrpc

'''
By nnp
http://www.unprotectedhex.com

This intended as a basic replacement for Sulley's process_monitor.py on *nix.
The below options are accepted. Crash details are limited to the signal that
caused the death and whatever operating system supported mechanism is in place (i.e
core dumps)

Replicated methods:
    - alive
    - log
    - post_send
    - pre_send
    _ start_target
    - stop_target
    - set_start_commands
    - set_stop_commands

Limitations
    - Cannot attach to an already running process
    - Currently only accepts one start_command
    - Limited 'crash binning'. Relies on the availability of core dumps. These
      should be created in the same directory the process is ran from on Linux
      and in the (hidden) /cores directory on OS X. On OS X you have to add
      the option COREDUMPS=-YES- to /etc/hostconfig and then `ulimit -c
      unlimited` as far as I know. A restart may be required. The file
      specified by crash_bin will any other available details such as the test
      that caused the crash and the signal received by the program
'''

USAGE = "USAGE: process_monitor_unix.py"\
        "\n    -c|--crash_bin             File to record crash info too" \
        "\n    [-P|--port PORT]             TCP port to bind this agent too"\
        "\n    [-l|--log_level LEVEL]       log level (default 1), increase for more verbosity"

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)


class DebuggerThread:
    def __init__(self, start_command):
        """
        This class isn't actually ran as a thread, only the start_monitoring
        method is. It can spawn/stop a process, wait for it to exit and report on
        the exit status/code.
        """

        self.start_command = start_command
        self.tokens = start_command.split(' ')
        self.cmd_args = []
        self.pid = None
        self.exit_status = None
        self.alive = False
        self.time = None
        self.starttime = None

    def spawn_target(self):
        print self.tokens
        lol = ['valgrind', '--tool=callgrind', '--dump-line=yes']
        lol.extend(self.tokens)
        self.pid = subprocess.Popen(lol).pid
        self.starttime = datetime.datetime.now()
        self.alive = True
        print '################################# START PROCESS - PID {} ##############################'.format(self.pid)

    def start_monitoring(self):
        """
        self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        while self.exit_status == (0, 0):
            self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        """

        print '################################# MONITORING PROC - PID {} #############################'.format(self.pid)
        self.exit_status = os.waitpid(self.pid, 0)
        # [0] is the pid
        self.exit_status = self.exit_status[1]

        self.alive = False

    def get_exit_status(self):
        return self.exit_status

    def stop_target(self):
        while self.check_alive():
            os.kill(self.pid, signal.SIGTERM)
            time.sleep(0.5)
        print '################################# STOPPED PROCESS - PID {} ##############################'.format(self.pid)
        self.alive = False

    def is_alive(self):
        return self.alive

    def check_alive(self):
        try:
            os.kill(self.pid, 0)
        except OSError:
            return False
        else:
            return True

class NIXProcessMonitorPedrpcServer(pedrpc.Server):
    def __init__(self, host, port, cbin, level=1):
        """
        @type host: str
        @param host: Hostname or IP address
        @type port: int
        @param port: Port to bind server to
        @type cbin: str
        @param cbin: Where to save monitored process crashes for analysis
        """

        pedrpc.Server.__init__(self, host, port)
        self.crash_bin      = cbin
        self.log_level      = level
        self.dbg            = None
        self.last_synopsis  = None
        self.test_number    = 0
        self.start_commands = None
        self.stop_commands  = None
        self.proc_name      = None
        self.log("Process Monitor PED-RPC server initialized:")
        self.log("Listening on %s:%s" % (host, port))
        self.log("awaiting requests...")

    # noinspection PyMethodMayBeStatic
    def alive(self):
        """
        Returns True. Useful for PED-RPC clients who want to see if the PED-RPC connection is still alive.
        """

        return True

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """

        if self.log_level >= level:
            print "[%s] %s" % (time.strftime("%I:%M.%S"), msg)

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        @rtype:  bool
        @return: Return True if the target is still active, False otherwise.
        """
        rec_file = open(self.crash_bin, 'a')
        if not self.dbg.is_alive():
            exit_status = self.dbg.get_exit_status()
            if os.WCOREDUMP(exit_status):
                reason = 'Segmentation fault'
            elif os.WIFSTOPPED(exit_status):
                reason = 'Stopped with signal ' + str(os.WTERMSIG(exit_status))
            elif os.WIFSIGNALED(exit_status):
                reason = 'Terminated with signal ' + str(os.WTERMSIG(exit_status))
            elif os.WIFEXITED(exit_status):
                reason = 'Exit with code - ' + str(os.WEXITSTATUS(exit_status))
            else:
                reason = 'Process died for unknown reason'

            self.last_synopsis = '[%s] Test:%d,callgrind.out.%s,%s,%s\n' % (
                time.strftime("%I:%M.%S"),
                self.test_number,
                self.dbg.pid,
                datetime.datetime.now() - self.dbg.starttime,
                reason
            )
        else:
            self.last_synopsis = '[%s] Test:%d,callgrind.out.%s,%s,None\n' % (
                time.strftime('%I:%M.%S'),
                self.test_number,
                self.dbg.pid,
                datetime.datetime.now() - self.dbg.starttime
            )
        rec_file.write(self.last_synopsis)
        rec_file.close()

        return self.dbg.is_alive()

    def pre_send(self, test_number):
        """
        This routine is called before the fuzzer transmits a test case and ensure the debugger thread is operational.
        (In this implementation do nothing for now)

        @type  test_number: Integer
        @param test_number: Test number to retrieve PCAP for.
        """
        if not self.dbg:
            self.start_target()

        self.log("pre_send(%d)" % test_number, 10)
        self.test_number = test_number

    def start_target(self):
        """
        Start up the target process by issuing the commands in self.start_commands.

        @returns True if successful. No failure detection yet.
        """

        self.log("starting target process")

        if self.dbg and self.dbg.alive:
            print 'Oh shit son, theres a proc running ey, kill that cunter!'
            self.stop_target()
            print 'Pretty sure I killed it....'

        self.dbg = DebuggerThread(self.start_commands[0])
        self.dbg.spawn_target()
        # prevent blocking by spawning off another thread to waitpid
        threading.Thread(target=self.dbg.start_monitoring).start()
        self.log("done. target up and running, giving it 5 seconds to settle in.")
        time.sleep(5)
        return True

    def stop_target(self):
        """
        Kill the current debugger thread and stop the target process by issuing the commands in self.stop_commands.
        """

        # give the debugger thread a chance to exit.
        time.sleep(1)

        self.log("stopping target process")

        for command in self.stop_commands:
            if command == "TERMINATE_PID":
                self.dbg.stop_target()
            else:
                os.system(command)

    def set_start_commands(self, start_commands):
        """
        We expect start_commands to be a list with one element for example
        ['/usr/bin/program arg1 arg2 arg3']
        """

        if len(start_commands) > 1:
            self.log("This process monitor does not accept > 1 start command")
            return

        self.log("updating start commands to: %s" % start_commands)
        self.start_commands = start_commands

    def set_stop_commands(self, stop_commands):
        self.log("updating stop commands to: %s" % stop_commands)

        self.stop_commands = stop_commands

    def set_proc_name(self, proc_name):
        self.log("updating target process name to '%s'" % proc_name)

        self.proc_name = proc_name

    def get_crash_synopsis(self):
        """
        Return the last recorded crash synopsis.

        @rtype:  String
        @return: Synopsis of last recorded crash.
        """

        return self.last_synopsis


if __name__ == "__main__":
    # parse command line options.
    opts = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:P:l:", ["crash_bin=", "port=", "log_level="])
    except getopt.GetoptError:
        ERR(USAGE)

    log_level = 1
    PORT = None
    crash_bin = None
    for opt, arg in opts:
        if opt in ("-c", "--crash_bin"):
            crash_bin  = arg
        if opt in ("-P", "--port"):
            PORT = int(arg)
        if opt in ("-l", "--log_level"):
            log_level  = int(arg)

    if not crash_bin:
        ERR(USAGE)

    if not PORT:
        PORT = 26002

    # spawn the PED-RPC servlet.

    servlet = NIXProcessMonitorPedrpcServer("0.0.0.0", PORT, crash_bin, log_level)
    servlet.serve_forever()
