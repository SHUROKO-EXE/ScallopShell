#include "emulatorAPI.hpp"

#ifdef _WIN32

#include "windows.h"

#else

#include <sys/personality.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <bits/stdc++.h>
#include <pty.h>
#include <termios.h>

#endif

/* Variables and helpers */
int child_pid_ = -1;
int qemu_output_fd_ = -1;  // File descriptor for reading QEMU's stdout/stderr
int qemu_input_fd_ = -1;   // File descriptor for writing to QEMU's stdin
bool Emulator::isEmulating = false;
std::string Emulator::binaryStem;

std::string pluginExtension() {
    #ifdef _WIN32 
        return ".dll";
    #else
        return ".so";
    #endif

}

std::string executableExtension() {
    #ifdef _WIN32 
        return ".exe";
    #else
        return "";
    #endif

}

bool Emulator::getIsEmulating()
{
    return isEmulating;
}

#ifdef _WIN32
int Emulator::startEmulation(const std::string &executablePathArg)
{
    return 1;
}
#else

static void stopEmulation() {
    if (child_pid_ <= 0) return;

    // Close the PTY master so the child loses its terminal I/O
    if (qemu_output_fd_ != -1) { ::close(qemu_output_fd_); qemu_output_fd_ = -1; }
    qemu_input_fd_ = -1;

    // Because you called setsid() in the child, pid is (typically) also its pgid.
    // Signal the whole process group.
    ::kill(-child_pid_, SIGTERM);

    // Wait a bit for clean shutdown
    const int max_tries = 50;               // 50 * 10ms = 500ms
    for (int i = 0; i < max_tries; i++) {
        int status = 0;
        pid_t r = ::waitpid(child_pid_, &status, WNOHANG);
        if (r == child_pid_) { child_pid_ = -1; return; }
        ::usleep(10 * 1000);
    }

    // Still alive -> hard kill whole group
    ::kill(-child_pid_, SIGKILL);

    // Reap (blocking, since we just SIGKILLed)
    int status = 0;
    (void)::waitpid(child_pid_, &status, 0);
    child_pid_ = -1;
}

int Emulator::startEmulation(const std::string &executablePathArg, const std::string& arch, bool system)
{
    static std::string executablePath = executablePathArg; // Path to the executable being debugged
    static std::string qemuArch = arch; // Architecture
    static bool isSystem = system; // Is system emulation

    if (child_pid_ != -1) {
        stopEmulation();
    }
    
    // If there's a new binary then replace the executable path
    if (executablePathArg != "")
    {
        executablePath = executablePathArg;
    }
    if (arch != "") {
        qemuArch = arch;
    }
    if (!executablePath.empty()) {
        binaryStem = std::filesystem::path(executablePath).stem().string();
    }


    // Find the QEMU binary to use on the target binary
    std::filesystem::path qemuPath = ::getenv("SCALLOP_QEMU_BUILD") ? ::getenv("SCALLOP_QEMU_BUILD") : "";
    qemuPath = qemuPath / "qemu-";
    qemuPath += (isSystem ? "system-" : "");
    qemuPath += qemuArch;
    qemuPath += (executableExtension());

    // Outputs for QEMU Plugin
    std::filesystem::path currentWorkingDir = std::filesystem::current_path();
    std::filesystem::path qemuTraceLog = std::filesystem::temp_directory_path() / "qemu.log";
    std::filesystem::path pluginPath = ::getenv("SCALLOP_QEMU_PLUGIN") ? ::getenv("SCALLOP_QEMU_PLUGIN") : currentWorkingDir / "qemu-plugins";
    std::filesystem::path csvPath = std::filesystem::temp_directory_path() / "branchlog.csv";

    // ---- build argv: [setarch <arch> -R] qemu -d plugin -D /tmp/branchlog.csv -plugin <.so> -- <target> ----
    std::vector<std::string> args_str;
    args_str.insert(args_str.end(), {
        qemuPath.string(),
        "-d", "plugin",
        "-D", qemuTraceLog.string(),
        "-plugin", pluginPath.string(),
        "--",
        executablePath});

    // Put everything in argv to prepare it for qemu
    std::vector<char *> argv;
    argv.reserve(args_str.size() + 1);
    for (auto &s : args_str)
    {
        argv.push_back(const_cast<char *>(s.c_str()));
        //fprintf(stderr, "%s ", s.c_str());
    }
    argv.push_back(nullptr);

    // ---- set up a pty for child's stdin/stdout/stderr ----
    // Using a pty instead of pipes ensures line-buffered output (real-time display)
    int pty_master, pty_slave;
    if (::openpty(&pty_master, &pty_slave, nullptr, nullptr, nullptr) < 0)
    {
        perror("openpty");
        return -1;
    }

    // ---- fork/exec QEMU ----
    pid_t pid = ::fork();

    if (pid < 0)
    {
        perror("fork");
        ::close(pty_master);
        ::close(pty_slave);
        return -1;
    }
    if (pid == 0)
    {
        // Child: set up a new session and controlling terminal
        ::setsid();

        // Close master in child
        ::close(pty_master);

        // Redirect stdin, stdout, stderr to the pty slave
        ::dup2(pty_slave, STDIN_FILENO);
        ::dup2(pty_slave, STDOUT_FILENO);
        ::dup2(pty_slave, STDERR_FILENO);

        if (pty_slave > STDERR_FILENO)
            ::close(pty_slave);

        ::execvp(argv[0], argv.data());
        perror("done with QEMU");
        _exit(127);
    }
    
    child_pid_ = pid;

    // If socket fails to initialize
    if (socket.initialize() != 0)
    {
        perror("socket failed to initialize!");
    }

    // Parent: close slave, keep master for read/write
    ::close(pty_slave);

    // Store the pty master fd and make it non-blocking for UI responsiveness
    qemu_output_fd_ = pty_master;
    qemu_input_fd_ = pty_master;  // pty master is bidirectional
    int flags = ::fcntl(pty_master, F_GETFL, 0);
    ::fcntl(pty_master, F_SETFL, flags | O_NONBLOCK);

    return child_pid_;
}

int Emulator::getOutputFd()
{
    return qemu_output_fd_;
}

int Emulator::getInputFd()
{
    return qemu_input_fd_;
}

pid_t Emulator::getChildPid()
{
    return child_pid_;
}
#endif
