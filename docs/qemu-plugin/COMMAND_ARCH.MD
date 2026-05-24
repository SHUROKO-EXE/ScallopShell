# Command Architecture in Scallop Shell's QEMU Plugin

Commands require an odd implementation process due to the multithreaded nature of the program. Every vCPU opens its own thread which runs the callbacks. vcpu_current_thread_index is the global variable which keeps track of which vCPU is currently run so the command functions can 