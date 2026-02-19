#pragma once
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "main.hpp"
#include "util.hpp"


/**
 * Identify what type of instruction it is in regards to branching. A Jmp
 * instruction that will always be taken is different than a conditional,
 * which will only sometimes be taken, and it is also different than a regular
 * mov instruction which will go to the fallthrough address every time.
 * 
 * Currently works via hardcoded string comparisons. Must be revamped 
 * later to be more cross platform.
 * @param d Disassembled instruction in std::string form.
 */
static std::string classify_insn(std::string d);

/**
 * The callback which handles logging all necessary data, and also handles
 * command execution. The reason it handles commands is because every QEMU
 * callback function gets something called "vCPU context". 
 * 
 * This vCPU context is required to make requests to the internal QEMU API. 
 * It keeps track of which vCPU you are calling from. However, you can also
 * lose context if you do certain things. If you call a function with arguments
 * that function will not have vCPU context, but if it has no arguments it 
 * will not lose context. I need to investigate this much further because it 
 * is completely undocumented.
 * 
 * @param vcpu_index Which CPU to query
 * @param udata The instruction which will be logged. Passed as an exec_ctx*
 */
static void log(unsigned int vcpu_index, void *udata);

/**
 * This is the callback made by QEMU at every block translation.
 * 
 * QEMU translates instructions in blocks, disassembles them, and then does the
 * emulation / execution. This function is called to set the 
 * "qemu_plugin_register_vcpu_insn_exec_cb()" callback with log() for each 
 * translation, 
 */
void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);