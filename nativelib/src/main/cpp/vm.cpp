//
// Created by fang on 23-12-19.
//
#include "fstream"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <sstream>
#include <unordered_map>
#include <sys/uio.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <string>
#include <QBDI/Callback.h>
#include "vm.h"
#include "logger.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
#include "TraceLogger.h"
#include "TraceUtils.h"
#include "HookUtils.h"
#include "shadowhook.h"
using namespace std;
using namespace QBDI;
g_trace_data* _g_trace_data = nullptr;
int bufsize = 0x1000000;
bool debugInsn = false;

func_arg_8 ori_arg8{};


void setBufferSize(int size)
{
    bufsize = size;
}

void enableDebugInsn(bool enable)
{
    debugInsn = enable;
}

void sync_regs(size_t* regs, size_t pc,QBDI::GPRState* qbdi_state)
{
    for(int i=0;i<31;i++)
    {
        QBDI_GPR_SET(qbdi_state,i,regs[i]);
    }
    qbdi_state->pc = pc;
}

static inline uintptr_t get_current_sp() {
    uintptr_t sp;
    __asm__ __volatile__("mov %0, sp" : "=r"(sp)); // 读取SP寄存器到sp变量
    return sp;
}

uintptr_t inline get_current_x30() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x30" : "=r"(reg));
    return reg;
}
// pending:暂存上一条指令待补全的信息
struct PendingInst {
    bool valid = false;
    char line[256];
    int  lineLen = 0;
    int  writeRegs[8];
    const char* writeNames[8];
    int  numWrite = 0;
    char memInfo[1024];      // 内存访问行(可能多条)
    int  memLen = 0;
};

static PendingInst pending;

// 把 pending(上一条指令)用当前寄存器状态补全并输出
static void flushPending(QBDI::GPRState *gprState)
{
    if (!pending.valid) return;

    appendlog_n(pending.line, pending.lineLen);   // 上一条的 "asm [读]"

    if (pending.numWrite > 0) {
        char wbuf[256];
        int woff = 0;
        for (int i = 0; i < pending.numWrite; ++i) {
            uint64_t v = QBDI_GPR_GET(gprState, pending.writeRegs[i]);  // 此刻 = 上一条执行后的值
            woff += snprintf(wbuf + woff, sizeof(wbuf) - woff, "%s=0x%" PRIx64 " ",
                             pending.writeNames[i], v);
            if (woff >= (int)sizeof(wbuf)) { woff = sizeof(wbuf) - 1; break; }
        }
        appendlog("\t => [");
        appendlog_n(wbuf, woff);
        appendlog("]");
    }
    appendlogendl();
    if (pending.memLen > 0) {
        appendlog_n(pending.memInfo, pending.memLen);
    }
    pending.valid = false;
}
static void save_regs(size_t* regs)
{
    regs[0] = get_current_x0();
    regs[1] = get_current_x1();
    regs[2] = get_current_x2();
    regs[3] = get_current_x3();
    regs[4] = get_current_x4();
    regs[5] = get_current_x5();
    regs[6] = get_current_x6();
    regs[7] = get_current_x7();
    regs[8] = get_current_x8();
    regs[9] = get_current_x9();
    regs[10] = get_current_x10();
    regs[11] = get_current_x11();
    regs[12] = get_current_x12();
    regs[13] = get_current_x13();
    regs[14] = get_current_x14();
    regs[15] = get_current_x15();
    regs[16] = get_current_x16();
    regs[17] = get_current_x17();
    regs[18] = get_current_x18();
    regs[19] = get_current_x19();
    regs[20] = get_current_x20();
    regs[21] = get_current_x21();
    regs[22] = get_current_x22();
    regs[23] = get_current_x23();
    regs[24] = get_current_x24();
    regs[25] = get_current_x25();
    regs[26] = get_current_x26();
    regs[27] = get_current_x27();
    regs[28] = get_current_x28();
    regs[29] = get_current_x29();
    regs[30] = get_current_x30();
}

extern "C" size_t do_qbdi_trace(size_t regs[31], size_t caller_sp)
{
    size_t function_address = _g_trace_data->start + _g_trace_data->target;
    LOGE("start trace:%p", (void*)function_address);
    shadowhook_unhook(_g_trace_data->hooktask);

    struct timeval start, end;
    gettimeofday(&start, nullptr);

    vm* vm_ = new vm();
    auto qvm = vm_->init(_g_trace_data->start, _g_trace_data->end);
    auto qbdi_state = qvm.getGPRState();
    initLogger(function_address);
    vm_->base = _g_trace_data->base;

    // 同步 x0 - x30 寄存器
    sync_regs(regs, function_address, qbdi_state);

    // 在当前栈上开辟空间给 QBDI 使用
    size_t current_sp = get_current_sp();
    size_t stack_size = 0x8000; // 稍微给大一点更安全
    // 确保 16 字节对齐 (ARM64 强要求 SP 16字节对齐)
    size_t new_sp = (current_sp - stack_size) & ~0xFUL;

    // 【核心修复】：将调用者原始栈上的参数拷贝到 QBDI 的新栈顶
    // 拷贝 256 字节（足够支持 8 + 32 = 40 个参数）
    size_t copy_size = 256;
    memcpy((void*)new_sp, (void*)caller_sp, copy_size);

    // 设置 QBDI 的 SP
    QBDI_GPR_SET(qbdi_state, QBDI::REG_SP, new_sp);
    // 注意：不要把 BP(x29) 设为 SP！x29 应该保持调用者的 Frame Pointer，sync_regs 已经同步过了
    // QBDI_GPR_SET(qbdi_state, QBDI::REG_BP, ...); // <--- 删掉原来这行

    QBDI::rword qbdi_retval;
    LOGE("trace begin");
    // qvm.call 会自动管理返回机制，并保持此时的 REG_SP 不变，刚好对准我们 memcpy 的参数
    bool qbdi_success = qvm.call(&qbdi_retval, (uint64_t)function_address);
    LOGE("trace end");

    flushPending(qbdi_state);
    if (qbdi_success) {
        writelog();
        LOGE("trace completed successfully %s", _logger->logfile.c_str());
    } else {
        LOGE("trace failed");
    }

    gettimeofday(&end, nullptr);
    long elapsed_sec = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000;
    LOGI("trace time cost:%lds", elapsed_sec);

    deleteLogger();
    delete vm_;

    // 重新加上 hook
    _g_trace_data->hooktask = shadowhook_hook_func_addr(
            (void*)(_g_trace_data->start + _g_trace_data->target),
            (void*)(hook_and_trace_arg8),
            (void**)&ori_arg8);

    return qbdi_retval;
}
extern "C" void* check_filter(size_t* regs, size_t caller_sp)
{
    // 获取前 8 个参数
    size_t x0 = regs[0];
    size_t x1 = regs[1];
    size_t x2 = regs[2];
    size_t* stack_args = (size_t*)caller_sp;
    size_t arg9  = stack_args[0]; // 第 9 个参数
    size_t arg10 = stack_args[1]; // 第 10 个参数

    // ================= 编写你的过滤条件 =================
    // 例如：当 x0 == 1 时，不进行 trace，直接走原函数
    if (x0 == 1)
    {
        // 返回原函数的地址（告诉汇编直接跳过去执行原函数）
       // return (void*)ori_arg8;
        return nullptr;
    }
    // 例如：如果你想过滤某个字符串参数 (假设 x1 是 char*)
    // if (x1 != 0 && strstr((const char*)x1, "target_str") == nullptr) {
    //     return (void*)ori_arg8;
    // }
    // ===================================================
    // 返回 nullptr (0) 表示通过过滤，需要执行 QBDI Trace！
    return nullptr;
}

extern "C" __attribute__((naked)) size_t hook_and_trace_arg8()
{
    __asm__ __volatile__(
            "mov x16, sp\n"
            "sub sp, sp, #256\n"

            // 保存所有寄存器 x0 - x30
            "stp x0, x1, [sp, #0]\n"
            "stp x2, x3, [sp, #16]\n"
            "stp x4, x5, [sp, #32]\n"
            "stp x6, x7, [sp, #48]\n"
            "stp x8, x9, [sp, #64]\n"
            "stp x10, x11, [sp, #80]\n"
            "stp x12, x13, [sp, #96]\n"
            "stp x14, x15, [sp, #112]\n"
            "stp x16, x17, [sp, #128]\n"
            "stp x18, x19, [sp, #144]\n"
            "stp x20, x21, [sp, #160]\n"
            "stp x22, x23, [sp, #176]\n"
            "stp x24, x25, [sp, #192]\n"
            "stp x26, x27, [sp, #208]\n"
            "stp x28, x29, [sp, #224]\n"
            "str x30, [sp, #240]\n"

            // 第一步：调用 check_filter(regs, caller_sp) 检查是否需要过滤
            "mov x0, sp\n"
            "mov x1, x16\n"
            "bl check_filter\n"

            // 如果 check_filter 返回非 0 (即返回了 ori_arg8 的地址)，则跳转到 1f 标签直接执行原函数
            "cbnz x0, 1f\n"

            // ---------------- 走 QBDI Trace 分支 ----------------
            "mov x0, sp\n"
            "ldr x1, [sp, #128]\n"   // 从栈上重新取出之前保存的 x16 (即 caller_sp)
            "bl do_qbdi_trace\n"     // 执行 trace

            // 恢复 callee-saved 寄存器并返回给调用者
            "ldp x18, x19, [sp, #144]\n"
            "ldp x20, x21, [sp, #160]\n"
            "ldp x22, x23, [sp, #176]\n"
            "ldp x24, x25, [sp, #192]\n"
            "ldp x26, x27, [sp, #208]\n"
            "ldp x28, x29, [sp, #224]\n"
            "ldr x30, [sp, #240]\n"
            "add sp, sp, #256\n"
            "ret\n"

            // ---------------- 走原函数 (跳过 Trace) 分支 ----------------
            "1:\n"
            "mov x17, x0\n"          // 把原函数地址 (ori_arg8) 暂存到 x17 (IP1 临时寄存器)

            // 100% 恢复进入函数时的所有参数寄存器 (x0-x15) 和上下文寄存器 (x18-x30)
            "ldp x0, x1, [sp, #0]\n"
            "ldp x2, x3, [sp, #16]\n"
            "ldp x4, x5, [sp, #32]\n"
            "ldp x6, x7, [sp, #48]\n"
            "ldp x8, x9, [sp, #64]\n"
            "ldp x10, x11, [sp, #80]\n"
            "ldp x12, x13, [sp, #96]\n"
            "ldp x14, x15, [sp, #112]\n"
            "ldp x18, x19, [sp, #144]\n"
            "ldp x20, x21, [sp, #160]\n"
            "ldp x22, x23, [sp, #176]\n"
            "ldp x24, x25, [sp, #192]\n"
            "ldp x26, x27, [sp, #208]\n"
            "ldp x28, x29, [sp, #224]\n"
            "ldr x30, [sp, #240]\n"

            // 恢复原始的 sp！此时栈顶又重新精确地指向第 9 个参数！
            "add sp, sp, #256\n"

            // 直接尾调用跳入原函数 ori_arg8！原函数执行完后会直接 ret 回最外层的调用者
            "br x17\n"
            );
}

bool checkAndCallHook(QBDI::VM *vm, QBDI::GPRState *gprState,size_t addr,size_t lastaddr)
{
    auto it = _g_hook_data->hookMap.find(addr);
    if(it != _g_hook_data->hookMap.end())
    {
        if(it->second->ignore != nullptr && it->second->ignorenum != 0)
        {
            for(int i=0;i<it->second->ignorenum;i++)
            {
                if(it->second->ignore[i] == lastaddr)
                {
                    return false;
                }
            }
        }
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

bool checkLibcTrace_pre(QBDI::VM *vm, QBDI::GPRState *gprState,size_t target)
{
    auto it = _g_libc_trace->map.find(target);
    if(it != _g_libc_trace->map.end())
    {
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

bool checkJniCall_pre(QBDI::VM *vm, QBDI::GPRState *gprState,size_t target)
{
    if(pJFunc == nullptr)
    {
        LOGE("checkJniCall,pJFunc not init");
        return false;
    }
    auto it = _g_jni_trace->map.find(target);
    if(it != _g_jni_trace->map.end())
    {
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

static size_t lastAddr = 0;

static unordered_map<uint32_t,char*> disassemblecache;

// 显示指令执行前的寄存器状态
QBDI::VMAction showPreInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;

    //上一条指令的信息全部拿到了，写入
    flushPending(gprState);

    // 获取当前指令的分析信息
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION  | QBDI::ANALYSIS_OPERANDS);
    uint32_t bytecode = *(uint32_t*)instAnalysis->address;

    //用缓存的反汇编，减低开销
    char* disasm;
    auto it = disassemblecache.find(bytecode);
    if (it != disassemblecache.end()) {
        disasm = it->second;
    } else {
        const QBDI::InstAnalysis *full = vm->getInstAnalysis(QBDI::ANALYSIS_DISASSEMBLY);
        size_t len = strlen(full->disassembly) + 1;
        disasm = (char*)malloc(len);
        memcpy(disasm, full->disassembly, len);
        disassemblecache.emplace(bytecode, disasm);
    }

    bool hasCheck = false;
    //执行前hook
    hasCheck = checkAndCallHook(vm,gprState,(instAnalysis->address-thiz->base),(lastAddr - thiz->base));

    if(!hasCheck)
    {
        //检查blr
        if(instAnalysis->isCall && !strcmp(instAnalysis->mnemonic,"BLR"))
        {
            for (int i = 0; i < instAnalysis->numOperands; ++i)
            {
                auto op = instAnalysis->operands[i];
                if (op.regAccess == QBDI::REGISTER_READ || op.regAccess == REGISTER_READ_WRITE)
                {
                    if (op.regCtxIdx != -1 && op.type == OPERAND_GPR && op.regCtxIdx != 31)
                    {
                        uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
                        hasCheck = checkJniCall_pre(vm,gprState,regValue);
                        break;
                    }
                }
            }
        }
    }

    if(!hasCheck)
    {
        //检查br
        if(instAnalysis->isBranch && !strcmp(instAnalysis->mnemonic,"BR") && hasLibctrace())
        {
            for (int i = 0; i < instAnalysis->numOperands; ++i)
            {
                auto op = instAnalysis->operands[i];
                if (op.regAccess == QBDI::REGISTER_READ || op.regAccess == REGISTER_READ_WRITE)
                {
                    if (op.regCtxIdx != -1 && op.type == OPERAND_GPR && op.regCtxIdx != 31)
                    {
                        uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
                        //br可能是libc调用，也可能是jni调用
                        if(!checkLibcTrace_pre(vm,gprState,regValue))
                        {
                            checkJniCall_pre(vm,gprState,regValue);
                        }
                        break;
                    }
                }
            }
        }
    }

    int off = 0;
    off += snprintf(pending.line + off, sizeof(pending.line) - off,
                    "0x%lx: %s", (instAnalysis->address - thiz->base), disasm);

    char rbuf[256];
    int roff = 0;
    bool any = false;
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto& op = instAnalysis->operands[i];
        if ((op.regAccess == QBDI::REGISTER_READ || op.regAccess == REGISTER_READ_WRITE)
            && op.regCtxIdx != -1 && op.type == OPERAND_GPR)
        {
            uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
            roff += snprintf(rbuf + roff, sizeof(rbuf) - roff, "%s=0x%" PRIx64 " ",
                             op.regName, regValue);
            any = true;
            if (roff >= (int)sizeof(rbuf)) { roff = sizeof(rbuf) - 1; break; }
        }
    }
    if (any) {
        off += snprintf(pending.line + off, sizeof(pending.line) - off, "\t[");
        // 把读寄存器拼进 pending.line
        int copyLen = roff;
        if (off + copyLen >= (int)sizeof(pending.line)) copyLen = sizeof(pending.line) - off - 2;
        if (copyLen > 0) { memcpy(pending.line + off, rbuf, copyLen); off += copyLen; }
        off += snprintf(pending.line + off, sizeof(pending.line) - off, "]");
    }

    pending.lineLen = off;

    // ④ 记录当前指令会写哪些寄存器,等下一条 PRE 来补值
    pending.numWrite = 0;
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto& op = instAnalysis->operands[i];
        if ((op.regAccess == REGISTER_WRITE || op.regAccess == REGISTER_READ_WRITE)
            && op.regCtxIdx != -1 && op.type == OPERAND_GPR)
        {
            if (pending.numWrite < 8) {
                pending.writeRegs[pending.numWrite]  = op.regCtxIdx;
                pending.writeNames[pending.numWrite] = op.regName;
                pending.numWrite++;
            }
        }
    }
    pending.memLen = 0;
    pending.valid = true;

    if(sdslen(_logger->buf) > bufsize)
    {
        writelog();
    }
    lastAddr = instAnalysis->address;
    return QBDI::VMAction::CONTINUE;
}

// 显示指令执行后的寄存器状态 打印字符串 hexdump
QBDI::VMAction showPostInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;

    // 获取当前指令的分析信息，包括指令、符号、操作数等
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_OPERANDS);

    std::stringstream output;
    std::stringstream regOutput;

    // 遍历操作数并记录写入的寄存器状态
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto op = instAnalysis->operands[i];
        if (op.regAccess == REGISTER_WRITE || op.regAccess == REGISTER_READ_WRITE)
        {
            if (op.regCtxIdx != -1 && op.type == OPERAND_GPR)
            {
                // 获取寄存器值
                uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
                // 输出寄存器名称和值
                output << op.regName << "=0x" << std::hex << regValue << " ";
                output.flush();
            }
        }
    }

    // 如果有写入的寄存器信息，格式化输出；否则，仅换行
    if (!output.str().empty())
    {
        appendlog("\t => [");
        appendlog(output.str().c_str());
        appendlog("]");
        appendlogendl();
    }
    else
    {
        appendlogendl();
        appendlog(regOutput.str().c_str());
    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction showMemoryAccess(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    const auto& accesses = vm->getInstMemoryAccess();   // 只调一次
    for (const auto &acc : accesses)
    {
        const char* tag = (acc.type == MEMORY_READ)  ? "mem[r]"
                                                     : (acc.type == MEMORY_WRITE) ? "mem[w]"
                                                                                  : "mem[rw]";
        pending.memLen += snprintf(pending.memInfo + pending.memLen,
                                   sizeof(pending.memInfo) - pending.memLen,
                                   "%s: 0x%" PRIx64 " size: %u value: 0x%" PRIx64 "\n",
                                   tag,
                                   (uint64_t)acc.accessAddress,
                                   (unsigned)acc.size,
                                   (uint64_t)acc.value);
        if (pending.memLen >= (int)sizeof(pending.memInfo)) {
            pending.memLen = sizeof(pending.memInfo) - 1;
            break;
        }
    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction showSyscall(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
    if (instAnalysis->mnemonic && strcasecmp(instAnalysis->mnemonic, "svc") == 0)
    {

    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VM vm::init(size_t start,size_t end)
{
    uint32_t cid;
    QBDI::GPRState *state;
    QBDI::VM qvm{};
    state = qvm.getGPRState();
    loadMemoryRanges();
    assert(state != nullptr);
    qvm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);

    //指令前hook
    cid = qvm.addCodeCB(QBDI::PREINST, showPreInstruction, this);
    assert(cid != QBDI::INVALID_EVENTID);

    //指令后hook
    //cid = qvm.addCodeCB(QBDI::POSTINST, showPostInstruction, this);
    //assert(cid != QBDI::INVALID_EVENTID);

    //TODO:syscall trace
    //cid = qvm.addCodeCB(QBDI::PREINST, showSyscall, this);
    //assert(cid != QBDI::INVALID_EVENTID);

    //读写trace
    cid = qvm.addMemAccessCB(MEMORY_READ_WRITE, showMemoryAccess, this);
    assert(cid != QBDI::INVALID_EVENTID);

    bool ret = qvm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(start));
    if(!ret)
    {
        LOGE("init vm fail");
        assert(ret == true);
    }
    LOGE("init vm success");
    return qvm;
}