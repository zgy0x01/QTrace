#include <jni.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <dlfcn.h>
#include <fstream>
#include <unistd.h>
#include "vm.h"
#include "HookUtils.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
#include "shadowhook.h"
using namespace std;

static void addHooks()
{
   // addHook(0x71DD54,hook_0x71DD54);
}

static void addLibctrace()
{
    void * handle = dlopen("libc.so",RTLD_LAZY);
    if(handle == nullptr)
    {
        LOGE("dlopen libc fail");
        return;
    }
    addLibctrace(handle,libc_access,"access");
    addLibctrace(handle,libc_system_property_get,"__system_property_get");
    addLibctrace(handle,libc_memcpy,"memcpy");
    addLibctrace(handle,libc_pthread_create,"pthread_create");
    addLibctrace(handle,libc_fopen,"fopen");
    addLibctrace(handle,libc_lstat,"lstat");
    addLibctrace(handle,libc_stat,"stat");
    addLibctrace(handle,libc_fstatat,"fstatat");
    addLibctrace(handle,libc_execve,"execve");
    addLibctrace(handle,libc_clock_gettime,"clock_gettime");
    addLibctrace(handle,libc_strlen,"strlen");
    addLibctrace(handle,libc_memmove,"memmove");
    addLibctrace(handle,libc_memset,"memset");
    addLibctrace(handle,libc_kill,"kill");
    addLibctrace(handle,libc_abort,"abort");
    addLibctrace(handle,libc_exit,"exit");
    dlclose(handle);
}

static void addJNItrace()
{
    addJNITrace((void*)pJFunc->NewStringUTF,"NewStringUTF",trace_NewStringUTF);
    addJNITrace((void*)pJFunc->GetStringUTFChars,"GetStringUTFChars",trace_GetStringUTFChars);
    addJNITrace((void*)pJFunc->NewString,"NewString",trace_NewString);
    addJNITrace((void*)pJFunc->FindClass,"FindClass",trace_FindClass);
    addJNITrace((void*)pJFunc->GetFieldID,"GetFieldID",trace_GetFieldID);
    addJNITrace((void*)pJFunc->GetMethodID,"GetMethodID",trace_GetMethodID);
    addJNITrace((void*)pJFunc->RegisterNatives,"RegisterNatives",trace_RegisterNatives);
    addJNITrace((void*)pJFunc->GetLongField,"GetLongField",trace_GetLongField);
    addJNITrace((void*)pJFunc->GetStaticMethodID,"GetStaticMethodID",trace_GetStaticMethodID);
    addJNITrace((void*)pJFunc->CallStaticObjectMethodV,"CallStaticObjectMethodV",trace_CallStaticObjectMethodV);
    addJNITrace((void*)pJFunc->GetStaticFieldID,"GetStaticFieldID",trace_GetStaticFieldID);
    addJNITrace((void*)pJFunc->GetIntField,"GetIntField",trace_GetIntField);
    addJNITrace((void*)pJFunc->GetByteArrayRegion,"GetByteArrayRegion",trace_GetByteArrayRegion);
    addJNITrace((void*)pJFunc->GetArrayLength,"GetArrayLength",trace_GetArrayLength);
    addJNITrace((void*)pJFunc->GetByteArrayElements,"GetByteArrayElements",trace_GetByteArrayElements);
}

/* trace的so的名称*/
string libname;

/* 将原始so放在手机的一个目录中，方便FQ读取,
 * FQ将通过这个so文p定位内存中目标so的位置'
 * 因为在maps中的so文件名不总是原始的so名，例如config.arm64_v8a.apk这种
 * */
const char* libdir = "/data/local/tmp/";
string libpath;
/*需要trace的函数地址*/
size_t trace_func = 0;

void config()
{
    libname = "libchinese_wall.so";

    string localdir(libdir);
    libpath = localdir + libname;

    trace_func = 0x3513C;

    //trace buffer 累计多少字节往本地写一次。设置为0表示每trace一条指令就写入本地
    setBufferSize(0x10000000);//每16M写一次

    //是否开启逐指令日志，每条指令trace都会输出在logcat中，数据量巨大，用于调试时使用。
    enableDebugInsn(false);

    //是否开启jni trace 日志，可在logcat中查看jni调用
    enable_jni_trace_debug(true);

    //是否开启libc trace 日志，可在logcat中查看libc调用
    enable_libc_trace_debug(true);

}

void init_shadowhook()
{
    shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);
    shadowhook_set_debuggable(true);
}

void trace()
{
    /*trace 配置*/
    config();

    /*JNI Trace*/
    initJni();
    //添加监控的jni函数
    addJNItrace();

    /*libc Trace*/
    initLibcTrace();
    //添加监控的libc函数
    addLibctrace();

    /*自定义hook监控*/
    initHookData();
    //添加目标so的hook点位
    addHooks();

    auto soinfo = getSoBaseAddress(libpath.c_str(),libname.c_str());
    if(soinfo.start != 0)
    {
        _g_trace_data = new g_trace_data();
        _g_trace_data->base = soinfo.start;
        _g_trace_data->start = soinfo.start;
        _g_trace_data->end = soinfo.start + soinfo.size;
        _g_trace_data->target = trace_func;
        _g_trace_data->hooktask = shadowhook_hook_func_addr((void*)(_g_trace_data->start + _g_trace_data->target),
                                                            (void*)(hook_and_trace_arg8),
                                                            (void**)&ori_arg8);
    }
    else
    {
        LOGE("fail to load %s",libname.c_str());
    }
}

void test()
{
    char value[16];
    memset(value,0x10,1);
    int res =  __system_property_get("ro.secure",value);
    LOGE("ro.secure:%d,%s",res,value);
}

__unused __attribute__((constructor)) void init_main() {
    LOGE("Injected!");
    init_shadowhook();
    trace();
}