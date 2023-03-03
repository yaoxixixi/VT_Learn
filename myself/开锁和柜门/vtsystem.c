#include "vtsystem.h"
#include "vtasm.h"
#include "exithandler.h"

VMX_CPU g_VMXCPU;




NTSTATUS StartVirtualTechnology()
{   
    _CR4 uCr4;
    _EFLAGS uEflags;
    if (!IsVTEnabled()) {
        return STATUS_UNSUCCESSFUL;
    }

    *((PULONG)&uCr4) = Asm_GetCr4();
    uCr4.VMXE = 1;
    Asm_SetCr4(*((PULONG)&uCr4));  //开锁

    g_VMXCPU.pVMXONRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'vmon');//申请虚拟地址
    RtlZeroMemory(g_VMXCPU.pVMXONRegion, 0x1000);//清0
    *(PULONG)g_VMXCPU.pVMXONRegion = 1;//设置版本号 和msr读出来的版本号一样
    g_VMXCPU.pVMXONRegion_PA = MmGetPhysicalAddress(g_VMXCPU.pVMXONRegion);//转物理地址

    Vmx_VmxOn(g_VMXCPU.pVMXONRegion_PA.LowPart, g_VMXCPU.pVMXONRegion_PA.HighPart);

    *((PULONG)&uEflags) = Asm_GetEflags();//读标志位

    if (uEflags.CF != 0)
    {
        Log("ERROR:VMXON指令调用失败!", 0);
        ExFreePool(g_VMXCPU.pVMXONRegion);
        return STATUS_UNSUCCESSFUL;
    }


    return STATUS_SUCCESS;
}

NTSTATUS StopVirtualTechnology()
{
    _CR4 uCr4;

    Vmx_VmxOff();

    *((PULONG)&uCr4) = Asm_GetCr4();
    uCr4.VMXE = 0;
    Asm_SetCr4(*((PULONG)&uCr4));//关锁
    
    ExFreePool(g_VMXCPU.pVMXONRegion);//释放内存空间

    return STATUS_SUCCESS;
}

static BOOLEAN IsVTEnabled()
{
    ULONG       uRet_EAX, uRet_ECX, uRet_EDX, uRet_EBX;
    _CPUID_ECX  uCPUID;
    _CR0        uCr0;
    _CR4    uCr4;
    IA32_FEATURE_CONTROL_MSR msr;

    //1. CPUID
    Asm_CPUID(1, &uRet_EAX, &uRet_EBX, &uRet_ECX, &uRet_EDX);
    *((PULONG)&uCPUID) = uRet_ECX;

    if (uCPUID.VMX != 1)
    {
        Log("ERROR: 这个CPU不支持VT!",0);
        return FALSE;
    }

    // 2. MSR
    *((PULONG)&msr) = (ULONG)Asm_ReadMsr(MSR_IA32_FEATURE_CONTROL);
    if (msr.Lock != 1)
    {
        Log("ERROR:VT指令未被锁定!", 0);
        return FALSE;
    }
    Log("SUCCESS:这个CPU支持VT!", 0);
    return TRUE;


    // 3. CR0 CR4
    *((PULONG)&uCr0) = Asm_GetCr0();
    *((PULONG)&uCr4) = Asm_GetCr4();

    if (uCr0.PE != 1 || uCr0.PG!=1 || uCr0.NE!=1)
    {
        Log("ERROR:这个CPU没有开启VT!",0);
        return FALSE;
    }

    if (uCr4.VMXE == 1)
    {
        Log("ERROR:这个CPU已经开启了VT!",0);
        Log("可能是别的驱动已经占用了VT，你必须关闭它后才能开启。",0);
        return FALSE;
    }


}
