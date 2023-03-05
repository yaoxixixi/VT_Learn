#include "vtsystem.h"
#include "vtasm.h"
#include "exithandler.h"

VMX_CPU g_VMXCPU;

static ULONG  VmxAdjustControls(ULONG Ctl, ULONG Msr)
{
    LARGE_INTEGER MsrValue;
    MsrValue.QuadPart = Asm_ReadMsr(Msr);
    Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}//msr[481]，msr[482]
void __declspec(naked) GuestEntry() {
    __asm {
        mov ax, es
        mov es, ax

        mov ax, ds
        mov ds, ax

        mov ax, fs
        mov fs, ax

        mov ax, gs
        mov gs, ax

        mov ax, ss
        mov ss, ax
    }
}
  
void SetupVMCS() {
    // 1.Guest State Area
 

  
    Vmx_VmWrite(GUEST_RFLAGS, Asm_GetEflags() & ~0x200);//cli关中断 

    Vmx_VmWrite(GUEST_ES_SELECTOR, Asm_GetEs() & 0xFFF8);
    Vmx_VmWrite(GUEST_CS_SELECTOR, Asm_GetCs() & 0xFFF8);
    Vmx_VmWrite(GUEST_DS_SELECTOR, Asm_GetDs() & 0xFFF8);
    Vmx_VmWrite(GUEST_FS_SELECTOR, Asm_GetFs() & 0xFFF8);
    Vmx_VmWrite(GUEST_GS_SELECTOR, Asm_GetGs() & 0xFFF8);
    Vmx_VmWrite(GUEST_SS_SELECTOR, Asm_GetSs() & 0xFFF8);
    Vmx_VmWrite(GUEST_TR_SELECTOR, Asm_GetTr() & 0xFFF8);

    Vmx_VmWrite(GUEST_ES_AR_BYTES, 0x10000);//不可用状态
    Vmx_VmWrite(GUEST_FS_AR_BYTES, 0x10000);
    Vmx_VmWrite(GUEST_DS_AR_BYTES, 0x10000);
    Vmx_VmWrite(GUEST_SS_AR_BYTES, 0x10000);
    Vmx_VmWrite(GUEST_GS_AR_BYTES, 0x10000);
    Vmx_VmWrite(GUEST_LDTR_AR_BYTES, 0x10000);

    Vmx_VmWrite(GUEST_CS_AR_BYTES, 0xc09b);//属性
    Vmx_VmWrite(GUEST_CS_BASE, 0);//基质
    Vmx_VmWrite(GUEST_CS_LIMIT, 0xffffffff);//界限

    Vmx_VmWrite(GUEST_TR_AR_BYTES, 0x008b);
    Vmx_VmWrite(GUEST_TR_BASE, 0x80042000);
    Vmx_VmWrite(GUEST_TR_LIMIT, 0x20ab);


    Vmx_VmWrite(GUEST_GDTR_BASE, GdtBase);
    Vmx_VmWrite(GUEST_GDTR_LIMIT, Asm_GetGdtLimit());
    Vmx_VmWrite(GUEST_IDTR_BASE, IdtBase);
    Vmx_VmWrite(GUEST_IDTR_LIMIT, Asm_GetIdtLimit());

    Vmx_VmWrite(GUEST_IA32_DEBUGCTL, Asm_ReadMsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
    Vmx_VmWrite(GUEST_IA32_DEBUGCTL_HIGH, Asm_ReadMsr(MSR_IA32_DEBUGCTL) >> 32);

    Vmx_VmWrite(GUEST_SYSENTER_CS, Asm_ReadMsr(MSR_IA32_SYSENTER_CS) & 0xFFFFFFFF);
    Vmx_VmWrite(GUEST_SYSENTER_ESP, Asm_ReadMsr(MSR_IA32_SYSENTER_ESP) & 0xFFFFFFFF);
    Vmx_VmWrite(GUEST_SYSENTER_EIP, Asm_ReadMsr(MSR_IA32_SYSENTER_EIP) & 0xFFFFFFFF); // KiFastCallEntry

    Vmx_VmWrite(GUEST_RSP, ((ULONG)g_VMXCPU.pStack) + 0x1000);     //Guest 临时栈
    Vmx_VmWrite(GUEST_RIP, (ULONG)GuestEntry);                     // 客户机的入口点

    Vmx_VmWrite(VMCS_LINK_POINTER, 0xffffffff);//物理地址不用设置为0xffffffff
    Vmx_VmWrite(VMCS_LINK_POINTER_HIGH, 0xffffffff);
    // 2.Host State Area
    ULONG GdtBase, IdtBase;
    Vmx_VmWrite(HOST_CR0, Asm_GetCr0());
    Vmx_VmWrite(HOST_CR3, Asm_GetCr3());
    Vmx_VmWrite(HOST_CR4, Asm_GetCr4());

    Vmx_VmWrite(HOST_ES_SELECTOR, Asm_GetEs() & 0xFFF8);
    Vmx_VmWrite(HOST_CS_SELECTOR, Asm_GetCs() & 0xFFF8);
    Vmx_VmWrite(HOST_DS_SELECTOR, Asm_GetDs() & 0xFFF8);
    Vmx_VmWrite(HOST_FS_SELECTOR, Asm_GetFs() & 0xFFF8);
    Vmx_VmWrite(HOST_GS_SELECTOR, Asm_GetGs() & 0xFFF8);
    Vmx_VmWrite(HOST_SS_SELECTOR, Asm_GetSs() & 0xFFF8);
    Vmx_VmWrite(HOST_TR_SELECTOR, Asm_GetTr() & 0xFFF8);

    Vmx_VmWrite(HOST_TR_BASE, 0x80042000);

    GdtBase = Asm_GetGdtBase();
    IdtBase = Asm_GetIdtBase();
    Vmx_VmWrite(HOST_GDTR_BASE, GdtBase);
    Vmx_VmWrite(HOST_IDTR_BASE, IdtBase);

    Vmx_VmWrite(HOST_IA32_SYSENTER_CS, Asm_ReadMsr(MSR_IA32_SYSENTER_CS) & 0xFFFFFFFF);
    Vmx_VmWrite(HOST_IA32_SYSENTER_ESP, Asm_ReadMsr(MSR_IA32_SYSENTER_ESP) & 0xFFFFFFFF);
    Vmx_VmWrite(HOST_IA32_SYSENTER_EIP, Asm_ReadMsr(MSR_IA32_SYSENTER_EIP) & 0xFFFFFFFF); // KiFastCallEntry

    Vmx_VmWrite(HOST_RSP, ((ULONG)g_VMXCPU.pStack) + 0x2000);     //Host 临时栈
    Vmx_VmWrite(HOST_RIP, (ULONG)VMMEntryPoint);                  //这里定义我们的VMM处理程序入口

    // 3.虚拟机运行控制域
    Vmx_VmWrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
    Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS));
    // 4.VMEntry运行控制域
    Vmx_VmWrite(VM_ENTRY_CONTROLS, VmxAdjustControls(0, MSR_IA32_VMX_ENTRY_CTLS));
     // 5.VMExit运行控制域
    Vmx_VmWrite(VM_EXIT_CONTROLS, VmxAdjustControls(0, MSR_IA32_VMX_EXIT_CTLS));
}
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
    Log("vmxon success", 0);


    //vmcs申请内存
    g_VMXCPU.pVMCSRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'vmcs');//申请虚拟地址
    RtlZeroMemory(g_VMXCPU.pVMCSRegion, 0x1000);//清0
    *(PULONG)g_VMXCPU.pVMCSRegion = 1;//设置版本号 和msr读出来的版本号一样
    g_VMXCPU.pVMCSRegion_PA = MmGetPhysicalAddress(g_VMXCPU.pVMCSRegion);//转物理地址
    //栈申请内存
    g_VMXCPU.pStack = ExAllocatePoolWithTag(NonPagedPool, 0x2000, 'stck');//申请虚拟地址
    RtlZeroMemory(g_VMXCPU.pStack, 0x2000);//清0
    //vmclear vmptrload
    Vmx_VmClear(g_VMXCPU.pVMCSRegion_PA.LowPart, g_VMXCPU.pVMCSRegion_PA.HighPart);
    Vmx_VmPtrld(g_VMXCPU.pVMCSRegion_PA.LowPart, g_VMXCPU.pVMCSRegion_PA.HighPart);
    //vmcs
    SetupVMCS();
    //vmlaunch  
    Vmx_VmLaunch();
    Log("ERROR:VmLaunch指令调用失败!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", Vmx_VmRead(VM_INSTRUCTION_ERROR))
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
    ExFreePool(g_VMXCPU.pVMCSRegion);
    Log("vmxoff success", 0);
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
