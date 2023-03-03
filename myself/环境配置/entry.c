#include <ntddk.h>
#include "vtsystem.h"

VOID DriverUnload(PDRIVER_OBJECT driver)
{

    DbgPrint("Driver is unloading...\r\n");
}



NTSTATUS 
  DriverEntry( 
    PDRIVER_OBJECT  driver,
    PUNICODE_STRING RegistryPath
    )
{
    //__asm int 3
    DbgPrint("Driver Entered!\r\n");
	driver->DriverUnload = DriverUnload;


   

	return STATUS_SUCCESS;
}


