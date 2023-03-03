#include <ntddk.h>
#include "vtsystem.h"

VOID DriverUnload(PDRIVER_OBJECT driver)
{
    StopVirtualTechnology();
    DbgPrint("Driver is unloading...\r\n");
}



NTSTATUS 
  DriverEntry( 
    PDRIVER_OBJECT  driver,
    PUNICODE_STRING RegistryPath
    )
{

    DbgPrint("Driver Entered!\r\n");
	driver->DriverUnload = DriverUnload;

    StartVirtualTechnology();
     


	return STATUS_SUCCESS;
}


