#ifndef DBKDRVR_H
#define DBKDRVR_H

#define dbkversion 2000027
#define eadbkversion 0000027

// Exposed control to disable driver functionality without unloading
#include <ntddk.h>
NTSTATUS DisableDriverFunctionality(void);

// Query state helper
BOOLEAN IsDriverDisabled(void);

#endif