#pragma once
#include <ntifs.h>

BOOLEAN isEyeAurasService(void);
void setIsEyeAurasService(BOOLEAN value);

HANDLE getMonitoringPID(void);
void setMonitoringPID(HANDLE processId);

void startProcessMonitoring(void);
void stopMonitoring(void);

void initializeMonitoring(IN PUNICODE_STRING RegistryPath);