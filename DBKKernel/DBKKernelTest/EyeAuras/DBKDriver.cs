// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;
using EyeAuras.Memory.Scaffolding;
using Microsoft.Win32.SafeHandles;
using PoeShared.Scaffolding;
using Win32Exception = System.ComponentModel.Win32Exception;

namespace EyeAuras.Memory.KD.Internal;

/// <summary>
/// Driver trace ID 6bb0f0b0-8c4b-4e0d-9e65-4a2f1f8b2d3a
/// </summary>
public sealed class DBKDriver : IDisposable
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, FileShare dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);
    
    private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
    private const uint METHOD_BUFFERED = 0;
    private const uint FILE_ANY_ACCESS = 0;
    private const uint FILE_READ_ACCESS = 0x0001;
    private const uint FILE_WRITE_ACCESS = 0x0002;
    private const uint FILE_RW_ACCESS = FILE_READ_ACCESS | FILE_WRITE_ACCESS;
    
    private readonly string driverRelativePath;
    private readonly string servicePath;

    private SafeFileHandle deviceHandle;
    
    /// <summary>
    /// 
    /// </summary>
    /// <param name="servicePath">Service path, e.g. \\.\EASVC73</param>
    public DBKDriver(string servicePath)
    {
        this.servicePath = servicePath;
    }

    public void Open()
    {
        deviceHandle = CreateFile(servicePath,
            FILE_RW_ACCESS,
            FileShare.ReadWrite,
            IntPtr.Zero,
            3, // OPEN_EXISTING
            0,
            IntPtr.Zero);

        if (deviceHandle.IsInvalid)
        {
            var errorCode = Marshal.GetLastWin32Error();
            throw new IOException($"Failed to open driver handle '{servicePath}'. Error code: {errorCode}.");
        }

        EnsureDeviceIsReady();
    }

    public int GetVersion()
    {
        return DeviceReadInt32(DBKIoctlCodes.IOCTL_CE_GETVERSION);
    }

    public ulong GetCR0()
    {
        return DeviceReadUInt64(DBKIoctlCodes.IOCTL_CE_GETCR0);
    }

    /// <summary>
    /// Returns whether write-protect bypass is currently active based on CR0.WP state.
    /// True means CR0.WP is cleared (bit 16 == 0), allowing supervisor writes to RO/RX pages.
    /// False means CR0.WP is set (normal Windows state), enforcing PTE write permissions.
    /// </summary>
    /// <remarks>
    /// This reflects the instantaneous CPU state as reported by the driver via GetCR0.
    /// The driver may clear WP only briefly during certain write operations when bypass is enabled,
    /// so this value can be transient if sampled during such operations.
    /// </remarks>
    public bool GetWriteProtectBypass()
    {
        const ulong CR0_WP = 1UL << 16; // Write Protect bit
        var cr0 = GetCR0();
        return (cr0 & CR0_WP) == 0; // bypass if WP is cleared
    }

    public ulong GetCR3()
    {
        return DeviceReadUInt64(DBKIoctlCodes.IOCTL_CE_GETCR3);
    }

    public ulong GetCR4()
    {
        return DeviceReadUInt64(DBKIoctlCodes.IOCTL_CE_GETCR4);
    }

    public ulong GetSDT()
    {
        return DeviceReadUInt64(DBKIoctlCodes.IOCTL_CE_GETSDT);
    }

    public string GetProcessNameFromPEProcess(int processId)
    {
        var peProcess = GetPEProcess(processId);

        var inBuffer = Marshal.AllocHGlobal(sizeof(ulong));
        var outBuffer = Marshal.AllocHGlobal(sizeof(ulong));
        try
        {
            Marshal.WriteIntPtr(inBuffer, peProcess);
            DeviceIoControl(DBKIoctlCodes.IOCTL_CE_GETPROCESSNAMEADDRESS, inBuffer, sizeof(ulong), outBuffer, sizeof(ulong), out var bytesReturned);
            var processNamePtr = Marshal.ReadIntPtr(outBuffer);
            if (processNamePtr == IntPtr.Zero)
            {
                throw new ArgumentException($"Failed to get PE process name pointer for process Id {processId}");
            }

            //actual image name is retrieved via SeLocateProcessImageName
            var nameBuffer = new byte[16]; //UCHAR ImageFileName[16]; 
            ReadProcessMemory64(processId, processNamePtr, nameBuffer, nameBuffer.Length);

            var processName = MemoryUtils.ReadNullTerminatedString(nameBuffer);
            return processName;
        }
        finally
        {
            Marshal.FreeHGlobal(inBuffer);
            Marshal.FreeHGlobal(outBuffer);
        }
    }


    public IntPtr GetPEProcess(int processId)
    {
        var inBuffer = Marshal.AllocHGlobal(sizeof(uint));
        var outBuffer = Marshal.AllocHGlobal(sizeof(ulong));
        try
        {
            Marshal.WriteInt32(inBuffer, processId);
            DeviceIoControl(DBKIoctlCodes.IOCTL_CE_GETPEPROCESS, inBuffer, sizeof(uint), outBuffer, (uint) sizeof(ulong), out var bytesReturned);
            return Marshal.ReadIntPtr(outBuffer);
        }
        finally
        {
            Marshal.FreeHGlobal(inBuffer);
            Marshal.FreeHGlobal(outBuffer);
        }
    }

    public void SetKernelWritesIgnoreWriteProtection(bool kernelWritesIgnoreWP)
    {
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_WRITESIGNOREWP, new TWritesIgnoresWPInputStruct
        {
            IgnoreWriteProtection = kernelWritesIgnoreWP ? (byte)1 : (byte)0
        });
    }

    public IntPtr OpenProcess(int processId)
    {
        var result = Ioctl<TOpenProcessInputStruct, TOpenProcessOutputStruct>(DBKIoctlCodes.IOCTL_CE_OPENPROCESS, new TOpenProcessInputStruct()
        {
            ProcessId = processId
        });
        return new IntPtr(result.Handle);
    }
    
    public IntPtr GetPEB(IntPtr eProcessPtr)
    {
        var inBuffer = Marshal.AllocHGlobal(sizeof(ulong));
        var outBuffer = Marshal.AllocHGlobal(sizeof(ulong));
        try
        {
            Marshal.WriteIntPtr(inBuffer, eProcessPtr);
            DeviceIoControl(DBKIoctlCodes.IOCTL_CE_GET_PEB, inBuffer, sizeof(ulong), outBuffer, (uint) sizeof(ulong), out var bytesReturned);
            return Marshal.ReadIntPtr(outBuffer);
        }
        finally
        {
            Marshal.FreeHGlobal(inBuffer);
            Marshal.FreeHGlobal(outBuffer);
        }
    }
    
    /// <summary>
    /// Queries the virtual memory region at the specified address in the given process.
    /// Returns the region length and protection as reported by the driver.
    /// </summary>
    public TQueryVirtualMemoryOutputStruct QueryVirtualMemory(int processId, IntPtr startAddress)
    {
        var input = new TQueryVirtualMemoryInputStruct
        {
            ProcessID = (ulong)processId,
            StartAddress = (ulong)startAddress
        };

        return Ioctl<TQueryVirtualMemoryInputStruct, TQueryVirtualMemoryOutputStruct>(
            DBKIoctlCodes.IOCTL_CE_QUERY_VIRTUAL_MEMORY, input);
    }
    
    /// <summary>
    /// Creates a user-mode APC in the target thread to execute specified address.
    /// </summary>
    public void CreateApc(ulong threadId, IntPtr addressToExecute)
    {
        var input = new TCreateApcInputStruct
        {
            ThreadId = threadId,
            AddressToExecute = (ulong)addressToExecute
        };
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_CREATEAPC, input);
    }

    /// <summary>
    /// Creates a user-mode APC in the target thread to execute specified address.
    /// </summary>
    public void CreateApc(int threadId, IntPtr addressToExecute) => CreateApc((ulong)threadId, addressToExecute);
    
    /// <summary>
    /// Suspends all threads in the specified process
    /// </summary>
    public void SuspendProcess(int processId)
    {
        var input = new TProcessIdInputStruct { ProcessId = unchecked((uint)processId) };
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_SUSPENDPROCESS, input);
    }

    /// <summary>
    /// Resumes all threads in the specified process
    /// </summary>
    public void ResumeProcess(int processId)
    {
        var input = new TProcessIdInputStruct { ProcessId = unchecked((uint)processId) };
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_RESUMEPROCESS, input);
    }

    /// <summary>
    /// Suspends a specific thread by its thread ID (TID).
    /// </summary>
    public void SuspendThread(int threadId)
    {
        var input = new TThreadIdInputStruct { ThreadId = unchecked((uint)threadId) };
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_SUSPENDTHREAD, input);
    }

    /// <summary>
    /// Resumes a specific thread by its thread ID (TID).
    /// </summary>
    public void ResumeThread(int threadId)
    {
        var input = new TThreadIdInputStruct { ThreadId = unchecked((uint)threadId) };
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_RESUMETHREAD, input);
    }

    public (IntPtr ThreadProcessHandle, IntPtr ThreadHandle) CreateRemoteThread(int processId, IntPtr startAddress, IntPtr parameter)
    {
        var input = new TCreateRemoteThreadInputStruct
        {
            ProcessId = unchecked((ulong)processId),
            StartAddress = unchecked((ulong)startAddress.ToInt64()),
            Parameter = unchecked((ulong)parameter.ToInt64())
        };

        var output = Ioctl<TCreateRemoteThreadInputStruct, TCreateRemoteThreadOutputStruct>(DBKIoctlCodes.IOCTL_CE_CREATEREMOTETHREAD, input);
        return (new IntPtr(unchecked((long)output.ThreadProcessId)), new IntPtr(unchecked((long)output.ThreadId)));
    }

    /// <summary>
    /// Allocates virtual memory in the target process via the kernel driver.
    /// Mirrors the VirtualAlloc semantics: you can optionally provide a base address (or IntPtr.Zero to let the system choose),
    /// an allocation size, allocation type flags (e.g., MEM_COMMIT | MEM_RESERVE), and page protection flags (PAGE_XXX).
    /// </summary>
    /// <param name="processId">Target process ID.</param>
    /// <param name="baseAddress">Preferred base address, or IntPtr.Zero to let the system pick.</param>
    /// <param name="size">Allocation size in bytes.</param>
    /// <param name="allocationType">MEM_XXX flags (e.g., 0x1000 for MEM_COMMIT, 0x2000 for MEM_RESERVE).</param>
    /// <param name="protect">PAGE_XXX flags (e.g., 0x04 for PAGE_READWRITE).</param>
    /// <returns>Base address of the allocated region inside the target process.</returns>
    public IntPtr AllocateMem(int processId, IntPtr baseAddress, ulong size, uint allocationType, uint protect)
    {
        var input = new TAllocateMemInputStruct
        {
            ProcessID = unchecked((ulong)processId),
            BaseAddress = unchecked((ulong)baseAddress.ToInt64()),
            Size = size,
            AllocationType = allocationType,
            Protect = protect
        };

        // Driver returns the allocated base address as 64-bit value
        var allocated = Ioctl<TAllocateMemInputStruct, ulong>(DBKIoctlCodes.IOCTL_CE_ALLOCATEMEM, input);
        return new IntPtr(unchecked((long)allocated));
    }

    /// <summary>
    /// Allocates nonpaged kernel memory via the driver (ExAllocatePool with NonPagedPool).
    /// This memory is in kernel space and not directly accessible from user-mode; it's meant for driver-assisted workflows.
    /// </summary>
    /// <param name="size">Allocation size in bytes.</param>
    /// <returns>Kernel virtual address of the allocated nonpaged buffer, or IntPtr.Zero on failure.</returns>
    public IntPtr AllocateNonPaged(uint size)
    {
        var input = new TAllocateNonPagedInputStruct { Size = size };
        var address = Ioctl<TAllocateNonPagedInputStruct, ulong>(DBKIoctlCodes.IOCTL_CE_ALLOCATEMEM_NONPAGED, input);
        return new IntPtr(unchecked((long)address));
    }

    /// <summary>
    /// Frees a previously allocated nonpaged kernel buffer.
    /// </summary>
    /// <param name="address">Kernel pointer previously obtained from <see cref="AllocateNonPaged"/>.</param>
    public void FreeNonPaged(IntPtr address)
    {
        var input = new TFreeNonPagedInputStruct { Address = unchecked((ulong)address.ToInt64()) };
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_FREE_NONPAGED, input);
    }

    /// <summary>
    /// Maps a locked view of pages from a source process into a destination process using the driver.
    /// On success returns the mapped user-mode address and provides the MDL used for the mapping via <paramref name="fromMdl"/>.
    /// </summary>
    /// <param name="fromProcessId">Source process ID owning the original address range. Use 0 for kernel/self as per driver semantics.</param>
    /// <param name="toProcessId">Destination process ID where the mapping will be created. Use 0 for kernel/self.</param>
    /// <param name="address">Base address in the source process to map.</param>
    /// <param name="size">Size in bytes to map.</param>
    /// <param name="fromMdl">Outputs the MDL allocated by the driver; required for unmapping.</param>
    /// <returns>User-mode mapped address in the destination process.</returns>
    public IntPtr MapMemory(int fromProcessId, int toProcessId, IntPtr address, uint size, out IntPtr fromMdl)
    {
        var input = new TMapMemoryInputStruct
        {
            FromPID = unchecked((ulong)fromProcessId),
            ToPID = unchecked((ulong)toProcessId),
            address = unchecked((ulong)address.ToInt64()),
            size = size
        };

        var output = Ioctl<TMapMemoryInputStruct, TMapMemoryOutputStruct>(DBKIoctlCodes.IOCTL_CE_MAP_MEMORY, input);
        fromMdl = new IntPtr(unchecked((long)output.FromMDL));
        return new IntPtr(unchecked((long)output.Address));
    }

    /// <summary>
    /// Unmaps and unlocks a previously mapped memory view created by <see cref="MapMemory"/>.
    /// </summary>
    /// <param name="mappedAddress">The mapped address returned by MapMemory.</param>
    /// <param name="fromMdl">The MDL returned via MapMemory out parameter.</param>
    public void UnmapMemory(IntPtr mappedAddress, IntPtr fromMdl)
    {
        var input = new TUnmapMemoryInputStruct
        {
            FromMDL = unchecked((ulong)fromMdl.ToInt64()),
            Address = unchecked((ulong)mappedAddress.ToInt64())
        };
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_UNMAP_MEMORY, input);
    }

    /// <summary>
    /// Locks a user-mode memory range in the context of the specified process and returns an MDL.
    /// </summary>
    /// <param name="processId">Process ID whose address range will be locked.</param>
    /// <param name="address">Base address to lock.</param>
    /// <param name="size">Size in bytes to lock.</param>
    /// <returns>Pointer to an MDL representing the locked pages.</returns>
    public IntPtr LockMemory(int processId, IntPtr address, ulong size)
    {
        var input = new TLockMemoryInputStruct
        {
            ProcessID = unchecked((ulong)processId),
            address = unchecked((ulong)address.ToInt64()),
            size = size
        };
        var output = Ioctl<TLockMemoryInputStruct, TLockMemoryOutputStruct>(DBKIoctlCodes.IOCTL_CE_LOCK_MEMORY, input);
        return new IntPtr(unchecked((long)output.mdl));
    }

    /// <summary>
    /// Unlocks and frees a previously obtained MDL from <see cref="LockMemory"/>.
    /// </summary>
    /// <param name="mdl">MDL pointer previously returned by <see cref="LockMemory"/>.</param>
    public void UnlockMemory(IntPtr mdl)
    {
        var input = new TUnlockMemoryInputStruct { mdl = unchecked((ulong)mdl.ToInt64()) };
        IoctlWrite(DBKIoctlCodes.IOCTL_CE_UNLOCK_MEMORY, input);
    }
    
    public void WriteProcessMemory64(int processId, IntPtr addr, byte[] buffer, int size)
    {
        EnsureDeviceIsReady();

        const int maxChunkSize = ushort.MaxValue;
        var bytesWritten = 0;

        var ioctlCode = DBKIoctlCodes.IOCTL_CE_WRITEMEMORY;
        var memPointer = (ulong)addr;
        var bufPointer = 0;
        var remaining = size;

        while (remaining > 0)
        {
            var toWrite = (ushort)Math.Min(remaining, maxChunkSize);

            var inputHeader = new TWriteProcessMemory64InputStruct
            {
                ProcessId = (ulong)processId,
                StartAddress = memPointer,
                BytesToWrite = toWrite
            };

            var inputHeaderSize = Marshal.SizeOf<TWriteProcessMemory64InputStruct>();
            var inputBuffer = Marshal.AllocHGlobal(inputHeaderSize + toWrite);

            try
            {
                // Write the header
                Marshal.StructureToPtr(inputHeader, inputBuffer, false);

                // Write the payload directly after the header
                var payloadPtr = IntPtr.Add(inputBuffer, inputHeaderSize);
                Marshal.Copy(buffer, bufPointer, payloadPtr, toWrite);

                if (!DeviceIoControl(deviceHandle, ioctlCode,
                        inputBuffer, (uint)(inputHeaderSize + toWrite),
                        IntPtr.Zero, 0,
                        out uint _, IntPtr.Zero))
                {
                    throw new Win32Exception($"Failed to write memory at {memPointer.ToHexadecimal()}, requested {toWrite} bytes.");
                }

                memPointer += toWrite;
                bufPointer += toWrite;
                bytesWritten += toWrite;
                remaining -= toWrite;
            }
            finally
            {
                Marshal.FreeHGlobal(inputBuffer);
            }
        }
    }

    public void ReadProcessMemory64(int processId, IntPtr addr, byte[] buffer, int size)
    {
        EnsureDeviceIsReady();

        const int maxChunkSize = ushort.MaxValue;
        var bytesRead = 0L;

        var ioctlCode = DBKIoctlCodes.IOCTL_CE_READMEMORY;
        
        var memPointer = (ulong)addr;
        var bufPointer = 0;
        long remaining = size;

        while (remaining > 0)
        {
            var toRead = (ushort)Math.Min(remaining, maxChunkSize);

            var input = new TReadProcessMemory64InputStruct
            {
                Processid = (ulong)processId,
                StartAddress = memPointer,
                BytesToRead = toRead
            };

            var inputSize = Marshal.SizeOf<TReadProcessMemory64InputStruct>();
            var inputPtr = Marshal.AllocHGlobal(inputSize);
            var outputPtr = Marshal.AllocHGlobal(toRead);

            try
            {
                Marshal.StructureToPtr(input, inputPtr, false);

                if (!DeviceIoControl(deviceHandle, ioctlCode,
                        inputPtr, (uint)inputSize,
                        outputPtr, toRead,
                        out var chunkBytesRead, IntPtr.Zero))
                {
                    throw new Win32Exception($"Failed to read memory at {memPointer.ToHexadecimal()}, requested {toRead} bytes.");
                }

                Marshal.Copy(outputPtr, buffer, bufPointer, (int)chunkBytesRead);

                memPointer += chunkBytesRead;
                bufPointer += (int)chunkBytesRead;
                bytesRead += chunkBytesRead;
                remaining -= chunkBytesRead;

                if (chunkBytesRead != toRead)
                {
                    throw new IOException($"Incomplete read at {memPointer.ToHexadecimal()}: requested {toRead}, got {chunkBytesRead}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
                Marshal.FreeHGlobal(outputPtr);
            }
        }
    }

    private void EnsureDeviceIsReady()
    {
        if (deviceHandle == null || deviceHandle.IsInvalid)
        {
            throw new InvalidOperationException("Device is not ready");
        }
    }

    public int DeviceReadInt32(uint ioctlCode)
    {
        return (int) DeviceReadUInt32(ioctlCode);
    }
    
    public uint DeviceReadUInt32(uint ioctlCode)
    {
        var outBuffer = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            DeviceRead(ioctlCode, outBuffer, (uint) sizeof(uint), out var _);
            var result = (uint) Marshal.ReadInt32(outBuffer);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(outBuffer);
        }
    }
    
    public void DeviceWriteByte(uint ioctlCode, byte value)
    {
        var inBuffer = Marshal.AllocHGlobal(sizeof(byte));
        try
        {
            Marshal.WriteByte(inBuffer, value);
            DeviceWrite(ioctlCode, inBuffer, sizeof(byte), out var _);
        }
        finally
        {
            Marshal.FreeHGlobal(inBuffer);
        }
    }

    public ulong DeviceReadUInt64(uint ioctlCode)
    {
        uint bytesReturned;
        ulong result = 0;

        var outBuffer = Marshal.AllocHGlobal(sizeof(ulong));
        try
        {
            DeviceRead(ioctlCode, outBuffer, (uint) sizeof(ulong), out bytesReturned);
            result = (ulong) Marshal.ReadInt64(outBuffer);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(outBuffer);
        }
    }

    public void DeviceRead(uint ioctlCode, IntPtr outBuffer, uint outBufferSize, out uint bytesReturned)
    {
        DeviceIoControl(ioctlCode, IntPtr.Zero, 0, outBuffer, outBufferSize, out bytesReturned);
    }
    
    public void DeviceWrite(uint ioctlCode, IntPtr inBuffer, uint inBufferSize, out uint bytesReturned)
    {
        DeviceIoControl(ioctlCode, inBuffer, inBufferSize, IntPtr.Zero, 0, out bytesReturned);
    }

    public void DeviceIoControl(uint ioctlCode, IntPtr inBuffer, uint inBufferSize, IntPtr outBuffer, uint outBufferSize, out uint bytesReturned)
    {
        EnsureDeviceIsReady();

        var success = DeviceIoControl(deviceHandle, ioctlCode,
            inBuffer, inBufferSize,
            outBuffer, outBufferSize,
            out bytesReturned, IntPtr.Zero);

        if (!success)
        {
            var lastError = Marshal.GetLastWin32Error();
            throw new Win32Exception(lastError, $"Operation failed, ioctlCode: {ioctlCode}, errorCode: {lastError}");
        }
    }

    public TOut Ioctl<TIn, TOut>(uint ioctlCode, in TIn input)
        where TIn : unmanaged
        where TOut : unmanaged
    {
        var inSize = (uint)Marshal.SizeOf<TIn>();
        var outSize = (uint)Marshal.SizeOf<TOut>();

        var inPtr = Marshal.AllocHGlobal((int)inSize);
        var outPtr = Marshal.AllocHGlobal((int)outSize);
        try
        {
            Marshal.StructureToPtr(input, inPtr, fDeleteOld: false);

            DeviceIoControl(ioctlCode, inPtr, inSize, outPtr, outSize, out var _);

            return Marshal.PtrToStructure<TOut>(outPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
            Marshal.FreeHGlobal(outPtr);
        }
    }

    public TOut IoctlRead<TOut>(uint ioctlCode)
        where TOut : unmanaged
    {
        var outSize = (uint)Marshal.SizeOf<TOut>();
        var outPtr = Marshal.AllocHGlobal((int)outSize);
        try
        {
            DeviceIoControl(ioctlCode, IntPtr.Zero, 0, outPtr, outSize, out var _);
            return Marshal.PtrToStructure<TOut>(outPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    public void IoctlWrite<TIn>(uint ioctlCode, in TIn input)
        where TIn : unmanaged
    {
        var inSize = (uint)Marshal.SizeOf<TIn>();
        var inPtr = Marshal.AllocHGlobal((int)inSize);
        try
        {
            Marshal.StructureToPtr(input, inPtr, fDeleteOld: false);
            DeviceIoControl(ioctlCode, inPtr, inSize, IntPtr.Zero, 0, out var _);
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
        }
    }

    /// <summary>
    /// Injects a DLL into a target process using IOCTL_BLACKBONE_INJECT_DLL.
    /// This uses BlackBone's driver path with ManualMap (default) and minimal options.
    /// </summary>
    /// <param name="processId">Target process ID.</param>
    /// <param name="fullDllPath">Fully-qualified path to the DLL to inject.</param>
    /// <param name="injectType"></param>
    /// <param name="initArg">Optional init routine argument string. Null or empty for none.</param>
    /// <param name="initRva">Optional init routine RVA; 0 to skip calling an init routine.</param>
    /// <param name="wait">Whether to wait on the injection thread to complete.</param>
    /// <param name="unlink">Whether to unlink the module after injection.</param>
    /// <param name="erasePE">Whether to erase PE headers after injection.</param>
    public void InjectDll(
        int processId, 
        string fullDllPath,
        InjectType injectType = InjectType.IT_Thread,
        string? initArg = null, 
        uint initRva = 0, 
        bool wait = true, 
        bool unlink = false, 
        bool erasePE = false)
    {
        if (string.IsNullOrWhiteSpace(fullDllPath))
        {
            throw new ArgumentException("Path must be a non-empty fully qualified path", nameof(fullDllPath));
        }

        if (Marshal.SizeOf<TInjectDllInputStruct>() != 2088)
        {
            throw new InvalidOperationException("TInjectDllInputStruct size changed, please update the driver");
        }

        var input = new TInjectDllInputStruct
        {
            type = injectType,
            initRVA = initRva,
            pid = unchecked((uint)processId),
            wait = wait ? (byte)1 : (byte)0,
            unlink = unlink ? (byte)1 : (byte)0,
            erasePE = erasePE ? (byte)1 : (byte)0,
            flags = KMmapFlags.KNoFlags,
            imageBase = 0,
            imageSize = 0,
            asImage = 0
        };

        // Copy strings as wide chars into fixed-size buffers
        input.SetFullDllPath(fullDllPath);
        if (!string.IsNullOrEmpty(initArg))
        {
            input.SetInitArg(initArg!);
        }

        IoctlWrite(DBKIoctlCodes.IOCTL_BLACKBONE_INJECT_DLL, input);
    }

    public void Dispose()
    {
        if (deviceHandle != null! && !deviceHandle.IsInvalid)
        {
            deviceHandle.Dispose();
            deviceHandle = null!;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TReadProcessMemory64InputStruct
    {
        public ulong Processid;
        public ulong StartAddress;
        public ushort BytesToRead;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TWriteProcessMemory64InputStruct
    {
        public ulong ProcessId;
        public ulong StartAddress;
        public ushort BytesToWrite;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TOpenProcessInputStruct
    {
        public long ProcessId;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TWritesIgnoresWPInputStruct
    {
        public byte IgnoreWriteProtection;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TOpenProcessOutputStruct
    {
        public long Handle;
        
        /// <summary>
        /// Set to 1 if driver had to open the process, 0 if it was already there
        /// </summary>
        public byte Special;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TQueryVirtualMemoryInputStruct
    {
        public ulong ProcessID;      
        public ulong StartAddress;  
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public record struct TQueryVirtualMemoryOutputStruct
    {
        public ulong Length;     
        public uint Protection;  
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TCreateApcInputStruct
    {
        public ulong ThreadId;          
        public ulong AddressToExecute;  
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TProcessIdInputStruct
    {
        public uint ProcessId; 
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TThreadIdInputStruct
    {
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TAllocateMemInputStruct
    {
        public ulong ProcessID;
        public ulong BaseAddress;
        public ulong Size;
        public ulong AllocationType;
        public ulong Protect;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TAllocateNonPagedInputStruct
    {
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TFreeNonPagedInputStruct
    {
        public ulong Address;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TMapMemoryInputStruct
    {
        public ulong FromPID;
        public ulong ToPID;
        public ulong address;
        public uint size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TMapMemoryOutputStruct
    {
        public ulong FromMDL;
        public ulong Address;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TUnmapMemoryInputStruct
    {
        public ulong FromMDL;
        public ulong Address;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TLockMemoryInputStruct
    {
        public ulong ProcessID;
        public ulong address;
        public ulong size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TLockMemoryOutputStruct
    {
        public ulong mdl;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TUnlockMemoryInputStruct
    {
        public ulong mdl;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TCreateRemoteThreadInputStruct
    {
        public ulong ProcessId;
        public ulong StartAddress;
        public ulong Parameter;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private record struct TCreateRemoteThreadOutputStruct
    {
        public ulong ThreadProcessId;
        public ulong ThreadId;
    }

    /// <summary>Injection type.</summary>
    public enum InjectType : uint
    {
        /// <summary>CreateThread into LdrLoadDll.</summary>
        IT_Thread = 0,
        /// <summary>Queue a user APC into LdrLoadDll.</summary>
        IT_Apc = 1,
        /// <summary>Manual map.</summary>
        IT_MMap = 2,
    }

    /// <summary>Manual-map flags (bitfield, matches native <c>KMmapFlags</c>).</summary>
    [Flags]
    public enum KMmapFlags : uint
    {
        /// <summary>No flags.</summary>
        KNoFlags        = 0x00000,
        /// <summary>Manually resolve/import libraries.</summary>
        KManualImports  = 0x00001,
        /// <summary>Wipe image PE headers.</summary>
        KWipeHeader     = 0x00004,
        /// <summary>Hide VAD (appear as PAGE_NOACCESS region).</summary>
        KHideVAD        = 0x00010,
        /// <summary>Replace process base if target image is EXE.</summary>
        KRebaseProcess  = 0x00040,
        /// <summary>Don’t create new threads; use hijacking.</summary>
        KNoThreads      = 0x00080,
        /// <summary>Do not install a custom exception handler.</summary>
        KNoExceptions   = 0x01000,
        /// <summary>Do not apply SxS activation context.</summary>
        KNoSxS          = 0x08000,
        /// <summary>Skip TLS init/callbacks.</summary>
        KNoTLS          = 0x10000,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    private unsafe struct TInjectDllInputStruct
    {
        public InjectType type;
        public fixed char FullDllPath[512];
        public fixed char initArg[512];
        public uint initRVA;
        public uint pid;
        public byte wait;
        public byte unlink;
        public byte erasePE;
        public KMmapFlags flags;
        public ulong imageBase;
        public uint imageSize;
        public byte asImage;
        
        public void SetFullDllPath(string value)
        {
            fixed (char* p = FullDllPath)
            {
                WriteFixedString(p, 512, value);
            }
        }

        public void SetInitArg(string value)
        {
            fixed (char* p = initArg)
            {
                WriteFixedString(p, 512, value);
            }
        }

        private static void WriteFixedString(char* dest, int capacity, string? value)
        {
            var span = new Span<char>(dest, capacity);
            span.Clear();
            if (string.IsNullOrEmpty(value)) return;
            var toCopy = Math.Min(value.Length, capacity - 1); // ensure null-terminated
            value.AsSpan(0, toCopy).CopyTo(span);
            span[toCopy] = '\0';
        }
    }
}