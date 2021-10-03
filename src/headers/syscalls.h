#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>



#define SW2_SEED 0xEAAF5BF8
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)


// New definitions
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_CREATE 0x00000002
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define MEM_EXTENDED_PARAMETER_TYPE_BITS 8
typedef UCHAR SE_SIGNING_LEVEL, *PSE_SIGNING_LEVEL;
#define SE_SIGNING_LEVEL_UNCHECKED         0x00000000
#define SE_SIGNING_LEVEL_UNSIGNED          0x00000001
#define SE_SIGNING_LEVEL_ENTERPRISE        0x00000002
#define SE_SIGNING_LEVEL_CUSTOM_1          0x00000003
#define SE_SIGNING_LEVEL_AUTHENTICODE      0x00000004
#define SE_SIGNING_LEVEL_CUSTOM_2          0x00000005
#define SE_SIGNING_LEVEL_STORE             0x00000006
#define SE_SIGNING_LEVEL_CUSTOM_3          0x00000007
#define SE_SIGNING_LEVEL_ANTIMALWARE       SE_SIGNING_LEVEL_CUSTOM_3
#define SE_SIGNING_LEVEL_MICROSOFT         0x00000008
#define SE_SIGNING_LEVEL_CUSTOM_4          0x00000009
#define SE_SIGNING_LEVEL_CUSTOM_5          0x0000000A
#define SE_SIGNING_LEVEL_DYNAMIC_CODEGEN   0x0000000B
#define SE_SIGNING_LEVEL_WINDOWS           0x0000000C
#define SE_SIGNING_LEVEL_CUSTOM_7          0x0000000D
#define SE_SIGNING_LEVEL_WINDOWS_TCB       0x0000000E
#define SE_SIGNING_LEVEL_CUSTOM_6          0x0000000F


// Typedefs are prefixed to avoid pollution.
typedef GUID UUID;
typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK *PACCESS_MASK;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct MEM_EXTENDED_PARAMETER {
  struct {
    DWORD64 Type : MEM_EXTENDED_PARAMETER_TYPE_BITS;
    DWORD64 Reserved : 64 - MEM_EXTENDED_PARAMETER_TYPE_BITS;
  } DUMMYSTRUCTNAME;
  union {
    DWORD64 ULong64;
    PVOID   Pointer;
    SIZE_T  Size;
    HANDLE  Handle;
    DWORD   ULong;
  } DUMMYUNIONNAME;
} MEM_EXTENDED_PARAMETER, *PMEM_EXTENDED_PARAMETER;

typedef void (WINAPI* _RtlInitUnicodeString) (PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS (WINAPI* _RtlSetCurrentTransaction) (PHANDLE);
typedef LONG KPRIORITY;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;



typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

DWORD SW2_HashSyscall(PCSTR FunctionName);
BOOL SW2_PopulateSyscallList();
EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash);


typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, *PWNF_TYPE_ID;

typedef enum _KCONTINUE_TYPE
{
	KCONTINUE_UNWIND,
	KCONTINUE_RESUME,
	KCONTINUE_LONGJUMP,
	KCONTINUE_SET,
	KCONTINUE_LAST
} KCONTINUE_TYPE;

/*
typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
*/

typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE, *PPS_CREATE_STATE;



typedef enum _PLUGPLAY_EVENT_CATEGORY
{
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	InvalidIDEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, *PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE
{
	PNP_VetoTypeUnknown, // unspecified
	PNP_VetoLegacyDevice, // instance path
	PNP_VetoPendingClose, // instance path
	PNP_VetoWindowsApp, // module
	PNP_VetoWindowsService, // service
	PNP_VetoOutstandingOpen, // instance path
	PNP_VetoDevice, // instance path
	PNP_VetoDriver, // driver service name
	PNP_VetoIllegalDeviceRequest, // instance path
	PNP_VetoInsufficientPower, // unspecified
	PNP_VetoNonDisableable, // instance path
	PNP_VetoLegacyDriver, // service
	PNP_VetoInsufficientRights  // unspecified
} PNP_VETO_TYPE, *PPNP_VETO_TYPE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;
	union
	{
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _WNF_STATE_NAME
{
	ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG           DataLength;
	ULONG           DataOffset;
	ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum.
} KEY_SET_INFORMATION_CLASS, *PKEY_SET_INFORMATION_CLASS;


typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG    Version;
	ULONG    Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, *PT2_SET_PARAMETERS;

typedef struct _FILE_PATH
{
	ULONG Version;
	ULONG Length;
	ULONG Type;
	CHAR  FilePath[1];
} FILE_PATH, *PFILE_PATH;

typedef struct _FILE_USER_QUOTA_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         SidLength;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER QuotaUsed;
	LARGE_INTEGER QuotaThreshold;
	LARGE_INTEGER QuotaLimit;
	SID           Sid[1];
} FILE_USER_QUOTA_INFORMATION, *PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	SID   Sid[1];
} FILE_QUOTA_LIST_INFORMATION, *PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
	ULONG         Unknown;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
	FilterBootOptionOperationOpenSystemStore,
	FilterBootOptionOperationSetElement,
	FilterBootOptionOperationDeleteElement,
	FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION, *PFILTER_BOOT_OPTION_OPERATION;

typedef enum _EVENT_TYPE
{
	NotificationEvent = 0,
	SynchronizationEvent = 1,
} EVENT_TYPE, *PEVENT_TYPE;

typedef struct _FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	BYTE  EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

typedef struct _BOOT_OPTIONS
{
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem = 0,
	WnfDataScopeSession = 1,
	WnfDataScopeUser = 2,
	WnfDataScopeProcess = 3,
	WnfDataScopeMachine = 4
} WNF_DATA_SCOPE, *PWNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName = 0,
	WnfPermanentStateName = 1,
	WnfPersistentStateName = 2,
	WnfTemporaryStateName = 3
} WNF_STATE_NAME_LIFETIME, *PWNF_STATE_NAME_LIFETIME;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS, *PVIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _IO_SESSION_EVENT
{
	IoSessionEventIgnore,
	IoSessionEventCreated,
	IoSessionEventTerminated,
	IoSessionEventConnected,
	IoSessionEventDisconnected,
	IoSessionEventLogon,
	IoSessionEventLogoff,
	IoSessionEventMax
} IO_SESSION_EVENT, *PIO_SESSION_EVENT;

typedef enum _PORT_INFORMATION_CLASS
{
	PortBasicInformation,
#if DEVL
	PortDumpInformation
#endif
} PORT_INFORMATION_CLASS, *PPORT_INFORMATION_CLASS;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
	PlugPlayControlEnumerateDevice,
	PlugPlayControlRegisterNewDevice,
	PlugPlayControlDeregisterDevice,
	PlugPlayControlInitializeDevice,
	PlugPlayControlStartDevice,
	PlugPlayControlUnlockDevice,
	PlugPlayControlQueryAndRemoveDevice,
	PlugPlayControlUserResponse,
	PlugPlayControlGenerateLegacyDevice,
	PlugPlayControlGetInterfaceDeviceList,
	PlugPlayControlProperty,
	PlugPlayControlDeviceClassAssociation,
	PlugPlayControlGetRelatedDevice,
	PlugPlayControlGetInterfaceDeviceAlias,
	PlugPlayControlDeviceStatus,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlQueryDeviceRelations,
	PlugPlayControlTargetDeviceRelation,
	PlugPlayControlQueryConflictList,
	PlugPlayControlRetrieveDock,
	PlugPlayControlResetDevice,
	PlugPlayControlHaltDevice,
	PlugPlayControlGetBlockedDriverList,
	MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, *PPLUGPLAY_CONTROL_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, *PIO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, *PSEMAPHORE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _VDMSERVICECLASS
{
	VdmStartExecution,
	VdmQueueInterrupt,
	VdmDelayInterrupt,
	VdmInitialize,
	VdmFeatures,
	VdmSetInt21Handler,
	VdmQueryDir,
	VdmPrinterDirectIoOpen,
	VdmPrinterDirectIoClose,
	VdmPrinterInitialize,
	VdmSetLdtEntries,
	VdmSetProcessLdtInfo,
	VdmAdlibEmulation,
	VdmPMCliControl,
	VdmQueryVdmProcess
} VDMSERVICECLASS, *PVDMSERVICECLASS;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR  WriteOutputOnExit : 1;
					UCHAR  DetectManifest : 1;
					UCHAR  IFEOSkipDebugger : 1;
					UCHAR  IFEODoNotPropagateKeyState : 1;
					UCHAR  SpareBits1 : 4;
					UCHAR  SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;
		// PsCreateFailOnSectionCreate
		struct {
			HANDLE FileHandle;
		} FailSection;
		// PsCreateFailExeFormat
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;
		// PsCreateFailExeName
		struct {
			HANDLE IFEOKey;
		} ExeName;
		// PsCreateSuccess
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR  ProtectedProcess : 1;
					UCHAR  AddressSpaceOverride : 1;
					UCHAR  DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR  ManifestDetected : 1;
					UCHAR  ProtectedProcessLight : 1;
					UCHAR  SpareBits1 : 3;
					UCHAR  SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE    FileHandle;
			HANDLE    SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG     UserProcessParametersWow64;
			ULONG     CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG     PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG     ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE, *PMEMORY_RESERVE_TYPE;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
	AlpcBasicInformation,
	AlpcPortInformation,
	AlpcAssociateCompletionPortInformation,
	AlpcConnectedSIDInformation,
	AlpcServerInformation,
	AlpcMessageZoneInformation,
	AlpcRegisterCompletionListInformation,
	AlpcUnregisterCompletionListInformation,
	AlpcAdjustCompletionListConcurrencyCountInformation,
	AlpcRegisterCallbackInformation,
	AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS, *PALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
	PVOID PortContext;
	PVOID MessageContext;
	ULONG SequenceNumber;
	ULONG MessageID;
	ULONG CallbackID;
} ALPC_CONTEXT_ATTR, *PALPC_CONTEXT_ATTR;

typedef struct _ALPC_DATA_VIEW_ATTR
{
	ULONG  Flags;
	HANDLE SectionHandle;
	PVOID  ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, *PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_SECURITY_ATTR
{
	ULONG                        Flags;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	HANDLE                       ContextHandle;
	ULONG                        Reserved1;
	ULONG                        Reserved2;
} ALPC_SECURITY_ATTR, *PALPC_SECURITY_ATTR;

typedef PVOID* PPVOID;

typedef enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24,
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
	AlpcMessageSidInformation,
	AlpcMessageTokenModifiedIdInformation
} ALPC_MESSAGE_INFORMATION_CLASS, *PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout,
	WorkerFactoryRetryTimeout,
	WorkerFactoryIdleTimeout,
	WorkerFactoryBindingCount,
	WorkerFactoryThreadMinimum,
	WorkerFactoryThreadMaximum,
	WorkerFactoryPaused,
	WorkerFactoryBasicInformation,
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation,
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
	SystemMemoryPartitionInformation,
	SystemMemoryPartitionMoveMemory,
	SystemMemoryPartitionAddPagefile,
	SystemMemoryPartitionCombineMemory,
	SystemMemoryPartitionInitialAddMemory,
	SystemMemoryPartitionGetMemoryEvents,
	SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS, *PMEMORY_PARTITION_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation,
	MutantOwnerInformation
} MUTANT_INFORMATION_CLASS, *PMUTANT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS, *PATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
	IN PVOID TimerContext,
	IN ULONG TimerLowValue,
	IN LONG TimerHighValue);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef LANGID* PLANGID;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
	GUID EventGuid;
	PLUGPLAY_EVENT_CATEGORY EventCategory;
	PULONG Result;
	ULONG Flags;
	ULONG TotalSize;
	PVOID DeviceObject;

	union
	{
		struct
		{
			GUID ClassGuid;
			WCHAR SymbolicLinkName[1];
		} DeviceClass;
		struct
		{
			WCHAR DeviceIds[1];
		} TargetDevice;
		struct
		{
			WCHAR DeviceId[1];
		} InstallDevice;
		struct
		{
			PVOID NotificationStructure;
			WCHAR DeviceIds[1];
		} CustomNotification;
		struct
		{
			PVOID Notification;
		} ProfileNotification;
		struct
		{
			ULONG NotificationCode;
			ULONG NotificationData;
		} PowerNotification;
		struct
		{
			PNP_VETO_TYPE VetoType;
			WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<null>VetoName<null><null>
		} VetoNotification;
		struct
		{
			GUID BlockedDriverGuid;
		} BlockedDriverNotification;
		struct
		{
			WCHAR ParentId[1];
		} InvalidIDNotification;
	} u;
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS
{
	DirectoryNotifyInformation = 1,
	DirectoryNotifyExtendedInformation = 2,
} DIRECTORY_NOTIFY_INFORMATION_CLASS, *PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS, *PEVENT_INFORMATION_CLASS;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	unsigned long AllocatedAttributes;
	unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG                       Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T                      MaxMessageLength;
	SIZE_T                      MemoryBandwidth;
	SIZE_T                      MaxPoolUsage;
	SIZE_T                      MaxSectionSize;
	SIZE_T                      MaxViewSize;
	SIZE_T                      MaxTotalSectionSize;
	ULONG                       DupObjectTypes;
#ifdef _WIN64
	ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef enum _IO_SESSION_STATE
{
	IoSessionStateCreated = 1,
	IoSessionStateInitialized = 2,
	IoSessionStateConnected = 3,
	IoSessionStateDisconnected = 4,
	IoSessionStateDisconnectedLoggedOn = 5,
	IoSessionStateLoggedOn = 6,
	IoSessionStateLoggedOff = 7,
	IoSessionStateTerminated = 8,
	IoSessionStateMax = 9,
} IO_SESSION_STATE, *PIO_SESSION_STATE;

typedef const WNF_STATE_NAME *PCWNF_STATE_NAME;

typedef const WNF_TYPE_ID *PCWNF_TYPE_ID;

typedef struct _WNF_DELIVERY_DESCRIPTOR
{
	unsigned __int64 SubscriptionId;
	WNF_STATE_NAME   StateName;
	unsigned long    ChangeStamp;
	unsigned long    StateDataSize;
	unsigned long    EventMask;
	WNF_TYPE_ID      TypeId;
	unsigned long    StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, *PWNF_DELIVERY_DESCRIPTOR;

typedef enum _DEBUG_CONTROL_CODE
{
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracePoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31
} DEBUG_CONTROL_CODE, *PDEBUG_CONTROL_CODE;

typedef struct _PORT_MESSAGE
{
	union
	{
		union
		{
			struct
			{
				short DataLength;
				short TotalLength;
			} s1;
			unsigned long Length;
		};
	} u1;
	union
	{
		union
		{
			struct
			{
				short Type;
				short DataInfoOffset;
			} s2;
			unsigned long ZeroInit;
		};
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double    DoNotUseThisField;
	};
	unsigned long MessageId;
	union
	{
		unsigned __int64 ClientViewSize;
		struct
		{
			unsigned long CallbackId;
			long          __PADDING__[1];
		};
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _PORT_SECTION_READ
{
	ULONG Length;
	ULONG ViewSize;
	ULONG ViewBase;
} PORT_SECTION_READ, *PPORT_SECTION_READ;

typedef struct _PORT_SECTION_WRITE
{
	ULONG  Length;
	HANDLE SectionHandle;
	ULONG  SectionOffset;
	ULONG  ViewSize;
	PVOID  ViewBase;
	PVOID  TargetViewBase;
} PORT_SECTION_WRITE, *PPORT_SECTION_WRITE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE, *PTIMER_TYPE;

typedef struct _BOOT_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

typedef USHORT RTL_ATOM, *PRTL_ATOM;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
	TimerSetCoalescableTimer,
	MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS, *PTIMER_SET_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsVolumeFlagsInformation = 10,
	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMetadataSizeInformation = 13,
	FileFsFullSizeInformationEx = 14,
	FileFsMaximumInformation = 15,
} FSINFOCLASS, *PFSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, *PWAIT_TYPE;

typedef struct _USER_STACK
{
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

typedef enum _APPHELPCACHESERVICECLASS
{
	ApphelpCacheServiceLookup = 0,
	ApphelpCacheServiceRemove = 1,
	ApphelpCacheServiceUpdate = 2,
	ApphelpCacheServiceFlush = 3,
	ApphelpCacheServiceDump = 4,
	ApphelpDBGReadRegistry = 0x100,
	ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, *PAPPHELPCACHESERVICECLASS;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID           KeyContext;
	PVOID           ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS, *PKEY_INFORMATION_CLASS;


typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS, *PTIMER_INFORMATION_CLASS;

typedef struct _KCONTINUE_ARGUMENT
{
	KCONTINUE_TYPE ContinueType;
	ULONG          ContinueFlags;
	ULONGLONG      Reserved[2];
} KCONTINUE_ARGUMENT, *PKCONTINUE_ARGUMENT;

EXTERN_C NTSTATUS NtAcceptConnectPort(
	OUT PHANDLE ServerPortHandle,
	IN ULONG AlternativeReceivePortHandle OPTIONAL,
	IN PPORT_MESSAGE ConnectionReply,
	IN BOOLEAN AcceptConnection,
	IN OUT PPORT_SECTION_WRITE ServerSharedMemory OPTIONAL,
	OUT PPORT_SECTION_READ ClientSharedMemory OPTIONAL);

EXTERN_C NTSTATUS NtAccessCheck(
	IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiaredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet OPTIONAL,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus);

EXTERN_C NTSTATUS NtAccessCheckAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN ACCESS_MASK DesiredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtAccessCheckByType(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ULONG DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus);

EXTERN_C NTSTATUS NtAccessCheckByTypeAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultList(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose);

EXTERN_C NTSTATUS NtAcquireCMFViewOwnership(
	OUT BOOLEAN TimeStamp,
	OUT BOOLEAN TokenTaken,
	IN BOOLEAN ReplaceExisting);

EXTERN_C NTSTATUS NtAcquireProcessActivityReference();

EXTERN_C NTSTATUS NtAddAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL);

EXTERN_C NTSTATUS NtAddAtomEx(
	IN PWSTR AtomName,
	IN ULONG Length,
	IN PRTL_ATOM Atom,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtAddBootEntry(
	IN PBOOT_ENTRY BootEntry,
	OUT PULONG Id OPTIONAL);

EXTERN_C NTSTATUS NtAddDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry,
	OUT PULONG Id OPTIONAL);

EXTERN_C NTSTATUS NtAdjustGroupsToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN ResetToDefault,
	IN PTOKEN_GROUPS NewState OPTIONAL,
	IN ULONG BufferLength OPTIONAL,
	OUT PTOKEN_GROUPS PreviousState OPTIONAL,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAdjustTokenClaimsAndDeviceGroups(
	IN HANDLE TokenHandle,
	IN BOOLEAN UserResetToDefault,
	IN BOOLEAN DeviceResetToDefault,
	IN BOOLEAN DeviceGroupsResetToDefault,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState OPTIONAL,
	IN PTOKEN_GROUPS NewDeviceGroupsState OPTIONAL,
	IN ULONG UserBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState OPTIONAL,
	IN ULONG DeviceBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState OPTIONAL,
	IN ULONG DeviceGroupsBufferLength,
	OUT PTOKEN_GROUPS PreviousDeviceGroups OPTIONAL,
	OUT PULONG UserReturnLength OPTIONAL,
	OUT PULONG DeviceReturnLength OPTIONAL,
	OUT PULONG DeviceGroupsReturnBufferLength OPTIONAL);

EXTERN_C NTSTATUS NtAlertResumeThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtAlertThread(
	IN HANDLE ThreadHandle);

EXTERN_C NTSTATUS NtAlertThreadByThreadId(
	IN ULONG ThreadId);

EXTERN_C NTSTATUS NtAllocateLocallyUniqueId(
	OUT PLUID Luid);

EXTERN_C NTSTATUS NtAllocateReserveObject(
	OUT PHANDLE MemoryReserveHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN MEMORY_RESERVE_TYPE Type);

EXTERN_C NTSTATUS NtAllocateUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	OUT PULONG UserPfnArray);

EXTERN_C NTSTATUS NtAllocateUuids(
	OUT PLARGE_INTEGER Time,
	OUT PULONG Range,
	OUT PULONG Sequence,
	OUT PUCHAR Seed);

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS NtAllocateVirtualMemoryEx(
	IN HANDLE ProcessHandle,
	IN OUT PPVOID lpAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T pSize,
	IN ULONG flAllocationType,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount);

EXTERN_C NTSTATUS NtAlpcAcceptConnectPort(
	OUT PHANDLE PortHandle,
	IN HANDLE ConnectionPortHandle,
	IN ULONG Flags,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ConnectionRequest,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes OPTIONAL,
	IN BOOLEAN AcceptConnection);

EXTERN_C NTSTATUS NtAlpcCancelMessage(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PALPC_CONTEXT_ATTR MessageContext);

EXTERN_C NTSTATUS NtAlpcConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PULONG BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtAlpcConnectPortEx(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
	IN POBJECT_ATTRIBUTES ClientPortObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSECURITY_DESCRIPTOR ServerSecurityRequirements OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtAlpcCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL);

EXTERN_C NTSTATUS NtAlpcCreatePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN SIZE_T SectionSize,
	OUT PHANDLE AlpcSectionHandle,
	OUT PSIZE_T ActualSectionSize);

EXTERN_C NTSTATUS NtAlpcCreateResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN SIZE_T MessageSize,
	OUT PHANDLE ResourceId);

EXTERN_C NTSTATUS NtAlpcCreateSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_DATA_VIEW_ATTR ViewAttributes);

EXTERN_C NTSTATUS NtAlpcCreateSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_SECURITY_ATTR SecurityAttribute);

EXTERN_C NTSTATUS NtAlpcDeletePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle);

EXTERN_C NTSTATUS NtAlpcDeleteResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ResourceId);

EXTERN_C NTSTATUS NtAlpcDeleteSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PVOID ViewBase);

EXTERN_C NTSTATUS NtAlpcDeleteSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle);

EXTERN_C NTSTATUS NtAlpcDisconnectPort(
	IN HANDLE PortHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtAlpcImpersonateClientContainerOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtAlpcImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN PVOID Flags);

EXTERN_C NTSTATUS NtAlpcOpenSenderProcess(
	OUT PHANDLE ProcessHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtAlpcOpenSenderThread(
	OUT PHANDLE ThreadHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtAlpcQueryInformation(
	IN HANDLE PortHandle OPTIONAL,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcQueryInformationMessage(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
	OUT PVOID MessageInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcRevokeSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle);

EXTERN_C NTSTATUS NtAlpcSendWaitReceivePort(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PPORT_MESSAGE SendMessage OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtAlpcSetInformation(
	IN HANDLE PortHandle,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN PVOID PortInformation OPTIONAL,
	IN ULONG Length);

EXTERN_C NTSTATUS NtApphelpCacheControl(
	IN APPHELPCACHESERVICECLASS Service,
	IN PVOID ServiceData);

EXTERN_C NTSTATUS NtAreMappedFilesTheSame(
	IN PVOID File1MappedAsAnImage,
	IN PVOID File2MappedAsFile);

EXTERN_C NTSTATUS NtAssignProcessToJobObject(
	IN HANDLE JobHandle,
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtAssociateWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN HANDLE IoCompletionHandle,
	IN HANDLE TargetObjectHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation,
	OUT PBOOLEAN AlreadySignaled OPTIONAL);

EXTERN_C NTSTATUS NtCallEnclave(
	IN PENCLAVE_ROUTINE Routine,
	IN PVOID Parameter,
	IN BOOLEAN WaitForThread,
	IN OUT PVOID ReturnValue OPTIONAL);

EXTERN_C NTSTATUS NtCallbackReturn(
	IN PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputLength,
	IN NTSTATUS Status);

EXTERN_C NTSTATUS NtCancelDeviceWakeupRequest(
	IN HANDLE DeviceHandle);

EXTERN_C NTSTATUS NtCancelIoFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtCancelIoFileEx(
	IN HANDLE FileHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtCancelSynchronousIoFile(
	IN HANDLE ThreadHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtCancelTimer(
	IN HANDLE TimerHandle,
	OUT PBOOLEAN CurrentState OPTIONAL);

EXTERN_C NTSTATUS NtCancelTimer2(
	IN HANDLE TimerHandle,
	IN PT2_CANCEL_PARAMETERS Parameters);

EXTERN_C NTSTATUS NtCancelWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN BOOLEAN RemoveSignaledPacket);

EXTERN_C NTSTATUS NtClearAllSavepointsTransaction(
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtClearEvent(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtClearSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId);

EXTERN_C NTSTATUS NtClose(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtCloseObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtCommitComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtCommitEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtCommitRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait);

EXTERN_C NTSTATUS NtCommitTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait);

EXTERN_C NTSTATUS NtCompactKeys(
	IN ULONG Count,
	IN HANDLE KeyArray);

EXTERN_C NTSTATUS NtCompareObjects(
	IN HANDLE FirstObjectHandle,
	IN HANDLE SecondObjectHandle);

EXTERN_C NTSTATUS NtCompareSigningLevels(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2);

EXTERN_C NTSTATUS NtCompareTokens(
	IN HANDLE FirstTokenHandle,
	IN HANDLE SecondTokenHandle,
	OUT PBOOLEAN Equal);

EXTERN_C NTSTATUS NtCompleteConnectPort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtCompressKey(
	IN HANDLE Key);

EXTERN_C NTSTATUS NtConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL);

EXTERN_C NTSTATUS NtContinue(
	IN PCONTEXT ContextRecord,
	IN BOOLEAN TestAlert);

EXTERN_C NTSTATUS NtContinueEx(
	IN PCONTEXT ContextRecord,
	IN PKCONTINUE_ARGUMENT ContinueArgument);

EXTERN_C NTSTATUS NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4);

EXTERN_C NTSTATUS NtCreateCrossVmEvent();

EXTERN_C NTSTATUS NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtCreateDirectoryObjectEx(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateEnclave(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T Size,
	IN SIZE_T InitialCommitment,
	IN ULONG EnclaveType,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtCreateEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN HANDLE TransactionHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN NOTIFICATION_MASK NotificationMask,
	IN PVOID EnlistmentKey OPTIONAL);

EXTERN_C NTSTATUS NtCreateEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN EVENT_TYPE EventType,
	IN BOOLEAN InitialState);

EXTERN_C NTSTATUS NtCreateEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength);

EXTERN_C NTSTATUS NtCreateIRTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess);

EXTERN_C NTSTATUS NtCreateIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Count OPTIONAL);

EXTERN_C NTSTATUS NtCreateJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtCreateJobSet(
	IN ULONG NumJob,
	IN PJOB_SET_ARRAY UserJobSet,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL);

EXTERN_C NTSTATUS NtCreateKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	IN HANDLE TransactionHandle,
	OUT PULONG Disposition OPTIONAL);

EXTERN_C NTSTATUS NtCreateKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateLowBoxToken(
	OUT PHANDLE TokenHandle,
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PSID PackageSid,
	IN ULONG CapabilityCount,
	IN PSID_AND_ATTRIBUTES Capabilities OPTIONAL,
	IN ULONG HandleCount,
	IN HANDLE Handles OPTIONAL);

EXTERN_C NTSTATUS NtCreateMailslotFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CreateOptions,
	IN ULONG MailslotQuota,
	IN ULONG MaximumMessageSize,
	IN PLARGE_INTEGER ReadTimeout);

EXTERN_C NTSTATUS NtCreateMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN BOOLEAN InitialOwner);

EXTERN_C NTSTATUS NtCreateNamedPipeFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN BOOLEAN NamedPipeType,
	IN BOOLEAN ReadMode,
	IN BOOLEAN CompletionMode,
	IN ULONG MaximumInstances,
	IN ULONG InboundQuota,
	IN ULONG OutboundQuota,
	IN PLARGE_INTEGER DefaultTimeout OPTIONAL);

EXTERN_C NTSTATUS NtCreatePagingFile(
	IN PUNICODE_STRING PageFileName,
	IN PULARGE_INTEGER MinimumSize,
	IN PULARGE_INTEGER MaximumSize,
	IN ULONG Priority);

EXTERN_C NTSTATUS NtCreatePartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG PreferredNode);

EXTERN_C NTSTATUS NtCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL);

EXTERN_C NTSTATUS NtCreatePrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PVOID BoundaryDescriptor);

EXTERN_C NTSTATUS NtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL);

EXTERN_C NTSTATUS NtCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel);

EXTERN_C NTSTATUS NtCreateProfile(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN ULONG ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN ULONG Affinity);

EXTERN_C NTSTATUS NtCreateProfileEx(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN SIZE_T ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN USHORT GroupCount,
	IN PGROUP_AFFINITY GroupAffinity);

EXTERN_C NTSTATUS NtCreateRegistryTransaction(
	OUT PHANDLE Handle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD Flags);

EXTERN_C NTSTATUS NtCreateResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID RmGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);

EXTERN_C NTSTATUS NtCreateSectionEx(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL,
	IN PMEM_EXTENDED_PARAMETER ExtendedParameters,
	IN ULONG ExtendedParametersCount);

EXTERN_C NTSTATUS NtCreateSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LONG InitialCount,
	IN LONG MaximumCount);

EXTERN_C NTSTATUS NtCreateSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING LinkTarget);

EXTERN_C NTSTATUS NtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PUSER_STACK InitialTeb,
	IN BOOLEAN CreateSuspended);

EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtCreateTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TIMER_TYPE TimerType);

EXTERN_C NTSTATUS NtCreateTimer2(
	OUT PHANDLE TimerHandle,
	IN PVOID Reserved1 OPTIONAL,
	IN PVOID Reserved2 OPTIONAL,
	IN ULONG Attributes,
	IN ACCESS_MASK DesiredAccess);

EXTERN_C NTSTATUS NtCreateToken(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource);

EXTERN_C NTSTATUS NtCreateTokenEx(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroups OPTIONAL,
	IN PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy OPTIONAL,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource);

EXTERN_C NTSTATUS NtCreateTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LPGUID Uow OPTIONAL,
	IN HANDLE TmHandle OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG IsolationLevel OPTIONAL,
	IN ULONG IsolationFlags OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS NtCreateTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG CommitStrength OPTIONAL);

EXTERN_C NTSTATUS NtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG ProcessFlags,
	IN ULONG ThreadFlags,
	IN PVOID ProcessParameters OPTIONAL,
	IN OUT PPS_CREATE_INFO CreateInfo,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtCreateWaitCompletionPacket(
	OUT PHANDLE WaitCompletionPacketHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtCreateWaitablePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL);

EXTERN_C NTSTATUS NtCreateWnfStateName(
	OUT PCWNF_STATE_NAME StateName,
	IN WNF_STATE_NAME_LIFETIME NameLifetime,
	IN WNF_DATA_SCOPE DataScope,
	IN BOOLEAN PersistData,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN ULONG MaximumStateSize,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor);

EXTERN_C NTSTATUS NtCreateWorkerFactory(
	OUT PHANDLE WorkerFactoryHandleReturn,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE CompletionPortHandle,
	IN HANDLE WorkerProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartParameter OPTIONAL,
	IN ULONG MaxThreadCount OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL);

EXTERN_C NTSTATUS NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);

EXTERN_C NTSTATUS NtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus);

EXTERN_C NTSTATUS NtDelayExecution(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval);

EXTERN_C NTSTATUS NtDeleteAtom(
	IN USHORT Atom);

EXTERN_C NTSTATUS NtDeleteBootEntry(
	IN ULONG Id);

EXTERN_C NTSTATUS NtDeleteDriverEntry(
	IN ULONG Id);

EXTERN_C NTSTATUS NtDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtDeleteKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtDeleteObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtDeletePrivateNamespace(
	IN HANDLE NamespaceHandle);

EXTERN_C NTSTATUS NtDeleteValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName);

EXTERN_C NTSTATUS NtDeleteWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID ExplicitScope OPTIONAL);

EXTERN_C NTSTATUS NtDeleteWnfStateName(
	IN PCWNF_STATE_NAME StateName);

EXTERN_C NTSTATUS NtDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtDisableLastKnownGood();

EXTERN_C NTSTATUS NtDisplayString(
	IN PUNICODE_STRING String);

EXTERN_C NTSTATUS NtDrawText(
	IN PUNICODE_STRING String);

EXTERN_C NTSTATUS NtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options);

EXTERN_C NTSTATUS NtDuplicateToken(
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN EffectiveOnly,
	IN TOKEN_TYPE TokenType,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtEnableLastKnownGood();

EXTERN_C NTSTATUS NtEnumerateBootEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtEnumerateDriverEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtEnumerateKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtEnumerateSystemEnvironmentValuesEx(
	IN ULONG InformationClass,
	OUT PVOID Buffer,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtEnumerateTransactionObject(
	IN HANDLE RootObjectHandle OPTIONAL,
	IN KTMOBJECT_TYPE QueryType,
	IN OUT PKTMOBJECT_CURSOR ObjectCursor,
	IN ULONG ObjectCursorLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtEnumerateValueKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtExtendSection(
	IN HANDLE SectionHandle,
	IN OUT PLARGE_INTEGER NewSectionSize);

EXTERN_C NTSTATUS NtFilterBootOption(
	IN FILTER_BOOT_OPTION_OPERATION FilterOperation,
	IN ULONG ObjectType,
	IN ULONG ElementType,
	IN PVOID SystemData OPTIONAL,
	IN ULONG DataSize);

EXTERN_C NTSTATUS NtFilterToken(
	IN HANDLE ExistingTokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtFilterTokenEx(
	IN HANDLE TokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	IN ULONG DisableUserClaimsCount,
	IN PUNICODE_STRING UserClaimsToDisable OPTIONAL,
	IN ULONG DisableDeviceClaimsCount,
	IN PUNICODE_STRING DeviceClaimsToDisable OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroupsToDisable OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS RestrictedDeviceGroups OPTIONAL,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtFindAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL);

EXTERN_C NTSTATUS NtFlushBuffersFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtFlushBuffersFileEx(
	IN HANDLE FileHandle,
	IN ULONG Flags,
	IN PVOID Parameters,
	IN ULONG ParametersSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtFlushInstallUILanguage(
	IN LANGID InstallUILanguage,
	IN ULONG SetComittedFlag);

EXTERN_C NTSTATUS NtFlushInstructionCache(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Length);

EXTERN_C NTSTATUS NtFlushKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtFlushProcessWriteBuffers();

EXTERN_C NTSTATUS NtFlushVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN OUT PULONG RegionSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtFlushWriteBuffer();

EXTERN_C NTSTATUS NtFreeUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	IN PULONG UserPfnArray);

EXTERN_C NTSTATUS NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType);

EXTERN_C NTSTATUS NtFreezeRegistry(
	IN ULONG TimeOutInSeconds);

EXTERN_C NTSTATUS NtFreezeTransactions(
	IN PLARGE_INTEGER FreezeTimeout,
	IN PLARGE_INTEGER ThawTimeout);

EXTERN_C NTSTATUS NtFsControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG FsControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtGetCachedSigningLevel(
	IN HANDLE File,
	OUT PULONG Flags,
	OUT PSE_SIGNING_LEVEL SigningLevel,
	OUT PUCHAR Thumbprint OPTIONAL,
	IN OUT PULONG ThumbprintSize OPTIONAL,
	OUT PULONG ThumbprintAlgorithm OPTIONAL);

EXTERN_C NTSTATUS NtGetCompleteWnfStateSubscription(
	IN PCWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
	IN PLARGE_INTEGER OldSubscriptionId OPTIONAL,
	IN ULONG OldDescriptorEventMask OPTIONAL,
	IN ULONG OldDescriptorStatus OPTIONAL,
	OUT PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
	IN ULONG DescriptorSize);

EXTERN_C NTSTATUS NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext);

EXTERN_C NTSTATUS NtGetCurrentProcessorNumber();

EXTERN_C NTSTATUS NtGetCurrentProcessorNumberEx(
	OUT PULONG ProcNumber OPTIONAL);

EXTERN_C NTSTATUS NtGetDevicePowerState(
	IN HANDLE Device,
	OUT PDEVICE_POWER_STATE State);

EXTERN_C NTSTATUS NtGetMUIRegistryInfo(
	IN ULONG Flags,
	IN OUT PULONG DataSize,
	OUT PVOID SystemData);

EXTERN_C NTSTATUS NtGetNextProcess(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewProcessHandle);

EXTERN_C NTSTATUS NtGetNextThread(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewThreadHandle);

EXTERN_C NTSTATUS NtGetNlsSectionPtr(
	IN ULONG SectionType,
	IN ULONG SectionData,
	IN PVOID ContextData,
	OUT PVOID SectionPointer,
	OUT PULONG SectionSize);

EXTERN_C NTSTATUS NtGetNotificationResourceManager(
	IN HANDLE ResourceManagerHandle,
	OUT PTRANSACTION_NOTIFICATION TransactionNotification,
	IN ULONG NotificationLength,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL,
	IN ULONG Asynchronous,
	IN ULONG AsynchronousContext OPTIONAL);

EXTERN_C NTSTATUS NtGetPlugPlayEvent(
	IN HANDLE EventHandle,
	IN PVOID Context OPTIONAL,
	OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
	IN ULONG EventBufferSize);

EXTERN_C NTSTATUS NtGetWriteWatch(
	IN HANDLE ProcessHandle,
	IN ULONG Flags,
	IN PVOID BaseAddress,
	IN ULONG RegionSize,
	OUT PULONG UserAddressArray,
	IN OUT PULONG EntriesInUserAddressArray,
	OUT PULONG Granularity);

EXTERN_C NTSTATUS NtImpersonateAnonymousToken(
	IN HANDLE ThreadHandle);

EXTERN_C NTSTATUS NtImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message);

EXTERN_C NTSTATUS NtImpersonateThread(
	IN HANDLE ServerThreadHandle,
	IN HANDLE ClientThreadHandle,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos);

EXTERN_C NTSTATUS NtInitializeEnclave(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtInitializeNlsFiles(
	OUT PVOID BaseAddress,
	OUT PLCID DefaultLocaleId,
	OUT PLARGE_INTEGER DefaultCasingTableSize);

EXTERN_C NTSTATUS NtInitializeRegistry(
	IN USHORT BootCondition);

EXTERN_C NTSTATUS NtInitiatePowerAction(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE LightestSystemState,
	IN ULONG Flags,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtIsProcessInJob(
	IN HANDLE ProcessHandle,
	IN HANDLE JobHandle OPTIONAL);

EXTERN_C NTSTATUS NtIsSystemResumeAutomatic();

EXTERN_C NTSTATUS NtIsUILanguageComitted();

EXTERN_C NTSTATUS NtListTransactions();

EXTERN_C NTSTATUS NtListenPort(
	IN HANDLE PortHandle,
	OUT PPORT_MESSAGE ConnectionRequest);

EXTERN_C NTSTATUS NtLoadDriver(
	IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS NtLoadEnclaveData(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T BufferSize,
	IN ULONG Protect,
	IN PVOID PageInformation,
	IN ULONG PageInformationLength,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtLoadHotPatch(
	IN PUNICODE_STRING HotPatchName,
	IN ULONG LoadFlag);

EXTERN_C NTSTATUS NtLoadKey(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile);

EXTERN_C NTSTATUS NtLoadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtLoadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags,
	IN HANDLE TrustClassKey OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	OUT PHANDLE RootHandle OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatus OPTIONAL);

EXTERN_C NTSTATUS NtLockFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key,
	IN BOOLEAN FailImmediately,
	IN BOOLEAN ExclusiveLock);

EXTERN_C NTSTATUS NtLockProductActivationKeys(
	IN OUT PULONG pPrivateVer OPTIONAL,
	OUT PULONG pSafeMode OPTIONAL);

EXTERN_C NTSTATUS NtLockRegistryKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtLockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PULONG RegionSize,
	IN ULONG MapType);

EXTERN_C NTSTATUS NtMakePermanentObject(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtMakeTemporaryObject(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtManageHotPatch(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4);

EXTERN_C NTSTATUS NtManagePartition(
	IN HANDLE TargetHandle,
	IN HANDLE SourceHandle,
	IN MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
	IN OUT PVOID PartitionInformation,
	IN ULONG PartitionInformationLength);

EXTERN_C NTSTATUS NtMapCMFModule(
	IN ULONG What,
	IN ULONG Index,
	OUT PULONG CacheIndexOut OPTIONAL,
	OUT PULONG CacheFlagsOut OPTIONAL,
	OUT PULONG ViewSizeOut OPTIONAL,
	OUT PVOID BaseAddress OPTIONAL);

EXTERN_C NTSTATUS NtMapUserPhysicalPages(
	IN PVOID VirtualAddress,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL);

EXTERN_C NTSTATUS NtMapUserPhysicalPagesScatter(
	IN PVOID VirtualAddresses,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL);

EXTERN_C NTSTATUS NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

EXTERN_C NTSTATUS NtMapViewOfSectionEx(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PLARGE_INTEGER SectionOffset,
	IN OUT PPVOID BaseAddress,
	IN OUT PSIZE_T ViewSize,
	IN ULONG AllocationType,
	IN ULONG Protect,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount);

EXTERN_C NTSTATUS NtMarshallTransaction();

EXTERN_C NTSTATUS NtModifyBootEntry(
	IN PBOOT_ENTRY BootEntry);

EXTERN_C NTSTATUS NtModifyDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry);

EXTERN_C NTSTATUS NtNotifyChangeDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_NOTIFY_INFORMATION Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree);

EXTERN_C NTSTATUS NtNotifyChangeDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	IN DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass OPTIONAL);

EXTERN_C NTSTATUS NtNotifyChangeKey(
	IN HANDLE KeyHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtNotifyChangeMultipleKeys(
	IN HANDLE MasterKeyHandle,
	IN ULONG Count OPTIONAL,
	IN POBJECT_ATTRIBUTES SubordinateObjects OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtNotifyChangeSession(
	IN HANDLE SessionHandle,
	IN ULONG ChangeSequenceNumber,
	IN PLARGE_INTEGER ChangeTimeStamp,
	IN IO_SESSION_EVENT Event,
	IN IO_SESSION_STATE NewState,
	IN IO_SESSION_STATE PreviousState,
	IN PVOID Payload OPTIONAL,
	IN ULONG PayloadSize);

EXTERN_C NTSTATUS NtOpenDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN LPGUID EnlistmentGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtOpenEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS NtOpenIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenKeyEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS NtOpenKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtOpenKeyTransactedEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions,
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtOpenKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN ACCESS_MASK GrantedAccess,
	IN PPRIVILEGE_SET Privileges OPTIONAL,
	IN BOOLEAN ObjectCreation,
	IN BOOLEAN AccessGranted,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtOpenPartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenPrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PVOID BoundaryDescriptor);

EXTERN_C NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtOpenProcessTokenEx(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtOpenRegistryTransaction(
	OUT PHANDLE RegistryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID ResourceManagerGuid OPTIONAL,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenSession(
	OUT PHANDLE SessionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtOpenThreadToken(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtOpenThreadTokenEx(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtOpenTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtOpenTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN LPGUID Uow,
	IN HANDLE TmHandle OPTIONAL);

EXTERN_C NTSTATUS NtOpenTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN LPGUID TmIdentity OPTIONAL,
	IN ULONG OpenOptions OPTIONAL);

EXTERN_C NTSTATUS NtPlugPlayControl(
	IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
	IN OUT PVOID PnPControlData,
	IN ULONG PnPControlDataLength);

EXTERN_C NTSTATUS NtPowerInformation(
	IN POWER_INFORMATION_LEVEL InformationLevel,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtPrePrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtPrePrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtPrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtPrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtPrivilegeCheck(
	IN HANDLE ClientToken,
	IN OUT PPRIVILEGE_SET RequiredPrivileges,
	OUT PBOOLEAN Result);

EXTERN_C NTSTATUS NtPrivilegeObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted);

EXTERN_C NTSTATUS NtPrivilegedServiceAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PUNICODE_STRING ServiceName,
	IN HANDLE ClientToken,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted);

EXTERN_C NTSTATUS NtPropagationComplete(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN ULONG BufferLength,
	IN PVOID Buffer);

EXTERN_C NTSTATUS NtPropagationFailed(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN NTSTATUS PropStatus);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtPullTransaction();

EXTERN_C NTSTATUS NtPulseEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtQueryAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_BASIC_INFORMATION FileInformation);

EXTERN_C NTSTATUS NtQueryAuxiliaryCounterFrequency(
	OUT PULONGLONG lpAuxiliaryCounterFrequency);

EXTERN_C NTSTATUS NtQueryBootEntryOrder(
	OUT PULONG Ids OPTIONAL,
	IN OUT PULONG Count);

EXTERN_C NTSTATUS NtQueryBootOptions(
	OUT PBOOT_OPTIONS BootOptions OPTIONAL,
	IN OUT PULONG BootOptionsLength);

EXTERN_C NTSTATUS NtQueryDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level);

EXTERN_C NTSTATUS NtQueryDefaultLocale(
	IN BOOLEAN UserProfile,
	OUT PLCID DefaultLocaleId);

EXTERN_C NTSTATUS NtQueryDefaultUILanguage(
	OUT PLANGID DefaultUILanguageId);

EXTERN_C NTSTATUS NtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtQueryDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN ULONG QueryFlags,
	IN PUNICODE_STRING FileName OPTIONAL);

EXTERN_C NTSTATUS NtQueryDirectoryObject(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryDriverEntryOrder(
	IN PULONG Ids OPTIONAL,
	IN OUT PULONG Count);

EXTERN_C NTSTATUS NtQueryEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_FULL_EA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_GET_EA_INFORMATION EaList OPTIONAL,
	IN ULONG EaListLength,
	IN PULONG EaIndex OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtQueryEvent(
	IN HANDLE EventHandle,
	IN EVENT_INFORMATION_CLASS EventInformationClass,
	OUT PVOID EventInformation,
	IN ULONG EventInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryFullAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation);

EXTERN_C NTSTATUS NtQueryInformationAtom(
	IN USHORT Atom,
	IN ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationByName(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtQueryInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	OUT PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtQueryInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	OUT PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationPort(
	IN HANDLE PortHandle,
	IN PORT_INFORMATION_CLASS PortInformationClass,
	OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	OUT PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID TokenInformation,
	IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtQueryInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	OUT PVOID TransactionInformation,
	IN ULONG TransactionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
	OUT PVOID TransactionManagerInformation,
	IN ULONG TransactionManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	OUT PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInstallUILanguage(
	OUT PLANGID InstallUILanguageId);

EXTERN_C NTSTATUS NtQueryIntervalProfile(
	IN KPROFILE_SOURCE ProfileSource,
	OUT PULONG Interval);

EXTERN_C NTSTATUS NtQueryIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
	OUT PVOID IoCompletionInformation,
	IN ULONG IoCompletionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryKey(
	IN HANDLE KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtQueryLicenseValue(
	IN PUNICODE_STRING ValueName,
	OUT PULONG Type OPTIONAL,
	OUT PVOID SystemData OPTIONAL,
	IN ULONG DataSize,
	OUT PULONG ResultDataSize);

EXTERN_C NTSTATUS NtQueryMultipleValueKey(
	IN HANDLE KeyHandle,
	IN OUT PKEY_VALUE_ENTRY ValueEntries,
	IN ULONG EntryCount,
	OUT PVOID ValueBuffer,
	IN PULONG BufferLength,
	OUT PULONG RequiredBufferLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryMutant(
	IN HANDLE MutantHandle,
	IN MUTANT_INFORMATION_CLASS MutantInformationClass,
	OUT PVOID MutantInformation,
	IN ULONG MutantInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryOpenSubKeys(
	IN POBJECT_ATTRIBUTES TargetKey,
	OUT PULONG HandleCount);

EXTERN_C NTSTATUS NtQueryOpenSubKeysEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG BufferLength,
	OUT PVOID Buffer,
	OUT PULONG RequiredSize);

EXTERN_C NTSTATUS NtQueryPerformanceCounter(
	OUT PLARGE_INTEGER PerformanceCounter,
	OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL);

EXTERN_C NTSTATUS NtQueryPortInformationProcess();

EXTERN_C NTSTATUS NtQueryQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_QUOTA_LIST_INFORMATION SidList OPTIONAL,
	IN ULONG SidListLength,
	IN PSID StartSid OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtQuerySection(
	IN HANDLE SectionHandle,
	IN SECTION_INFORMATION_CLASS SectionInformationClass,
	OUT PVOID SectionInformation,
	IN ULONG SectionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySecurityAttributesToken(
	IN HANDLE TokenHandle,
	IN PUNICODE_STRING Attributes OPTIONAL,
	IN ULONG NumberOfAttributes,
	OUT PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtQuerySecurityObject(
	IN HANDLE Handle,
	IN SECURITY_INFORMATION SecurityInformation,
	OUT PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN ULONG Length,
	OUT PULONG LengthNeeded);

EXTERN_C NTSTATUS NtQuerySecurityPolicy(
	IN ULONG_PTR UnknownParameter1,
	IN ULONG_PTR UnknownParameter2,
	IN ULONG_PTR UnknownParameter3,
	IN ULONG_PTR UnknownParameter4,
	IN ULONG_PTR UnknownParameter5,
	IN ULONG_PTR UnknownParameter6);

EXTERN_C NTSTATUS NtQuerySemaphore(
	IN HANDLE SemaphoreHandle,
	IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
	OUT PVOID SemaphoreInformation,
	IN ULONG SemaphoreInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySymbolicLinkObject(
	IN HANDLE LinkHandle,
	IN OUT PUNICODE_STRING LinkTarget,
	OUT PULONG ReturnedLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	OUT PVOID VariableValue,
	IN ULONG ValueLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	OUT PVOID Value OPTIONAL,
	IN OUT PULONG ValueLength,
	OUT PULONG Attributes OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemInformationEx(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemTime(
	OUT PLARGE_INTEGER SystemTime);

EXTERN_C NTSTATUS NtQueryTimer(
	IN HANDLE TimerHandle,
	IN TIMER_INFORMATION_CLASS TimerInformationClass,
	OUT PVOID TimerInformation,
	IN ULONG TimerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryTimerResolution(
	OUT PULONG MaximumTime,
	OUT PULONG MinimumTime,
	OUT PULONG CurrentTime);

EXTERN_C NTSTATUS NtQueryValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtQueryVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FsInformation,
	IN ULONG Length,
	IN FSINFOCLASS FsInformationClass);

EXTERN_C NTSTATUS NtQueryWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PWNF_CHANGE_STAMP ChangeStamp,
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferSize);

EXTERN_C NTSTATUS NtQueryWnfStateNameInformation(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID NameInfoClass,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PVOID InfoBuffer,
	IN ULONG InfoBufferSize);

EXTERN_C NTSTATUS NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtQueueApcThreadEx(
	IN HANDLE ThreadHandle,
	IN HANDLE UserApcReserveHandle OPTIONAL,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtRaiseException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN BOOLEAN FirstChance);

EXTERN_C NTSTATUS NtRaiseHardError(
	IN NTSTATUS ErrorStatus,
	IN ULONG NumberOfParameters,
	IN ULONG UnicodeStringParameterMask,
	IN PULONG_PTR Parameters,
	IN ULONG ValidResponseOptions,
	OUT PULONG Response);

EXTERN_C NTSTATUS NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	OUT PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtReadFileScatter(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtReadOnlyEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtReadRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG DataEntryIndex,
	OUT PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtRecoverEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PVOID EnlistmentKey OPTIONAL);

EXTERN_C NTSTATUS NtRecoverResourceManager(
	IN HANDLE ResourceManagerHandle);

EXTERN_C NTSTATUS NtRecoverTransactionManager(
	IN HANDLE TransactionManagerHandle);

EXTERN_C NTSTATUS NtRegisterProtocolAddressInformation(
	IN HANDLE ResourceManager,
	IN LPGUID ProtocolId,
	IN ULONG ProtocolInformationSize,
	IN PVOID ProtocolInformation,
	IN ULONG CreateOptions OPTIONAL);

EXTERN_C NTSTATUS NtRegisterThreadTerminatePort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtReleaseCMFViewOwnership();

EXTERN_C NTSTATUS NtReleaseKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID KeyValue,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtReleaseMutant(
	IN HANDLE MutantHandle,
	OUT PULONG PreviousCount OPTIONAL);

EXTERN_C NTSTATUS NtReleaseSemaphore(
	IN HANDLE SemaphoreHandle,
	IN LONG ReleaseCount,
	OUT PLONG PreviousCount OPTIONAL);

EXTERN_C NTSTATUS NtReleaseWorkerFactoryWorker(
	IN HANDLE WorkerFactoryHandle);

EXTERN_C NTSTATUS NtRemoveIoCompletion(
	IN HANDLE IoCompletionHandle,
	OUT PULONG KeyContext,
	OUT PULONG ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtRemoveIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	OUT PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
	IN ULONG Count,
	OUT PULONG NumEntriesRemoved,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN BOOLEAN Alertable);

EXTERN_C NTSTATUS NtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);

EXTERN_C NTSTATUS NtRenameKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING NewName);

EXTERN_C NTSTATUS NtRenameTransactionManager(
	IN PUNICODE_STRING LogFileName,
	IN LPGUID ExistingTransactionManagerGuid);

EXTERN_C NTSTATUS NtReplaceKey(
	IN POBJECT_ATTRIBUTES NewFile,
	IN HANDLE TargetHandle,
	IN POBJECT_ATTRIBUTES OldFile);

EXTERN_C NTSTATUS NtReplacePartitionUnit(
	IN PUNICODE_STRING TargetInstancePath,
	IN PUNICODE_STRING SpareInstancePath,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtReplyWaitReceivePort(
	IN HANDLE PortHandle,
	OUT PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage);

EXTERN_C NTSTATUS NtReplyWaitReceivePortEx(
	IN HANDLE PortHandle,
	OUT PULONG PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtReplyWaitReplyPort(
	IN HANDLE PortHandle,
	IN OUT PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtRequestDeviceWakeup(
	IN HANDLE DeviceHandle);

EXTERN_C NTSTATUS NtRequestPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage);

EXTERN_C NTSTATUS NtRequestWaitReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage,
	OUT PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtRequestWakeupLatency(
	IN ULONG LatencyTime);

EXTERN_C NTSTATUS NtResetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtResetWriteWatch(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG RegionSize);

EXTERN_C NTSTATUS NtRestoreKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtResumeProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtRevertContainerImpersonation();

EXTERN_C NTSTATUS NtRollbackComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtRollbackEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtRollbackRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait);

EXTERN_C NTSTATUS NtRollbackSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId);

EXTERN_C NTSTATUS NtRollbackTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait);

EXTERN_C NTSTATUS NtRollforwardTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtSaveKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle);

EXTERN_C NTSTATUS NtSaveKeyEx(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Format);

EXTERN_C NTSTATUS NtSaveMergedKeys(
	IN HANDLE HighPrecedenceKeyHandle,
	IN HANDLE LowPrecedenceKeyHandle,
	IN HANDLE FileHandle);

EXTERN_C NTSTATUS NtSavepointComplete(
	IN HANDLE TransactionHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Flag,
	OUT ULONG SavePointId);

EXTERN_C NTSTATUS NtSecureConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL);

EXTERN_C NTSTATUS NtSerializeBoot();

EXTERN_C NTSTATUS NtSetBootEntryOrder(
	IN PULONG Ids,
	IN ULONG Count);

EXTERN_C NTSTATUS NtSetBootOptions(
	IN PBOOT_OPTIONS BootOptions,
	IN ULONG FieldsToChange);

EXTERN_C NTSTATUS NtSetCachedSigningLevel(
	IN ULONG Flags,
	IN SE_SIGNING_LEVEL InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL);

EXTERN_C NTSTATUS NtSetCachedSigningLevel2(
	IN ULONG Flags,
	IN ULONG InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL,
	IN PVOID LevelInformation OPTIONAL);

EXTERN_C NTSTATUS NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context);

EXTERN_C NTSTATUS NtSetDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level,
	IN BOOLEAN State);

EXTERN_C NTSTATUS NtSetDefaultHardErrorPort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtSetDefaultLocale(
	IN BOOLEAN UserProfile,
	IN LCID DefaultLocaleId);

EXTERN_C NTSTATUS NtSetDefaultUILanguage(
	IN LANGID DefaultUILanguageId);

EXTERN_C NTSTATUS NtSetDriverEntryOrder(
	IN PULONG Ids,
	IN PULONG Count);

EXTERN_C NTSTATUS NtSetEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_FULL_EA_INFORMATION EaBuffer,
	IN ULONG EaBufferSize);

EXTERN_C NTSTATUS NtSetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtSetEventBoostPriority(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtSetHighEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetHighWaitLowEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetIRTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationDebugObject(
	IN HANDLE DebugObject,
	IN DEBUGOBJECTINFOCLASS InformationClass,
	IN PVOID Information,
	IN ULONG InformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	IN PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength);

EXTERN_C NTSTATUS NtSetInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtSetInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	IN PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength);

EXTERN_C NTSTATUS NtSetInformationKey(
	IN HANDLE KeyHandle,
	IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
	IN PVOID KeySetInformation,
	IN ULONG KeySetInformationLength);

EXTERN_C NTSTATUS NtSetInformationObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID ObjectInformation,
	IN ULONG ObjectInformationLength);

EXTERN_C NTSTATUS NtSetInformationProcess(
	IN HANDLE DeviceHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG Length);

EXTERN_C NTSTATUS NtSetInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	IN PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength);

EXTERN_C NTSTATUS NtSetInformationSymbolicLink(
	IN HANDLE Handle,
	IN ULONG Class,
	IN PVOID Buffer,
	IN ULONG BufferLength);

EXTERN_C NTSTATUS NtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength);

EXTERN_C NTSTATUS NtSetInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	IN PVOID TokenInformation,
	IN ULONG TokenInformationLength);

EXTERN_C NTSTATUS NtSetInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength);

EXTERN_C NTSTATUS NtSetInformationTransactionManager(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength);

EXTERN_C NTSTATUS NtSetInformationVirtualMemory(
	IN HANDLE ProcessHandle,
	IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
	IN ULONG_PTR NumberOfEntries,
	IN PMEMORY_RANGE_ENTRY VirtualAddresses,
	IN PVOID VmInformation,
	IN ULONG VmInformationLength);

EXTERN_C NTSTATUS NtSetInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	IN PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength);

EXTERN_C NTSTATUS NtSetIntervalProfile(
	IN ULONG Interval,
	IN KPROFILE_SOURCE Source);

EXTERN_C NTSTATUS NtSetIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN ULONG CompletionKey,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN NTSTATUS CompletionStatus,
	IN ULONG NumberOfBytesTransfered);

EXTERN_C NTSTATUS NtSetIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	IN HANDLE IoCompletionPacketHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation);

EXTERN_C NTSTATUS NtSetLdtEntries(
	IN ULONG Selector0,
	IN ULONG Entry0Low,
	IN ULONG Entry0Hi,
	IN ULONG Selector1,
	IN ULONG Entry1Low,
	IN ULONG Entry1Hi);

EXTERN_C NTSTATUS NtSetLowEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetLowWaitHighEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length);

EXTERN_C NTSTATUS NtSetSecurityObject(
	IN HANDLE ObjectHandle,
	IN SECURITY_INFORMATION SecurityInformationClass,
	IN PSECURITY_DESCRIPTOR DescriptorBuffer);

EXTERN_C NTSTATUS NtSetSystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	IN PUNICODE_STRING Value);

EXTERN_C NTSTATUS NtSetSystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	IN PVOID Value OPTIONAL,
	IN ULONG ValueLength,
	IN ULONG Attributes);

EXTERN_C NTSTATUS NtSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength);

EXTERN_C NTSTATUS NtSetSystemPowerState(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE MinSystemState,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtSetSystemTime(
	IN PLARGE_INTEGER SystemTime,
	OUT PLARGE_INTEGER PreviousTime OPTIONAL);

EXTERN_C NTSTATUS NtSetThreadExecutionState(
	IN EXECUTION_STATE ExecutionState,
	OUT PEXECUTION_STATE PreviousExecutionState);

EXTERN_C NTSTATUS NtSetTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
	IN PVOID TimerContext OPTIONAL,
	IN BOOLEAN ResumeTimer,
	IN LONG Period OPTIONAL,
	OUT PBOOLEAN PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtSetTimer2(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PLARGE_INTEGER Period OPTIONAL,
	IN PT2_SET_PARAMETERS Parameters);

EXTERN_C NTSTATUS NtSetTimerEx(
	IN HANDLE TimerHandle,
	IN TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
	IN OUT PVOID TimerSetInformation OPTIONAL,
	IN ULONG TimerSetInformationLength);

EXTERN_C NTSTATUS NtSetTimerResolution(
	IN ULONG DesiredResolution,
	IN BOOLEAN SetResolution,
	OUT PULONG CurrentResolution);

EXTERN_C NTSTATUS NtSetUuidSeed(
	IN PUCHAR Seed);

EXTERN_C NTSTATUS NtSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID SystemData,
	IN ULONG DataSize);

EXTERN_C NTSTATUS NtSetVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileSystemInformation,
	IN ULONG Length,
	IN FSINFOCLASS FileSystemInformationClass);

EXTERN_C NTSTATUS NtSetWnfProcessNotificationEvent(
	IN HANDLE NotificationEvent);

EXTERN_C NTSTATUS NtShutdownSystem(
	IN SHUTDOWN_ACTION Action);

EXTERN_C NTSTATUS NtShutdownWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN OUT PLONG PendingWorkerCount);

EXTERN_C NTSTATUS NtSignalAndWaitForSingleObject(
	IN HANDLE hObjectToSignal,
	IN HANDLE hObjectToWaitOn,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER dwMilliseconds OPTIONAL);

EXTERN_C NTSTATUS NtSinglePhaseReject(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtStartProfile(
	IN HANDLE ProfileHandle);

EXTERN_C NTSTATUS NtStartTm();

EXTERN_C NTSTATUS NtStopProfile(
	IN HANDLE ProfileHandle);

EXTERN_C NTSTATUS NtSubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName,
	IN WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
	IN ULONG EventMask,
	OUT PLARGE_INTEGER SubscriptionId OPTIONAL);

EXTERN_C NTSTATUS NtSuspendProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount);

EXTERN_C NTSTATUS NtSystemDebugControl(
	IN DEBUG_CONTROL_CODE Command,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtTerminateEnclave(
	IN PVOID BaseAddress,
	IN BOOLEAN WaitForThread);

EXTERN_C NTSTATUS NtTerminateJobObject(
	IN HANDLE JobHandle,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtTerminateProcess(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtTerminateThread(
	IN HANDLE ThreadHandle,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtTestAlert();

EXTERN_C NTSTATUS NtThawRegistry();

EXTERN_C NTSTATUS NtThawTransactions();

EXTERN_C NTSTATUS NtTraceControl(
	IN ULONG FunctionCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtTraceEvent(
	IN HANDLE TraceHandle,
	IN ULONG Flags,
	IN ULONG FieldSize,
	IN PVOID Fields);

EXTERN_C NTSTATUS NtTranslateFilePath(
	IN PFILE_PATH InputFilePath,
	IN ULONG OutputType,
	OUT PFILE_PATH OutputFilePath OPTIONAL,
	IN OUT PULONG OutputFilePathLength OPTIONAL);

EXTERN_C NTSTATUS NtUmsThreadYield(
	IN PVOID SchedulerParam);

EXTERN_C NTSTATUS NtUnloadDriver(
	IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS NtUnloadKey(
	IN POBJECT_ATTRIBUTES DestinationKeyName);

EXTERN_C NTSTATUS NtUnloadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtUnloadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN HANDLE Event OPTIONAL);

EXTERN_C NTSTATUS NtUnlockFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key);

EXTERN_C NTSTATUS NtUnlockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID * BaseAddress,
	IN PSIZE_T NumberOfBytesToUnlock,
	IN ULONG LockType);

EXTERN_C NTSTATUS NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress);

EXTERN_C NTSTATUS NtUnmapViewOfSectionEx(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtUnsubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName);

EXTERN_C NTSTATUS NtUpdateWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID Buffer OPTIONAL,
	IN ULONG Length OPTIONAL,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	IN WNF_CHANGE_STAMP MatchingChangeStamp,
	IN ULONG CheckStamp);

EXTERN_C NTSTATUS NtVdmControl(
	IN VDMSERVICECLASS Service,
	IN OUT PVOID ServiceData);

EXTERN_C NTSTATUS NtWaitForAlertByThreadId(
	IN HANDLE Handle,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PVOID WaitStateChange);

EXTERN_C NTSTATUS NtWaitForKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID Key,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtWaitForMultipleObjects32(
	IN ULONG ObjectCount,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtWaitForSingleObject(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL);

EXTERN_C NTSTATUS NtWaitForWnfNotifications();

EXTERN_C NTSTATUS NtWaitForWorkViaWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	OUT PVOID MiniPacket);

EXTERN_C NTSTATUS NtWaitHighEventPair(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtWaitLowEventPair(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtWorkerFactoryWorkerReady(
	IN HANDLE WorkerFactoryHandle);

EXTERN_C NTSTATUS NtWriteFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtWriteFileGather(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtWriteRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Request,
	IN ULONG DataIndex,
	IN PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ResultLength OPTIONAL);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtYieldExecution();

EXTERN_C NTSTATUS RtlCreateUserThread(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientID);

#endif


// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW2_SYSCALL_LIST SW2_SyscallList = {0,1};

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

BOOL SW2_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW2_SyscallList.Count) return TRUE;

    PSW2_PEB Peb = (PSW2_PEB)__readgsqword(0x60);
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW2_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW2_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}
#define ZwAcceptConnectPort NtAcceptConnectPort
__asm__("NtAcceptConnectPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0257620E8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAccessCheck NtAccessCheck
__asm__("NtAccessCheck: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09AB44A88\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAccessCheckAndAuditAlarm NtAccessCheckAndAuditAlarm
__asm__("NtAccessCheckAndAuditAlarm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AEAFA733\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAccessCheckByType NtAccessCheckByType
__asm__("NtAccessCheckByType: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09F47CA77\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAccessCheckByTypeAndAuditAlarm NtAccessCheckByTypeAndAuditAlarm
__asm__("NtAccessCheckByTypeAndAuditAlarm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0389F1810\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAccessCheckByTypeResultList NtAccessCheckByTypeResultList
__asm__("NtAccessCheckByTypeResultList: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x024BC1023\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAccessCheckByTypeResultListAndAuditAlarm NtAccessCheckByTypeResultListAndAuditAlarm
__asm__("NtAccessCheckByTypeResultListAndAuditAlarm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x030A015F6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAccessCheckByTypeResultListAndAuditAlarmByHandle NtAccessCheckByTypeResultListAndAuditAlarmByHandle
__asm__("NtAccessCheckByTypeResultListAndAuditAlarmByHandle: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0973B4998\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAcquireCMFViewOwnership NtAcquireCMFViewOwnership
__asm__("NtAcquireCMFViewOwnership: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05E86064E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAcquireProcessActivityReference NtAcquireProcessActivityReference
__asm__("NtAcquireProcessActivityReference: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00AD847EE\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAddAtom NtAddAtom
__asm__("NtAddAtom: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x054805328\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAddAtomEx NtAddAtomEx
__asm__("NtAddAtomEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00FA83B15\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAddBootEntry NtAddBootEntry
__asm__("NtAddBootEntry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x035B8F1F4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAddDriverEntry NtAddDriverEntry
__asm__("NtAddDriverEntry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0869A9204\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAdjustGroupsToken NtAdjustGroupsToken
__asm__("NtAdjustGroupsToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x017950B04\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0DB6E8542\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAdjustTokenClaimsAndDeviceGroups NtAdjustTokenClaimsAndDeviceGroups
__asm__("NtAdjustTokenClaimsAndDeviceGroups: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E3B526E0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlertResumeThread NtAlertResumeThread
__asm__("NtAlertResumeThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00CAF449B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlertThread NtAlertThread
__asm__("NtAlertThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A730BD86\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlertThreadByThreadId NtAlertThreadByThreadId
__asm__("NtAlertThreadByThreadId: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0ECACAE8A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAllocateLocallyUniqueId NtAllocateLocallyUniqueId
__asm__("NtAllocateLocallyUniqueId: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B3AF146C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAllocateReserveObject NtAllocateReserveObject
__asm__("NtAllocateReserveObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00B279B28\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAllocateUserPhysicalPages NtAllocateUserPhysicalPages
__asm__("NtAllocateUserPhysicalPages: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09ABCA308\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAllocateUuids NtAllocateUuids
__asm__("NtAllocateUuids: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04BE0794D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08D589FB3\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAllocateVirtualMemoryEx NtAllocateVirtualMemoryEx
__asm__("NtAllocateVirtualMemoryEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x024EC6031\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcAcceptConnectPort NtAlpcAcceptConnectPort
__asm__("NtAlpcAcceptConnectPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05EC97152\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcCancelMessage NtAlpcCancelMessage
__asm__("NtAlpcCancelMessage: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x071AD7412\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcConnectPort NtAlpcConnectPort
__asm__("NtAlpcConnectPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F972FAFD\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcConnectPortEx NtAlpcConnectPortEx
__asm__("NtAlpcConnectPortEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0858E57D5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcCreatePort NtAlpcCreatePort
__asm__("NtAlpcCreatePort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0217326E9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcCreatePortSection NtAlpcCreatePortSection
__asm__("NtAlpcCreatePortSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0DD023858\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcCreateResourceReserve NtAlpcCreateResourceReserve
__asm__("NtAlpcCreateResourceReserve: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0149A2441\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcCreateSectionView NtAlpcCreateSectionView
__asm__("NtAlpcCreateSectionView: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01FB5ECCF\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcCreateSecurityContext NtAlpcCreateSecurityContext
__asm__("NtAlpcCreateSecurityContext: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0944BB1DA\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcDeletePortSection NtAlpcDeletePortSection
__asm__("NtAlpcDeletePortSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x009A8CEFA\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcDeleteResourceReserve NtAlpcDeleteResourceReserve
__asm__("NtAlpcDeleteResourceReserve: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04ADB343F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcDeleteSectionView NtAlpcDeleteSectionView
__asm__("NtAlpcDeleteSectionView: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09420E5AB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcDeleteSecurityContext NtAlpcDeleteSecurityContext
__asm__("NtAlpcDeleteSecurityContext: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09E428DC2\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcDisconnectPort NtAlpcDisconnectPort
__asm__("NtAlpcDisconnectPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E674E3EA\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcImpersonateClientContainerOfPort NtAlpcImpersonateClientContainerOfPort
__asm__("NtAlpcImpersonateClientContainerOfPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E5720329\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcImpersonateClientOfPort NtAlpcImpersonateClientOfPort
__asm__("NtAlpcImpersonateClientOfPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06CFD7752\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcOpenSenderProcess NtAlpcOpenSenderProcess
__asm__("NtAlpcOpenSenderProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0DD973207\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcOpenSenderThread NtAlpcOpenSenderThread
__asm__("NtAlpcOpenSenderThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00C90CEB6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcQueryInformation NtAlpcQueryInformation
__asm__("NtAlpcQueryInformation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C6ABC03E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcQueryInformationMessage NtAlpcQueryInformationMessage
__asm__("NtAlpcQueryInformationMessage: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02594BAA4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcRevokeSecurityContext NtAlpcRevokeSecurityContext
__asm__("NtAlpcRevokeSecurityContext: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07EEA6142\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcSendWaitReceivePort NtAlpcSendWaitReceivePort
__asm__("NtAlpcSendWaitReceivePort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02A80471E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAlpcSetInformation NtAlpcSetInformation
__asm__("NtAlpcSetInformation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D24C2A07\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwApphelpCacheControl NtApphelpCacheControl
__asm__("NtApphelpCacheControl: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x007D00B43\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAreMappedFilesTheSame NtAreMappedFilesTheSame
__asm__("NtAreMappedFilesTheSame: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0163971BB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAssignProcessToJobObject NtAssignProcessToJobObject
__asm__("NtAssignProcessToJobObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01AB5F4F8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAssociateWaitCompletionPacket NtAssociateWaitCompletionPacket
__asm__("NtAssociateWaitCompletionPacket: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x084B0B61E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCallEnclave NtCallEnclave
__asm__("NtCallEnclave: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05EBA7230\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCallbackReturn NtCallbackReturn
__asm__("NtCallbackReturn: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0008BFFC6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCancelDeviceWakeupRequest NtCancelDeviceWakeupRequest
__asm__("NtCancelDeviceWakeupRequest: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01FC106AC\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCancelIoFile NtCancelIoFile
__asm__("NtCancelIoFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03C67B844\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCancelIoFileEx NtCancelIoFileEx
__asm__("NtCancelIoFileEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x078234497\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCancelSynchronousIoFile NtCancelSynchronousIoFile
__asm__("NtCancelSynchronousIoFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x017981301\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCancelTimer NtCancelTimer
__asm__("NtCancelTimer: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0115A23D6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCancelTimer2 NtCancelTimer2
__asm__("NtCancelTimer2: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C74B4B95\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCancelWaitCompletionPacket NtCancelWaitCompletionPacket
__asm__("NtCancelWaitCompletionPacket: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x083C6B37A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwClearAllSavepointsTransaction NtClearAllSavepointsTransaction
__asm__("NtClearAllSavepointsTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05A8E7C1F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwClearEvent NtClearEvent
__asm__("NtClearEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F0EBFF68\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwClearSavepointTransaction NtClearSavepointTransaction
__asm__("NtClearSavepointTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00549C31A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwClose NtClose
__asm__("NtClose: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D51D0230\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCloseObjectAuditAlarm NtCloseObjectAuditAlarm
__asm__("NtCloseObjectAuditAlarm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x054CA5854\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCommitComplete NtCommitComplete
__asm__("NtCommitComplete: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0069EF2D0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCommitEnlistment NtCommitEnlistment
__asm__("NtCommitEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A936BA91\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCommitRegistryTransaction NtCommitRegistryTransaction
__asm__("NtCommitRegistryTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02E9A507B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCommitTransaction NtCommitTransaction
__asm__("NtCommitTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x006EE067D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCompactKeys NtCompactKeys
__asm__("NtCompactKeys: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05FA77C28\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCompareObjects NtCompareObjects
__asm__("NtCompareObjects: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E6ACEE34\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCompareSigningLevels NtCompareSigningLevels
__asm__("NtCompareSigningLevels: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D652CAD6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCompareTokens NtCompareTokens
__asm__("NtCompareTokens: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x067DD9CB5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCompleteConnectPort NtCompleteConnectPort
__asm__("NtCompleteConnectPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C234C3B8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCompressKey NtCompressKey
__asm__("NtCompressKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x074235996\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwConnectPort NtConnectPort
__asm__("NtConnectPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x066B06B22\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwContinue NtContinue
__asm__("NtContinue: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06ED81D50\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwContinueEx NtContinueEx
__asm__("NtContinueEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07389314C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
__asm__("NtConvertBetweenAuxiliaryCounterAndPerformanceCounter: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06FD3052F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateCrossVmEvent NtCreateCrossVmEvent
__asm__("NtCreateCrossVmEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09955F881\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateDebugObject NtCreateDebugObject
__asm__("NtCreateDebugObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x006AA3027\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateDirectoryObject NtCreateDirectoryObject
__asm__("NtCreateDirectoryObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0BE22949F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateDirectoryObjectEx NtCreateDirectoryObjectEx
__asm__("NtCreateDirectoryObjectEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B0BDCE5B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateEnclave NtCreateEnclave
__asm__("NtCreateEnclave: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06ACB8288\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateEnlistment NtCreateEnlistment
__asm__("NtCreateEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x059D77841\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateEvent NtCreateEvent
__asm__("NtCreateEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x032AD4D46\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateEventPair NtCreateEventPair
__asm__("NtCreateEventPair: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01C4CC82D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateFile NtCreateFile
__asm__("NtCreateFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AB1BF9AD\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateIRTimer NtCreateIRTimer
__asm__("NtCreateIRTimer: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06454B81D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateIoCompletion NtCreateIoCompletion
__asm__("NtCreateIoCompletion: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0FC64BEB5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateJobObject NtCreateJobObject
__asm__("NtCreateJobObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x008B46659\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateJobSet NtCreateJobSet
__asm__("NtCreateJobSet: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0009C7871\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateKey NtCreateKey
__asm__("NtCreateKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00A332DA8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateKeyTransacted NtCreateKeyTransacted
__asm__("NtCreateKeyTransacted: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0226D60B2\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateKeyedEvent NtCreateKeyedEvent
__asm__("NtCreateKeyedEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0300115A8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateLowBoxToken NtCreateLowBoxToken
__asm__("NtCreateLowBoxToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F99812C0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateMailslotFile NtCreateMailslotFile
__asm__("NtCreateMailslotFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02ABCB2BA\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateMutant NtCreateMutant
__asm__("NtCreateMutant: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0BA9C78CB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateNamedPipeFile NtCreateNamedPipeFile
__asm__("NtCreateNamedPipeFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D5761C51\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreatePagingFile NtCreatePagingFile
__asm__("NtCreatePagingFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0188280B0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreatePartition NtCreatePartition
__asm__("NtCreatePartition: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x002A5D306\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreatePort NtCreatePort
__asm__("NtCreatePort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A735BAA5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreatePrivateNamespace NtCreatePrivateNamespace
__asm__("NtCreatePrivateNamespace: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03897BBB9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateProcess NtCreateProcess
__asm__("NtCreateProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B02D8961\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateProcessEx NtCreateProcessEx
__asm__("NtCreateProcessEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A14CF792\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateProfile NtCreateProfile
__asm__("NtCreateProfile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07B3A5DE0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateProfileEx NtCreateProfileEx
__asm__("NtCreateProfileEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x020DAE6A7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateRegistryTransaction NtCreateRegistryTransaction
__asm__("NtCreateRegistryTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x013887752\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateResourceManager NtCreateResourceManager
__asm__("NtCreateResourceManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x087AED16A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateSection NtCreateSection
__asm__("NtCreateSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E30EE39C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateSectionEx NtCreateSectionEx
__asm__("NtCreateSectionEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00092F5EF\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateSemaphore NtCreateSemaphore
__asm__("NtCreateSemaphore: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0148EEFD0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateSymbolicLinkObject NtCreateSymbolicLinkObject
__asm__("NtCreateSymbolicLinkObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00A170A8B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateThread NtCreateThread
__asm__("NtCreateThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x084AE9C12\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateThreadEx NtCreateThreadEx
__asm__("NtCreateThreadEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09CBDD866\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateTimer NtCreateTimer
__asm__("NtCreateTimer: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x007B27348\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateTimer2 NtCreateTimer2
__asm__("NtCreateTimer2: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04FB5B37B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateToken NtCreateToken
__asm__("NtCreateToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x007906F0A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateTokenEx NtCreateTokenEx
__asm__("NtCreateTokenEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06A95B8FF\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateTransaction NtCreateTransaction
__asm__("NtCreateTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05C8E064B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateTransactionManager NtCreateTransactionManager
__asm__("NtCreateTransactionManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07BA594F8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateUserProcess NtCreateUserProcess
__asm__("NtCreateUserProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E22AADF7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateWaitCompletionPacket NtCreateWaitCompletionPacket
__asm__("NtCreateWaitCompletionPacket: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C99CF51F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateWaitablePort NtCreateWaitablePort
__asm__("NtCreateWaitablePort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A8AD22B3\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateWnfStateName NtCreateWnfStateName
__asm__("NtCreateWnfStateName: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0CD92B446\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateWorkerFactory NtCreateWorkerFactory
__asm__("NtCreateWorkerFactory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08817BEBA\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDebugActiveProcess NtDebugActiveProcess
__asm__("NtDebugActiveProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C59F2A0F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDebugContinue NtDebugContinue
__asm__("NtDebugContinue: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00C9D6B7E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDelayExecution NtDelayExecution
__asm__("NtDelayExecution: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0574C1591\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteAtom NtDeleteAtom
__asm__("NtDeleteAtom: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F43FD5AE\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteBootEntry NtDeleteBootEntry
__asm__("NtDeleteBootEntry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00D943928\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteDriverEntry NtDeleteDriverEntry
__asm__("NtDeleteDriverEntry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0090079E8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteFile NtDeleteFile
__asm__("NtDeleteFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F8D8D842\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteKey NtDeleteKey
__asm__("NtDeleteKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0EC2C034B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteObjectAuditAlarm NtDeleteObjectAuditAlarm
__asm__("NtDeleteObjectAuditAlarm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01EB9FEF6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeletePrivateNamespace NtDeletePrivateNamespace
__asm__("NtDeletePrivateNamespace: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0EECA2B64\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteValueKey NtDeleteValueKey
__asm__("NtDeleteValueKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x013837658\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteWnfStateData NtDeleteWnfStateData
__asm__("NtDeleteWnfStateData: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x072920582\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeleteWnfStateName NtDeleteWnfStateName
__asm__("NtDeleteWnfStateName: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0729C0685\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeviceIoControlFile NtDeviceIoControlFile
__asm__("NtDeviceIoControlFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x078E05072\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDisableLastKnownGood NtDisableLastKnownGood
__asm__("NtDisableLastKnownGood: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06BB95F62\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDisplayString NtDisplayString
__asm__("NtDisplayString: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E64D9A88\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDrawText NtDrawText
__asm__("NtDrawText: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x028AF5F4C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDuplicateObject NtDuplicateObject
__asm__("NtDuplicateObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x017B5F9C7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDuplicateToken NtDuplicateToken
__asm__("NtDuplicateToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00590F611\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwEnableLastKnownGood NtEnableLastKnownGood
__asm__("NtEnableLastKnownGood: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06FBE770A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwEnumerateBootEntries NtEnumerateBootEntries
__asm__("NtEnumerateBootEntries: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02098596B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwEnumerateDriverEntries NtEnumerateDriverEntries
__asm__("NtEnumerateDriverEntries: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02E97BBBF\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwEnumerateKey NtEnumerateKey
__asm__("NtEnumerateKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AF9B76C8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwEnumerateSystemEnvironmentValuesEx NtEnumerateSystemEnvironmentValuesEx
__asm__("NtEnumerateSystemEnvironmentValuesEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05B4B6FF6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwEnumerateTransactionObject NtEnumerateTransactionObject
__asm__("NtEnumerateTransactionObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x084B9AC05\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwEnumerateValueKey NtEnumerateValueKey
__asm__("NtEnumerateValueKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x041F9B687\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwExtendSection NtExtendSection
__asm__("NtExtendSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07CDB5287\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFilterBootOption NtFilterBootOption
__asm__("NtFilterBootOption: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00A83EC17\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFilterToken NtFilterToken
__asm__("NtFilterToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x025911D10\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFilterTokenEx NtFilterTokenEx
__asm__("NtFilterTokenEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B882E644\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFindAtom NtFindAtom
__asm__("NtFindAtom: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D681D72D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFlushBuffersFile NtFlushBuffersFile
__asm__("NtFlushBuffersFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x055D22349\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFlushBuffersFileEx NtFlushBuffersFileEx
__asm__("NtFlushBuffersFileEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x064982267\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFlushInstallUILanguage NtFlushInstallUILanguage
__asm__("NtFlushInstallUILanguage: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07FCB2DF2\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFlushInstructionCache NtFlushInstructionCache
__asm__("NtFlushInstructionCache: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01FAD4917\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFlushKey NtFlushKey
__asm__("NtFlushKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08C9BA728\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFlushProcessWriteBuffers NtFlushProcessWriteBuffers
__asm__("NtFlushProcessWriteBuffers: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x059387996\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFlushVirtualMemory NtFlushVirtualMemory
__asm__("NtFlushVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08614ACB4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFlushWriteBuffer NtFlushWriteBuffer
__asm__("NtFlushWriteBuffer: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00BB23503\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFreeUserPhysicalPages NtFreeUserPhysicalPages
__asm__("NtFreeUserPhysicalPages: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x031A4CF27\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFreeVirtualMemory NtFreeVirtualMemory
__asm__("NtFreeVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00B901D7F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFreezeRegistry NtFreezeRegistry
__asm__("NtFreezeRegistry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x042ED4C69\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFreezeTransactions NtFreezeTransactions
__asm__("NtFreezeTransactions: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A72B999B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFsControlFile NtFsControlFile
__asm__("NtFsControlFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AC359AA8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetCachedSigningLevel NtGetCachedSigningLevel
__asm__("NtGetCachedSigningLevel: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01A923408\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetCompleteWnfStateSubscription NtGetCompleteWnfStateSubscription
__asm__("NtGetCompleteWnfStateSubscription: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00E87201B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetContextThread NtGetContextThread
__asm__("NtGetContextThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F1A9F135\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetCurrentProcessorNumber NtGetCurrentProcessorNumber
__asm__("NtGetCurrentProcessorNumber: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09A3CA2F6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetCurrentProcessorNumberEx NtGetCurrentProcessorNumberEx
__asm__("NtGetCurrentProcessorNumberEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x034CD780A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetDevicePowerState NtGetDevicePowerState
__asm__("NtGetDevicePowerState: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00A9BD4A2\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetMUIRegistryInfo NtGetMUIRegistryInfo
__asm__("NtGetMUIRegistryInfo: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x022B6FEFB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetNextProcess NtGetNextProcess
__asm__("NtGetNextProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x041DB5A74\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetNextThread NtGetNextThread
__asm__("NtGetNextThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09A27D48D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetNlsSectionPtr NtGetNlsSectionPtr
__asm__("NtGetNlsSectionPtr: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E313EA8C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetNotificationResourceManager NtGetNotificationResourceManager
__asm__("NtGetNotificationResourceManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00B362B85\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetPlugPlayEvent NtGetPlugPlayEvent
__asm__("NtGetPlugPlayEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0014D04DC\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetWriteWatch NtGetWriteWatch
__asm__("NtGetWriteWatch: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x028B71412\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwImpersonateAnonymousToken NtImpersonateAnonymousToken
__asm__("NtImpersonateAnonymousToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B5628BCA\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwImpersonateClientOfPort NtImpersonateClientOfPort
__asm__("NtImpersonateClientOfPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03C6E75B0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwImpersonateThread NtImpersonateThread
__asm__("NtImpersonateThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B78EB336\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwInitializeEnclave NtInitializeEnclave
__asm__("NtInitializeEnclave: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0EA35B40C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwInitializeNlsFiles NtInitializeNlsFiles
__asm__("NtInitializeNlsFiles: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F0C701B8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwInitializeRegistry NtInitializeRegistry
__asm__("NtInitializeRegistry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07CF14A5D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwInitiatePowerAction NtInitiatePowerAction
__asm__("NtInitiatePowerAction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x036A9B3B2\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwIsProcessInJob NtIsProcessInJob
__asm__("NtIsProcessInJob: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E4913FAB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwIsSystemResumeAutomatic NtIsSystemResumeAutomatic
__asm__("NtIsSystemResumeAutomatic: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01EB0DB8A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwIsUILanguageComitted NtIsUILanguageComitted
__asm__("NtIsUILanguageComitted: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0955CC267\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwListTransactions NtListTransactions
__asm__("NtListTransactions: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0CF9B37ED\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwListenPort NtListenPort
__asm__("NtListenPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02ABF2120\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLoadDriver NtLoadDriver
__asm__("NtLoadDriver: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x058B93064\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLoadEnclaveData NtLoadEnclaveData
__asm__("NtLoadEnclaveData: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0FD5D08C9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLoadHotPatch NtLoadHotPatch
__asm__("NtLoadHotPatch: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02CE0785C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLoadKey NtLoadKey
__asm__("NtLoadKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00AF30B6B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLoadKey2 NtLoadKey2
__asm__("NtLoadKey2: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x061F9AEE4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLoadKeyEx NtLoadKeyEx
__asm__("NtLoadKeyEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0FF9922CD\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLockFile NtLockFile
__asm__("NtLockFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04119013C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLockProductActivationKeys NtLockProductActivationKeys
__asm__("NtLockProductActivationKeys: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C926DAC2\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLockRegistryKey NtLockRegistryKey
__asm__("NtLockRegistryKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0BE8C9518\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwLockVirtualMemory NtLockVirtualMemory
__asm__("NtLockVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0BB54C197\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMakePermanentObject NtMakePermanentObject
__asm__("NtMakePermanentObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x060DD0821\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMakeTemporaryObject NtMakeTemporaryObject
__asm__("NtMakeTemporaryObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x004A8FDA4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwManageHotPatch NtManageHotPatch
__asm__("NtManageHotPatch: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A4B8D024\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwManagePartition NtManagePartition
__asm__("NtManagePartition: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B8283E3D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMapCMFModule NtMapCMFModule
__asm__("NtMapCMFModule: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0000E00A8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMapUserPhysicalPages NtMapUserPhysicalPages
__asm__("NtMapUserPhysicalPages: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0DEB931C5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMapUserPhysicalPagesScatter NtMapUserPhysicalPagesScatter
__asm__("NtMapUserPhysicalPagesScatter: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0018E3333\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMapViewOfSection NtMapViewOfSection
__asm__("NtMapViewOfSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0DC8FC60B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMapViewOfSectionEx NtMapViewOfSectionEx
__asm__("NtMapViewOfSectionEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01E84283A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMarshallTransaction NtMarshallTransaction
__asm__("NtMarshallTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x006E6087B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwModifyBootEntry NtModifyBootEntry
__asm__("NtModifyBootEntry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01B870700\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwModifyDriverEntry NtModifyDriverEntry
__asm__("NtModifyDriverEntry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02BA64F4A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwNotifyChangeDirectoryFile NtNotifyChangeDirectoryFile
__asm__("NtNotifyChangeDirectoryFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0FF3D0375\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwNotifyChangeDirectoryFileEx NtNotifyChangeDirectoryFileEx
__asm__("NtNotifyChangeDirectoryFileEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F449B095\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwNotifyChangeKey NtNotifyChangeKey
__asm__("NtNotifyChangeKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0863BEDDB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwNotifyChangeMultipleKeys NtNotifyChangeMultipleKeys
__asm__("NtNotifyChangeMultipleKeys: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x085028292\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwNotifyChangeSession NtNotifyChangeSession
__asm__("NtNotifyChangeSession: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x073B62F7C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenDirectoryObject NtOpenDirectoryObject
__asm__("NtOpenDirectoryObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x058C0121D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenEnlistment NtOpenEnlistment
__asm__("NtOpenEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x013B53623\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenEvent NtOpenEvent
__asm__("NtOpenEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0484247D8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenEventPair NtOpenEventPair
__asm__("NtOpenEventPair: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x080A8A03E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenFile NtOpenFile
__asm__("NtOpenFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x069030712\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenIoCompletion NtOpenIoCompletion
__asm__("NtOpenIoCompletion: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x002886247\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenJobObject NtOpenJobObject
__asm__("NtOpenJobObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0388417DF\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenKey NtOpenKey
__asm__("NtOpenKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00E1DEA42\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenKeyEx NtOpenKeyEx
__asm__("NtOpenKeyEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0785EB629\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenKeyTransacted NtOpenKeyTransacted
__asm__("NtOpenKeyTransacted: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A49B6CB7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenKeyTransactedEx NtOpenKeyTransactedEx
__asm__("NtOpenKeyTransactedEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D82D1A57\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenKeyedEvent NtOpenKeyedEvent
__asm__("NtOpenKeyedEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x033542ED4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenMutant NtOpenMutant
__asm__("NtOpenMutant: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x072DE6B3A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenObjectAuditAlarm NtOpenObjectAuditAlarm
__asm__("NtOpenObjectAuditAlarm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0CE81F02C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenPartition NtOpenPartition
__asm__("NtOpenPartition: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01883D8D1\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenPrivateNamespace NtOpenPrivateNamespace
__asm__("NtOpenPrivateNamespace: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09C32999B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D22ACDA7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C65AC2C0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenProcessTokenEx NtOpenProcessTokenEx
__asm__("NtOpenProcessTokenEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00A9AC9C1\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenRegistryTransaction NtOpenRegistryTransaction
__asm__("NtOpenRegistryTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F4AD16BD\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenResourceManager NtOpenResourceManager
__asm__("NtOpenResourceManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01B5DCC18\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenSection NtOpenSection
__asm__("NtOpenSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0CF84F357\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenSemaphore NtOpenSemaphore
__asm__("NtOpenSemaphore: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01E8A4BBA\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenSession NtOpenSession
__asm__("NtOpenSession: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04F9D1736\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenSymbolicLinkObject NtOpenSymbolicLinkObject
__asm__("NtOpenSymbolicLinkObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08EA5BFE8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenThread NtOpenThread
__asm__("NtOpenThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00828CA86\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenThreadToken NtOpenThreadToken
__asm__("NtOpenThreadToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03DA81734\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenThreadTokenEx NtOpenThreadTokenEx
__asm__("NtOpenThreadTokenEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02A9F6448\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenTimer NtOpenTimer
__asm__("NtOpenTimer: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x045572C4C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenTransaction NtOpenTransaction
__asm__("NtOpenTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00EE7286F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenTransactionManager NtOpenTransactionManager
__asm__("NtOpenTransactionManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07B3CAD78\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPlugPlayControl NtPlugPlayControl
__asm__("NtPlugPlayControl: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01F7102F8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPowerInformation NtPowerInformation
__asm__("NtPowerInformation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C24BECD7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPrePrepareComplete NtPrePrepareComplete
__asm__("NtPrePrepareComplete: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04E92665C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPrePrepareEnlistment NtPrePrepareEnlistment
__asm__("NtPrePrepareEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x057C86C7F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPrepareComplete NtPrepareComplete
__asm__("NtPrepareComplete: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03693C888\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPrepareEnlistment NtPrepareEnlistment
__asm__("NtPrepareEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F966DEBD\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPrivilegeCheck NtPrivilegeCheck
__asm__("NtPrivilegeCheck: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AA117EB0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPrivilegeObjectAuditAlarm NtPrivilegeObjectAuditAlarm
__asm__("NtPrivilegeObjectAuditAlarm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D03E2F6E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPrivilegedServiceAuditAlarm NtPrivilegedServiceAuditAlarm
__asm__("NtPrivilegedServiceAuditAlarm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0DA581808\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPropagationComplete NtPropagationComplete
__asm__("NtPropagationComplete: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04527AC68\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPropagationFailed NtPropagationFailed
__asm__("NtPropagationFailed: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x006C94210\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwProtectVirtualMemory NtProtectVirtualMemory
__asm__("NtProtectVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x001911911\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPullTransaction NtPullTransaction
__asm__("NtPullTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C086E256\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwPulseEvent NtPulseEvent
__asm__("NtPulseEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01A3C73A0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryAttributesFile NtQueryAttributesFile
__asm__("NtQueryAttributesFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0913DB9B0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryAuxiliaryCounterFrequency NtQueryAuxiliaryCounterFrequency
__asm__("NtQueryAuxiliaryCounterFrequency: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x082287655\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryBootEntryOrder NtQueryBootEntryOrder
__asm__("NtQueryBootEntryOrder: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0CF72FDD3\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryBootOptions NtQueryBootOptions
__asm__("NtQueryBootOptions: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0FF29BDFD\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryDebugFilterState NtQueryDebugFilterState
__asm__("NtQueryDebugFilterState: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07617609C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryDefaultLocale NtQueryDefaultLocale
__asm__("NtQueryDefaultLocale: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x001204DF4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryDefaultUILanguage NtQueryDefaultUILanguage
__asm__("NtQueryDefaultUILanguage: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0EFCFF872\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryDirectoryFile NtQueryDirectoryFile
__asm__("NtQueryDirectoryFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01EBD4C8A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryDirectoryFileEx NtQueryDirectoryFileEx
__asm__("NtQueryDirectoryFileEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C8360740\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryDirectoryObject NtQueryDirectoryObject
__asm__("NtQueryDirectoryObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00AA4765B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryDriverEntryOrder NtQueryDriverEntryOrder
__asm__("NtQueryDriverEntryOrder: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02C8FF5C4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryEaFile NtQueryEaFile
__asm__("NtQueryEaFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0663D2AEB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryEvent NtQueryEvent
__asm__("NtQueryEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x062D8B09E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryFullAttributesFile NtQueryFullAttributesFile
__asm__("NtQueryFullAttributesFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0509E384C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationAtom NtQueryInformationAtom
__asm__("NtQueryInformationAtom: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0EE70EDE4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationByName NtQueryInformationByName
__asm__("NtQueryInformationByName: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0ECB4DF63\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationEnlistment NtQueryInformationEnlistment
__asm__("NtQueryInformationEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0BE21D9BA\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationFile NtQueryInformationFile
__asm__("NtQueryInformationFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0BE662A54\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationJobObject NtQueryInformationJobObject
__asm__("NtQueryInformationJobObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09F204B7F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationPort NtQueryInformationPort
__asm__("NtQueryInformationPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02AB5212A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationProcess NtQueryInformationProcess
__asm__("NtQueryInformationProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0822FAD77\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationResourceManager NtQueryInformationResourceManager
__asm__("NtQueryInformationResourceManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09E098E8F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationThread NtQueryInformationThread
__asm__("NtQueryInformationThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B585B539\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationToken NtQueryInformationToken
__asm__("NtQueryInformationToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01B9AFA89\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationTransaction NtQueryInformationTransaction
__asm__("NtQueryInformationTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x005B3391C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationTransactionManager NtQueryInformationTransactionManager
__asm__("NtQueryInformationTransactionManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09B8556D9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationWorkerFactory NtQueryInformationWorkerFactory
__asm__("NtQueryInformationWorkerFactory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07C6F108A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInstallUILanguage NtQueryInstallUILanguage
__asm__("NtQueryInstallUILanguage: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x097B444F5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryIntervalProfile NtQueryIntervalProfile
__asm__("NtQueryIntervalProfile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00CBAD30E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryIoCompletion NtQueryIoCompletion
__asm__("NtQueryIoCompletion: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x002980207\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryKey NtQueryKey
__asm__("NtQueryKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AE6E8DB5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryLicenseValue NtQueryLicenseValue
__asm__("NtQueryLicenseValue: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0CCBBEF77\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryMultipleValueKey NtQueryMultipleValueKey
__asm__("NtQueryMultipleValueKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01B9EF5F9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryMutant NtQueryMutant
__asm__("NtQueryMutant: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x072CE4A8A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryObject NtQueryObject
__asm__("NtQueryObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00A941429\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryOpenSubKeys NtQueryOpenSubKeys
__asm__("NtQueryOpenSubKeys: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02BD71C5C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryOpenSubKeysEx NtQueryOpenSubKeysEx
__asm__("NtQueryOpenSubKeysEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B58CED4C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryPerformanceCounter NtQueryPerformanceCounter
__asm__("NtQueryPerformanceCounter: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0896AD7CB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryPortInformationProcess NtQueryPortInformationProcess
__asm__("NtQueryPortInformationProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08910AC40\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryQuotaInformationFile NtQueryQuotaInformationFile
__asm__("NtQueryQuotaInformationFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A5317D75\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySection NtQuerySection
__asm__("NtQuerySection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0CAA81000\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySecurityAttributesToken NtQuerySecurityAttributesToken
__asm__("NtQuerySecurityAttributesToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01A0CF70E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySecurityObject NtQuerySecurityObject
__asm__("NtQuerySecurityObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0EA44DAE8\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySecurityPolicy NtQuerySecurityPolicy
__asm__("NtQuerySecurityPolicy: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01681EBC4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySemaphore NtQuerySemaphore
__asm__("NtQuerySemaphore: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00DE09EDE\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySymbolicLinkObject NtQuerySymbolicLinkObject
__asm__("NtQuerySymbolicLinkObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00A91200F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySystemEnvironmentValue NtQuerySystemEnvironmentValue
__asm__("NtQuerySystemEnvironmentValue: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01CC88EF0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySystemEnvironmentValueEx NtQuerySystemEnvironmentValueEx
__asm__("NtQuerySystemEnvironmentValueEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x012395EFE\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySystemInformation NtQuerySystemInformation
__asm__("NtQuerySystemInformation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01E461AD7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySystemInformationEx NtQuerySystemInformationEx
__asm__("NtQuerySystemInformationEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08291B02A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySystemTime NtQuerySystemTime
__asm__("NtQuerySystemTime: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A107DB06\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryTimer NtQueryTimer
__asm__("NtQueryTimer: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04DA77F04\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryTimerResolution NtQueryTimerResolution
__asm__("NtQueryTimerResolution: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E836EAA7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryValueKey NtQueryValueKey
__asm__("NtQueryValueKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x060417DD4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryVirtualMemory NtQueryVirtualMemory
__asm__("NtQueryVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00792130D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryVolumeInformationFile NtQueryVolumeInformationFile
__asm__("NtQueryVolumeInformationFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x058FC6C6E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryWnfStateData NtQueryWnfStateData
__asm__("NtQueryWnfStateData: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01E85F00C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryWnfStateNameInformation NtQueryWnfStateNameInformation
__asm__("NtQueryWnfStateNameInformation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01BB51926\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueueApcThread NtQueueApcThread
__asm__("NtQueueApcThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02501A039\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueueApcThreadEx NtQueueApcThreadEx
__asm__("NtQueueApcThreadEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06538A580\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRaiseException NtRaiseException
__asm__("NtRaiseException: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0185204C7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRaiseHardError NtRaiseHardError
__asm__("NtRaiseHardError: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C793E701\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReadFile NtReadFile
__asm__("NtReadFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02EB13012\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReadFileScatter NtReadFileScatter
__asm__("NtReadFileScatter: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06FF1F7FB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReadOnlyEnlistment NtReadOnlyEnlistment
__asm__("NtReadOnlyEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x082BAE16D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReadRequestData NtReadRequestData
__asm__("NtReadRequestData: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A32756B3\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x002167EE3\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRecoverEnlistment NtRecoverEnlistment
__asm__("NtRecoverEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x089C48E4F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRecoverResourceManager NtRecoverResourceManager
__asm__("NtRecoverResourceManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0BD215042\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRecoverTransactionManager NtRecoverTransactionManager
__asm__("NtRecoverTransactionManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x007951338\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRegisterProtocolAddressInformation NtRegisterProtocolAddressInformation
__asm__("NtRegisterProtocolAddressInformation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09806FF17\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRegisterThreadTerminatePort NtRegisterThreadTerminatePort
__asm__("NtRegisterThreadTerminatePort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A0F1A560\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReleaseCMFViewOwnership NtReleaseCMFViewOwnership
__asm__("NtReleaseCMFViewOwnership: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x056EE88A0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReleaseKeyedEvent NtReleaseKeyedEvent
__asm__("NtReleaseKeyedEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D08A34E3\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReleaseMutant NtReleaseMutant
__asm__("NtReleaseMutant: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0308C3534\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReleaseSemaphore NtReleaseSemaphore
__asm__("NtReleaseSemaphore: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F499C1C9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReleaseWorkerFactoryWorker NtReleaseWorkerFactoryWorker
__asm__("NtReleaseWorkerFactoryWorker: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x010ADCAE5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRemoveIoCompletion NtRemoveIoCompletion
__asm__("NtRemoveIoCompletion: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0848DA61D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRemoveIoCompletionEx NtRemoveIoCompletionEx
__asm__("NtRemoveIoCompletionEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A291EE64\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRemoveProcessDebug NtRemoveProcessDebug
__asm__("NtRemoveProcessDebug: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0FFAADAE0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRenameKey NtRenameKey
__asm__("NtRenameKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x019AC32FE\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRenameTransactionManager NtRenameTransactionManager
__asm__("NtRenameTransactionManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x039A10B1A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReplaceKey NtReplaceKey
__asm__("NtReplaceKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E5330840\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReplacePartitionUnit NtReplacePartitionUnit
__asm__("NtReplacePartitionUnit: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x020325EB0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReplyPort NtReplyPort
__asm__("NtReplyPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x020B3ADA2\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReplyWaitReceivePort NtReplyWaitReceivePort
__asm__("NtReplyWaitReceivePort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x026B7CBEE\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReplyWaitReceivePortEx NtReplyWaitReceivePortEx
__asm__("NtReplyWaitReceivePortEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F7583224\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReplyWaitReplyPort NtReplyWaitReplyPort
__asm__("NtReplyWaitReplyPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0673F7A97\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRequestDeviceWakeup NtRequestDeviceWakeup
__asm__("NtRequestDeviceWakeup: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03993310A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRequestPort NtRequestPort
__asm__("NtRequestPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05CFFAF90\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRequestWaitReplyPort NtRequestWaitReplyPort
__asm__("NtRequestWaitReplyPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05CF9536A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRequestWakeupLatency NtRequestWakeupLatency
__asm__("NtRequestWakeupLatency: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01A817714\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwResetEvent NtResetEvent
__asm__("NtResetEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A8338B84\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwResetWriteWatch NtResetWriteWatch
__asm__("NtResetWriteWatch: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x064CB98AF\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRestoreKey NtRestoreKey
__asm__("NtRestoreKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x067A382DD\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwResumeProcess NtResumeProcess
__asm__("NtResumeProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x027AD2631\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwResumeThread NtResumeThread
__asm__("NtResumeThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01CBFDA9D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRevertContainerImpersonation NtRevertContainerImpersonation
__asm__("NtRevertContainerImpersonation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D64DD4D9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRollbackComplete NtRollbackComplete
__asm__("NtRollbackComplete: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0489817A2\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRollbackEnlistment NtRollbackEnlistment
__asm__("NtRollbackEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08029797B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRollbackRegistryTransaction NtRollbackRegistryTransaction
__asm__("NtRollbackRegistryTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x006EE267D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRollbackSavepointTransaction NtRollbackSavepointTransaction
__asm__("NtRollbackSavepointTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00800269D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRollbackTransaction NtRollbackTransaction
__asm__("NtRollbackTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0940FD4DD\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwRollforwardTransactionManager NtRollforwardTransactionManager
__asm__("NtRollforwardTransactionManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0852A97B6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSaveKey NtSaveKey
__asm__("NtSaveKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07EA8943B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSaveKeyEx NtSaveKeyEx
__asm__("NtSaveKeyEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x068922845\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSaveMergedKeys NtSaveMergedKeys
__asm__("NtSaveMergedKeys: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x021842416\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSavepointComplete NtSavepointComplete
__asm__("NtSavepointComplete: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01E93C4AC\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSavepointTransaction NtSavepointTransaction
__asm__("NtSavepointTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x002A9407D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSecureConnectPort NtSecureConnectPort
__asm__("NtSecureConnectPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x060FE6174\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSerializeBoot NtSerializeBoot
__asm__("NtSerializeBoot: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x074E03A39\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetBootEntryOrder NtSetBootEntryOrder
__asm__("NtSetBootEntryOrder: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A58D77A9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetBootOptions NtSetBootOptions
__asm__("NtSetBootOptions: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x051845D1F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetCachedSigningLevel NtSetCachedSigningLevel
__asm__("NtSetCachedSigningLevel: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0EF7BE5C5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetCachedSigningLevel2 NtSetCachedSigningLevel2
__asm__("NtSetCachedSigningLevel2: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02A94ABCC\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetContextThread NtSetContextThread
__asm__("NtSetContextThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x038A47A4D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetDebugFilterState NtSetDebugFilterState
__asm__("NtSetDebugFilterState: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02A8FC002\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetDefaultHardErrorPort NtSetDefaultHardErrorPort
__asm__("NtSetDefaultHardErrorPort: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02088251A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetDefaultLocale NtSetDefaultLocale
__asm__("NtSetDefaultLocale: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01D248D11\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetDefaultUILanguage NtSetDefaultUILanguage
__asm__("NtSetDefaultUILanguage: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E3DC9800\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetDriverEntryOrder NtSetDriverEntryOrder
__asm__("NtSetDriverEntryOrder: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0320E0AA0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetEaFile NtSetEaFile
__asm__("NtSetEaFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x054C05C72\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetEvent NtSetEvent
__asm__("NtSetEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x070CD4168\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetEventBoostPriority NtSetEventBoostPriority
__asm__("NtSetEventBoostPriority: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02CAA3438\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetHighEventPair NtSetHighEventPair
__asm__("NtSetHighEventPair: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0736E197A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetHighWaitLowEventPair NtSetHighWaitLowEventPair
__asm__("NtSetHighWaitLowEventPair: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x022BE222C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetIRTimer NtSetIRTimer
__asm__("NtSetIRTimer: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x079A1773E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationDebugObject NtSetInformationDebugObject
__asm__("NtSetInformationDebugObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0229E1013\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationEnlistment NtSetInformationEnlistment
__asm__("NtSetInformationEnlistment: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x084169592\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationFile NtSetInformationFile
__asm__("NtSetInformationFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E577AE57\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationJobObject NtSetInformationJobObject
__asm__("NtSetInformationJobObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0309C4E71\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationKey NtSetInformationKey
__asm__("NtSetInformationKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E0D5812D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationObject NtSetInformationObject
__asm__("NtSetInformationObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01EB46479\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationProcess NtSetInformationProcess
__asm__("NtSetInformationProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08E14A64B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationResourceManager NtSetInformationResourceManager
__asm__("NtSetInformationResourceManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E05B0901\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationSymbolicLink NtSetInformationSymbolicLink
__asm__("NtSetInformationSymbolicLink: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0933793A1\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationThread NtSetInformationThread
__asm__("NtSetInformationThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AB0C712D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationToken NtSetInformationToken
__asm__("NtSetInformationToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A79E7433\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationTransaction NtSetInformationTransaction
__asm__("NtSetInformationTransaction: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07CBA026B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationTransactionManager NtSetInformationTransactionManager
__asm__("NtSetInformationTransactionManager: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C39EE922\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationVirtualMemory NtSetInformationVirtualMemory
__asm__("NtSetInformationVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x003910903\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetInformationWorkerFactory NtSetInformationWorkerFactory
__asm__("NtSetInformationWorkerFactory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C4D7CE47\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetIntervalProfile NtSetIntervalProfile
__asm__("NtSetIntervalProfile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0481B925A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetIoCompletion NtSetIoCompletion
__asm__("NtSetIoCompletion: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0048E2411\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetIoCompletionEx NtSetIoCompletionEx
__asm__("NtSetIoCompletionEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C49EF624\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetLdtEntries NtSetLdtEntries
__asm__("NtSetLdtEntries: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0CE96CB09\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetLowEventPair NtSetLowEventPair
__asm__("NtSetLowEventPair: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A232CAD3\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetLowWaitHighEventPair NtSetLowWaitHighEventPair
__asm__("NtSetLowWaitHighEventPair: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E3D4DD78\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetQuotaInformationFile NtSetQuotaInformationFile
__asm__("NtSetQuotaInformationFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F5C43E91\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetSecurityObject NtSetSecurityObject
__asm__("NtSetSecurityObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03A84AA88\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetSystemEnvironmentValue NtSetSystemEnvironmentValue
__asm__("NtSetSystemEnvironmentValue: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05AFD053A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetSystemEnvironmentValueEx NtSetSystemEnvironmentValueEx
__asm__("NtSetSystemEnvironmentValueEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0DFC69312\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetSystemInformation NtSetSystemInformation
__asm__("NtSetSystemInformation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03AA6202F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetSystemPowerState NtSetSystemPowerState
__asm__("NtSetSystemPowerState: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0934CFD45\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetSystemTime NtSetSystemTime
__asm__("NtSetSystemTime: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AC325F25\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetThreadExecutionState NtSetThreadExecutionState
__asm__("NtSetThreadExecutionState: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0FEB5866A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetTimer NtSetTimer
__asm__("NtSetTimer: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x067DC4560\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetTimer2 NtSetTimer2
__asm__("NtSetTimer2: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x007BBCF25\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetTimerEx NtSetTimerEx
__asm__("NtSetTimerEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x022B3E0E9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetTimerResolution NtSetTimerResolution
__asm__("NtSetTimerResolution: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E608005D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetUuidSeed NtSetUuidSeed
__asm__("NtSetUuidSeed: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A1FAA146\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetValueKey NtSetValueKey
__asm__("NtSetValueKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0018A3C3C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetVolumeInformationFile NtSetVolumeInformationFile
__asm__("NtSetVolumeInformationFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0889B798F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetWnfProcessNotificationEvent NtSetWnfProcessNotificationEvent
__asm__("NtSetWnfProcessNotificationEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x018ABFEC1\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwShutdownSystem NtShutdownSystem
__asm__("NtShutdownSystem: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0188ACFB0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwShutdownWorkerFactory NtShutdownWorkerFactory
__asm__("NtShutdownWorkerFactory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x004974C46\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSignalAndWaitForSingleObject NtSignalAndWaitForSingleObject
__asm__("NtSignalAndWaitForSingleObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0059D5344\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSinglePhaseReject NtSinglePhaseReject
__asm__("NtSinglePhaseReject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03698003B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwStartProfile NtStartProfile
__asm__("NtStartProfile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05CA0AD34\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwStartTm NtStartTm
__asm__("NtStartTm: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x055881B2A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwStopProfile NtStopProfile
__asm__("NtStopProfile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x074E05E74\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSubscribeWnfStateChange NtSubscribeWnfStateChange
__asm__("NtSubscribeWnfStateChange: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01221941D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSuspendProcess NtSuspendProcess
__asm__("NtSuspendProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AEBCAF33\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSuspendThread NtSuspendThread
__asm__("NtSuspendThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x021253B83\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSystemDebugControl NtSystemDebugControl
__asm__("NtSystemDebugControl: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0D50FF7D9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTerminateEnclave NtTerminateEnclave
__asm__("NtTerminateEnclave: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x05CBA6018\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTerminateJobObject NtTerminateJobObject
__asm__("NtTerminateJobObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04EDDA641\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTerminateProcess NtTerminateProcess
__asm__("NtTerminateProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00597020C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTerminateThread NtTerminateThread
__asm__("NtTerminateThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02E8E2427\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTestAlert NtTestAlert
__asm__("NtTestAlert: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x076B95310\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwThawRegistry NtThawRegistry
__asm__("NtThawRegistry: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x000AA0825\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwThawTransactions NtThawTransactions
__asm__("NtThawTransactions: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x019CC5B1B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTraceControl NtTraceControl
__asm__("NtTraceControl: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0855FA789\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTraceEvent NtTraceEvent
__asm__("NtTraceEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x000C81D68\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTranslateFilePath NtTranslateFilePath
__asm__("NtTranslateFilePath: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x070D27F74\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUmsThreadYield NtUmsThreadYield
__asm__("NtUmsThreadYield: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06FB3B7F7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnloadDriver NtUnloadDriver
__asm__("NtUnloadDriver: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x02C9D07C4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnloadKey NtUnloadKey
__asm__("NtUnloadKey: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E8CE0E92\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnloadKey2 NtUnloadKey2
__asm__("NtUnloadKey2: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x07A268EE0\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnloadKeyEx NtUnloadKeyEx
__asm__("NtUnloadKeyEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0725D3483\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnlockFile NtUnlockFile
__asm__("NtUnlockFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0AE3AA6AC\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnlockVirtualMemory NtUnlockVirtualMemory
__asm__("NtUnlockVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01E4FF62E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnmapViewOfSection NtUnmapViewOfSection
__asm__("NtUnmapViewOfSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09E04DAD7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnmapViewOfSectionEx NtUnmapViewOfSectionEx
__asm__("NtUnmapViewOfSectionEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x058D36664\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnsubscribeWnfStateChange NtUnsubscribeWnfStateChange
__asm__("NtUnsubscribeWnfStateChange: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x086248580\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUpdateWnfStateData NtUpdateWnfStateData
__asm__("NtUpdateWnfStateData: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x076DDE8E4\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwVdmControl NtVdmControl
__asm__("NtVdmControl: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x085941DA7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForAlertByThreadId NtWaitForAlertByThreadId
__asm__("NtWaitForAlertByThreadId: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B4BD6F8B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForDebugEvent NtWaitForDebugEvent
__asm__("NtWaitForDebugEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F6ACCF06\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForKeyedEvent NtWaitForKeyedEvent
__asm__("NtWaitForKeyedEvent: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x030B20B14\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForMultipleObjects NtWaitForMultipleObjects
__asm__("NtWaitForMultipleObjects: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0E132E9AF\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForMultipleObjects32 NtWaitForMultipleObjects32
__asm__("NtWaitForMultipleObjects32: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00C9D0A52\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForSingleObject NtWaitForSingleObject
__asm__("NtWaitForSingleObject: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x038A6663B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForWnfNotifications NtWaitForWnfNotifications
__asm__("NtWaitForWnfNotifications: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0164B18D1\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForWorkViaWorkerFactory NtWaitForWorkViaWorkerFactory
__asm__("NtWaitForWorkViaWorkerFactory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0889E9A12\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitHighEventPair NtWaitHighEventPair
__asm__("NtWaitHighEventPair: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x054D5B48B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitLowEventPair NtWaitLowEventPair
__asm__("NtWaitLowEventPair: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x006AD223F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWorkerFactoryWorkerReady NtWorkerFactoryWorkerReady
__asm__("NtWorkerFactoryWorkerReady: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01ABAE0C6\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWriteFile NtWriteFile
__asm__("NtWriteFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B822B194\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWriteFileGather NtWriteFileGather
__asm__("NtWriteFileGather: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C3D1D175\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWriteRequestData NtWriteRequestData
__asm__("NtWriteRequestData: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x06CC4935A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWriteVirtualMemory NtWriteVirtualMemory
__asm__("NtWriteVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x08714B3A9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwYieldExecution NtYieldExecution
__asm__("NtYieldExecution: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04ADC2C49\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define RtlCreateUserThread RtlCreateUserThread
__asm__("RtlCreateUserThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F2CEEC7F\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");