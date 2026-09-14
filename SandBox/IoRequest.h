#pragma once
#include "Common.h"
#include "ObjectHelper.h"




//LPC

#define MAX_MESSAGE_LENGTH 328   //Ring3  Ring0 通过端口传递数据的大小


typedef struct _MESSAGE_DATA
{
    void* ClassContext;
    UCHAR BufferData[MAX_MESSAGE_LENGTH];
} MESSAGE_DATA;


typedef enum _LPC_TYPE {
    LPC_NEW_MESSAGE,            // 0
    LPC_REQUEST,                // 1
    LPC_REPLY,                  // 2
    LPC_DATAGRAM,               // 3
    LPC_LOST_REPLY,             // 4
    LPC_PORT_CLOSED,            // 5
    LPC_CLIENT_DIED,            // 6
    LPC_EXCEPTION,              // 7
    LPC_DEBUG_EVENT,            // 8
    LPC_ERROR_EVENT,            // 9
    LPC_CONNECTION_REQUEST,     // 10
    LPC_CONNECTION_REFUSED,     // 11
    LPC_MAXIMUM,
    LPC_KERNELMODE_MESSAGE = 0x8000
} LPC_TYPE;

typedef struct _PORT_MESSAGE {
    union {
        struct {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;       // force quadword alignment
    };
    ULONG MessageId;
    union {
        ULONG_PTR ClientViewSize;       // for LPC_CONNECTION_REQUEST message
        ULONG CallbackId;               // for LPC_REQUEST message
    };
    UCHAR Data[0];
} PORT_MESSAGE, * PPORT_MESSAGE;



//创建端口
typedef
NTSTATUS(NTAPI* LPFN_NTCREATEPORT)(OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG MaxConnectInfoLength,
    IN ULONG MaxDataLength,
    IN ULONG MaxPoolUsage);

extern LPFN_NTCREATEPORT __NtCreatePort;



//等待端口数据
typedef
NTSTATUS(__stdcall* LPFN_NTREPLYWAITRECEIVEPORT)(
    IN  HANDLE PortHandle,
    OUT PVOID* PortContext OPTIONAL,
    IN  PPORT_MESSAGE ReplyMessage OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage);
extern LPFN_NTREPLYWAITRECEIVEPORT __NtReplyWaitReceivePort;



//向端口发送数据
typedef
NTSTATUS(NTAPI* LPFN_LPCREQUESTPORT)(IN PVOID PortObject,
    IN PPORT_MESSAGE LpcMessage);





//FastIo
#define IO_CTL_CODE_1 \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)






bool InitializeIoDevice();
LONG IoctlRequest(ULONG ServiceIndex, LONG ParameterCounts, ...);
NTSTATUS IoctlRequestInternal(ULONG64* ParameterData);



