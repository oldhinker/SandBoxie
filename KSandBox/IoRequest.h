#pragma once
#include "Common.h"
#include "ProcessHelper.h"


enum {
	FIRST_2 = 0x23450000L,


	INJECT_PROCESS,


	LAST_2
};



BOOLEAN FastIoDeviceControl(
	FILE_OBJECT* FileObject, BOOLEAN Wait,
	void* InputBuffer, ULONG InputBufferLength,
	void* OutputBuffer, ULONG OutputBufferLength,
	ULONG IoControlCode, IO_STATUS_BLOCK* IoStatus,
	DEVICE_OBJECT* DeviceObject);


NTSTATUS IrpCreateDispatch(DEVICE_OBJECT* DeviceObject, IRP* Irp);
NTSTATUS IrpCleanUpDispatch(DEVICE_OBJECT* DeviceObject, IRP* Irp);



extern FAST_IO_DISPATCH* __FastIoDispatch;

typedef NTSTATUS(*LPFN_FUNCTION)(PROCESS* Process, ULONG64* ParameterData);



#define MAX_MESSAGE_LENGTH 328   



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

NTSTATUS
NTAPI
LpcRequestPort(IN PVOID PortObject,
	IN PPORT_MESSAGE LpcMessage);   //ϵͳ



#define DATA_LENGTH    \
            (MAX_MESSAGE_LENGTH - (sizeof(PORT_MESSAGE) + sizeof(ULONG)))



#define IO_CTL_CODE_1 \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)


//
BOOLEAN SendLpcMessage(ULONG Protocol, ULONG DataLength, void* MessageData);


