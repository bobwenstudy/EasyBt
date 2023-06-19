#include "base\types.h"

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int uint;
typedef unsigned long long ull;

#define ALIGN(x)		__attribute__((aligned (x)))
#define ASSERT(x)		do { if(!(x)) assert(0x4000);} while(0)

#define LOBYTE(x)  ((byte)((x) & 0xff))
#define HIBYTE(x)  ((byte)((x) >> 8 & 0xff))
#define TRDBYTE(x)  ((byte)((x) >> 16 & 0xff))
#define WORD(x)				LOBYTE(x),HIBYTE(x)
#define TBYTE(x)				WORD(x),TRDBYTE(x)
#define DWORD(x)			WORD(x),WORD(x >> 16)

#define GETW(addr)			(*(byte *)(addr) | *(byte *)((int)(addr) + 1) << 8)
#define GETT(addr)			(*(byte *)(addr + 2) << 16 | GETW(addr))
#define GETL(addr)			(*(byte *)(addr + 3) << 24 | GETT(addr))
#define PUTW(addr, val)		*(byte *)(addr) = (val) & 0xff, *(byte *)((int)(addr) + 1) = (val) >> 8 & 0xff
#define PUTT(addr, val)		PUTW(addr, val), *(byte *)((int)(addr) + 2) = (val) >> 16 & 0xff
#define PUTL(addr, val)		PUTT(addr, val), *(byte *)((int)(addr) + 3) = (val) >> 24 & 0xff

#define GETW_BE(addr)		(*(byte *)(addr) << 8 | *(byte *)((int)(addr) + 1))
#define GETL_BE(addr)		(*(byte *)(addr + 2) << 8 | *(byte *)(addr + 3) | GETW_BE(addr) << 16)

#define PUTW_BE(addr, val)	*(byte *)(addr) = (val) >> 8 & 0xff, *(byte *)((int)(addr) + 1) = (val)
#define PUTT_BE(addr, val)		*(byte *)(addr) = (val) >> 16, *(byte *)((int)(addr) + 1) = (val) >> 8, *(byte *)((int)(addr) + 2) = (val)
#define MEMPTR(val)			(void *)((int)(val) | 0x10000)
#define INCPTR(p, inc, buf)		if((p += inc) >= buf + sizeof(buf)) p -= sizeof(buf)
#define ITEMS(wptr, rptr, buf)	((wptr) > (rptr) ? (wptr) - (rptr) : sizeof(buf) + (wptr) - (rptr))
#define DIFF(x,y)				((x) > (y) ? (x)- (y) : (y) - (x))


#define DEBUG_SEC			1
#define DEBUG_SEC_AR		2
#define DEBUG_SEC_ARS		4
#define DEBUG_LMP			8
#define DEBUG_L2CAP			16

#define BLEMODE_1M		1
#define BLEMODE_2M		2
#define BLEMODE_S2		4
#define BLEMODE_S8		12

#define TX_SHIFT			4

#define TRANSMIT_WINDOW_DELAY	DSLOT

#define LE_ADV_IND               0
#define LE_ADV_DIRECT_IND        1
#define LE_ADV_NONCONN_IND       2
#define LE_SCAN_REQ              3
#define LE_SCAN_RSP              4
#define LE_CONNECT_IND           5
#define LE_ADV_SCAN_IND          6
#define LE_ADV_EXT_IND           7

#define LE_ADV_ACCESS			0x8e89bed6
#define LE_ADV_CRCINIT			0x555555

#define ADTYPE_FLAGS												  0x01	
#define ADTYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS        0x02	
#define ADTYPE_COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS          0x03	
#define ADTYPE_INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS        0x04	
#define ADTYPE_COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS          0x05	
#define ADTYPE_INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS       0x06	
#define ADTYPE_COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS         0x07	
#define ADTYPE_SHORTENED_LOCAL_NAME                                 0x08	
#define ADTYPE_COMPLETE_LOCAL_NAME                                  0x09	
#define ADTYPE_TX_POWER_LEVEL                                       0x0A	
#define ADTYPE_CLASS_OF_DEVICE                                      0x0D	
#define ADTYPE_SIMPLE_PAIRING_HASH_C                                0x0E	
#define ADTYPE_SIMPLE_PAIRING_RANDOMIZER_R                          0x0F	
#define ADTYPE_DEVICE_ID                                            0x10	
#define ADTYPE_SECURITY_MANAGER_OUT_OF_BAND_FLAGS                   0x11	
#define ADTYPE_SLAVE_CONNECTION_INTERVAL_RANGE                      0x12	
#define ADTYPE_LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS            0x14	
#define ADTYPE_LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS           0x1F	
#define ADTYPE_LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS           0x15	
#define ADTYPE_SERVICE_DATA                                         0x16	
#define ADTYPE_SERVICE_DATA_16_BIT_UUID                            0x16	
#define ADTYPE_PUBLIC_TARGET_ADDRESS                                0x17	
#define ADTYPE_RANDOM_TARGET_ADDRESS                                0x18	
#define ADTYPE_APPEARANCE                                           0x19	
#define ADTYPE_ADVERTISING_INTERVAL                                0x1A	
#define ADTYPE_LE_BLUETOOTH_DEVICE_ADDRESS                         0x1B 
#define ADTYPE_LE_ROLE                                           0x1C	
#define ADTYPE_SIMPLE_PAIRING_HASH_C_256                         0x1D	
#define ADTYPE_SIMPLE_PAIRING_RANDOMIZER_R_256                   0x1E	
#define ADTYPE_SERVICE_DATA_32_BIT_UUID                            0x20	
#define ADTYPE_SERVICE_DATA_128_BIT_UUID                          0x21	  
#define ADTYPE_3D_INFORMATION_DATA                                0x3D	  


#define LLID_CONTINUE 	0x01
#define LLID_START    		0x02
#define LLID_LE_LL    		0x03
#define ARQ_NESN		0x4
#define ARQ_SN			0x8
#define ARQ_MD			0x10
#define ARQ_RXMD		0x40
#define ARQ_WAK			0x80

#define MAX_PAYLOAD_LEN		37

#define LL_CONNECTION_UPDATE_IND         0x00
#define LL_CHANNEL_MAP_IND               0x01
#define LL_TERMINATE_IND                 0x02
#define LL_ENC_REQ                       0x03
#define LL_ENC_RSP                       0x04
#define LL_START_ENC_REQ                 0x05
#define LL_START_ENC_RSP                 0x06
#define LL_UNKNOWN_RSP                   0x07
#define LL_FEATURE_REQ                   0x08
#define LL_FEATURE_RSP                   0x09
#define LL_PAUSE_ENC_REQ                 0x0A
#define LL_PAUSE_ENC_RSP                 0x0B
#define LL_VERSION_IND                   0x0C
#define LL_REJECT_IND                    0x0D
#define LL_SLAVE_FEATURE_REQ             0x0E
#define LL_CONNECTION_PARAM_REQ          0x0F
#define LL_CONNECTION_PARAM_RSP          0x10
#define LL_REJECT_IND_EXT                0x11
#define LL_PING_REQ                      0x12
#define LL_PING_RSP                      0x13
#define LL_LENGTH_REQ                    0x14
#define LL_LENGTH_RSP                    0x15
#define LL_PHY_REQ                       0x16
#define LL_PHY_RSP                       0x17
#define LL_PHY_UPDATE_IND                0x18
#define LL_MIN_USED_CHANNELS_IND         0x19
#define LL_CTE_REQ                       0x1A
#define LL_CTE_RSP                       0x1B
#define LL_PERIODIC_SYNC_IND             0x1C
#define LL_CLOCK_ACCURACY_REQ            0x1D
#define LL_CLOCK_ACCURACY_RSP            0x1E
#define LL_CIS_REQ                       0x1F
#define LL_CIS_RSP                       0x20
#define LL_CIS_IND                       0x21
#define LL_CIS_TERMINATE_IND             0x22
#define LL_POWER_CONTROL_REQ             0x23
#define LL_POWER_CONTROL_RSP             0x24
#define LL_POWER_CHANGE_IND              0x25

#define LE_L2CAP_CID_ATT		0x0004
#define LE_L2CAP_CID_SIGNAL    	0x0005
#define LE_L2CAP_CID_SMP       	0x0006

#define SMP_PAIRING_REQUEST                       0x01
#define SMP_PAIRING_RESPONSE                      0x02
#define SMP_PAIRING_CONFIRM                       0x03
#define SMP_PAIRING_RANDOM                        0x04
#define SMP_PAIRING_FAILED                        0x05
#define SMP_ENCRYPTION_INFORMATION                0x06
#define SMP_MASTER_IDENTIFICATION                 0x07
#define SMP_IDENTITY_INFORMATION                  0x08
#define SMP_IDENTITY_ADDRESS_INFORMATION          0x09
#define SMP_SIGNING_INFORMATION                   0x0A
#define SMP_SECURITY_REQUEST                      0x0B
#define SMP_PUBLIC_KEY                      0x0c
#define SMP_DHKEY_CHECK                      0x0d
#define SMP_PAIRING_KEYPRESS_NOTFICATION                      0x0e

#define IOCAP_DISPLAYONLY     0 
#define IOCAP_DISPLAYYESNO    1 
#define IOCAP_KEYBOARDONLY    2 
#define IOCAP_NOINPUTNOOUTPUT 3 
#define IOCAP_KEYBOARDDISPLAY 4 

#define BONDING_FLAG	1

#define KEYDIST_ENCKEY		1
#define KEYDIST_IDKEY		2
#define KEYDIST_SIGNKEY		4
#define KEYDIST_LINKKEY		8

#define PAIRING_FAILED_RESERVED                              0x00 
#define PAIRING_FAILED_PASSKEY_ENTRY_FAILED                  0x01 
#define PAIRING_FAILED_OOB_NOT_AVAILABLE                     0x02 
#define PAIRING_FAILED_AUTHENTICATION_REQUIRE                0x03 
#define PAIRING_FAILED_CONFIRM_VALUE_FAILED                  0x04 
#define PAIRING_FAILED_PAIRING_NOT_SUPPORTED                 0x05 
#define PAIRING_FAILED_ENCRYPTION_KEY_SIZE                   0x06 
#define PAIRING_FAILED_COMMAND_NOT_SUPPORTED                 0x07 
#define PAIRING_FAILED_UNSPECIFIED_REASON                    0x08 
#define PAIRING_FAILED_REPEATED_ATTEMPTS                     0x09 
#define PAIRING_FAILED_INVALID_PARAMETERS                    0x0A 
#define PAIRING_FAILED_DHKEY_CHECK_FAILED                    0x0B 
#define PAIRING_FAILED_NUMERIC_COMPARISON_FAILED             0x0C 
#define PAIRING_FAILED_BR_EDR_PAIRING_IN_PROGRESS            0x0D 
#define PAIRING_FAILED_KEY_DERIVATION_GENERATION_NOT_ALLOWED 0x0E 


#define ATTOP_ERROR_RESPONSE                         0x01
#define ATTOP_EXCHANGE_MTU_REQUEST                   0x02
#define ATTOP_EXCHANGE_MTU_RESPONSE                  0x03
#define ATTOP_FIND_INFORMATION_REQUEST               0x04
#define ATTOP_FIND_INFORMATION_RESPONSE              0x05
#define ATTOP_FIND_BY_TYPE_VALUE_REQUEST             0x06
#define ATTOP_FIND_BY_TYPE_VALUE_RESPONSE            0x07
#define ATTOP_READ_BY_TYPE_REQUEST                   0x08
#define ATTOP_READ_BY_TYPE_RESPONSE                  0x09
#define ATTOP_READ_REQUEST                           0x0A
#define ATTOP_READ_RESPONSE                          0x0B
#define ATTOP_READ_BLOB_REQUEST                      0x0C
#define ATTOP_READ_BLOB_RESPONSE                     0x0D
#define ATTOP_READ_MULTIPLE_REQUEST                  0x0E
#define ATTOP_READ_MULTIPLE_RESPONSE                 0x0F
#define ATTOP_READ_BY_GROUP_TYPE_REQUEST             0x10
#define ATTOP_READ_BY_GROUP_TYPE_RESPONSE            0x11
#define ATTOP_WRITE_REQUEST                          0x12
#define ATTOP_WRITE_RESPONSE                         0x13
#define ATTOP_PREPARE_WRITE_REQUEST                  0x16
#define ATTOP_PREPARE_WRITE_RESPONSE                 0x17
#define ATTOP_EXECUTE_WRITE_REQUEST                  0x18
#define ATTOP_EXECUTE_WRITE_RESPONSE                 0x19
#define ATTOP_HANDLE_VALUE_NOTIFICATION              0x1B
#define ATTOP_HANDLE_VALUE_INDICATION                0x1D
#define ATTOP_HANDLE_VALUE_CONFIRMATION              0x1E
#define ATTOP_WRITE_COMMAND                          0x52
#define ATTOP_SIGNED_WRITE_COMMAND                   0xD2
#define ATTOP_CONTINUE                               0x1f

#define ATT_ERR_INVALID_HANDLE                            0x01 
#define ATT_ERR_READ_NOT_PERMITTED                        0x02 
#define ATT_ERR_WRITE_NOT_PERMITTED                       0x03 
#define ATT_ERR_INVALID_PDU                               0x04 
#define ATT_ERR_INSUFFICIENT_AUTHENTICATION               0x05 
#define ATT_ERR_REQUEST_NOT_SUPPORTED                     0x06 
#define ATT_ERR_INVALID_OFFSET                            0x07 
#define ATT_ERR_INSUFFICIENT_AUTHORIZATION                0x08 
#define ATT_ERR_PREPARE_QUEUE_FULL                        0x09 
#define ATT_ERR_ATTRIBUTE_NOT_FOUND                       0x0A 
#define ATT_ERR_ATTRIBUTE_NOT_LONG                        0x0B 
#define ATT_ERR_INSUFFICIENT_ENCRYPTION_KEY_SIZE          0x0C 
#define ATT_ERR_INVALID_ATTRIBUTE_VALUE_LENGTH            0x0D 
#define ATT_ERR_UNLIKELY_ERROR                            0x0E 
#define ATT_ERR_INSUFFICIENT_ENCRYPTION                   0x0F 
#define ATT_ERR_UNSUPPORTED_GROUP_TYPE                    0x10 
#define ATT_ERR_INSUFFICIENT_RESOURCES                    0x11 


#define UUID_SERVICE_GENERIC_ACCESS           0x1800 
#define UUID_SERVICE_GENERIC_ATT           0x1801 
#define UUID_IMMEDIATE_ALERT  0x1802	
#define UUID_LINK_LOSS        0x1803	
#define UUID_TX_POWER         0x1804	
#define UUID_SERVICE_DEVICE_INFO           0x180a 
#define UUID_SERVICE_BATTERY               0x180f 
#define UUID_SERVICE_HIDS                  0x1812 
#define UUID_GATT_PRIMARY_SERVICE          0x2800 
#define UUID_GATT_SECONDARY_SERVICE        0x2801 
#define UUID_GATT_INCLUDE                  0x2802 
#define UUID_GATT_CHARACTERISTIC           0x2803 
#define UUID_CHARACTERISTIC_EXTENDED_PROPERTIES   0x2900	
#define UUID_CHARACTERISTIC_USER_DESCRIPTION      0x2901	
#define UUID_CLIENT_CHARACTERISTIC_CONFIGURATION  0x2902	
#define UUID_SERVER_CHARACTERISTIC_CONFIGURATION  0x2903	
#define UUID_DEVICE_NAME                                        0x2a00
#define UUID_APPEARANCE                                         0x2a01
#define UUID_PERIPHERAL_PRIVACY_FLAG                            0x2a02
#define UUID_RECONNECTION_ADDRESS                               0x2a03
#define UUID_PREFERRED_PARAMETERS         0x2a04
#define UUID_SERVICE_CHANGED                                    0x2a05
#define UUID_ALERT_LEVEL                                        0x2a06
#define UUID_TX_POWER_LEVEL                                     0x2a07
#define UUID_DATE_TIME                                          0x2a08
#define UUID_BATTERY_LEVEL          0x2A19 
#define UUID_KEYBOARD_INPUT         0x2A22 
#define UUID_SYSTEM_ID              0x2A23 
#define UUID_SERIAL_NUMBER          0x2A25 
#define UUID_FIRMWARE               0x2A26 
#define UUID_MANUFACTURE_NAME               0x2A29
#define UUID_KEYBOARD_OUTPUT        0x2A32 
#define UUID_MOUSE_INPUT            0x2A33 
#define UUID_HID_INFO               0x2A4A 
#define UUID_REPORT_MAP             0x2A4B 
#define UUID_HID_CTRL_POINT         0x2A4C 
#define UUID_REPORT                 0x2A4D 
#define UUID_PROTOCOL_MODE          0x2A4E 

#define UUID_FMT_16BITS		1
#define UUID_FMT_128BITS	2

#define CP_BCST				1
#define CP_READ				2
#define CP_WR_NORSP		4
#define CP_WRITE			8
#define CP_NOTIFY			0x10
#define CP_INDICATE			0x20
#define CP_AUTH_WR			0x40
#define CP_EXTENDED		0x80


#define ISR_WAIT_TXEND		1
#define ISR_WAIT_RXSYNC	2
#define ISR_WAIT_RXDATA		3

#define STATE_WAIT_ADV			2
#define STATE_SCAN_REQ			3
#define STATE_SCAN_RES			4
#define STATE_WAIT_REQ			5
#define STATE_WAIT_RES			6
#define STATE_CONN_IND_TX		7
#define STATE_WAIT_CONN		8
#define STATE_MASTER_TX		9
#define STATE_MASTER_RX		10
#define STATE_SLAVE_RX			11
#define STATE_SLAVE_TX			12
#define STATE_TEST_TX			13
#define STATE_RXOK				14

#define CONN_ACTIVE				(1 << 0)
#define CONN_MASTER			(1 << 1)
#define CONN_LINK_MADE			(1 << 2)
#define CONN_RX_WINDOW		(1 << 3)
#define CONN_UPDATE_CHMAP	(1 << 4)
#define CONN_UPDATE_CONN		(1 << 5)
#define CONN_UPDATE_PHY		(1 << 6)
#define CONN_TERMINATE			(1 << 7)
#define CONN_ENC				(1 << 8)
#define CONN_START_ENC			(1 << 9)
#define CONN_ANCHOR			(1 << 10)

#define TYPE_ENC				0x10000

#define CMD_RX				1
#define CMD_SLEEP			2
#define CMD_SCAN_RSP		3
#define CMD_ADV				4
#define CMD_RX_ENC			5

typedef struct {
	byte io_cap;
	byte oob_flag;
	byte auth_req;
	byte keysize;
	byte init_kdist;
	byte res_kdist;
} smp_cap;


typedef struct {
	byte bdaddr[6];
	word adv_event_interval;
	int adv_interval;
	word scan_window;
	byte features[8];
	byte version[5];
	smp_cap smp;
	int flag;
	char pin[16];
	word mtu;
} ledevice;


typedef struct {
	// conn_ind packet, total 34 bytes
	byte own_addr[6];
	byte peer_addr[6];
	uint access;
	byte crcinit[3];
	byte win_size;
	word win_offset;
	word interval;
	word latency;
	word timeout;
	byte map[5];
	byte hopinc:5;
	byte sca:3;

	// connection information
	byte used_ch;
	byte head;
	byte hop;
	byte ch;
	word status;
	uint anchor;
	uint sync_ts;
	uint rxcnt;
	uint mic;
	byte *txptr;
	byte key[16];			// should be 32bit aligned 
	byte ltk[16];
	byte rand[16];
	byte rconfirm[16];
	byte rctr[5];
	byte tctr[5];
	byte uparam[9];
	byte mode;
	word evcnt;
	word instant;
	byte ivm[4];
	byte ivs[4];
	byte ediv[2];
	smp_cap smp;
	
} leconn;


typedef struct {
	word uuid;
	byte len;
	byte dat[30];
} att_record;

extern leconn *ct;
extern leconn conn;
extern ledevice dev;

// tmrtask *add_timeout_timer(uint timeout, void (*cb)(), int arg);
byte *tx_alloc(int len);
void tx_queue(int type, int len, byte *payload);
void le_send_l2cap(word cid, word len, byte *p);
void generate_sk(byte *skdm, byte *sdks);
uint le_crypt(int enc, byte *ctr, word header, byte *pkt);
void le_send_smp_encinfo();

