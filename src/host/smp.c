#include "le.h"

#if defined(CONFIG_BT_SMP)
void encryption_block(byte *blk, int ctr, byte ctr_hi)
{
	blk[0] = 1;
	PUTL(blk + 1, ctr);
	blk[5] = ctr_hi;
	memcpy(blk + 6, ct->ivm, 8);
}


//	c1 (k, r, preq, pres, iat, rat, ia, ra) = e(k, e(k, r XOR p1) XOR p2)
void function_c1(byte *key, byte *r, smp_cap *preq, smp_cap *pres, byte iat, byte rat, byte *ia, byte *ra, byte *out)
{
	byte p[32];
	
		// p1 = pres || preq || rat� || iat�
	p[0] = iat, p[1] = rat, p[2] = SMP_PAIRING_REQUEST;
	memcpy(p + 3, preq, 6);
	p[9] = SMP_PAIRING_RESPONSE;
	memcpy(p + 10, pres, 6);
	for(int i = 0;i < 16;i++)
		p[i] ^= r[i];
		// p2 = padding || ia || ra
	memcpy(p + 16, ra, 6);
	memcpy(p + 22, ia, 6);
	*(int*)(p + 28) = 0;
	aes_encrypt(AES_KEY_DWORD | AES_DATA_DWORD | AES_BIG_ENDIAN, key, p, 32);
	aes_result(out);
}

//	s1 (k, r1, r2) = e(k, e(k, r1 ||r2)
void function_s1(byte *key, byte *r1, byte *r2, byte *out)
{
	byte p[16];
	memcpy(p, r2, 8);
	memcpy(p + 8, r1, 8);
	aes_encrypt(AES_BIG_ENDIAN, key, p, 16);
	aes_result(out);
}

void test_aes()
{
	byte r[] = {0xE0,0x2E,0x70,0xC6,0x4E,0x27,0x88,0x63,0x0E,0x6F,0xAD,0x56,0x21,0xD5,0x83,0x57,};
	byte c1[] = {0x86,0x3B,0xF1,0xBE,0xC5,0x4D,0xA7,0xD2,0xEA,0x88,0x89,0x87,0xEF,0x3F,0x1E,0x1E};
	byte key[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	byte key2[] = {1, 2, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	smp_cap preq = {0x01,0x00,0x00,0x10,0x07,0x07};
	smp_cap pres = {0x03,0x00,0x00,0x08,0x00,0x05};
	byte ra[] = {0xB6,0xB5,0xB4,0xB3,0xB2,0xB1};
	byte ia[] = {0xA6,0xA5,0xA4,0xA3,0xA2,0xA1};
	byte r1[] = {0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x00};
	byte r2[] = {0x00,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01};
	byte s1[] = {0x62,0xa0,0x6d,0x79,0xae,0x16,0x42,0x5b,0x9b,0xf4,0xb0,0xe8,0xf0,0xe1,0x1f,0x9a};
	byte k[] = {0x99,0xAD,0x1B,0x52,0x26,0xA3,0x7E,0x3E,0x05,0x8E,0x3B,0x8E,0x27,0xC2,0xC6,0x66};
	byte cnt[] = {1,0,0,0,0};
	byte iv[] = {0x24,0xab,0xdc,0xba,0xbe,0xba,0xaf,0xde};
	byte p[] = {0x17,0x00,0x37,0x36,0x35,0x34,0x33,0x32,0x31,0x30,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51};
	byte enc[] = {0xF3,0x88,0x81,0xE7,0xBD,0x94,0xC9,0xC3,0x69,0xB9,0xA6,0x68,0x46,0xDD,0x47,0x86,0xAA,0x8C,0x39,0xCE,0x54,0x0D,0x0D,0xAE,0x3A,0xDC,0xDF,0x89,0xB9,0x60,0x88};
	byte out[16];
	int i;
	if(core_revision & 1) {
		function_c1(key, r, &preq, &pres, 1, 0, ia, ra, out);
		for(i = 0;i < 16;i++)
			if(out[i] != c1[i]) assert(1);
		function_s1(key2 + 2, r1, r2, out);
		for(i = 0;i < 16;i++)
			if(out[i] != s1[i]) assert(2);
		ct = &conn;
		memcpy(ct->key, k, 16);
		memcpy(ct->ivm, iv, 8);
		if(le_crypt(1, cnt, sizeof(p) << 8 | 2, p) != GETL(enc + sizeof(enc) - 4)) assert(3); 
		for(i = 0;i < sizeof(p);i++)
			if(p[i] != enc[i]) assert(4);
		success();
        }
        while(1);
}


void le_send_smp(byte op, word len, byte *p)
{
	p[4] = op;
	le_send_l2cap(LE_L2CAP_CID_SMP, len + 1, p);
}

void le_send_smp_encinfo()
{
	byte *p;
	p = malloc(21);
	memcpy(p + 5, ct->ltk, 16);
	le_send_smp(SMP_ENCRYPTION_INFORMATION, 16, p);

	p = malloc(15);
	memcpy(p + 5, ct->ediv, 2);
	memcpy(p + 7, ct->rand, 8);
	le_send_smp(SMP_MASTER_IDENTIFICATION, 10, p);

	p = malloc(21);
	memcpy(p + 5, ct->ltk, 16);
	le_send_smp(SMP_IDENTITY_INFORMATION, 16, p);

	p = malloc(12);
	p[5] = 0;
	memcpy(p + 6, dev.bdaddr, 6);
	le_send_smp(SMP_IDENTITY_ADDRESS_INFORMATION, 7, p);
	
}

void le_parse_smp(byte *rxp)
{
	byte *txp, buf[16];
	if(!(txp = malloc(37))) return;
	switch(rxp[6]) {
	case SMP_PAIRING_REQUEST:
		memcpy(&ct->smp, rxp + 7, 6);
		memcpy(txp + 5, &dev.smp, 6);
		le_send_smp(SMP_PAIRING_RESPONSE, 6, txp);
		break;
	case SMP_PAIRING_CONFIRM:
		memcpy(ct->rconfirm, rxp + 7, 16);
		rand(ct->rand, 16);
		function_c1(ct->key, ct->rand, &ct->smp, &dev.smp, 1, 0, ct->peer_addr, dev.bdaddr, txp + 5);
		le_send_smp(SMP_PAIRING_CONFIRM, 16, txp);
		break;
	case SMP_PAIRING_RANDOM:
		function_c1(ct->key, rxp + 7, &ct->smp, &dev.smp, 1, 0, ct->peer_addr, dev.bdaddr, buf);
		if(memcmp(buf, ct->rconfirm, 16)) {
			txp[5] = PAIRING_FAILED_CONFIRM_VALUE_FAILED;
			le_send_smp(SMP_PAIRING_FAILED, 1, txp);
		} else {
			function_s1(ct->key, ct->rand, rxp + 7, ct->ltk);
			memcpy(txp + 5, ct->rand, 16);
			le_send_smp(SMP_PAIRING_RANDOM, 16, txp);
		}
	default:
		free(txp);
	}
}
#endif
