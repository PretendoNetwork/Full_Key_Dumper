#include "wiiu/symbols.h"
#include "wiiu/debugger.h"
#include "wiiu/iosu_kernel.h"
#include "wiiu/patcher.h"

void printHex(const char *title, uint8_t *ptr, size_t len) {

	WiiU::Debugger::Logf("%20s: ", title);
	for(size_t i = 0; i < len; i++) {
		WiiU::Debugger::Logf("%02x", ptr[i]);
	}
	WiiU::Debugger::Log("\n");

}

extern "C" void kern_write(void *addr, uint32_t value);
extern "C" int __entry(int argc, char **argv)
{

	/* Initialize symbols and debugger */
	WiiU::Symbols::LoadWiiUSymbols();
	WiiU::Debugger::Start();

	/* Do the kernel exploit */
	WiiU::IOSU_Kernel::Exploit();

	FSInit();

	char outSdPath[0x300];
	char mountPath[128];
	FSClient *fsClient = (FSClient*)malloc(sizeof(FSClient));
	FSCmdBlock *fsCmdBlock = (FSCmdBlock*)malloc(sizeof(FSCmdBlock));

	FSAddClient(fsClient, -1);
	FSInitCmdBlock(fsCmdBlock);

	/* Mount the SD Card */
	FSGetMountSource(fsClient, fsCmdBlock, 0, outSdPath, -1);
	FSMount(fsClient, fsCmdBlock, outSdPath, mountPath, 128, -1);

	int otp_handle = -1;
	int boss_handle = -1;
	int idbe_handle = -1;

	/* It crashes when using the MEM1 addr */
	uint8_t *mem2_data = (uint8_t*)memalign(0x40, 0x1000);
	DCInvalidateRange((void*)0xF5FFF000, 0x800);
	memcpy(mem2_data, (void*)0xF5FFF000, 0x800);

	/* Write the OTP */
	FSOpenFile(fsClient, fsCmdBlock, "/vol/external01/otp.bin", "wb", &otp_handle, -1);
	FSWriteFile(fsClient, fsCmdBlock, mem2_data, 0x400, 1, otp_handle, 0, -1);
	FSCloseFile(fsClient, fsCmdBlock, otp_handle, -1);

	/* Write the BOSS keys */
	FSOpenFile(fsClient, fsCmdBlock, "/vol/external01/boss_keys.bin", "wb", &boss_handle, -1);
	FSWriteFile(fsClient, fsCmdBlock, mem2_data + 0x400, 0x60, 1, boss_handle, 0, -1);
	FSCloseFile(fsClient, fsCmdBlock, boss_handle, -1);

	/* Log the BOSS keys */
	uint8_t *boss_data_key = mem2_data + 0x400;
	uint8_t *boss_pushmore_key = mem2_data + 0x410;
	uint8_t *boss_hmac_key = mem2_data + 0x420;
	
	char *boss_data_key_str = (char*)calloc(4, 6);
	memcpy(boss_data_key_str, boss_data_key, 16);
	WiiU::Debugger::Logf("BOSS Data Key: %16s\n", boss_data_key_str);
	WiiU::Debugger::Logf("BOSS HMAC Key: %64s\n\n", boss_hmac_key);
	printHex("BOSS Pushmore Key", boss_pushmore_key, 0x10);
	
	/* Load "nn_idbe.rpl", then get the relocated address of the keys from the instructions that load the pointer to the keys and IVs */
	uint32_t idbe_rpl;
	uint32_t idbe_ptr;
	OSDynLoad_Acquire("nn_idbe.rpl", &idbe_rpl);
	OSDynLoad_FindExport(idbe_rpl, 0, "DestroyDownloadContext__Q2_2nn4idbeFPQ3_2nn4idbe15DownloadContext", (void**)&idbe_ptr);

	uint8_t *data = (uint8_t*)(idbe_ptr - 0x39C + 0x934);
	uint32_t *lookupData = (uint32_t*)malloc(0x18);
	memcpy(lookupData, data, 0x18);
	uint32_t idbe_keys_ptr = ((lookupData[0] & 0xffff) << 16) | (lookupData[5] & 0xffff);
	uint8_t *idbe_keys = (uint8_t*)memalign(0x40, 0x50);
	memcpy(idbe_keys, (uint8_t*)idbe_keys_ptr, 0x50);

	/* Write the IDBE keys */
	FSOpenFile(fsClient, fsCmdBlock, "/vol/external01/idbe_keys.bin", "wb", &idbe_handle, -1);
	FSWriteFile(fsClient, fsCmdBlock, idbe_keys, 0x50, 1, idbe_handle, 0, -1);
	FSCloseFile(fsClient, fsCmdBlock, idbe_handle, -1);

	/* Log the IDBE keys */
	printHex("IDBE Key", idbe_keys + 0x00, 0x10);
	printHex("IDBE IV0", idbe_keys + 0x10, 0x10);
	printHex("IDBE IV1", idbe_keys + 0x20, 0x10);
	printHex("IDBE IV2", idbe_keys + 0x30, 0x10);
	printHex("IDBE IV3", idbe_keys + 0x40, 0x10);

	return RETURN_TO_HBL;
}
