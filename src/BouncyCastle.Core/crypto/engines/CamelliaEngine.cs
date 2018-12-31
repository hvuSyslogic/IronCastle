using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	
	/// <summary>
	/// Camellia - based on RFC 3713.
	/// </summary>
	public class CamelliaEngine : BlockCipher
	{
		private bool initialised = false;
		private bool _keyIs128;

		private const int BLOCK_SIZE = 16;
		private const int MASK8 = 0xff;

		private int[] subkey = new int[24 * 4];
		private int[] kw = new int[4 * 2]; // for whitening
		private int[] ke = new int[6 * 2]; // for FL and FL^(-1)
		private int[] state = new int[4]; // for encryption and decryption

		private static readonly int[] SIGMA = new int[] {unchecked((int)0xa09e667f), 0x3bcc908b, unchecked((int)0xb67ae858), 0x4caa73b2, unchecked((int)0xc6ef372f), unchecked((int)0xe94f82be), 0x54ff53a5, unchecked((int)0xf1d36f1c), 0x10e527fa, unchecked((int)0xde682d1d), unchecked((int)0xb05688c2), unchecked((int)0xb3e6c1fd)};

		/*
		*
		* S-box data
		*
		*/
		private static readonly int[] SBOX1_1110 = new int[] {0x70707000, unchecked((int)0x82828200), 0x2c2c2c00, unchecked((int)0xececec00), unchecked((int)0xb3b3b300), 0x27272700, unchecked((int)0xc0c0c000), unchecked((int)0xe5e5e500), unchecked((int)0xe4e4e400), unchecked((int)0x85858500), 0x57575700, 0x35353500, unchecked((int)0xeaeaea00), 0x0c0c0c00, unchecked((int)0xaeaeae00), 0x41414100, 0x23232300, unchecked((int)0xefefef00), 0x6b6b6b00, unchecked((int)0x93939300), 0x45454500, 0x19191900, unchecked((int)0xa5a5a500), 0x21212100, unchecked((int)0xededed00), 0x0e0e0e00, 0x4f4f4f00, 0x4e4e4e00, 0x1d1d1d00, 0x65656500, unchecked((int)0x92929200), unchecked((int)0xbdbdbd00), unchecked((int)0x86868600), unchecked((int)0xb8b8b800), unchecked((int)0xafafaf00), unchecked((int)0x8f8f8f00), 0x7c7c7c00, unchecked((int)0xebebeb00), 0x1f1f1f00, unchecked((int)0xcecece00), 0x3e3e3e00, 0x30303000, unchecked((int)0xdcdcdc00), 0x5f5f5f00, 0x5e5e5e00, unchecked((int)0xc5c5c500), 0x0b0b0b00, 0x1a1a1a00, unchecked((int)0xa6a6a600), unchecked((int)0xe1e1e100), 0x39393900, unchecked((int)0xcacaca00), unchecked((int)0xd5d5d500), 0x47474700, 0x5d5d5d00, 0x3d3d3d00, unchecked((int)0xd9d9d900), 0x01010100, 0x5a5a5a00, unchecked((int)0xd6d6d600), 0x51515100, 0x56565600, 0x6c6c6c00, 0x4d4d4d00, unchecked((int)0x8b8b8b00), 0x0d0d0d00, unchecked((int)0x9a9a9a00), 0x66666600, unchecked((int)0xfbfbfb00), unchecked((int)0xcccccc00), unchecked((int)0xb0b0b000), 0x2d2d2d00, 0x74747400, 0x12121200, 0x2b2b2b00, 0x20202000, unchecked((int)0xf0f0f000), unchecked((int)0xb1b1b100), unchecked((int)0x84848400), unchecked((int)0x99999900), unchecked((int)0xdfdfdf00), 0x4c4c4c00, unchecked((int)0xcbcbcb00), unchecked((int)0xc2c2c200), 0x34343400, 0x7e7e7e00, 0x76767600, 0x05050500, 0x6d6d6d00, unchecked((int)0xb7b7b700), unchecked((int)0xa9a9a900), 0x31313100, unchecked((int)0xd1d1d100), 0x17171700, 0x04040400, unchecked((int)0xd7d7d700), 0x14141400, 0x58585800, 0x3a3a3a00, 0x61616100, unchecked((int)0xdedede00), 0x1b1b1b00, 0x11111100, 0x1c1c1c00, 0x32323200, 0x0f0f0f00, unchecked((int)0x9c9c9c00), 0x16161600, 0x53535300, 0x18181800, unchecked((int)0xf2f2f200), 0x22222200, unchecked((int)0xfefefe00), 0x44444400, unchecked((int)0xcfcfcf00), unchecked((int)0xb2b2b200), unchecked((int)0xc3c3c300), unchecked((int)0xb5b5b500), 0x7a7a7a00, unchecked((int)0x91919100), 0x24242400, 0x08080800, unchecked((int)0xe8e8e800), unchecked((int)0xa8a8a800), 0x60606000, unchecked((int)0xfcfcfc00), 0x69696900, 0x50505000, unchecked((int)0xaaaaaa00), unchecked((int)0xd0d0d000), unchecked((int)0xa0a0a000), 0x7d7d7d00, unchecked((int)0xa1a1a100), unchecked((int)0x89898900), 0x62626200, unchecked((int)0x97979700), 0x54545400, 0x5b5b5b00, 0x1e1e1e00, unchecked((int)0x95959500), unchecked((int)0xe0e0e000), unchecked((int)0xffffff00), 0x64646400, unchecked((int)0xd2d2d200), 0x10101000, unchecked((int)0xc4c4c400), 0x00000000, 0x48484800, unchecked((int)0xa3a3a300), unchecked((int)0xf7f7f700), 0x75757500, unchecked((int)0xdbdbdb00), unchecked((int)0x8a8a8a00), 0x03030300, unchecked((int)0xe6e6e600), unchecked((int)0xdadada00), 0x09090900, 0x3f3f3f00, unchecked((int)0xdddddd00), unchecked((int)0x94949400), unchecked((int)0x87878700), 0x5c5c5c00, unchecked((int)0x83838300), 0x02020200, unchecked((int)0xcdcdcd00), 0x4a4a4a00, unchecked((int)0x90909000), 0x33333300, 0x73737300, 0x67676700, unchecked((int)0xf6f6f600), unchecked((int)0xf3f3f300), unchecked((int)0x9d9d9d00), 0x7f7f7f00, unchecked((int)0xbfbfbf00), unchecked((int)0xe2e2e200), 0x52525200, unchecked((int)0x9b9b9b00), unchecked((int)0xd8d8d800), 0x26262600, unchecked((int)0xc8c8c800), 0x37373700, unchecked((int)0xc6c6c600), 0x3b3b3b00, unchecked((int)0x81818100), unchecked((int)0x96969600), 0x6f6f6f00, 0x4b4b4b00, 0x13131300, unchecked((int)0xbebebe00), 0x63636300, 0x2e2e2e00, unchecked((int)0xe9e9e900), 0x79797900, unchecked((int)0xa7a7a700), unchecked((int)0x8c8c8c00), unchecked((int)0x9f9f9f00), 0x6e6e6e00, unchecked((int)0xbcbcbc00), unchecked((int)0x8e8e8e00), 0x29292900, unchecked((int)0xf5f5f500), unchecked((int)0xf9f9f900), unchecked((int)0xb6b6b600), 0x2f2f2f00, unchecked((int)0xfdfdfd00), unchecked((int)0xb4b4b400), 0x59595900, 0x78787800, unchecked((int)0x98989800), 0x06060600, 0x6a6a6a00, unchecked((int)0xe7e7e700), 0x46464600, 0x71717100, unchecked((int)0xbababa00), unchecked((int)0xd4d4d400), 0x25252500, unchecked((int)0xababab00), 0x42424200, unchecked((int)0x88888800), unchecked((int)0xa2a2a200), unchecked((int)0x8d8d8d00), unchecked((int)0xfafafa00), 0x72727200, 0x07070700, unchecked((int)0xb9b9b900), 0x55555500, unchecked((int)0xf8f8f800), unchecked((int)0xeeeeee00), unchecked((int)0xacacac00), 0x0a0a0a00, 0x36363600, 0x49494900, 0x2a2a2a00, 0x68686800, 0x3c3c3c00, 0x38383800, unchecked((int)0xf1f1f100), unchecked((int)0xa4a4a400), 0x40404000, 0x28282800, unchecked((int)0xd3d3d300), 0x7b7b7b00, unchecked((int)0xbbbbbb00), unchecked((int)0xc9c9c900), 0x43434300, unchecked((int)0xc1c1c100), 0x15151500, unchecked((int)0xe3e3e300), unchecked((int)0xadadad00), unchecked((int)0xf4f4f400), 0x77777700, unchecked((int)0xc7c7c700), unchecked((int)0x80808000), unchecked((int)0x9e9e9e00)};

		private static readonly int[] SBOX4_4404 = new int[] {0x70700070, 0x2c2c002c, unchecked((int)0xb3b300b3), unchecked((int)0xc0c000c0), unchecked((int)0xe4e400e4), 0x57570057, unchecked((int)0xeaea00ea), unchecked((int)0xaeae00ae), 0x23230023, 0x6b6b006b, 0x45450045, unchecked((int)0xa5a500a5), unchecked((int)0xeded00ed), 0x4f4f004f, 0x1d1d001d, unchecked((int)0x92920092), unchecked((int)0x86860086), unchecked((int)0xafaf00af), 0x7c7c007c, 0x1f1f001f, 0x3e3e003e, unchecked((int)0xdcdc00dc), 0x5e5e005e, 0x0b0b000b, unchecked((int)0xa6a600a6), 0x39390039, unchecked((int)0xd5d500d5), 0x5d5d005d, unchecked((int)0xd9d900d9), 0x5a5a005a, 0x51510051, 0x6c6c006c, unchecked((int)0x8b8b008b), unchecked((int)0x9a9a009a), unchecked((int)0xfbfb00fb), unchecked((int)0xb0b000b0), 0x74740074, 0x2b2b002b, unchecked((int)0xf0f000f0), unchecked((int)0x84840084), unchecked((int)0xdfdf00df), unchecked((int)0xcbcb00cb), 0x34340034, 0x76760076, 0x6d6d006d, unchecked((int)0xa9a900a9), unchecked((int)0xd1d100d1), 0x04040004, 0x14140014, 0x3a3a003a, unchecked((int)0xdede00de), 0x11110011, 0x32320032, unchecked((int)0x9c9c009c), 0x53530053, unchecked((int)0xf2f200f2), unchecked((int)0xfefe00fe), unchecked((int)0xcfcf00cf), unchecked((int)0xc3c300c3), 0x7a7a007a, 0x24240024, unchecked((int)0xe8e800e8), 0x60600060, 0x69690069, unchecked((int)0xaaaa00aa), unchecked((int)0xa0a000a0), unchecked((int)0xa1a100a1), 0x62620062, 0x54540054, 0x1e1e001e, unchecked((int)0xe0e000e0), 0x64640064, 0x10100010, 0x00000000, unchecked((int)0xa3a300a3), 0x75750075, unchecked((int)0x8a8a008a), unchecked((int)0xe6e600e6), 0x09090009, unchecked((int)0xdddd00dd), unchecked((int)0x87870087), unchecked((int)0x83830083), unchecked((int)0xcdcd00cd), unchecked((int)0x90900090), 0x73730073, unchecked((int)0xf6f600f6), unchecked((int)0x9d9d009d), unchecked((int)0xbfbf00bf), 0x52520052, unchecked((int)0xd8d800d8), unchecked((int)0xc8c800c8), unchecked((int)0xc6c600c6), unchecked((int)0x81810081), 0x6f6f006f, 0x13130013, 0x63630063, unchecked((int)0xe9e900e9), unchecked((int)0xa7a700a7), unchecked((int)0x9f9f009f), unchecked((int)0xbcbc00bc), 0x29290029, unchecked((int)0xf9f900f9), 0x2f2f002f, unchecked((int)0xb4b400b4), 0x78780078, 0x06060006, unchecked((int)0xe7e700e7), 0x71710071, unchecked((int)0xd4d400d4), unchecked((int)0xabab00ab), unchecked((int)0x88880088), unchecked((int)0x8d8d008d), 0x72720072, unchecked((int)0xb9b900b9), unchecked((int)0xf8f800f8), unchecked((int)0xacac00ac), 0x36360036, 0x2a2a002a, 0x3c3c003c, unchecked((int)0xf1f100f1), 0x40400040, unchecked((int)0xd3d300d3), unchecked((int)0xbbbb00bb), 0x43430043, 0x15150015, unchecked((int)0xadad00ad), 0x77770077, unchecked((int)0x80800080), unchecked((int)0x82820082), unchecked((int)0xecec00ec), 0x27270027, unchecked((int)0xe5e500e5), unchecked((int)0x85850085), 0x35350035, 0x0c0c000c, 0x41410041, unchecked((int)0xefef00ef), unchecked((int)0x93930093), 0x19190019, 0x21210021, 0x0e0e000e, 0x4e4e004e, 0x65650065, unchecked((int)0xbdbd00bd), unchecked((int)0xb8b800b8), unchecked((int)0x8f8f008f), unchecked((int)0xebeb00eb), unchecked((int)0xcece00ce), 0x30300030, 0x5f5f005f, unchecked((int)0xc5c500c5), 0x1a1a001a, unchecked((int)0xe1e100e1), unchecked((int)0xcaca00ca), 0x47470047, 0x3d3d003d, 0x01010001, unchecked((int)0xd6d600d6), 0x56560056, 0x4d4d004d, 0x0d0d000d, 0x66660066, unchecked((int)0xcccc00cc), 0x2d2d002d, 0x12120012, 0x20200020, unchecked((int)0xb1b100b1), unchecked((int)0x99990099), 0x4c4c004c, unchecked((int)0xc2c200c2), 0x7e7e007e, 0x05050005, unchecked((int)0xb7b700b7), 0x31310031, 0x17170017, unchecked((int)0xd7d700d7), 0x58580058, 0x61610061, 0x1b1b001b, 0x1c1c001c, 0x0f0f000f, 0x16160016, 0x18180018, 0x22220022, 0x44440044, unchecked((int)0xb2b200b2), unchecked((int)0xb5b500b5), unchecked((int)0x91910091), 0x08080008, unchecked((int)0xa8a800a8), unchecked((int)0xfcfc00fc), 0x50500050, unchecked((int)0xd0d000d0), 0x7d7d007d, unchecked((int)0x89890089), unchecked((int)0x97970097), 0x5b5b005b, unchecked((int)0x95950095), unchecked((int)0xffff00ff), unchecked((int)0xd2d200d2), unchecked((int)0xc4c400c4), 0x48480048, unchecked((int)0xf7f700f7), unchecked((int)0xdbdb00db), 0x03030003, unchecked((int)0xdada00da), 0x3f3f003f, unchecked((int)0x94940094), 0x5c5c005c, 0x02020002, 0x4a4a004a, 0x33330033, 0x67670067, unchecked((int)0xf3f300f3), 0x7f7f007f, unchecked((int)0xe2e200e2), unchecked((int)0x9b9b009b), 0x26260026, 0x37370037, 0x3b3b003b, unchecked((int)0x96960096), 0x4b4b004b, unchecked((int)0xbebe00be), 0x2e2e002e, 0x79790079, unchecked((int)0x8c8c008c), 0x6e6e006e, unchecked((int)0x8e8e008e), unchecked((int)0xf5f500f5), unchecked((int)0xb6b600b6), unchecked((int)0xfdfd00fd), 0x59590059, unchecked((int)0x98980098), 0x6a6a006a, 0x46460046, unchecked((int)0xbaba00ba), 0x25250025, 0x42420042, unchecked((int)0xa2a200a2), unchecked((int)0xfafa00fa), 0x07070007, 0x55550055, unchecked((int)0xeeee00ee), 0x0a0a000a, 0x49490049, 0x68680068, 0x38380038, unchecked((int)0xa4a400a4), 0x28280028, 0x7b7b007b, unchecked((int)0xc9c900c9), unchecked((int)0xc1c100c1), unchecked((int)0xe3e300e3), unchecked((int)0xf4f400f4), unchecked((int)0xc7c700c7), unchecked((int)0x9e9e009e)};

		private static readonly int[] SBOX2_0222 = new int[] {0x00e0e0e0, 0x00050505, 0x00585858, 0x00d9d9d9, 0x00676767, 0x004e4e4e, 0x00818181, 0x00cbcbcb, 0x00c9c9c9, 0x000b0b0b, 0x00aeaeae, 0x006a6a6a, 0x00d5d5d5, 0x00181818, 0x005d5d5d, 0x00828282, 0x00464646, 0x00dfdfdf, 0x00d6d6d6, 0x00272727, 0x008a8a8a, 0x00323232, 0x004b4b4b, 0x00424242, 0x00dbdbdb, 0x001c1c1c, 0x009e9e9e, 0x009c9c9c, 0x003a3a3a, 0x00cacaca, 0x00252525, 0x007b7b7b, 0x000d0d0d, 0x00717171, 0x005f5f5f, 0x001f1f1f, 0x00f8f8f8, 0x00d7d7d7, 0x003e3e3e, 0x009d9d9d, 0x007c7c7c, 0x00606060, 0x00b9b9b9, 0x00bebebe, 0x00bcbcbc, 0x008b8b8b, 0x00161616, 0x00343434, 0x004d4d4d, 0x00c3c3c3, 0x00727272, 0x00959595, 0x00ababab, 0x008e8e8e, 0x00bababa, 0x007a7a7a, 0x00b3b3b3, 0x00020202, 0x00b4b4b4, 0x00adadad, 0x00a2a2a2, 0x00acacac, 0x00d8d8d8, 0x009a9a9a, 0x00171717, 0x001a1a1a, 0x00353535, 0x00cccccc, 0x00f7f7f7, 0x00999999, 0x00616161, 0x005a5a5a, 0x00e8e8e8, 0x00242424, 0x00565656, 0x00404040, 0x00e1e1e1, 0x00636363, 0x00090909, 0x00333333, 0x00bfbfbf, 0x00989898, 0x00979797, 0x00858585, 0x00686868, 0x00fcfcfc, 0x00ececec, 0x000a0a0a, 0x00dadada, 0x006f6f6f, 0x00535353, 0x00626262, 0x00a3a3a3, 0x002e2e2e, 0x00080808, 0x00afafaf, 0x00282828, 0x00b0b0b0, 0x00747474, 0x00c2c2c2, 0x00bdbdbd, 0x00363636, 0x00222222, 0x00383838, 0x00646464, 0x001e1e1e, 0x00393939, 0x002c2c2c, 0x00a6a6a6, 0x00303030, 0x00e5e5e5, 0x00444444, 0x00fdfdfd, 0x00888888, 0x009f9f9f, 0x00656565, 0x00878787, 0x006b6b6b, 0x00f4f4f4, 0x00232323, 0x00484848, 0x00101010, 0x00d1d1d1, 0x00515151, 0x00c0c0c0, 0x00f9f9f9, 0x00d2d2d2, 0x00a0a0a0, 0x00555555, 0x00a1a1a1, 0x00414141, 0x00fafafa, 0x00434343, 0x00131313, 0x00c4c4c4, 0x002f2f2f, 0x00a8a8a8, 0x00b6b6b6, 0x003c3c3c, 0x002b2b2b, 0x00c1c1c1, 0x00ffffff, 0x00c8c8c8, 0x00a5a5a5, 0x00202020, 0x00898989, 0x00000000, 0x00909090, 0x00474747, 0x00efefef, 0x00eaeaea, 0x00b7b7b7, 0x00151515, 0x00060606, 0x00cdcdcd, 0x00b5b5b5, 0x00121212, 0x007e7e7e, 0x00bbbbbb, 0x00292929, 0x000f0f0f, 0x00b8b8b8, 0x00070707, 0x00040404, 0x009b9b9b, 0x00949494, 0x00212121, 0x00666666, 0x00e6e6e6, 0x00cecece, 0x00ededed, 0x00e7e7e7, 0x003b3b3b, 0x00fefefe, 0x007f7f7f, 0x00c5c5c5, 0x00a4a4a4, 0x00373737, 0x00b1b1b1, 0x004c4c4c, 0x00919191, 0x006e6e6e, 0x008d8d8d, 0x00767676, 0x00030303, 0x002d2d2d, 0x00dedede, 0x00969696, 0x00262626, 0x007d7d7d, 0x00c6c6c6, 0x005c5c5c, 0x00d3d3d3, 0x00f2f2f2, 0x004f4f4f, 0x00191919, 0x003f3f3f, 0x00dcdcdc, 0x00797979, 0x001d1d1d, 0x00525252, 0x00ebebeb, 0x00f3f3f3, 0x006d6d6d, 0x005e5e5e, 0x00fbfbfb, 0x00696969, 0x00b2b2b2, 0x00f0f0f0, 0x00313131, 0x000c0c0c, 0x00d4d4d4, 0x00cfcfcf, 0x008c8c8c, 0x00e2e2e2, 0x00757575, 0x00a9a9a9, 0x004a4a4a, 0x00575757, 0x00848484, 0x00111111, 0x00454545, 0x001b1b1b, 0x00f5f5f5, 0x00e4e4e4, 0x000e0e0e, 0x00737373, 0x00aaaaaa, 0x00f1f1f1, 0x00dddddd, 0x00595959, 0x00141414, 0x006c6c6c, 0x00929292, 0x00545454, 0x00d0d0d0, 0x00787878, 0x00707070, 0x00e3e3e3, 0x00494949, 0x00808080, 0x00505050, 0x00a7a7a7, 0x00f6f6f6, 0x00777777, 0x00939393, 0x00868686, 0x00838383, 0x002a2a2a, 0x00c7c7c7, 0x005b5b5b, 0x00e9e9e9, 0x00eeeeee, 0x008f8f8f, 0x00010101, 0x003d3d3d};

		private static readonly int[] SBOX3_3033 = new int[] {0x38003838, 0x41004141, 0x16001616, 0x76007676, unchecked((int)0xd900d9d9), unchecked((int)0x93009393), 0x60006060, unchecked((int)0xf200f2f2), 0x72007272, unchecked((int)0xc200c2c2), unchecked((int)0xab00abab), unchecked((int)0x9a009a9a), 0x75007575, 0x06000606, 0x57005757, unchecked((int)0xa000a0a0), unchecked((int)0x91009191), unchecked((int)0xf700f7f7), unchecked((int)0xb500b5b5), unchecked((int)0xc900c9c9), unchecked((int)0xa200a2a2), unchecked((int)0x8c008c8c), unchecked((int)0xd200d2d2), unchecked((int)0x90009090), unchecked((int)0xf600f6f6), 0x07000707, unchecked((int)0xa700a7a7), 0x27002727, unchecked((int)0x8e008e8e), unchecked((int)0xb200b2b2), 0x49004949, unchecked((int)0xde00dede), 0x43004343, 0x5c005c5c, unchecked((int)0xd700d7d7), unchecked((int)0xc700c7c7), 0x3e003e3e, unchecked((int)0xf500f5f5), unchecked((int)0x8f008f8f), 0x67006767, 0x1f001f1f, 0x18001818, 0x6e006e6e, unchecked((int)0xaf00afaf), 0x2f002f2f, unchecked((int)0xe200e2e2), unchecked((int)0x85008585), 0x0d000d0d, 0x53005353, unchecked((int)0xf000f0f0), unchecked((int)0x9c009c9c), 0x65006565, unchecked((int)0xea00eaea), unchecked((int)0xa300a3a3), unchecked((int)0xae00aeae), unchecked((int)0x9e009e9e), unchecked((int)0xec00ecec), unchecked((int)0x80008080), 0x2d002d2d, 0x6b006b6b, unchecked((int)0xa800a8a8), 0x2b002b2b, 0x36003636, unchecked((int)0xa600a6a6), unchecked((int)0xc500c5c5), unchecked((int)0x86008686), 0x4d004d4d, 0x33003333, unchecked((int)0xfd00fdfd), 0x66006666, 0x58005858, unchecked((int)0x96009696), 0x3a003a3a, 0x09000909, unchecked((int)0x95009595), 0x10001010, 0x78007878, unchecked((int)0xd800d8d8), 0x42004242, unchecked((int)0xcc00cccc), unchecked((int)0xef00efef), 0x26002626, unchecked((int)0xe500e5e5), 0x61006161, 0x1a001a1a, 0x3f003f3f, 0x3b003b3b, unchecked((int)0x82008282), unchecked((int)0xb600b6b6), unchecked((int)0xdb00dbdb), unchecked((int)0xd400d4d4), unchecked((int)0x98009898), unchecked((int)0xe800e8e8), unchecked((int)0x8b008b8b), 0x02000202, unchecked((int)0xeb00ebeb), 0x0a000a0a, 0x2c002c2c, 0x1d001d1d, unchecked((int)0xb000b0b0), 0x6f006f6f, unchecked((int)0x8d008d8d), unchecked((int)0x88008888), 0x0e000e0e, 0x19001919, unchecked((int)0x87008787), 0x4e004e4e, 0x0b000b0b, unchecked((int)0xa900a9a9), 0x0c000c0c, 0x79007979, 0x11001111, 0x7f007f7f, 0x22002222, unchecked((int)0xe700e7e7), 0x59005959, unchecked((int)0xe100e1e1), unchecked((int)0xda00dada), 0x3d003d3d, unchecked((int)0xc800c8c8), 0x12001212, 0x04000404, 0x74007474, 0x54005454, 0x30003030, 0x7e007e7e, unchecked((int)0xb400b4b4), 0x28002828, 0x55005555, 0x68006868, 0x50005050, unchecked((int)0xbe00bebe), unchecked((int)0xd000d0d0), unchecked((int)0xc400c4c4), 0x31003131, unchecked((int)0xcb00cbcb), 0x2a002a2a, unchecked((int)0xad00adad), 0x0f000f0f, unchecked((int)0xca00caca), 0x70007070, unchecked((int)0xff00ffff), 0x32003232, 0x69006969, 0x08000808, 0x62006262, 0x00000000, 0x24002424, unchecked((int)0xd100d1d1), unchecked((int)0xfb00fbfb), unchecked((int)0xba00baba), unchecked((int)0xed00eded), 0x45004545, unchecked((int)0x81008181), 0x73007373, 0x6d006d6d, unchecked((int)0x84008484), unchecked((int)0x9f009f9f), unchecked((int)0xee00eeee), 0x4a004a4a, unchecked((int)0xc300c3c3), 0x2e002e2e, unchecked((int)0xc100c1c1), 0x01000101, unchecked((int)0xe600e6e6), 0x25002525, 0x48004848, unchecked((int)0x99009999), unchecked((int)0xb900b9b9), unchecked((int)0xb300b3b3), 0x7b007b7b, unchecked((int)0xf900f9f9), unchecked((int)0xce00cece), unchecked((int)0xbf00bfbf), unchecked((int)0xdf00dfdf), 0x71007171, 0x29002929, unchecked((int)0xcd00cdcd), 0x6c006c6c, 0x13001313, 0x64006464, unchecked((int)0x9b009b9b), 0x63006363, unchecked((int)0x9d009d9d), unchecked((int)0xc000c0c0), 0x4b004b4b, unchecked((int)0xb700b7b7), unchecked((int)0xa500a5a5), unchecked((int)0x89008989), 0x5f005f5f, unchecked((int)0xb100b1b1), 0x17001717, unchecked((int)0xf400f4f4), unchecked((int)0xbc00bcbc), unchecked((int)0xd300d3d3), 0x46004646, unchecked((int)0xcf00cfcf), 0x37003737, 0x5e005e5e, 0x47004747, unchecked((int)0x94009494), unchecked((int)0xfa00fafa), unchecked((int)0xfc00fcfc), 0x5b005b5b, unchecked((int)0x97009797), unchecked((int)0xfe00fefe), 0x5a005a5a, unchecked((int)0xac00acac), 0x3c003c3c, 0x4c004c4c, 0x03000303, 0x35003535, unchecked((int)0xf300f3f3), 0x23002323, unchecked((int)0xb800b8b8), 0x5d005d5d, 0x6a006a6a, unchecked((int)0x92009292), unchecked((int)0xd500d5d5), 0x21002121, 0x44004444, 0x51005151, unchecked((int)0xc600c6c6), 0x7d007d7d, 0x39003939, unchecked((int)0x83008383), unchecked((int)0xdc00dcdc), unchecked((int)0xaa00aaaa), 0x7c007c7c, 0x77007777, 0x56005656, 0x05000505, 0x1b001b1b, unchecked((int)0xa400a4a4), 0x15001515, 0x34003434, 0x1e001e1e, 0x1c001c1c, unchecked((int)0xf800f8f8), 0x52005252, 0x20002020, 0x14001414, unchecked((int)0xe900e9e9), unchecked((int)0xbd00bdbd), unchecked((int)0xdd00dddd), unchecked((int)0xe400e4e4), unchecked((int)0xa100a1a1), unchecked((int)0xe000e0e0), unchecked((int)0x8a008a8a), unchecked((int)0xf100f1f1), unchecked((int)0xd600d6d6), 0x7a007a7a, unchecked((int)0xbb00bbbb), unchecked((int)0xe300e3e3), 0x40004040, 0x4f004f4f};

		private static int rightRotate(int x, int s)
		{
			return (((int)((uint)(x) >> (s))) + ((x) << (32 - s)));
		}

		private static int leftRotate(int x, int s)
		{
			return ((x) << (s)) + ((int)((uint)(x) >> (32 - s)));
		}

		private static void roldq(int rot, int[] ki, int ioff, int[] ko, int ooff)
		{
			ko[0 + ooff] = (ki[0 + ioff] << rot) | ((int)((uint)ki[1 + ioff] >> (32 - rot)));
			ko[1 + ooff] = (ki[1 + ioff] << rot) | ((int)((uint)ki[2 + ioff] >> (32 - rot)));
			ko[2 + ooff] = (ki[2 + ioff] << rot) | ((int)((uint)ki[3 + ioff] >> (32 - rot)));
			ko[3 + ooff] = (ki[3 + ioff] << rot) | ((int)((uint)ki[0 + ioff] >> (32 - rot)));
			ki[0 + ioff] = ko[0 + ooff];
			ki[1 + ioff] = ko[1 + ooff];
			ki[2 + ioff] = ko[2 + ooff];
			ki[3 + ioff] = ko[3 + ooff];
		}

		private static void decroldq(int rot, int[] ki, int ioff, int[] ko, int ooff)
		{
			ko[2 + ooff] = (ki[0 + ioff] << rot) | ((int)((uint)ki[1 + ioff] >> (32 - rot)));
			ko[3 + ooff] = (ki[1 + ioff] << rot) | ((int)((uint)ki[2 + ioff] >> (32 - rot)));
			ko[0 + ooff] = (ki[2 + ioff] << rot) | ((int)((uint)ki[3 + ioff] >> (32 - rot)));
			ko[1 + ooff] = (ki[3 + ioff] << rot) | ((int)((uint)ki[0 + ioff] >> (32 - rot)));
			ki[0 + ioff] = ko[2 + ooff];
			ki[1 + ioff] = ko[3 + ooff];
			ki[2 + ioff] = ko[0 + ooff];
			ki[3 + ioff] = ko[1 + ooff];
		}

		private static void roldqo32(int rot, int[] ki, int ioff, int[] ko, int ooff)
		{
			ko[0 + ooff] = (ki[1 + ioff] << (rot - 32)) | ((int)((uint)ki[2 + ioff] >> (64 - rot)));
			ko[1 + ooff] = (ki[2 + ioff] << (rot - 32)) | ((int)((uint)ki[3 + ioff] >> (64 - rot)));
			ko[2 + ooff] = (ki[3 + ioff] << (rot - 32)) | ((int)((uint)ki[0 + ioff] >> (64 - rot)));
			ko[3 + ooff] = (ki[0 + ioff] << (rot - 32)) | ((int)((uint)ki[1 + ioff] >> (64 - rot)));
			ki[0 + ioff] = ko[0 + ooff];
			ki[1 + ioff] = ko[1 + ooff];
			ki[2 + ioff] = ko[2 + ooff];
			ki[3 + ioff] = ko[3 + ooff];
		}

		private static void decroldqo32(int rot, int[] ki, int ioff, int[] ko, int ooff)
		{
			ko[2 + ooff] = (ki[1 + ioff] << (rot - 32)) | ((int)((uint)ki[2 + ioff] >> (64 - rot)));
			ko[3 + ooff] = (ki[2 + ioff] << (rot - 32)) | ((int)((uint)ki[3 + ioff] >> (64 - rot)));
			ko[0 + ooff] = (ki[3 + ioff] << (rot - 32)) | ((int)((uint)ki[0 + ioff] >> (64 - rot)));
			ko[1 + ooff] = (ki[0 + ioff] << (rot - 32)) | ((int)((uint)ki[1 + ioff] >> (64 - rot)));
			ki[0 + ioff] = ko[2 + ooff];
			ki[1 + ioff] = ko[3 + ooff];
			ki[2 + ioff] = ko[0 + ooff];
			ki[3 + ioff] = ko[1 + ooff];
		}

		private int bytes2int(byte[] src, int offset)
		{
			int word = 0;

			for (int i = 0; i < 4; i++)
			{
				word = (word << 8) + (src[i + offset] & MASK8);
			}
			return word;
		}

		private void int2bytes(int word, byte[] dst, int offset)
		{
			for (int i = 0; i < 4; i++)
			{
				dst[(3 - i) + offset] = (byte)word;
				word = (int)((uint)word >> 8);
			}
		}

		private void camelliaF2(int[] s, int[] skey, int keyoff)
		{
			int t1, t2, u, v;

			t1 = s[0] ^ skey[0 + keyoff];
			u = SBOX4_4404[t1 & MASK8];
			u ^= SBOX3_3033[((int)((uint)t1 >> 8)) & MASK8];
			u ^= SBOX2_0222[((int)((uint)t1 >> 16)) & MASK8];
			u ^= SBOX1_1110[((int)((uint)t1 >> 24)) & MASK8];
			t2 = s[1] ^ skey[1 + keyoff];
			v = SBOX1_1110[t2 & MASK8];
			v ^= SBOX4_4404[((int)((uint)t2 >> 8)) & MASK8];
			v ^= SBOX3_3033[((int)((uint)t2 >> 16)) & MASK8];
			v ^= SBOX2_0222[((int)((uint)t2 >> 24)) & MASK8];

			s[2] ^= u ^ v;
			s[3] ^= u ^ v ^ rightRotate(u, 8);

			t1 = s[2] ^ skey[2 + keyoff];
			u = SBOX4_4404[t1 & MASK8];
			u ^= SBOX3_3033[((int)((uint)t1 >> 8)) & MASK8];
			u ^= SBOX2_0222[((int)((uint)t1 >> 16)) & MASK8];
			u ^= SBOX1_1110[((int)((uint)t1 >> 24)) & MASK8];
			t2 = s[3] ^ skey[3 + keyoff];
			v = SBOX1_1110[t2 & MASK8];
			v ^= SBOX4_4404[((int)((uint)t2 >> 8)) & MASK8];
			v ^= SBOX3_3033[((int)((uint)t2 >> 16)) & MASK8];
			v ^= SBOX2_0222[((int)((uint)t2 >> 24)) & MASK8];

			s[0] ^= u ^ v;
			s[1] ^= u ^ v ^ rightRotate(u, 8);
		}

		private void camelliaFLs(int[] s, int[] fkey, int keyoff)
		{

			s[1] ^= leftRotate(s[0] & fkey[0 + keyoff], 1);
			s[0] ^= fkey[1 + keyoff] | s[1];

			s[2] ^= fkey[3 + keyoff] | s[3];
			s[3] ^= leftRotate(fkey[2 + keyoff] & s[2], 1);
		}

		private void setKey(bool forEncryption, byte[] key)
		{
			int[] k = new int[8];
			int[] ka = new int[4];
			int[] kb = new int[4];
			int[] t = new int[4];

			switch (key.Length)
			{
				case 16:
					_keyIs128 = true;
					k[0] = bytes2int(key, 0);
					k[1] = bytes2int(key, 4);
					k[2] = bytes2int(key, 8);
					k[3] = bytes2int(key, 12);
					k[4] = k[5] = k[6] = k[7] = 0;
					break;
				case 24:
					k[0] = bytes2int(key, 0);
					k[1] = bytes2int(key, 4);
					k[2] = bytes2int(key, 8);
					k[3] = bytes2int(key, 12);
					k[4] = bytes2int(key, 16);
					k[5] = bytes2int(key, 20);
					k[6] = ~k[4];
					k[7] = ~k[5];
					_keyIs128 = false;
					break;
				case 32:
					k[0] = bytes2int(key, 0);
					k[1] = bytes2int(key, 4);
					k[2] = bytes2int(key, 8);
					k[3] = bytes2int(key, 12);
					k[4] = bytes2int(key, 16);
					k[5] = bytes2int(key, 20);
					k[6] = bytes2int(key, 24);
					k[7] = bytes2int(key, 28);
					_keyIs128 = false;
					break;
				default:
					throw new IllegalArgumentException("key sizes are only 16/24/32 bytes.");
			}

			for (int i = 0; i < 4; i++)
			{
				ka[i] = k[i] ^ k[i + 4];
			}
			/* compute KA */
			camelliaF2(ka, SIGMA, 0);
			for (int i = 0; i < 4; i++)
			{
				ka[i] ^= k[i];
			}
			camelliaF2(ka, SIGMA, 4);

			if (_keyIs128)
			{
				if (forEncryption)
				{
					/* KL dependant keys */
					kw[0] = k[0];
					kw[1] = k[1];
					kw[2] = k[2];
					kw[3] = k[3];
					roldq(15, k, 0, subkey, 4);
					roldq(30, k, 0, subkey, 12);
					roldq(15, k, 0, t, 0);
					subkey[18] = t[2];
					subkey[19] = t[3];
					roldq(17, k, 0, ke, 4);
					roldq(17, k, 0, subkey, 24);
					roldq(17, k, 0, subkey, 32);
					/* KA dependant keys */
					subkey[0] = ka[0];
					subkey[1] = ka[1];
					subkey[2] = ka[2];
					subkey[3] = ka[3];
					roldq(15, ka, 0, subkey, 8);
					roldq(15, ka, 0, ke, 0);
					roldq(15, ka, 0, t, 0);
					subkey[16] = t[0];
					subkey[17] = t[1];
					roldq(15, ka, 0, subkey, 20);
					roldqo32(34, ka, 0, subkey, 28);
					roldq(17, ka, 0, kw, 4);

				}
				else
				{ // decryption
					/* KL dependant keys */
					kw[4] = k[0];
					kw[5] = k[1];
					kw[6] = k[2];
					kw[7] = k[3];
					decroldq(15, k, 0, subkey, 28);
					decroldq(30, k, 0, subkey, 20);
					decroldq(15, k, 0, t, 0);
					subkey[16] = t[0];
					subkey[17] = t[1];
					decroldq(17, k, 0, ke, 0);
					decroldq(17, k, 0, subkey, 8);
					decroldq(17, k, 0, subkey, 0);
					/* KA dependant keys */
					subkey[34] = ka[0];
					subkey[35] = ka[1];
					subkey[32] = ka[2];
					subkey[33] = ka[3];
					decroldq(15, ka, 0, subkey, 24);
					decroldq(15, ka, 0, ke, 4);
					decroldq(15, ka, 0, t, 0);
					subkey[18] = t[2];
					subkey[19] = t[3];
					decroldq(15, ka, 0, subkey, 12);
					decroldqo32(34, ka, 0, subkey, 4);
					roldq(17, ka, 0, kw, 0);
				}
			}
			else
			{ // 192bit or 256bit
				/* compute KB */
				for (int i = 0; i < 4; i++)
				{
					kb[i] = ka[i] ^ k[i + 4];
				}
				camelliaF2(kb, SIGMA, 8);

				if (forEncryption)
				{
					/* KL dependant keys */
					kw[0] = k[0];
					kw[1] = k[1];
					kw[2] = k[2];
					kw[3] = k[3];
					roldqo32(45, k, 0, subkey, 16);
					roldq(15, k, 0, ke, 4);
					roldq(17, k, 0, subkey, 32);
					roldqo32(34, k, 0, subkey, 44);
					/* KR dependant keys */
					roldq(15, k, 4, subkey, 4);
					roldq(15, k, 4, ke, 0);
					roldq(30, k, 4, subkey, 24);
					roldqo32(34, k, 4, subkey, 36);
					/* KA dependant keys */
					roldq(15, ka, 0, subkey, 8);
					roldq(30, ka, 0, subkey, 20);
					/* 32bit rotation */
					ke[8] = ka[1];
					ke[9] = ka[2];
					ke[10] = ka[3];
					ke[11] = ka[0];
					roldqo32(49, ka, 0, subkey, 40);

					/* KB dependant keys */
					subkey[0] = kb[0];
					subkey[1] = kb[1];
					subkey[2] = kb[2];
					subkey[3] = kb[3];
					roldq(30, kb, 0, subkey, 12);
					roldq(30, kb, 0, subkey, 28);
					roldqo32(51, kb, 0, kw, 4);

				}
				else
				{ // decryption
					/* KL dependant keys */
					kw[4] = k[0];
					kw[5] = k[1];
					kw[6] = k[2];
					kw[7] = k[3];
					decroldqo32(45, k, 0, subkey, 28);
					decroldq(15, k, 0, ke, 4);
					decroldq(17, k, 0, subkey, 12);
					decroldqo32(34, k, 0, subkey, 0);
					/* KR dependant keys */
					decroldq(15, k, 4, subkey, 40);
					decroldq(15, k, 4, ke, 8);
					decroldq(30, k, 4, subkey, 20);
					decroldqo32(34, k, 4, subkey, 8);
					/* KA dependant keys */
					decroldq(15, ka, 0, subkey, 36);
					decroldq(30, ka, 0, subkey, 24);
					/* 32bit rotation */
					ke[2] = ka[1];
					ke[3] = ka[2];
					ke[0] = ka[3];
					ke[1] = ka[0];
					decroldqo32(49, ka, 0, subkey, 4);

					/* KB dependant keys */
					subkey[46] = kb[0];
					subkey[47] = kb[1];
					subkey[44] = kb[2];
					subkey[45] = kb[3];
					decroldq(30, kb, 0, subkey, 32);
					decroldq(30, kb, 0, subkey, 16);
					roldqo32(51, kb, 0, kw, 0);
				}
			}
		}

		private int processBlock128(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			for (int i = 0; i < 4; i++)
			{
				state[i] = bytes2int(@in, inOff + (i * 4));
				state[i] ^= kw[i];
			}

			camelliaF2(state, subkey, 0);
			camelliaF2(state, subkey, 4);
			camelliaF2(state, subkey, 8);
			camelliaFLs(state, ke, 0);
			camelliaF2(state, subkey, 12);
			camelliaF2(state, subkey, 16);
			camelliaF2(state, subkey, 20);
			camelliaFLs(state, ke, 4);
			camelliaF2(state, subkey, 24);
			camelliaF2(state, subkey, 28);
			camelliaF2(state, subkey, 32);

			state[2] ^= kw[4];
			state[3] ^= kw[5];
			state[0] ^= kw[6];
			state[1] ^= kw[7];

			int2bytes(state[2], @out, outOff);
			int2bytes(state[3], @out, outOff + 4);
			int2bytes(state[0], @out, outOff + 8);
			int2bytes(state[1], @out, outOff + 12);

			return BLOCK_SIZE;
		}

		private int processBlock192or256(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			for (int i = 0; i < 4; i++)
			{
				state[i] = bytes2int(@in, inOff + (i * 4));
				state[i] ^= kw[i];
			}

			camelliaF2(state, subkey, 0);
			camelliaF2(state, subkey, 4);
			camelliaF2(state, subkey, 8);
			camelliaFLs(state, ke, 0);
			camelliaF2(state, subkey, 12);
			camelliaF2(state, subkey, 16);
			camelliaF2(state, subkey, 20);
			camelliaFLs(state, ke, 4);
			camelliaF2(state, subkey, 24);
			camelliaF2(state, subkey, 28);
			camelliaF2(state, subkey, 32);
			camelliaFLs(state, ke, 8);
			camelliaF2(state, subkey, 36);
			camelliaF2(state, subkey, 40);
			camelliaF2(state, subkey, 44);

			state[2] ^= kw[4];
			state[3] ^= kw[5];
			state[0] ^= kw[6];
			state[1] ^= kw[7];

			int2bytes(state[2], @out, outOff);
			int2bytes(state[3], @out, outOff + 4);
			int2bytes(state[0], @out, outOff + 8);
			int2bytes(state[1], @out, outOff + 12);
			return BLOCK_SIZE;
		}

		public CamelliaEngine()
		{
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("only simple KeyParameter expected.");
			}

			setKey(forEncryption, ((KeyParameter)@params).getKey());
			initialised = true;
		}

		public virtual string getAlgorithmName()
		{
			return "Camellia";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (!initialised)
			{
				throw new IllegalStateException("Camellia engine not initialised");
			}

			if ((inOff + BLOCK_SIZE) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + BLOCK_SIZE) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (_keyIs128)
			{
				return processBlock128(@in, inOff, @out, outOff);
			}
			else
			{
				return processBlock192or256(@in, inOff, @out, outOff);
			}
		}

		public virtual void reset()
		{
			// nothing

		}
	}

}