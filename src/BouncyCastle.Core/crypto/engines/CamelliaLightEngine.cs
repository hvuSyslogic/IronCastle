using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	/// <summary>
	/// Camellia - based on RFC 3713, smaller implementation, about half the size of CamelliaEngine.
	/// </summary>

	public class CamelliaLightEngine : BlockCipher
	{
		private const int BLOCK_SIZE = 16;
		private const int MASK8 = 0xff;
		private bool initialized;
		private bool _keyis128;

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
		private static readonly byte[] SBOX1 = new byte[] {112, unchecked(130), 44, unchecked(236), unchecked(179), 39, unchecked(192), unchecked(229), unchecked(228), unchecked(133), 87, 53, unchecked(234), 12, unchecked(174), 65, 35, unchecked(239), 107, unchecked(147), 69, 25, unchecked(165), 33, unchecked(237), 14, 79, 78, 29, 101, unchecked(146), unchecked(189), unchecked(134), unchecked(184), unchecked(175), unchecked(143), 124, unchecked(235), 31, unchecked(206), 62, 48, unchecked(220), 95, 94, unchecked(197), 11, 26, unchecked(166), unchecked(225), 57, unchecked(202), unchecked(213), 71, 93, 61, unchecked(217), 1, 90, unchecked(214), 81, 86, 108, 77, unchecked(139), 13, unchecked(154), 102, unchecked(251), unchecked(204), unchecked(176), 45, 116, 18, 43, 32, unchecked(240), unchecked(177), unchecked(132), unchecked(153), unchecked(223), 76, unchecked(203), unchecked(194), 52, 126, 118, 5, 109, unchecked(183), unchecked(169), 49, unchecked(209), 23, 4, unchecked(215), 20, 88, 58, 97, unchecked(222), 27, 17, 28, 50, 15, unchecked(156), 22, 83, 24, unchecked(242), 34, unchecked(254), 68, unchecked(207), unchecked(178), unchecked(195), unchecked(181), 122, unchecked(145), 36, 8, unchecked(232), unchecked(168), 96, unchecked(252), 105, 80, unchecked(170), unchecked(208), unchecked(160), 125, unchecked(161), unchecked(137), 98, unchecked(151), 84, 91, 30, unchecked(149), unchecked(224), unchecked(255), 100, unchecked(210), 16, unchecked(196), 0, 72, unchecked(163), unchecked(247), 117, unchecked(219), unchecked(138), 3, unchecked(230), unchecked(218), 9, 63, unchecked(221), unchecked(148), unchecked(135), 92, unchecked(131), 2, unchecked(205), 74, unchecked(144), 51, 115, 103, unchecked(246), unchecked(243), unchecked(157), 127, unchecked(191), unchecked(226), 82, unchecked(155), unchecked(216), 38, unchecked(200), 55, unchecked(198), 59, unchecked(129), unchecked(150), 111, 75, 19, unchecked(190), 99, 46, unchecked(233), 121, unchecked(167), unchecked(140), unchecked(159), 110, unchecked(188), unchecked(142), 41, unchecked(245), unchecked(249), unchecked(182), 47, unchecked(253), unchecked(180), 89, 120, unchecked(152), 6, 106, unchecked(231), 70, 113, unchecked(186), unchecked(212), 37, unchecked(171), 66, unchecked(136), unchecked(162), unchecked(141), unchecked(250), 114, 7, unchecked(185), 85, unchecked(248), unchecked(238), unchecked(172), 10, 54, 73, 42, 104, 60, 56, unchecked(241), unchecked(164), 64, 40, unchecked(211), 123, unchecked(187), unchecked(201), 67, unchecked(193), 21, unchecked(227), unchecked(173), unchecked(244), 119, unchecked(199), unchecked(128), unchecked(158)};

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

		private byte lRot8(byte v, int rot)
		{
			return (byte)((v << rot) | ((int)((uint)(v & 0xff) >> (8 - rot))));
		}

		private int sbox2(int x)
		{
			return (lRot8(SBOX1[x], 1) & MASK8);
		}

		private int sbox3(int x)
		{
			return (lRot8(SBOX1[x], 7) & MASK8);
		}

		private int sbox4(int x)
		{
			return (SBOX1[(lRot8((byte)x, 1) & MASK8)] & MASK8);
		}

		private void camelliaF2(int[] s, int[] skey, int keyoff)
		{
			int t1, t2, u, v;

			t1 = s[0] ^ skey[0 + keyoff];
			u = sbox4((t1 & MASK8));
			u |= (sbox3((((int)((uint)t1 >> 8)) & MASK8)) << 8);
			u |= (sbox2((((int)((uint)t1 >> 16)) & MASK8)) << 16);
			u |= ((SBOX1[(((int)((uint)t1 >> 24)) & MASK8)] & MASK8) << 24);

			t2 = s[1] ^ skey[1 + keyoff];
			v = SBOX1[(t2 & MASK8)] & MASK8;
			v |= (sbox4((((int)((uint)t2 >> 8)) & MASK8)) << 8);
			v |= (sbox3((((int)((uint)t2 >> 16)) & MASK8)) << 16);
			v |= (sbox2((((int)((uint)t2 >> 24)) & MASK8)) << 24);

			v = leftRotate(v, 8);
			u ^= v;
			v = leftRotate(v, 8) ^ u;
			u = rightRotate(u, 8) ^ v;
			s[2] ^= leftRotate(v, 16) ^ u;
			s[3] ^= leftRotate(u, 8);

			t1 = s[2] ^ skey[2 + keyoff];
			u = sbox4((t1 & MASK8));
			u |= sbox3((((int)((uint)t1 >> 8)) & MASK8)) << 8;
			u |= sbox2((((int)((uint)t1 >> 16)) & MASK8)) << 16;
			u |= (SBOX1[(((int)((uint)t1 >> 24)) & MASK8)] & MASK8) << 24;

			t2 = s[3] ^ skey[3 + keyoff];
			v = (SBOX1[(t2 & MASK8)] & MASK8);
			v |= sbox4((((int)((uint)t2 >> 8)) & MASK8)) << 8;
			v |= sbox3((((int)((uint)t2 >> 16)) & MASK8)) << 16;
			v |= sbox2((((int)((uint)t2 >> 24)) & MASK8)) << 24;

			v = leftRotate(v, 8);
			u ^= v;
			v = leftRotate(v, 8) ^ u;
			u = rightRotate(u, 8) ^ v;
			s[0] ^= leftRotate(v, 16) ^ u;
			s[1] ^= leftRotate(u, 8);
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
					_keyis128 = true;
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
					_keyis128 = false;
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
					_keyis128 = false;
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

			if (_keyis128)
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

		public CamelliaLightEngine()
		{
		}

		public virtual string getAlgorithmName()
		{
			return "Camellia";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("only simple KeyParameter expected.");
			}

			setKey(forEncryption, ((KeyParameter)@params).getKey());
			initialized = true;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{

			if (!initialized)
			{
				throw new IllegalStateException("Camellia is not initialized");
			}

			if ((inOff + BLOCK_SIZE) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + BLOCK_SIZE) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (_keyis128)
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
		}
	}

}