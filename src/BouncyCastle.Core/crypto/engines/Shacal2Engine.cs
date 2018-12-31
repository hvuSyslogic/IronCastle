using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
		
	/// <summary>
	/// Block cipher Shacal2, designed by Helena Handschuh and David Naccache,
	/// based on hash function SHA-256,
	/// using SHA-256-Initialization-Values as data and SHA-256-Data as key.
	/// <para>
	/// A description of Shacal can be found at:
	///    http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.3.4066
	/// Best known cryptanalytic (Wikipedia 11.2013):
	///    Related-key rectangle attack on 44-rounds (Jiqiang Lu, Jongsung Kim).
	/// Comments are related to SHA-256-Naming as described in FIPS PUB 180-2
	/// </para>
	/// </summary>
	public class Shacal2Engine : BlockCipher
	{
		private static readonly int[] K = new int[] {0x428a2f98, 0x71374491, unchecked((int)0xb5c0fbcf), unchecked((int)0xe9b5dba5), 0x3956c25b, 0x59f111f1, unchecked((int)0x923f82a4), unchecked((int)0xab1c5ed5), unchecked((int)0xd807aa98), 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, unchecked((int)0x80deb1fe), unchecked((int)0x9bdc06a7), unchecked((int)0xc19bf174), unchecked((int)0xe49b69c1), unchecked((int)0xefbe4786), 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, unchecked((int)0x983e5152), unchecked((int)0xa831c66d), unchecked((int)0xb00327c8), unchecked((int)0xbf597fc7), unchecked((int)0xc6e00bf3), unchecked((int)0xd5a79147), 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, unchecked((int)0x81c2c92e), unchecked((int)0x92722c85), unchecked((int)0xa2bfe8a1), unchecked((int)0xa81a664b), unchecked((int)0xc24b8b70), unchecked((int)0xc76c51a3), unchecked((int)0xd192e819), unchecked((int)0xd6990624), unchecked((int)0xf40e3585), 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, unchecked((int)0x84c87814), unchecked((int)0x8cc70208), unchecked((int)0x90befffa), unchecked((int)0xa4506ceb), unchecked((int)0xbef9a3f7), unchecked((int)0xc67178f2)};

		private const int BLOCK_SIZE = 32;
		private bool forEncryption = false;
		private const int ROUNDS = 64;

		private int[] workingKey = null; // expanded key: corresponds to the message block W in FIPS PUB 180-2

		public Shacal2Engine()
		{
		}

		public virtual void reset()
		{
		}

		public virtual string getAlgorithmName()
		{
			return "Shacal2";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual void init(bool _forEncryption, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("only simple KeyParameter expected.");
			}
			this.forEncryption = _forEncryption;
			workingKey = new int[64];
			setKey(((KeyParameter)@params).getKey());
		}

		public virtual void setKey(byte[] kb)
		{
			if (kb.Length == 0 || kb.Length > 64 || kb.Length < 16 || kb.Length % 8 != 0)
			{
				throw new IllegalArgumentException("Shacal2-key must be 16 - 64 bytes and multiple of 8");
			}

			bytes2ints(kb, workingKey, 0, 0);

			for (int i = 16; i < 64; i++)
			{ // Key-Expansion, implicitly Zero-Padding for 16 > i > kb.length/4
				workingKey[i] = (((int)((uint)workingKey[i - 2] >> 17) | workingKey[i - 2] << -17) ^ ((int)((uint)workingKey[i - 2] >> 19) | workingKey[i - 2] << -19) ^ ((int)((uint)workingKey[i - 2] >> 10))) + workingKey[i - 7] + (((int)((uint)workingKey[i - 15] >> 7) | workingKey[i - 15] << -7) ^ ((int)((uint)workingKey[i - 15] >> 18) | workingKey[i - 15] << -18) ^ ((int)((uint)workingKey[i - 15] >> 3))) + workingKey[i - 16];
			}
		}

		private void encryptBlock(byte[] @in, int inOffset, byte[] @out, int outOffset)
		{
			int[] block = new int[BLOCK_SIZE / 4]; // corresponds to working variables a,b,c,d,e,f,g,h of FIPS PUB 180-2
			byteBlockToInts(@in, block, inOffset, 0);

			for (int i = 0; i < ROUNDS; i++)
			{
				int tmp = ((((int)((uint)block[4] >> 6)) | (block[4] << -6)) ^ (((int)((uint)block[4] >> 11)) | (block[4] << -11)) ^ (((int)((uint)block[4] >> 25)) | (block[4] << -25))) + ((block[4] & block[5]) ^ ((~block[4]) & block[6])) + block[7] + K[i] + workingKey[i]; // corresponds to T1 of FIPS PUB 180-2
				block[7] = block[6];
				block[6] = block[5];
				block[5] = block[4];
				block[4] = block[3] + tmp;
				block[3] = block[2];
				block[2] = block[1];
				block[1] = block[0];
				block[0] = tmp + ((((int)((uint)block[0] >> 2)) | (block[0] << -2)) ^ (((int)((uint)block[0] >> 13)) | (block[0] << -13)) ^ (((int)((uint)block[0] >> 22)) | (block[0] << -22))) + ((block[0] & block[2]) ^ (block[0] & block[3]) ^ (block[2] & block[3]));
				//corresponds to T2 of FIPS PUB 180-2, block[1] and block[2] replaced
			}
			ints2bytes(block, @out, outOffset);
		}

		private void decryptBlock(byte[] @in, int inOffset, byte[] @out, int outOffset)
		{
			int[] block = new int[BLOCK_SIZE / 4];
			byteBlockToInts(@in, block, inOffset, 0);
			for (int i = ROUNDS - 1; i > -1; i--)
			{
				int tmp = block[0] - ((((int)((uint)block[1] >> 2)) | (block[1] << -2)) ^ (((int)((uint)block[1] >> 13)) | (block[1] << -13)) ^ (((int)((uint)block[1] >> 22)) | (block[1] << -22))) - ((block[1] & block[2]) ^ (block[1] & block[3]) ^ (block[2] & block[3])); // T2
				block[0] = block[1];
				block[1] = block[2];
				block[2] = block[3];
				block[3] = block[4] - tmp;
				block[4] = block[5];
				block[5] = block[6];
				block[6] = block[7];
				block[7] = tmp - K[i] - workingKey[i] - ((((int)((uint)block[4] >> 6)) | (block[4] << -6)) ^ (((int)((uint)block[4] >> 11)) | (block[4] << -11)) ^ (((int)((uint)block[4] >> 25)) | (block[4] << -25))) - ((block[4] & block[5]) ^ ((~block[4]) & block[6])); // T1
			}
			ints2bytes(block, @out, outOffset);
		}

		public virtual int processBlock(byte[] @in, int inOffset, byte[] @out, int outOffset)
		{
			if (workingKey == null)
			{
				throw new IllegalStateException("Shacal2 not initialised");
			}

			if ((inOffset + BLOCK_SIZE) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOffset + BLOCK_SIZE) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (forEncryption)
			{
				encryptBlock(@in, inOffset, @out, outOffset);
			}
			else
			{
				decryptBlock(@in, inOffset, @out, outOffset);
			}

			return BLOCK_SIZE;
		}

		private void byteBlockToInts(byte[] bytes, int[] block, int bytesPos, int blockPos)
		{
			for (int i = blockPos; i < BLOCK_SIZE / 4; i++)
			{
				block[i] = ((bytes[bytesPos++] & 0xFF) << 24) | ((bytes[bytesPos++] & 0xFF) << 16) | ((bytes[bytesPos++] & 0xFF) << 8) | (bytes[bytesPos++] & 0xFF);
			}
		}

		private void bytes2ints(byte[] bytes, int[] block, int bytesPos, int blockPos)
		{
			for (int i = blockPos; i < bytes.Length / 4; i++)
			{
				block[i] = ((bytes[bytesPos++] & 0xFF) << 24) | ((bytes[bytesPos++] & 0xFF) << 16) | ((bytes[bytesPos++] & 0xFF) << 8) | (bytes[bytesPos++] & 0xFF);
			}
		}

		private void ints2bytes(int[] block, byte[] @out, int pos)
		{
			for (int i = 0; i < block.Length; i++)
			{
				@out[pos++] = (byte)((int)((uint)block[i] >> 24));
				@out[pos++] = (byte)((int)((uint)block[i] >> 16));
				@out[pos++] = (byte)((int)((uint)block[i] >> 8));
				@out[pos++] = (byte)block[i];
			}
		}
	}

}