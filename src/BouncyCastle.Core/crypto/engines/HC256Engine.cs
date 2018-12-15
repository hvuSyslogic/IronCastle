using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	/// <summary>
	/// HC-256 is a software-efficient stream cipher created by Hongjun Wu. It 
	/// generates keystream from a 256-bit secret key and a 256-bit initialization 
	/// vector.
	/// <para>
	/// http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc256_p3.pdf
	/// </para>
	/// </para><para>
	/// Its brother, HC-128, is a third phase candidate in the eStream contest.
	/// The algorithm is patent-free. No attacks are known as of today (April 2007). 
	/// See
	/// 
	/// http://www.ecrypt.eu.org/stream/hcp3.html
	/// </p>
	/// </summary>
	public class HC256Engine : StreamCipher
	{
		private int[] p = new int[1024];
		private int[] q = new int[1024];
		private int cnt = 0;

		private int step()
		{
			int j = cnt & 0x3FF;
			int ret;
			if (cnt < 1024)
			{
				int x = p[(j - 3 & 0x3FF)];
				int y = p[(j - 1023 & 0x3FF)];
				p[j] += p[(j - 10 & 0x3FF)] + (rotateRight(x, 10) ^ rotateRight(y, 23)) + q[((x ^ y) & 0x3FF)];

				x = p[(j - 12 & 0x3FF)];
				ret = (q[x & 0xFF] + q[((x >> 8) & 0xFF) + 256] + q[((x >> 16) & 0xFF) + 512] + q[((x >> 24) & 0xFF) + 768]) ^ p[j];
			}
			else
			{
				int x = q[(j - 3 & 0x3FF)];
				int y = q[(j - 1023 & 0x3FF)];
				q[j] += q[(j - 10 & 0x3FF)] + (rotateRight(x, 10) ^ rotateRight(y, 23)) + p[((x ^ y) & 0x3FF)];

				x = q[(j - 12 & 0x3FF)];
				ret = (p[x & 0xFF] + p[((x >> 8) & 0xFF) + 256] + p[((x >> 16) & 0xFF) + 512] + p[((x >> 24) & 0xFF) + 768]) ^ q[j];
			}
			cnt = cnt + 1 & 0x7FF;
			return ret;
		}

		private byte[] key, iv;
		private bool initialised;

		private void init()
		{
			if (key.Length != 32 && key.Length != 16)
			{
				throw new IllegalArgumentException("The key must be 128/256 bits long");
			}

			if (iv.Length < 16)
			{
				throw new IllegalArgumentException("The IV must be at least 128 bits long");
			}

			if (key.Length != 32)
			{
				byte[] k = new byte[32];

				JavaSystem.arraycopy(key, 0, k, 0, key.Length);
				JavaSystem.arraycopy(key, 0, k, 16, key.Length);

				key = k;
			}

			if (iv.Length < 32)
			{
				byte[] newIV = new byte[32];

				JavaSystem.arraycopy(iv, 0, newIV, 0, iv.Length);
				JavaSystem.arraycopy(iv, 0, newIV, iv.Length, newIV.Length - iv.Length);

				iv = newIV;
			}

			idx = 0;
			cnt = 0;

			int[] w = new int[2560];

			for (int i = 0; i < 32; i++)
			{
				w[i >> 2] |= (key[i] & 0xff) << (8 * (i & 0x3));
			}

			for (int i = 0; i < 32; i++)
			{
				w[(i >> 2) + 8] |= (iv[i] & 0xff) << (8 * (i & 0x3));
			}

			for (int i = 16; i < 2560; i++)
			{
				int x = w[i - 2];
				int y = w[i - 15];
				w[i] = (rotateRight(x, 17) ^ rotateRight(x, 19) ^ ((int)((uint)x >> 10))) + w[i - 7] + (rotateRight(y, 7) ^ rotateRight(y, 18) ^ ((int)((uint)y >> 3))) + w[i - 16] + i;
			}

			JavaSystem.arraycopy(w, 512, p, 0, 1024);
			JavaSystem.arraycopy(w, 1536, q, 0, 1024);

			for (int i = 0; i < 4096; i++)
			{
				step();
			}

			cnt = 0;
		}

		public virtual string getAlgorithmName()
		{
			return "HC-256";
		}

		/// <summary>
		/// Initialise a HC-256 cipher.
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. Irrelevant, as
		///                      encryption and decryption are the same. </param>
		/// <param name="params">        the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		///                                  inappropriate (ie. the key is not 256 bit long). </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			CipherParameters keyParam = @params;

			if (@params is ParametersWithIV)
			{
				iv = ((ParametersWithIV)@params).getIV();
				keyParam = ((ParametersWithIV)@params).getParameters();
			}
			else
			{
				iv = new byte[0];
			}

			if (keyParam is KeyParameter)
			{
				key = ((KeyParameter)keyParam).getKey();
				init();
			}
			else
			{
				throw new IllegalArgumentException("Invalid parameter passed to HC256 init - " + @params.GetType().getName());
			}

			initialised = true;
		}

		private byte[] buf = new byte[4];
		private int idx = 0;

		private byte getByte()
		{
			if (idx == 0)
			{
				int step1 = step();
				buf[0] = unchecked((byte)(step1 & 0xFF));
				step1 >>= 8;
				buf[1] = unchecked((byte)(step1 & 0xFF));
				step1 >>= 8;
				buf[2] = unchecked((byte)(step1 & 0xFF));
				step1 >>= 8;
				buf[3] = unchecked((byte)(step1 & 0xFF));
			}
			byte ret = buf[idx];
			idx = idx + 1 & 0x3;
			return ret;
		}

		public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
			if (!initialised)
			{
				throw new IllegalStateException(getAlgorithmName() + " not initialised");
			}

			if ((inOff + len) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + len) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			for (int i = 0; i < len; i++)
			{
				@out[outOff + i] = (byte)(@in[inOff + i] ^ getByte());
			}

			return len;
		}

		public virtual void reset()
		{
			init();
		}

		public virtual byte returnByte(byte @in)
		{
			return (byte)(@in ^ getByte());
		}

		private static int rotateRight(int x, int bits)
		{
			return ((int)((uint)x >> bits)) | (x << -bits);
		}
	}

}