using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// an implementation of the AES Key Wrapper from the NIST Key Wrap
	/// Specification as described in RFC 3394.
	/// <para>
	/// For further details see: <a href="http://www.ietf.org/rfc/rfc3394.txt">http://www.ietf.org/rfc/rfc3394.txt</a>
	/// and  <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
	/// </para>
	/// </summary>
	public class RFC3394WrapEngine : Wrapper
	{
		private BlockCipher engine;
		private bool wrapCipherMode;
		private KeyParameter param;
		private bool forWrapping;

		private byte[] iv = new byte[] {unchecked(0xa6), unchecked(0xa6), unchecked(0xa6), unchecked(0xa6), unchecked(0xa6), unchecked(0xa6), unchecked(0xa6), unchecked(0xa6)};

		/// <summary>
		/// Create a RFC 3394 WrapEngine specifying the encrypt for wrapping, decrypt for unwrapping.
		/// </summary>
		/// <param name="engine"> the block cipher to be used for wrapping. </param>
		public RFC3394WrapEngine(BlockCipher engine) : this(engine, false)
		{
		}

		/// <summary>
		/// Create a RFC 3394 WrapEngine specifying the direction for wrapping and unwrapping..
		/// </summary>
		/// <param name="engine"> the block cipher to be used for wrapping. </param>
		/// <param name="useReverseDirection"> true if engine should be used in decryption mode for wrapping, false otherwise. </param>
		public RFC3394WrapEngine(BlockCipher engine, bool useReverseDirection)
		{
			this.engine = engine;
			this.wrapCipherMode = (useReverseDirection) ? false : true;
		}

		public virtual void init(bool forWrapping, CipherParameters param)
		{
			this.forWrapping = forWrapping;

			if (param is ParametersWithRandom)
			{
				param = ((ParametersWithRandom) param).getParameters();
			}

			if (param is KeyParameter)
			{
				this.param = (KeyParameter)param;
			}
			else if (param is ParametersWithIV)
			{
				this.iv = ((ParametersWithIV)param).getIV();
				this.param = (KeyParameter)((ParametersWithIV) param).getParameters();
				if (this.iv.Length != 8)
				{
				   throw new IllegalArgumentException("IV not equal to 8");
				}
			}
		}

		public virtual string getAlgorithmName()
		{
			return engine.getAlgorithmName();
		}

		public virtual byte[] wrap(byte[] @in, int inOff, int inLen)
		{
			if (!forWrapping)
			{
				throw new IllegalStateException("not set for wrapping");
			}

			int n = inLen / 8;

			if ((n * 8) != inLen)
			{
				throw new DataLengthException("wrap data must be a multiple of 8 bytes");
			}

			byte[] block = new byte[inLen + iv.Length];
			byte[] buf = new byte[8 + iv.Length];

			JavaSystem.arraycopy(iv, 0, block, 0, iv.Length);
			JavaSystem.arraycopy(@in, inOff, block, iv.Length, inLen);

			engine.init(wrapCipherMode, param);

			for (int j = 0; j != 6; j++)
			{
				for (int i = 1; i <= n; i++)
				{
					JavaSystem.arraycopy(block, 0, buf, 0, iv.Length);
					JavaSystem.arraycopy(block, 8 * i, buf, iv.Length, 8);
					engine.processBlock(buf, 0, buf, 0);

					int t = n * j + i;
					for (int k = 1; t != 0; k++)
					{
						byte v = (byte)t;

						buf[iv.Length - k] ^= v;

						t = (int)((uint)t >> 8);
					}

					JavaSystem.arraycopy(buf, 0, block, 0, 8);
					JavaSystem.arraycopy(buf, 8, block, 8 * i, 8);
				}
			}

			return block;
		}

		public virtual byte[] unwrap(byte[] @in, int inOff, int inLen)
		{
			if (forWrapping)
			{
				throw new IllegalStateException("not set for unwrapping");
			}

			int n = inLen / 8;

			if ((n * 8) != inLen)
			{
				throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
			}

			byte[] block = new byte[inLen - iv.Length];
			byte[] a = new byte[iv.Length];
			byte[] buf = new byte[8 + iv.Length];

			JavaSystem.arraycopy(@in, inOff, a, 0, iv.Length);
			JavaSystem.arraycopy(@in, inOff + iv.Length, block, 0, inLen - iv.Length);

			engine.init(!wrapCipherMode, param);

			n = n - 1;

			for (int j = 5; j >= 0; j--)
			{
				for (int i = n; i >= 1; i--)
				{
					JavaSystem.arraycopy(a, 0, buf, 0, iv.Length);
					JavaSystem.arraycopy(block, 8 * (i - 1), buf, iv.Length, 8);

					int t = n * j + i;
					for (int k = 1; t != 0; k++)
					{
						byte v = (byte)t;

						buf[iv.Length - k] ^= v;

						t = (int)((uint)t >> 8);
					}

					engine.processBlock(buf, 0, buf, 0);
					JavaSystem.arraycopy(buf, 0, a, 0, 8);
					JavaSystem.arraycopy(buf, 8, block, 8 * (i - 1), 8);
				}
			}

			if (!Arrays.constantTimeAreEqual(a, iv))
			{
				throw new InvalidCipherTextException("checksum failed");
			}

			return block;
		}
	}

}