using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	
	/// <summary>
	/// An TEA engine.
	/// </summary>
	public class TEAEngine : BlockCipher
	{
		private const int rounds = 32, block_size = 8, delta = unchecked((int)0x9E3779B9), d_sum = unchecked((int)0xC6EF3720); // sum on decrypt
		/*
		 * the expanded key array of 4 subkeys
		 */
		private int _a, _b, _c, _d;
		private bool _initialised;
		private bool _forEncryption;

		/// <summary>
		/// Create an instance of the TEA encryption algorithm
		/// and set some defaults
		/// </summary>
		public TEAEngine()
		{
			_initialised = false;
		}

		public virtual string getAlgorithmName()
		{
			return "TEA";
		}

		public virtual int getBlockSize()
		{
			return block_size;
		}

		/// <summary>
		/// initialise
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("invalid parameter passed to TEA init - " + @params.GetType().getName());
			}

			_forEncryption = forEncryption;
			_initialised = true;

			KeyParameter p = (KeyParameter)@params;

			setKey(p.getKey());
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (!_initialised)
			{
				throw new IllegalStateException(getAlgorithmName() + " not initialised");
			}

			if ((inOff + block_size) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + block_size) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			return (_forEncryption) ? encryptBlock(@in, inOff, @out, outOff) : decryptBlock(@in, inOff, @out, outOff);
		}

		public virtual void reset()
		{
		}

		/// <summary>
		/// Re-key the cipher.
		/// <para>
		/// </para>
		/// </summary>
		/// <param name="key">  the key to be used </param>
		private void setKey(byte[] key)
		{
			if (key.Length != 16)
			{
				throw new IllegalArgumentException("Key size must be 128 bits.");
			}

			_a = bytesToInt(key, 0);
			_b = bytesToInt(key, 4);
			_c = bytesToInt(key, 8);
			_d = bytesToInt(key, 12);
		}

		private int encryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			// Pack bytes into integers
			int v0 = bytesToInt(@in, inOff);
			int v1 = bytesToInt(@in, inOff + 4);

			int sum = 0;

			for (int i = 0; i != rounds; i++)
			{
				sum += delta;
				v0 += ((v1 << 4) + _a) ^ (v1 + sum) ^ (((int)((uint)v1 >> 5)) + _b);
				v1 += ((v0 << 4) + _c) ^ (v0 + sum) ^ (((int)((uint)v0 >> 5)) + _d);
			}

			unpackInt(v0, @out, outOff);
			unpackInt(v1, @out, outOff + 4);

			return block_size;
		}

		private int decryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			// Pack bytes into integers
			int v0 = bytesToInt(@in, inOff);
			int v1 = bytesToInt(@in, inOff + 4);

			int sum = d_sum;

			for (int i = 0; i != rounds; i++)
			{
				v1 -= ((v0 << 4) + _c) ^ (v0 + sum) ^ (((int)((uint)v0 >> 5)) + _d);
				v0 -= ((v1 << 4) + _a) ^ (v1 + sum) ^ (((int)((uint)v1 >> 5)) + _b);
				sum -= delta;
			}

			unpackInt(v0, @out, outOff);
			unpackInt(v1, @out, outOff + 4);

			return block_size;
		}

		private int bytesToInt(byte[] @in, int inOff)
		{
			return ((@in[inOff++]) << 24) | ((@in[inOff++] & 255) << 16) | ((@in[inOff++] & 255) << 8) | ((@in[inOff] & 255));
		}

		private void unpackInt(int v, byte[] @out, int outOff)
		{
			@out[outOff++] = (byte)((int)((uint)v >> 24));
			@out[outOff++] = (byte)((int)((uint)v >> 16));
			@out[outOff++] = (byte)((int)((uint)v >> 8));
			@out[outOff] = (byte)v;
		}
	}

}