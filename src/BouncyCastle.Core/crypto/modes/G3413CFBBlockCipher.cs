using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.modes
{
		
	/// <summary>
	/// An implementation of the CFB mode for GOST 3412 2015 cipher.
	/// See  <a href="http://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
	/// </summary>
	public class G3413CFBBlockCipher : StreamBlockCipher
	{
		private readonly int s;
		private int m;
		private int blockSize;
		private byte[] R;
		private byte[] R_init;
		private BlockCipher cipher;
		private bool forEncryption;
		private bool initialized = false;

		private byte[] gamma;
		private byte[] inBuf;
		private int byteCount;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="cipher"> base cipher </param>
		public G3413CFBBlockCipher(BlockCipher cipher) : this(cipher, cipher.getBlockSize() * 8)
		{
		}

		/// <summary>
		/// Base constructor with specific block size.
		/// </summary>
		/// <param name="cipher"> base cipher </param>
		/// <param name="bitBlockSize"> basic unit (defined as s) </param>
		public G3413CFBBlockCipher(BlockCipher cipher, int bitBlockSize) : base(cipher)
		{

			if (bitBlockSize < 0 || bitBlockSize > cipher.getBlockSize() * 8)
			{
				throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= " + cipher.getBlockSize() * 8);
			}

			this.blockSize = cipher.getBlockSize();
			this.cipher = cipher;
			this.s = bitBlockSize / 8;
			inBuf = new byte[getBlockSize()];
		}

		/// <summary>
		/// Initialise the cipher and initialisation vector R.
		/// If an IV isn't passed as part of the parameter, the IV will be all zeros.
		/// An IV which is too short is handled in FIPS compliant fashion.
		/// R_init = IV, and R1 = R_init
		/// </summary>
		/// <param name="forEncryption"> ignored because encryption and decryption are same </param>
		/// <param name="params">        the key and other data required by the cipher. </param>
		/// <exception cref="IllegalArgumentException"> </exception>
		public override void init(bool forEncryption, CipherParameters @params)
		{
			this.forEncryption = forEncryption;
			if (@params is ParametersWithIV)
			{
				ParametersWithIV ivParam = (ParametersWithIV)@params;

				byte[] iv = ivParam.getIV();

				if (iv.Length < blockSize)
				{
					throw new IllegalArgumentException("Parameter m must blockSize <= m");
				}
				m = iv.Length;

				initArrays();

				R_init = Arrays.clone(iv);
				JavaSystem.arraycopy(R_init, 0, R, 0, R_init.Length);


				// if null it's an IV changed only.
				if (ivParam.getParameters() != null)
				{
					cipher.init(true, ivParam.getParameters());
				}
			}
			else
			{
				setupDefaultParams();

				initArrays();
				JavaSystem.arraycopy(R_init, 0, R, 0, R_init.Length);


				// if it's null, key is to be reused.
				if (@params != null)
				{
					cipher.init(true, @params);
				}
			}

			initialized = true;
		}

		/// <summary>
		/// allocate memory for R and R_init arrays
		/// </summary>
		private void initArrays()
		{
			R = new byte[m];
			R_init = new byte[m];
		}

		/// <summary>
		/// this method sets default values to <b>s</b> and <b>m</b> parameters:<br>
		/// s = <b>blockSize</b>; <br>
		/// m = <b>2 * blockSize</b>
		/// </summary>
		private void setupDefaultParams()
		{
			this.m = 2 * blockSize;
		}


		public override string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
		}

		public override int getBlockSize()
		{
			return s;
		}

		public override int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			this.processBytes(@in, inOff, getBlockSize(), @out, outOff);

			return getBlockSize();
		}

		public override byte calculateByte(byte @in)
		{
			if (byteCount == 0)
			{
				gamma = createGamma();
			}

			byte rv = (byte)(gamma[byteCount] ^ @in);
			inBuf[byteCount++] = (forEncryption) ? rv : @in;

			if (byteCount == getBlockSize())
			{
				byteCount = 0;
				generateR(inBuf);
			}

			return rv;
		}

		/// <summary>
		/// creating gamma value
		/// </summary>
		/// <returns> gamma </returns>
		public virtual byte[] createGamma()
		{
			byte[] msb = GOST3413CipherUtil.MSB(R, blockSize);
			byte[] encryptedMsb = new byte[msb.Length];
			cipher.processBlock(msb, 0, encryptedMsb, 0);
			return GOST3413CipherUtil.MSB(encryptedMsb, s);
		}

		/// <summary>
		/// generate new R value
		/// </summary>
		/// <param name="C"> processed block </param>
		public virtual void generateR(byte[] C)
		{

			byte[] buf = GOST3413CipherUtil.LSB(R, m - s);
			JavaSystem.arraycopy(buf, 0, R, 0, buf.Length);
			JavaSystem.arraycopy(C, 0, R, buf.Length, m - buf.Length);
		}

		/// <summary>
		/// copy R_init into R and reset the underlying
		/// cipher.
		/// </summary>
		public override void reset()
		{

			byteCount = 0;
			Arrays.clear(inBuf);
			Arrays.clear(gamma);

			if (initialized)
			{
				JavaSystem.arraycopy(R_init, 0, R, 0, R_init.Length);

				cipher.reset();
			}
		}
	}

}