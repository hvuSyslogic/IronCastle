using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.modes
{
		
	/// <summary>
	/// implements the GOST 3412 2015 CTR counter mode (GCTR).
	/// </summary>
	public class G3413CTRBlockCipher : StreamBlockCipher
	{


		private readonly int s;
		private byte[] CTR;
		private byte[] IV;
		private byte[] buf;
		private readonly int blockSize;
		private readonly BlockCipher cipher;
		private int byteCount = 0;
		private bool initialized;


		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> the block cipher to be used as the basis of the
		///               counter mode (must have a 64 bit block size). </param>
		public G3413CTRBlockCipher(BlockCipher cipher) : this(cipher, cipher.getBlockSize() * 8)
		{
		}

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher">       the block cipher to be used as the basis of the
		///                     counter mode (must have a 64 bit block size). </param>
		/// <param name="bitBlockSize"> basic unit (defined as s) </param>
		public G3413CTRBlockCipher(BlockCipher cipher, int bitBlockSize) : base(cipher)
		{

			if (bitBlockSize < 0 || bitBlockSize > cipher.getBlockSize() * 8)
			{
				throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= " + cipher.getBlockSize() * 8);
			}

			this.cipher = cipher;
			this.blockSize = cipher.getBlockSize();
			this.s = bitBlockSize / 8;
			CTR = new byte[blockSize];
		}

		/// <summary>
		/// Initialise the cipher and, possibly, the initialisation vector (IV).
		/// If an IV isn't passed as part of the parameter, the IV will be all zeros.
		/// An IV which is too short is handled in FIPS compliant fashion.
		/// </summary>
		/// <param name="encrypting"> if true the cipher is initialised for
		///                   encryption, if false for decryption. </param>
		/// <param name="params">     the key and other data required by the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public override void init(bool encrypting, CipherParameters @params)
		{

			if (@params is ParametersWithIV)
			{
				ParametersWithIV ivParam = (ParametersWithIV)@params;

				initArrays();

				IV = Arrays.clone(ivParam.getIV());

				if (IV.Length != blockSize / 2)
				{
					throw new IllegalArgumentException("Parameter IV length must be == blockSize/2");
				}

				JavaSystem.arraycopy(IV, 0, CTR, 0, IV.Length);
				for (int i = IV.Length; i < blockSize; i++)
				{
					CTR[i] = 0;
				}

				// if null it's an IV changed only.
				if (ivParam.getParameters() != null)
				{
					cipher.init(true, ivParam.getParameters());
				}
			}
			else
			{
				initArrays();

				// if it's null, key is to be reused.
				if (@params != null)
				{
					cipher.init(true, @params);
				}
			}

			initialized = true;
		}

		private void initArrays()
		{
			IV = new byte[blockSize / 2];
			CTR = new byte[blockSize];
			buf = new byte[s];
		}

		/// <summary>
		/// return the algorithm name and mode.
		/// </summary>
		/// <returns> the name of the underlying algorithm followed by "/GCTR"
		/// and the block size in bits </returns>
		public override string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/GCTR";
		}

		/// <summary>
		/// return the block size we are operating at (in bytes).
		/// </summary>
		/// <returns> the block size we are operating at (in bytes). </returns>
		public override int getBlockSize()
		{
			return s;
		}

		/// <summary>
		/// Process one block of input from the array in and write it to
		/// the out array.
		/// </summary>
		/// <param name="in">     the array containing the input data. </param>
		/// <param name="inOff">  offset into the in array the data starts at. </param>
		/// <param name="out">    the array the output data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <returns> the number of bytes processed and produced. </returns>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		public override int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{

			processBytes(@in, inOff, s, @out, outOff);

			return s;
		}

		public override byte calculateByte(byte @in)
		{

			if (byteCount == 0)
			{
				buf = generateBuf();
			}

			byte rv = (byte)(buf[byteCount] ^ @in);
			byteCount++;

			if (byteCount == s)
			{
				byteCount = 0;
				generateCRT();
			}

			return rv;

		}

		private void generateCRT()
		{
			CTR[CTR.Length - 1]++;
		}


		private byte[] generateBuf()
		{

			byte[] encryptedCTR = new byte[CTR.Length];
			cipher.processBlock(CTR, 0, encryptedCTR, 0);

			return GOST3413CipherUtil.MSB(encryptedCTR, s);

		}


		/// <summary>
		/// reset the feedback vector back to the IV and reset the underlying
		/// cipher.
		/// </summary>
		public override void reset()
		{
			if (initialized)
			{
				JavaSystem.arraycopy(IV, 0, CTR, 0, IV.Length);
				for (int i = IV.Length; i < blockSize; i++)
				{
					CTR[i] = 0;
				}
				byteCount = 0;
				cipher.reset();
			}
		}
	}

}