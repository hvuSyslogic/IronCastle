using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// An implementation of the OFB mode for GOST 3412 2015 cipher.
	/// See  <a href="http://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
	/// </summary>
	public class G3413OFBBlockCipher : StreamBlockCipher
	{
		//    private int s;
		private int m;
		private int blockSize;
		private byte[] R;
		private byte[] R_init;
		private byte[] Y;
		private BlockCipher cipher;
		private int byteCount;
		private bool initialized = false;

		/// <param name="cipher"> base cipher </param>
		public G3413OFBBlockCipher(BlockCipher cipher) : base(cipher)
		{
			this.blockSize = cipher.getBlockSize();
			this.cipher = cipher;
			Y = new byte[blockSize];
		}

		public override void init(bool forEncryption, CipherParameters @params)
		{
			if (@params is ParametersWithIV)
			{
				ParametersWithIV ivParam = (ParametersWithIV)@params;

				byte[] iv = ivParam.getIV();

				if (iv.Length < blockSize)
				{
					throw new IllegalArgumentException("Parameter m must blockSize <= m");
				}
				this.m = iv.Length;

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
			return cipher.getAlgorithmName() + "/OFB";
		}

		public override int getBlockSize()
		{
			return blockSize;
		}

		public override int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{

			processBytes(@in, inOff, blockSize, @out, outOff);
			return blockSize;
		}


		public override byte calculateByte(byte @in)
		{
			if (byteCount == 0)
			{
				generateY();
			}

			byte rv = (byte)(Y[byteCount] ^ @in);
			byteCount++;

			if (byteCount == getBlockSize())
			{
				byteCount = 0;
				generateR();
			}

			return rv;
		}

		/// <summary>
		/// generate new Y value
		/// </summary>
		private void generateY()
		{
			byte[] msb = GOST3413CipherUtil.MSB(R, blockSize);
			cipher.processBlock(msb, 0, Y, 0);
		}


		/// <summary>
		/// generate new R value
		/// </summary>
		private void generateR()
		{
			byte[] buf = GOST3413CipherUtil.LSB(R, m - blockSize);
			JavaSystem.arraycopy(buf, 0, R, 0, buf.Length);
			JavaSystem.arraycopy(Y, 0, R, buf.Length, m - buf.Length);
		}


		public override void reset()
		{
			if (initialized)
			{
				JavaSystem.arraycopy(R_init, 0, R, 0, R_init.Length);
				Arrays.clear(Y);
				byteCount = 0;
				cipher.reset();
			}
		}
	}

}