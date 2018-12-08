using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// An implementation of the CBC mode for GOST 3412 2015 cipher.
	/// See  <a href="http://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
	/// </summary>
	public class G3413CBCBlockCipher : BlockCipher
	{

		private int m;
		private int blockSize;
		private byte[] R;
		private byte[] R_init;
		private BlockCipher cipher;
		private bool initialized = false;
		private bool forEncryption;

		/// <param name="cipher"> base cipher </param>
		public G3413CBCBlockCipher(BlockCipher cipher)
		{
			this.blockSize = cipher.getBlockSize();
			this.cipher = cipher;
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
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
				this.m = iv.Length;

				initArrays();

				R_init = Arrays.clone(iv);
				JavaSystem.arraycopy(R_init, 0, R, 0, R_init.Length);

				// if null it's an IV changed only.
				if (ivParam.getParameters() != null)
				{
					cipher.init(forEncryption, ivParam.getParameters());
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
					cipher.init(forEncryption, @params);
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
		/// this method sets default values to <b>m</b> parameter:<br>
		/// m = <b>blockSize</b>
		/// </summary>
		private void setupDefaultParams()
		{
			this.m = blockSize;
		}

		public virtual string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/CBC";
		}

		public virtual int getBlockSize()
		{
			return blockSize;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{

			return (forEncryption) ? encrypt(@in, inOff, @out, outOff) : decrypt(@in, inOff, @out, outOff);
		}


		private int encrypt(byte[] @in, int inOff, byte[] @out, int outOff)
		{

			byte[] msb = GOST3413CipherUtil.MSB(R, blockSize);
			byte[] input = GOST3413CipherUtil.copyFromInput(@in, blockSize, inOff);
			byte[] sum = GOST3413CipherUtil.sum(input, msb);
			byte[] c = new byte[sum.Length];
			cipher.processBlock(sum, 0, c, 0);

			JavaSystem.arraycopy(c, 0, @out, outOff, c.Length);

			if (@out.Length > (outOff + sum.Length))
			{
				generateR(c);
			}

			return c.Length;
		}


		private int decrypt(byte[] @in, int inOff, byte[] @out, int outOff)
		{

			byte[] msb = GOST3413CipherUtil.MSB(R, blockSize);
			byte[] input = GOST3413CipherUtil.copyFromInput(@in, blockSize, inOff);

			byte[] c = new byte[input.Length];
			cipher.processBlock(input, 0, c, 0);

			byte[] sum = GOST3413CipherUtil.sum(c, msb);

			JavaSystem.arraycopy(sum, 0, @out, outOff, sum.Length);


			if (@out.Length > (outOff + sum.Length))
			{
				generateR(input);
			}

			return sum.Length;
		}

		/// <summary>
		/// generate new R value
		/// </summary>
		/// <param name="C"> processed block </param>
		private void generateR(byte[] C)
		{
			byte[] buf = GOST3413CipherUtil.LSB(R, m - blockSize);
			JavaSystem.arraycopy(buf, 0, R, 0, buf.Length);
			JavaSystem.arraycopy(C, 0, R, buf.Length, m - buf.Length);
		}


		public virtual void reset()
		{
			if (initialized)
			{
				JavaSystem.arraycopy(R_init, 0, R, 0, R_init.Length);
				cipher.reset();
			}
		}
	}

}