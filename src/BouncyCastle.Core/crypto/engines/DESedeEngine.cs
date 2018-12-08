using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	/// <summary>
	/// a class that provides a basic DESede (or Triple DES) engine.
	/// </summary>
	public class DESedeEngine : DESEngine
	{
		protected internal new const int BLOCK_SIZE = 8;

		private int[] workingKey1 = null;
		private int[] workingKey2 = null;
		private int[] workingKey3 = null;

		private bool forEncryption;

		/// <summary>
		/// standard constructor.
		/// </summary>
		public DESedeEngine()
		{
		}

		/// <summary>
		/// initialise a DESede cipher.
		/// </summary>
		/// <param name="encrypting"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public override void init(bool encrypting, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("invalid parameter passed to DESede init - " + @params.GetType().getName());
			}

			byte[] keyMaster = ((KeyParameter)@params).getKey();

			if (keyMaster.Length != 24 && keyMaster.Length != 16)
			{
				throw new IllegalArgumentException("key size must be 16 or 24 bytes.");
			}

			this.forEncryption = encrypting;

			byte[] key1 = new byte[8];
			JavaSystem.arraycopy(keyMaster, 0, key1, 0, key1.Length);
			workingKey1 = generateWorkingKey(encrypting, key1);

			byte[] key2 = new byte[8];
			JavaSystem.arraycopy(keyMaster, 8, key2, 0, key2.Length);
			workingKey2 = generateWorkingKey(!encrypting, key2);

			if (keyMaster.Length == 24)
			{
				byte[] key3 = new byte[8];
				JavaSystem.arraycopy(keyMaster, 16, key3, 0, key3.Length);
				workingKey3 = generateWorkingKey(encrypting, key3);
			}
			else // 16 byte key
			{
				workingKey3 = workingKey1;
			}
		}

		public override string getAlgorithmName()
		{
			return "DESede";
		}

		public override int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public override int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (workingKey1 == null)
			{
				throw new IllegalStateException("DESede engine not initialised");
			}

			if ((inOff + BLOCK_SIZE) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + BLOCK_SIZE) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			byte[] temp = new byte[BLOCK_SIZE];

			if (forEncryption)
			{
				desFunc(workingKey1, @in, inOff, temp, 0);
				desFunc(workingKey2, temp, 0, temp, 0);
				desFunc(workingKey3, temp, 0, @out, outOff);
			}
			else
			{
				desFunc(workingKey3, @in, inOff, temp, 0);
				desFunc(workingKey2, temp, 0, temp, 0);
				desFunc(workingKey1, temp, 0, @out, outOff);
			}

			return BLOCK_SIZE;
		}

		public override void reset()
		{
		}
	}

}