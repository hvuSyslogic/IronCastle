using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Note that counter is only supported at the location presented in the
	/// NIST SP 800-108 specification, not in the additional locations present
	/// in the CAVP test vectors.
	/// </summary>
	public sealed class KDFFeedbackParameters : DerivationParameters
	{

		// could be any valid value, using 32, don't know why
		private const int UNUSED_R = -1;

		private readonly byte[] ki;
		private readonly byte[] iv;
		private readonly bool useCounter_Renamed;
		private readonly int r;
		private readonly byte[] fixedInputData;

		private KDFFeedbackParameters(byte[] ki, byte[] iv, byte[] fixedInputData, int r, bool useCounter)
		{
			if (ki == null)
			{
				throw new IllegalArgumentException("A KDF requires Ki (a seed) as input");
			}
			this.ki = Arrays.clone(ki);

			if (fixedInputData == null)
			{
				this.fixedInputData = new byte[0];
			}
			else
			{
				this.fixedInputData = Arrays.clone(fixedInputData);
			}

			this.r = r;

			if (iv == null)
			{
				this.iv = new byte[0];
			}
			else
			{
				this.iv = Arrays.clone(iv);
			}

			this.useCounter_Renamed = useCounter;
		}


		public static KDFFeedbackParameters createWithCounter(byte[] ki, byte[] iv, byte[] fixedInputData, int r)
		{
			if (r != 8 && r != 16 && r != 24 && r != 32)
			{
				throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
			}

			return new KDFFeedbackParameters(ki, iv, fixedInputData, r, true);
		}


		public static KDFFeedbackParameters createWithoutCounter(byte[] ki, byte[] iv, byte[] fixedInputData)
		{
			return new KDFFeedbackParameters(ki, iv, fixedInputData, UNUSED_R, false);
		}

		public byte[] getKI()
		{
			return ki;
		}

		public byte[] getIV()
		{
			return iv;
		}

		public bool useCounter()
		{
			return useCounter_Renamed;
		}

		public int getR()
		{
			return r;
		}

		public byte[] getFixedInputData()
		{
			return Arrays.clone(fixedInputData);
		}
	}

}