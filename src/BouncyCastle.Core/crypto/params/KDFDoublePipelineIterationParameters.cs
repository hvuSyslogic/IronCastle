using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Note that counter is only supported at the location presented in the
	/// NIST SP 800-108 specification, not in the additional locations present
	/// in the CAVP test vectors.
	/// </summary>
	public sealed class KDFDoublePipelineIterationParameters : DerivationParameters
	{

		// could be any valid value, using 32, don't know why
		private const int UNUSED_R = 32;

		private readonly byte[] ki;
		private readonly bool useCounter_Renamed;
		private readonly int r;
		private readonly byte[] fixedInputData;

		private KDFDoublePipelineIterationParameters(byte[] ki, byte[] fixedInputData, int r, bool useCounter)
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

			if (r != 8 && r != 16 && r != 24 && r != 32)
			{
				throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
			}
			this.r = r;

			this.useCounter_Renamed = useCounter;
		}

		public static KDFDoublePipelineIterationParameters createWithCounter(byte[] ki, byte[] fixedInputData, int r)
		{
			return new KDFDoublePipelineIterationParameters(ki, fixedInputData, r, true);
		}

		public static KDFDoublePipelineIterationParameters createWithoutCounter(byte[] ki, byte[] fixedInputData)
		{
			return new KDFDoublePipelineIterationParameters(ki, fixedInputData, UNUSED_R, false);
		}

		public byte[] getKI()
		{
			return ki;
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