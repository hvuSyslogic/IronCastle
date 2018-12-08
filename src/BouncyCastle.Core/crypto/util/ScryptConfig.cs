using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.util
{
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;

	/// <summary>
	/// Configuration class for a PBKDF based around scrypt.
	/// </summary>
	public class ScryptConfig : PBKDFConfig
	{
		public class Builder
		{
			internal readonly int costParameter;
			internal readonly int blockSize;
			internal readonly int parallelizationParameter;

			internal int saltLength = 16;

			/// <summary>
			/// Base constructor.
			/// </summary>
			/// <param name="costParameter"> cost parameter (must be a power of 2) </param>
			/// <param name="blockSize"> block size </param>
			/// <param name="parallelizationParameter"> parallelization parameter </param>
			public Builder(int costParameter, int blockSize, int parallelizationParameter)
			{
				if (costParameter <= 1 || !isPowerOf2(costParameter))
				{
					throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2");
				}

				this.costParameter = costParameter;
				this.blockSize = blockSize;
				this.parallelizationParameter = parallelizationParameter;
			}

			/// <summary>
			/// Set the length of the salt to use.
			/// </summary>
			/// <param name="saltLength"> the length of the salt (in octets) to use. </param>
			/// <returns> the current builder. </returns>
			public virtual Builder withSaltLength(int saltLength)
			{
				this.saltLength = saltLength;

				return this;
			}

			public virtual ScryptConfig build()
			{
				return new ScryptConfig(this);
			}

			// note: we know X is non-zero
			internal static bool isPowerOf2(int x)
			{
				return ((x & (x - 1)) == 0);
			}
		}

		private readonly int costParameter;
		private readonly int blockSize;
		private readonly int parallelizationParameter;
		private readonly int saltLength;

		private ScryptConfig(Builder builder) : base(org.bouncycastle.asn1.misc.MiscObjectIdentifiers_Fields.id_scrypt)
		{

			this.costParameter = builder.costParameter;
			this.blockSize = builder.blockSize;
			this.parallelizationParameter = builder.parallelizationParameter;
			this.saltLength = builder.saltLength;
		}

		public virtual int getCostParameter()
		{
			return costParameter;
		}

		public virtual int getBlockSize()
		{
			return blockSize;
		}

		public virtual int getParallelizationParameter()
		{
			return parallelizationParameter;
		}

		public virtual int getSaltLength()
		{
			return saltLength;
		}
	}

}