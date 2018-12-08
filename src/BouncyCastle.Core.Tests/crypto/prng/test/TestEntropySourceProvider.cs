namespace org.bouncycastle.crypto.prng.test
{

	public class TestEntropySourceProvider : EntropySourceProvider
	{
		private readonly byte[] data;
		private readonly bool isPredictionResistant;

		public TestEntropySourceProvider(byte[] data, bool isPredictionResistant)
		{
			this.data = data;
			this.isPredictionResistant = isPredictionResistant;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.crypto.prng.EntropySource get(final int bitsRequired)
		public virtual EntropySource get(int bitsRequired)
		{
			return new EntropySourceAnonymousInnerClass(this, bitsRequired);
		}

		public class EntropySourceAnonymousInnerClass : EntropySource
		{
			private readonly TestEntropySourceProvider outerInstance;

			private int bitsRequired;

			public EntropySourceAnonymousInnerClass(TestEntropySourceProvider outerInstance, int bitsRequired)
			{
				this.outerInstance = outerInstance;
				this.bitsRequired = bitsRequired;
				index = 0;
			}

			internal int index;

			public bool isPredictionResistant()
			{
				return outerInstance.isPredictionResistant;
			}

			public byte[] getEntropy()
			{
				byte[] rv = new byte[bitsRequired / 8];

				JavaSystem.arraycopy(outerInstance.data, index, rv, 0, rv.Length);

				index += bitsRequired / 8;

				return rv;
			}

			public int entropySize()
			{
				return bitsRequired;
			}
		}
	}

}