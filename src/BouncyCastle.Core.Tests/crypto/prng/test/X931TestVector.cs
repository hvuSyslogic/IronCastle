namespace org.bouncycastle.crypto.prng.test
{

	public class X931TestVector
	{
		private readonly BlockCipher engine;
		private readonly EntropySourceProvider entropyProvider;
		private readonly string key;
		private readonly string dateTimeVector;
		private readonly bool predictionResistant;
		private readonly string[] expected;

		public X931TestVector(BlockCipher engine, EntropySourceProvider entropyProvider, string key, string dateTimeVector, bool predictionResistant, string[] expected)
		{
			this.engine = engine;
			this.entropyProvider = entropyProvider;
			this.key = key;


			this.dateTimeVector = dateTimeVector;
			this.predictionResistant = predictionResistant;
			this.expected = expected;
		}

		public virtual string getDateTimeVector()
		{
			return dateTimeVector;
		}

		public virtual BlockCipher getEngine()
		{
			return engine;
		}

		public virtual EntropySourceProvider getEntropyProvider()
		{
			return entropyProvider;
		}

		public virtual string[] getExpected()
		{
			return expected;
		}

		public virtual string getKey()
		{
			return key;
		}

		public virtual bool isPredictionResistant()
		{
			return predictionResistant;
		}
	}

}