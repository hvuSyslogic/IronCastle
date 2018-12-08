namespace org.bouncycastle.crypto.test.cavp
{

	using KDFCounterBytesGenerator = org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
	using KDFCounterParameters = org.bouncycastle.crypto.@params.KDFCounterParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using TestFailedException = org.bouncycastle.util.test.TestFailedException;

	public sealed class KDFCounterTests : CAVPListener
	{
		private PrintWriter @out;

		public void receiveCAVPVectors(string name, Properties config, Properties vectors)
		{

			// create Mac based PRF from PRF property, create the KDF
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.Mac prf = CAVPReader.createPRF(config);
			Mac prf = CAVPReader.createPRF(config);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.generators.KDFCounterBytesGenerator gen = new org.bouncycastle.crypto.generators.KDFCounterBytesGenerator(prf);
			KDFCounterBytesGenerator gen = new KDFCounterBytesGenerator(prf);


			Matcher matcherForR = CAVPReader.PATTERN_FOR_R.matcher(config.getProperty("RLEN"));
			if (!matcherForR.matches())
			{
				throw new IllegalStateException("RLEN value should always match");
			}
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int r = int.Parse(matcherForR.group(1));
			int r = int.Parse(matcherForR.group(1));

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int count = int.Parse(vectors.getProperty("COUNT"));
			int count = int.Parse(vectors.getProperty("COUNT"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int l = int.Parse(vectors.getProperty("L"));
			int l = int.Parse(vectors.getProperty("L"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] ki = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("KI"));
			byte[] ki = Hex.decode(vectors.getProperty("KI"));

			//Three variants of this KDF are possible, with the counter before the fixed data, after the fixed data, or in the middle of the fixed data.
			if (config.getProperty("CTRLOCATION").matches("BEFORE_FIXED"))
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] fixedInputData = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("FixedInputData"));
				byte[] fixedInputData = Hex.decode(vectors.getProperty("FixedInputData"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.KDFCounterParameters params = new org.bouncycastle.crypto.params.KDFCounterParameters(ki, null, fixedInputData, r);
				KDFCounterParameters @params = new KDFCounterParameters(ki, null, fixedInputData, r);
				gen.init(@params);
			}
			else if (config.getProperty("CTRLOCATION").matches("AFTER_FIXED"))
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] fixedInputData = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("FixedInputData"));
				byte[] fixedInputData = Hex.decode(vectors.getProperty("FixedInputData"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.KDFCounterParameters params = new org.bouncycastle.crypto.params.KDFCounterParameters(ki, fixedInputData, null, r);
				KDFCounterParameters @params = new KDFCounterParameters(ki, fixedInputData, null, r);
				gen.init(@params);
			}
			else if (config.getProperty("CTRLOCATION").matches("MIDDLE_FIXED"))
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] DataBeforeCtrData = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("DataBeforeCtrData"));
				byte[] DataBeforeCtrData = Hex.decode(vectors.getProperty("DataBeforeCtrData"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] DataAfterCtrData = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("DataAfterCtrData"));
				byte[] DataAfterCtrData = Hex.decode(vectors.getProperty("DataAfterCtrData"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.KDFCounterParameters params = new org.bouncycastle.crypto.params.KDFCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
				KDFCounterParameters @params = new KDFCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
				gen.init(@params);
			}
			else
			{
				return; // Unknown CTRLOCATION
			}


//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] koGenerated = new byte[l / 8];
			byte[] koGenerated = new byte[l / 8];
			gen.generateBytes(koGenerated, 0, koGenerated.Length);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] koVectors = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("KO"));
			byte[] koVectors = Hex.decode(vectors.getProperty("KO"));

			compareKO(name, config, count, koGenerated, koVectors);
		}

		private static void compareKO(string name, Properties config, int test, byte[] calculatedOKM, byte[] testOKM)
		{

			if (!Arrays.areEqual(calculatedOKM, testOKM))
			{
				throw new TestFailedException(new SimpleTestResult(false, name + " using " + config + " test " + test + " failed"));

			}
		}

		public void receiveCommentLine(string commentLine)
		{
			//                out.println("# " + commentLine);
		}

		public void receiveStart(string name)
		{
			// do nothing
		}

		public void receiveEnd()
		{
			@out.println(" *** *** *** ");
		}

		public void setup()
		{
			try
			{
				@out = new PrintWriter(new FileWriter("KDFCTR.gen"));
			}
			catch (IOException e)
			{
				throw new IllegalStateException(e);
			}
		}

		public void tearDown()
		{
			@out.close();
		}
	}
}