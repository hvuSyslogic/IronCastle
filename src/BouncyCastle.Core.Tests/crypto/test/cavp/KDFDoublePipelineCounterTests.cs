namespace org.bouncycastle.crypto.test.cavp
{

	using KDFDoublePipelineIterationBytesGenerator = org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator;
	using KDFDoublePipelineIterationParameters = org.bouncycastle.crypto.@params.KDFDoublePipelineIterationParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using TestFailedException = org.bouncycastle.util.test.TestFailedException;

	public sealed class KDFDoublePipelineCounterTests : CAVPListener
	{
		private PrintWriter @out;

		public void receiveCAVPVectors(string name, Properties config, Properties vectors)
		{
			//                out.println(" === " + name + " === ");
			//                out.println(" --- config --- ");
			//                out.println(config);
			//                out.println(" --- vectors --- ");
			//                out.println(vectors);

			// always skip AFTER_FIXED
			if (!config.getProperty("CTRLOCATION").matches("AFTER_ITER"))
			{
				return;
			}

			// create Mac based PRF from PRF property, create the KDF
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.Mac prf = CAVPReader.createPRF(config);
			Mac prf = CAVPReader.createPRF(config);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator gen = new org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator(prf);
			KDFDoublePipelineIterationBytesGenerator gen = new KDFDoublePipelineIterationBytesGenerator(prf);


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
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] fixedInputData = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("FixedInputData"));
			byte[] fixedInputData = Hex.decode(vectors.getProperty("FixedInputData"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.KDFDoublePipelineIterationParameters params = org.bouncycastle.crypto.params.KDFDoublePipelineIterationParameters.createWithCounter(ki, fixedInputData, r);
			KDFDoublePipelineIterationParameters @params = KDFDoublePipelineIterationParameters.createWithCounter(ki, fixedInputData, r);
			gen.init(@params);

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
				@out = new PrintWriter(new FileWriter("KDFDblPipelineCounter.gen"));
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