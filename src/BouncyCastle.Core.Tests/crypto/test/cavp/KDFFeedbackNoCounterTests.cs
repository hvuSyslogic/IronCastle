namespace org.bouncycastle.crypto.test.cavp
{

	using KDFFeedbackBytesGenerator = org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator;
	using KDFFeedbackParameters = org.bouncycastle.crypto.@params.KDFFeedbackParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using TestFailedException = org.bouncycastle.util.test.TestFailedException;

	public sealed class KDFFeedbackNoCounterTests : CAVPListener
	{
		private PrintWriter @out;

		public void receiveCAVPVectors(string name, Properties config, Properties vectors)
		{


			// create Mac based PRF from PRF property, create the KDF
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.Mac prf = CAVPReader.createPRF(config);
			Mac prf = CAVPReader.createPRF(config);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator gen = new org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator(prf);
			KDFFeedbackBytesGenerator gen = new KDFFeedbackBytesGenerator(prf);

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
//ORIGINAL LINE: final byte[] iv = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("IV"));
			byte[] iv = Hex.decode(vectors.getProperty("IV"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] fixedInputData = org.bouncycastle.util.encoders.Hex.decode(vectors.getProperty("FixedInputData"));
			byte[] fixedInputData = Hex.decode(vectors.getProperty("FixedInputData"));
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.KDFFeedbackParameters params = org.bouncycastle.crypto.params.KDFFeedbackParameters.createWithoutCounter(ki, iv, fixedInputData);
			KDFFeedbackParameters @params = KDFFeedbackParameters.createWithoutCounter(ki, iv, fixedInputData);
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
				@out = new PrintWriter(new FileWriter("KDFFeedbackNoCounter.gen"));
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