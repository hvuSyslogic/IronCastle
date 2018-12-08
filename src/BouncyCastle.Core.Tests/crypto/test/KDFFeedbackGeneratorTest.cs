namespace org.bouncycastle.crypto.test
{

	using CAVPReader = org.bouncycastle.crypto.test.cavp.CAVPReader;
	using KDFFeedbackCounterTests = org.bouncycastle.crypto.test.cavp.KDFFeedbackCounterTests;
	using KDFFeedbackNoCounterTests = org.bouncycastle.crypto.test.cavp.KDFFeedbackNoCounterTests;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class KDFFeedbackGeneratorTest : SimpleTest
	{
		public override string getName()
		{
			return this.GetType().getSimpleName();
		}

		public override void performTest()
		{
			testFeedbackCounter();
			testFeedbackNoCounter();
		}

		private static void testFeedbackCounter()
		{

			CAVPReader cavpReader = new CAVPReader(new KDFFeedbackCounterTests());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.InputStream stream = org.bouncycastle.crypto.test.cavp.CAVPReader.class.getResourceAsStream("KDFFeedbackCounter_gen.rsp");
			InputStream stream = typeof(CAVPReader).getResourceAsStream("KDFFeedbackCounter_gen.rsp");
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.Reader reader = new java.io.InputStreamReader(stream, java.nio.charset.Charset.forName("UTF-8"));
			Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
			cavpReader.setInput("KDFFeedbackCounter", reader);

			try
			{
				cavpReader.readAll();
			}
			catch (IOException e)
			{
				throw new IllegalStateException("Something is rotten in the state of Denmark ", e);
			}
		}

		private static void testFeedbackNoCounter()
		{

			CAVPReader cavpReader = new CAVPReader(new KDFFeedbackNoCounterTests());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.InputStream stream = org.bouncycastle.crypto.test.cavp.CAVPReader.class.getResourceAsStream("KDFFeedbackNoCounter_gen.rsp");
			InputStream stream = typeof(CAVPReader).getResourceAsStream("KDFFeedbackNoCounter_gen.rsp");
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.Reader reader = new java.io.InputStreamReader(stream, java.nio.charset.Charset.forName("UTF-8"));
			Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
			cavpReader.setInput("KDFFeedbackNoCounter", reader);

			try
			{
				cavpReader.readAll();
			}
			catch (IOException e)
			{
				throw new IllegalStateException("Something is rotten in the state of Denmark", e);
			}
		}

		public static void Main(string[] args)
		{
			runTest(new KDFDoublePipelineIteratorGeneratorTest());
		}
	}

}