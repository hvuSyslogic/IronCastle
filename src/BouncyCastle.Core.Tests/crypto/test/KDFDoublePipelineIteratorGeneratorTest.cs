namespace org.bouncycastle.crypto.test
{

	using CAVPReader = org.bouncycastle.crypto.test.cavp.CAVPReader;
	using KDFDoublePipelineCounterTests = org.bouncycastle.crypto.test.cavp.KDFDoublePipelineCounterTests;
	using KDFDoublePipelineIterationNoCounterTests = org.bouncycastle.crypto.test.cavp.KDFDoublePipelineIterationNoCounterTests;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class KDFDoublePipelineIteratorGeneratorTest : SimpleTest
	{
		public override string getName()
		{
			return this.GetType().getSimpleName();
		}

		public override void performTest()
		{
			testDoublePipelineIterationCounter();
			testDoublePipelineIterationNoCounter();
		}

		private static void testDoublePipelineIterationCounter()
		{

			CAVPReader cavpReader = new CAVPReader(new KDFDoublePipelineCounterTests());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.InputStream stream = org.bouncycastle.crypto.test.cavp.CAVPReader.class.getResourceAsStream("KDFDblPipelineCounter_gen.rsp");
			InputStream stream = typeof(CAVPReader).getResourceAsStream("KDFDblPipelineCounter_gen.rsp");
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.Reader reader = new java.io.InputStreamReader(stream, java.nio.charset.Charset.forName("UTF-8"));
			Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
			cavpReader.setInput("KDFDoublePipelineIterationCounter", reader);

			try
			{
				cavpReader.readAll();
			}
			catch (IOException e)
			{
				throw new IllegalStateException("Something is rotten in the state of Denmark", e);
			}
		}

		private static void testDoublePipelineIterationNoCounter()
		{

			CAVPReader cavpReader = new CAVPReader(new KDFDoublePipelineIterationNoCounterTests());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.InputStream stream = org.bouncycastle.crypto.test.cavp.CAVPReader.class.getResourceAsStream("KDFDblPipelineNoCounter_gen.rsp");
			InputStream stream = typeof(CAVPReader).getResourceAsStream("KDFDblPipelineNoCounter_gen.rsp");
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.Reader reader = new java.io.InputStreamReader(stream, java.nio.charset.Charset.forName("UTF-8"));
			Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
			cavpReader.setInput("KDFDblPipelineIterationNoCounter", reader);

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