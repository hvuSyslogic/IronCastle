namespace org.bouncycastle.crypto.test
{

	using CAVPReader = org.bouncycastle.crypto.test.cavp.CAVPReader;
	using KDFCounterTests = org.bouncycastle.crypto.test.cavp.KDFCounterTests;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class KDFCounterGeneratorTest : SimpleTest
	{

		private static void testCounter()
		{

			CAVPReader cavpReader = new CAVPReader(new KDFCounterTests());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.InputStream stream = org.bouncycastle.crypto.test.cavp.CAVPReader.class.getResourceAsStream("KDFCTR_gen.rsp");
			InputStream stream = typeof(CAVPReader).getResourceAsStream("KDFCTR_gen.rsp");
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.io.Reader reader = new java.io.InputStreamReader(stream, java.nio.charset.Charset.forName("UTF-8"));
			Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
			cavpReader.setInput("KDFCounter", reader);

			try
			{
				cavpReader.readAll();
			}
			catch (IOException e)
			{
				throw new IllegalStateException("Something is rotten in the state of Denmark", e);
			}
		}

		public override string getName()
		{
			return this.GetType().getSimpleName();
		}

		public override void performTest()
		{
			testCounter();
		}

		public static void Main(string[] args)
		{
			runTest(new KDFCounterGeneratorTest());
		}
	}

}