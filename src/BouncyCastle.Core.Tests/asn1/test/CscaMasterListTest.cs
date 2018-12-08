namespace org.bouncycastle.asn1.test
{

	using CscaMasterList = org.bouncycastle.asn1.icao.CscaMasterList;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CscaMasterListTest : SimpleTest
	{
		public override string getName()
		{
			return "CscaMasterList";
		}

		public override void performTest()
		{
			byte[] input = getInput("masterlist-content.data");
			CscaMasterList parsedList = CscaMasterList.getInstance(ASN1Primitive.fromByteArray(input));

			if (parsedList.getCertStructs().Length != 3)
			{
				fail("Cert structure parsing failed: incorrect length");
			}

			byte[] output = parsedList.getEncoded();
			if (!Arrays.areEqual(input, output))
			{
				fail("Encoding failed after parse");
			}
		}

		private byte[] getInput(string name)
		{
			return Streams.readAll(this.GetType().getResourceAsStream(name));
		}

		public static void Main(string[] args)
		{
			runTest(new CscaMasterListTest());
		}
	}

}