namespace org.bouncycastle.openpgp.test
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;
	using Streams = org.bouncycastle.util.io.Streams;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class PGPUtilTest : SimpleTest
	{
		public override string getName()
		{
			return "PGPUtilTest";
		}

		public override void performTest()
		{
			byte[] contentMessage = Strings.toByteArray("Hello, world!\r\nhello, World!\r\n");

			File dataFile = File.createTempFile("bcpg", ".txt");

			FileOutputStream fOut = new FileOutputStream(dataFile);

			fOut.write(contentMessage);

			fOut.close();

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			PGPUtil.writeFileToLiteralData(bOut, 't', dataFile);

			testLiteralData("no buf", bOut.toByteArray(), dataFile.getName(), 't', contentMessage);

			bOut = new ByteArrayOutputStream();

			PGPUtil.writeFileToLiteralData(bOut, 't', dataFile, new byte[1 << 16]);

			testLiteralData("buf", bOut.toByteArray(), dataFile.getName(), 't', contentMessage);

			dataFile.delete();
		}

		private void testLiteralData(string id, byte[] data, string fileName, char type, byte[] content)
		{
			PGPLiteralData ld = new PGPLiteralData(new BCPGInputStream(new ByteArrayInputStream(data)));

			isEquals(fileName, ld.getFileName());
			isTrue(type == (char)ld.getFormat());

			byte[] bytes = Streams.readAll(ld.getDataStream());

			isTrue(id + " contents mismatch", Arrays.areEqual(bytes, content));
		}

		public static void Main(string[] args)
		{
			runTest(new PGPUtilTest());
		}
	}

}