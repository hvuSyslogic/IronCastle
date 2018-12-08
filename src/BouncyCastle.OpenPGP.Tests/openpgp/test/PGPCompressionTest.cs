using System;

namespace org.bouncycastle.openpgp.test
{

	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using UncloseableOutputStream = org.bouncycastle.util.test.UncloseableOutputStream;

	public class PGPCompressionTest : SimpleTest
	{
		public override void performTest()
		{
			testCompression(PGPCompressedData.UNCOMPRESSED);
			testCompression(PGPCompressedData.ZIP);
			testCompression(PGPCompressedData.ZLIB);
			testCompression(PGPCompressedData.BZIP2);

			//
			// new style - using stream close
			//
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

			OutputStream @out = cPacket.open(new UncloseableOutputStream(bOut), new byte[4]);

			@out.write("hello world! !dlrow olleh".GetBytes());

			@out.close();

			validateData(bOut.toByteArray());

			try
			{
				@out.close();
				cPacket.close();
			}
			catch (Exception)
			{
				fail("Redundant close() should be ignored");
			}

			//
			// new style - using generator close
			//
			bOut = new ByteArrayOutputStream();
			cPacket = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

			@out = cPacket.open(new UncloseableOutputStream(bOut), new byte[4]);

			@out.write("hello world! !dlrow olleh".GetBytes());

			cPacket.close();

			validateData(bOut.toByteArray());

			try
			{
				@out.close();
				cPacket.close();
			}
			catch (Exception)
			{
				fail("Redundant close() should be ignored");
			}
		}

		private void validateData(byte[] data)
		{
			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(data);
			PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();
			InputStream pIn = c1.getDataStream();

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			int ch;
			while ((ch = pIn.read()) >= 0)
			{
				bOut.write(ch);
			}

			if (!areEqual(bOut.toByteArray(), "hello world! !dlrow olleh".GetBytes()))
			{
				fail("compression test failed");
			}
		}

		private void testCompression(int type)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(type);

			OutputStream @out = cPacket.open(new UncloseableOutputStream(bOut));

			@out.write("hello world!".GetBytes());

			@out.close();

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(bOut.toByteArray());
			PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();
			InputStream pIn = c1.getDataStream();

			bOut.reset();

			int ch;
			while ((ch = pIn.read()) >= 0)
			{
				bOut.write(ch);
			}

			if (!areEqual(bOut.toByteArray(), "hello world!".GetBytes()))
			{
				fail("compression test failed");
			}
		}

		public override string getName()
		{
			return "PGPCompressionTest";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new PGPCompressionTest());
		}
	}

}