using System;

namespace org.bouncycastle.openpgp.test
{

	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using JcaPGPDigestCalculatorProviderBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
	using JcePBEDataDecryptorFactoryBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
	using JcePBEKeyEncryptionMethodGenerator = org.bouncycastle.openpgp.@operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
	using JcePGPDataEncryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePGPDataEncryptorBuilder;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using UncloseableOutputStream = org.bouncycastle.util.test.UncloseableOutputStream;

	public class PGPPBETest : SimpleTest
	{
		private static readonly DateTime TEST_DATE = new DateTime(1062200111000L);

		internal byte[] enc1 = Base64.decode("jA0EAwMC5M5wWBP2HBZgySvUwWFAmMRLn7dWiZN6AkQMvpE3b6qwN3SSun7zInw2" + "hxxdgFzVGfbjuB8w");

		internal byte[] enc1crc = Base64.decode("H66L");

		internal char[] pass = new char[] {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

		/// <summary>
		/// Message with both PBE and symmetric
		/// </summary>
		internal byte[] testPBEAsym = Base64.decode("hQIOA/ZlQEFWB5vuEAf/covEUaBve7NlWWdiO5NZubdtTHGElEXzG9hyBycp9At8" + "nZGi27xOZtEGFQo7pfz4JySRc3O0s6w7PpjJSonFJyNSxuze2LuqRwFWBYYcbS8/" + "7YcjB6PqutrT939OWsozfNqivI9/QyZCjBvFU89pp7dtUngiZ6MVv81ds2I+vcvk" + "GlIFcxcE1XoCIB3EvbqWNaoOotgEPT60unnB2BeDV1KD3lDRouMIYHfZ3SzBwOOI" + "6aK39sWnY5sAK7JjFvnDAMBdueOiI0Fy+gxbFD/zFDt4cWAVSAGTC4w371iqppmT" + "25TM7zAtCgpiq5IsELPlUZZnXKmnYQ7OCeysF0eeVwf+OFB9fyvCEv/zVQocJCg8" + "fWxfCBlIVFNeNQpeGygn/ZmRaILvB7IXDWP0oOw7/F2Ym66IdYYIp2HeEZv+jFwa" + "l41w5W4BH/gtbwGjFQ6CvF/m+lfUv6ZZdzsMIeEOwhP5g7rXBxrbcnGBaU+PXbho" + "gjDqaYzAWGlrmAd6aPSj51AGeYXkb2T1T/yoJ++M3GvhH4C4hvitamDkksh/qRnM" + "M/s8Nku6z1+RXO3M6p5QC1nlAVqieU8esT43945eSoC77K8WyujDNbysDyUCUTzt" + "p/aoQwe/HgkeOTJNelKR9y2W3xinZLFzep0SqpNI/e468yB/2/LGsykIyQa7JX6r" + "BYwuBAIDAkOKfv5rK8v0YDfnN+eFqwhTcrfBj5rDH7hER6nW3lNWcMataUiHEaMg" + "o6Q0OO1vptIGxW8jClTD4N1sCNwNu9vKny8dKYDDHbCjE06DNTv7XYVW3+JqTL5E" + "BnidvGgOmA==");

		/// <summary>
		/// decrypt the passed in message stream
		/// </summary>
		private byte[] decryptMessage(byte[] message, DateTime date)
		{
			JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(message);
			PGPEncryptedDataList enc = (PGPEncryptedDataList)pgpF.nextObject();
			PGPPBEEncryptedData pbe = (PGPPBEEncryptedData)enc.get(0);

			InputStream clear = pbe.getDataStream((new JcePBEDataDecryptorFactoryBuilder((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build())).setProvider("BC").build(pass));

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);
			PGPCompressedData cData = (PGPCompressedData)pgpFact.nextObject();

			pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

			PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			if (!ld.getFileName().Equals("test.txt") && !ld.getFileName().Equals("_CONSOLE"))
			{
				fail("wrong filename in packet");
			}
			if (!ld.getModificationTime().Equals(date))
			{
				fail("wrong modification time in packet: " + ld.getModificationTime().Ticks + " " + date.Ticks);
			}

			InputStream unc = ld.getInputStream();
			int ch;

			while ((ch = unc.read()) >= 0)
			{
				bOut.write(ch);
			}

			if (pbe.isIntegrityProtected() && !pbe.verify())
			{
				fail("integrity check failed");
			}

			return bOut.toByteArray();
		}

		private byte[] decryptMessageBuffered(byte[] message, DateTime date)
		{
			JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(message);
			PGPEncryptedDataList enc = (PGPEncryptedDataList)pgpF.nextObject();
			PGPPBEEncryptedData pbe = (PGPPBEEncryptedData)enc.get(0);

			InputStream clear = pbe.getDataStream((new JcePBEDataDecryptorFactoryBuilder((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build())).setProvider("BC").build(pass));

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);
			PGPCompressedData cData = (PGPCompressedData)pgpFact.nextObject();

			pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

			PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			if (!ld.getFileName().Equals("test.txt") && !ld.getFileName().Equals("_CONSOLE"))
			{
				fail("wrong filename in packet");
			}
			if (!ld.getModificationTime().Equals(date))
			{
				fail("wrong modification time in packet: " + ld.getModificationTime().Ticks + " " + date.Ticks);
			}

			InputStream unc = ld.getInputStream();
			byte[] buf = new byte[1024];
			int len;

			while ((len = unc.read(buf)) >= 0)
			{
				bOut.write(buf, 0, len);
			}

			if (pbe.isIntegrityProtected() && !pbe.verify())
			{
				fail("integrity check failed");
			}

			return bOut.toByteArray();
		}

		public override void performTest()
		{
			byte[] @out = decryptMessage(enc1, TEST_DATE);

			if (@out[0] != (byte)'h' || @out[1] != (byte)'e' || @out[2] != (byte)'l')
			{
				fail("wrong plain text in packet");
			}

			//
			// create a PBE encrypted message and read it back.
			//
			byte[] text = new byte[] {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};

			//
			// encryption step - convert to literal data, compress, encode.
			//
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

			DateTime cDate = new DateTime((System.currentTimeMillis() / 1000) * 1000);
			PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
			OutputStream comOut = comData.open(new UncloseableOutputStream(bOut));
			OutputStream ldOut = lData.open(new UncloseableOutputStream(comOut), PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, text.Length, cDate);

			ldOut.write(text);

			ldOut.close();

			comOut.close();

			//
			// encrypt - with stream close
			//
			ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
			PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)).setSecureRandom(new SecureRandom()).setProvider("BC"));

			cPk.addMethod((new JcePBEKeyEncryptionMethodGenerator(pass)).setProvider("BC"));

			OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), bOut.toByteArray().length);

			cOut.write(bOut.toByteArray());

			cOut.close();

			@out = decryptMessage(cbOut.toByteArray(), cDate);

			if (!areEqual(@out, text))
			{
				fail("wrong plain text in generated packet");
			}

			//
			// encrypt - with generator close
			//
			cbOut = new ByteArrayOutputStream();
			cPk = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)).setSecureRandom(new SecureRandom()).setProvider("BC"));

			cPk.addMethod((new JcePBEKeyEncryptionMethodGenerator(pass)).setProvider("BC"));

			cOut = cPk.open(new UncloseableOutputStream(cbOut), bOut.toByteArray().length);

			cOut.write(bOut.toByteArray());

			cPk.close();

			@out = decryptMessage(cbOut.toByteArray(), cDate);

			if (!areEqual(@out, text))
			{
				fail("wrong plain text in generated packet");
			}

			//
			// encrypt - partial packet style.
			//
			SecureRandom rand = new SecureRandom();
			byte[] test = new byte[1233];

			rand.nextBytes(test);

			bOut = new ByteArrayOutputStream();

			comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
			comOut = comData.open(bOut);
			lData = new PGPLiteralDataGenerator();

			ldOut = lData.open(new UncloseableOutputStream(comOut), PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, TEST_DATE, new byte[16]);


			ldOut.write(test);

			ldOut.close();

			comOut.close();

			cbOut = new ByteArrayOutputStream();
			cPk = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)).setSecureRandom(rand).setProvider("BC"));

			cPk.addMethod((new JcePBEKeyEncryptionMethodGenerator(pass)).setProvider("BC"));

			cOut = cPk.open(new UncloseableOutputStream(cbOut), new byte[16]);

			cOut.write(bOut.toByteArray());

			cOut.close();

			@out = decryptMessage(cbOut.toByteArray(), TEST_DATE);
			if (!areEqual(@out, test))
			{
				fail("wrong plain text in generated packet");
			}

			//
			// with integrity packet
			//
			cbOut = new ByteArrayOutputStream();
			cPk = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)).setWithIntegrityPacket(true).setSecureRandom(rand).setProvider("BC"));

			cPk.addMethod((new JcePBEKeyEncryptionMethodGenerator(pass)).setProvider("BC"));

			cOut = cPk.open(new UncloseableOutputStream(cbOut), new byte[16]);

			cOut.write(bOut.toByteArray());

			cOut.close();

			@out = decryptMessage(cbOut.toByteArray(), TEST_DATE);
			if (!areEqual(@out, test))
			{
				fail("wrong plain text in generated packet");
			}

			//
			// decrypt with buffering
			//
			@out = decryptMessageBuffered(cbOut.toByteArray(), TEST_DATE);
			if (!areEqual(@out, test))
			{
				fail("wrong plain text in buffer generated packet");
			}

			//
			// sample message
			//
			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(testPBEAsym);

			PGPEncryptedDataList enc = (PGPEncryptedDataList)pgpFact.nextObject();

			PGPPBEEncryptedData pbe = (PGPPBEEncryptedData)enc.get(1);

			InputStream clear = pbe.getDataStream((new JcePBEDataDecryptorFactoryBuilder((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build())).setProvider("BC").build("password".ToCharArray()));

			pgpFact = new JcaPGPObjectFactory(clear);

			PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

			bOut = new ByteArrayOutputStream();
			InputStream unc = ld.getInputStream();
			int ch;

			while ((ch = unc.read()) >= 0)
			{
				bOut.write(ch);
			}

			if (!areEqual(bOut.toByteArray(), Hex.decode("5361742031302e30322e30370d0a")))
			{
				fail("data mismatch on combined PBE");
			}

			//
			// with integrity packet - one byte message
			//
			byte[] msg = new byte[1];
			bOut = new ByteArrayOutputStream();

			comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

			lData = new PGPLiteralDataGenerator();
			comOut = comData.open(new UncloseableOutputStream(bOut));
			ldOut = lData.open(new UncloseableOutputStream(comOut), PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, msg.Length, cDate);

			ldOut.write(msg);

			ldOut.close();

			comOut.close();

			cbOut = new ByteArrayOutputStream();
			cPk = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)).setWithIntegrityPacket(true).setSecureRandom(rand).setProvider("BC"));

			cPk.addMethod((new JcePBEKeyEncryptionMethodGenerator(pass)).setProvider("BC"));

			cOut = cPk.open(new UncloseableOutputStream(cbOut), new byte[16]);

			cOut.write(bOut.toByteArray());

			cOut.close();

			@out = decryptMessage(cbOut.toByteArray(), cDate);
			if (!areEqual(@out, msg))
			{
				fail("wrong plain text in generated packet");
			}

			//
			// decrypt with buffering
			//
			@out = decryptMessageBuffered(cbOut.toByteArray(), cDate);
			if (!areEqual(@out, msg))
			{
				fail("wrong plain text in buffer generated packet");
			}
		}

		public override string getName()
		{
			return "PGPPBETest";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new PGPPBETest());
		}
	}

}