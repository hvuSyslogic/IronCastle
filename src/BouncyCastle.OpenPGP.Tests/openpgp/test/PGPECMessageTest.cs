using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp.test
{

	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using SExprParser = org.bouncycastle.gpg.SExprParser;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using JcaPGPPublicKeyRing = org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;
	using BcPublicKeyDataDecryptorFactory = org.bouncycastle.openpgp.@operator.bc.BcPublicKeyDataDecryptorFactory;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcaPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentSignerBuilder;
	using JcaPGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentVerifierBuilderProvider;
	using JcaPGPDigestCalculatorProviderBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
	using JcePBEProtectionRemoverFactory = org.bouncycastle.openpgp.@operator.jcajce.JcePBEProtectionRemoverFactory;
	using JcePublicKeyDataDecryptorFactoryBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class PGPECMessageTest : SimpleTest
	{
		internal byte[] testPubKey = Base64.decode("mFIEU5SAxhMIKoZIzj0DAQcCAwRqnFLCB8EEZkAELNqznk8yQau/f1PACUTU/Qe9\n" + "jlybc22bO55BdvZdFoa3RmNQHhR980/KeVwCQ3cPpe6OQJFAtD9OSVNUIFAtMjU2\n" + "IChHZW5lcmF0ZWQgYnkgR1BHIDIuMSBiZXRhKSA8bmlzdC1wLTI1NkBleGFtcGxl\n" + "LmNvbT6IeQQTEwgAIQUCU5SAxgIbAwYLCQgHAwIGFQgCCQoLAxYCAQIeAQIXgAAK\n" + "CRA2iYNe+deDntxvAP90U2BUL2YcxrJYnsK783VIPM5U5/2IhH7azbRfaHiLZgEA\n" + "1/BVNxRG/Q07gPSdEGagRZcrzPxMQPLjBL4T7Nq5eSG4VgRTlIDqEggqhkjOPQMB\n" + "BwIDBJlWEj5qR12xbmp5dkjEkV+PRSfk37NKnw8axSJkyDTsFNZLIugMLX/zTn3r\n" + "rOamvHUdXNbLy1s8PeyrztMcOnwDAQgHiGEEGBMIAAkFAlOUgOoCGwwACgkQNomD\n" + "XvnXg556SQD+MCXRkYgLPd0NWWbCKl5wYk4NwWRvOCDFGk7eYoRTKaYBAIkt3J86\n" + "Bn0zCzsphjrIUlGPXhLSX/2aJQDuuK3zzLmn");

		internal byte[] sExprKeySub = Base64.decode("KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTA6TklT" + "VCBQLTI1NikoMTpxNjU6BJlWEj5qR12xbmp5dkjEkV+PRSfk37NKnw8axSJk" + "yDTsFNZLIugMLX/zTn3rrOamvHUdXNbLy1s8PeyrztMcOnwpKDk6cHJvdGVj" + "dGVkMjU6b3BlbnBncC1zMmszLXNoYTEtYWVzLWNiYygoNDpzaGExODpu2e7w" + "pW4L5jg6MTI5MDU0NzIpMTY6ohIkbi1P1O7QX1zgPd7Ejik5NjrCoM9qBxzy" + "LVJJMVRGlsjltF9/CeLnRPN1sjeiQrP1vAlZMPiOpYTmGDVRcZhdkCRO06MY" + "UTLDZK1wsxELVD0s9irpbskcOnXwqtXbIqhoK4B+9pnkR0h5gi0xPIGSTtYp" + "KDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE1MjgxMCkpKQ==");

		internal byte[] sExprKeyMaster = Base64.decode("KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTA6TklT" + "VCBQLTI1NikoMTpxNjU6BGqcUsIHwQRmQAQs2rOeTzJBq79/U8AJRNT9B72O" + "XJtzbZs7nkF29l0WhrdGY1AeFH3zT8p5XAJDdw+l7o5AkUApKDk6cHJvdGVj" + "dGVkMjU6b3BlbnBncC1zMmszLXNoYTEtYWVzLWNiYygoNDpzaGExODr4PqHT" + "9W4lpTg6MTI5MDU0NzIpMTY6VsooQy9aGsuMpiObZk4y1ik5NjoCArOSmSsJ" + "IYUzxkRwy/HyDYPqjAqrNrh3m8lQco6k64Pf4SDda/0gKjkum7zYDEzBEvXI" + "+ZodAST6z3IDkPHL7LUy5qp2LdG73xLRFjfsqOsZgP+nwoOSUiC7N4AWJPAp" + "KDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE1MjcwOSkpKQ==");

		internal byte[] encMessage = Base64.decode("hH4DrQCblwYU61MSAgMEVXjgPW2hvIhUMQ2qlAQlAliZKbyujaYfLnwZTeGvu+pt\n" + "gJXt+JJ8zWoENxLAp+Nb3PxJW4CjvkXQ2dEmmvkhBzAhDer86XJBrQLBQUL+6EmE\n" + "l+/3Yzt+cPEyEn32BSpkt31F2yGncoefCUDgj9tKiFXSRwGhjRno0qzB3CfRWzDu\n" + "eelwwtRcxnvXNc44TuHRf4PgZ3d4dDU69bWQswdQ5UTP/Bjjo92yMLtJ3HtBuym+\n" + "NazbQUh4M+SP");

		internal byte[] signedEncMessage = Base64.decode("hH4DrQCblwYU61MSAgMEC/jpqjgnqotzKWNWJ3bhOxmmChghrV2PLQbQqtHtVvbj\n" + "zyLpaPgeqLslMAjsdy8rlANCjlweZhtP1DmvHiYgjDAA54eptpLMtbULaQOoRcsZ\n" + "ZnMqhx9s5phAohNFGC+DnVU/IwxDOnI+ya54LOoXUrrSsgEKDTlAmYr4/oDmLTXt\n" + "TaLgk0T9nBxGe8WbLwhPRBIyq6NX151aQ+pOobajrRiLwg/CwUsbAZ50bBPn2JjX\n" + "wgBhBjyAn7D6bZ4hMl3YSluSiFkJhxZcYSydtIAlX35q4D/pJjT4mPT/y7ypytCU\n" + "0wWo53O6NCSeM/EpeFw8RRh8fe+m33qpA6T5sR3Alg4ZukiIxLa36k6Cv5KTHmB3\n" + "6lKZcgQDHNIKStV1bW4Cva1aXXQ=");

		private void testMasterKey()
		{
			SExprParser parser = new SExprParser(null);
			PGPSecretKey key = parser.parseSecretKey(new ByteArrayInputStream(sExprKeyMaster), new JcePBEProtectionRemoverFactory("test".ToCharArray()), new JcaKeyFingerprintCalculator());

			PGPSignatureGenerator signGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags_Fields.SHA256)).setProvider("BC"));

			signGen.init(PGPSignature.BINARY_DOCUMENT, key.extractPrivateKey(null));

			signGen.update("hello world!".GetBytes());

			PGPSignature sig = signGen.generate();

			PGPPublicKey publicKey = (new JcaPGPPublicKeyRing(testPubKey)).getPublicKey();

			sig.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), publicKey);

			sig.update("hello world!".GetBytes());

			if (!sig.verify())
			{
				fail("signature failed to verify!");
			}
		}

		private void testEncMessage()
		{
			SExprParser parser = new SExprParser(null);
			PGPObjectFactory pgpFact = new JcaPGPObjectFactory(encMessage);

			PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

			PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

			PGPPublicKey publicKey = (new JcaPGPPublicKeyRing(testPubKey)).getPublicKey(encP.getKeyID());

			PGPSecretKey secretKey = parser.parseSecretKey(new ByteArrayInputStream(sExprKeySub), new JcePBEProtectionRemoverFactory("test".ToCharArray()), publicKey);

			InputStream clear = encP.getDataStream((new JcePublicKeyDataDecryptorFactoryBuilder()).setProvider("BC").build(secretKey.extractPrivateKey(null)));

			PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

			PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();

			PGPObjectFactory compFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());

			PGPLiteralData lData = (PGPLiteralData)compFact.nextObject();

			if (!"test.txt".Equals(lData.getFileName()))
			{
				fail("wrong file name detected");
			}
		}

		private void testSignedEncMessage()
		{
			PGPObjectFactory pgpFact = new JcaPGPObjectFactory(signedEncMessage);

			PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

			PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

			JcaPGPPublicKeyRing publicKeyRing = new JcaPGPPublicKeyRing(testPubKey);

			PGPPublicKey publicKey = publicKeyRing.getPublicKey(encP.getKeyID());

			SExprParser sExprParser = new SExprParser((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build());
			PGPSecretKey secretKey = sExprParser.parseSecretKey(new ByteArrayInputStream(sExprKeySub), new JcePBEProtectionRemoverFactory("test".ToCharArray()), publicKey);

			InputStream clear = encP.getDataStream((new JcePublicKeyDataDecryptorFactoryBuilder()).setProvider("BC").build(secretKey.extractPrivateKey(null)));

			PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

			PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();

			PGPObjectFactory compFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());

			PGPOnePassSignatureList sList = (PGPOnePassSignatureList)compFact.nextObject();

			PGPOnePassSignature ops = sList.get(0);

			PGPLiteralData lData = (PGPLiteralData)compFact.nextObject();

			if (!"test.txt".Equals(lData.getFileName()))
			{
				fail("wrong file name detected");
			}

			InputStream dIn = lData.getInputStream();
			int ch;

			ops.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), publicKeyRing.getPublicKey(ops.getKeyID()));

			while ((ch = dIn.read()) >= 0)
			{
				ops.update((byte)ch);
			}

			PGPSignatureList p3 = (PGPSignatureList)compFact.nextObject();

			if (!ops.verify(p3.get(0)))
			{
				fail("Failed signature check");
			}
		}

		private void testBCEncMessage()
		{
			PGPObjectFactory pgpFact = new JcaPGPObjectFactory(encMessage);

			PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

			PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

			PGPPublicKey publicKey = (new JcaPGPPublicKeyRing(testPubKey)).getPublicKey(encP.getKeyID());

			SExprParser sExprParser = new SExprParser((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build());
			PGPSecretKey secretKey = sExprParser.parseSecretKey(new ByteArrayInputStream(sExprKeySub), new JcePBEProtectionRemoverFactory("test".ToCharArray()), publicKey);

			InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(secretKey.extractPrivateKey(null)));

			PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

			PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();

			PGPObjectFactory compFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());

			PGPLiteralData lData = (PGPLiteralData)compFact.nextObject();

			if (!"test.txt".Equals(lData.getFileName()))
			{
				fail("wrong file name detected");
			}
		}

		private void testBCSignedEncMessage()
		{
			SExprParser parser = new SExprParser(null);
			PGPObjectFactory pgpFact = new JcaPGPObjectFactory(signedEncMessage);

			PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

			PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

			JcaPGPPublicKeyRing publicKeyRing = new JcaPGPPublicKeyRing(testPubKey);

			PGPPublicKey publicKey = publicKeyRing.getPublicKey(encP.getKeyID());

			PGPSecretKey secretKey = parser.parseSecretKey(new ByteArrayInputStream(sExprKeySub), new JcePBEProtectionRemoverFactory("test".ToCharArray()), publicKey);

			InputStream clear = encP.getDataStream((new JcePublicKeyDataDecryptorFactoryBuilder()).setProvider("BC").build(secretKey.extractPrivateKey(null)));

			PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

			PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();

			PGPObjectFactory compFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());

			PGPOnePassSignatureList sList = (PGPOnePassSignatureList)compFact.nextObject();

			PGPOnePassSignature ops = sList.get(0);

			PGPLiteralData lData = (PGPLiteralData)compFact.nextObject();

			if (!"test.txt".Equals(lData.getFileName()))
			{
				fail("wrong file name detected");
			}

			InputStream dIn = lData.getInputStream();
			int ch;

			ops.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), publicKeyRing.getPublicKey(ops.getKeyID()));

			while ((ch = dIn.read()) >= 0)
			{
				ops.update((byte)ch);
			}

			PGPSignatureList p3 = (PGPSignatureList)compFact.nextObject();

			if (!ops.verify(p3.get(0)))
			{
				fail("Failed signature check");
			}
		}

		public override void performTest()
		{
			testMasterKey();
			testEncMessage();
			testSignedEncMessage();
			testBCEncMessage();
			testBCSignedEncMessage();
		}

		public override string getName()
		{
			return "PGPECMessageTest";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new PGPECMessageTest());
		}
	}

}