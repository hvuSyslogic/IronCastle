using org.bouncycastle.jce.provider;
using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcaPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentSignerBuilder;
	using JcaPGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentVerifierBuilderProvider;
	using JcaPGPDigestCalculatorProviderBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
	using JcePBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyDecryptorBuilder;
	using UncloseableOutputStream = org.bouncycastle.util.test.UncloseableOutputStream;

	/// <summary>
	/// GPG compatability test vectors
	/// </summary>
	public class DSA2Test : TestCase
	{
		public virtual void setUp()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public virtual void testK1024H160()
		{
			doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-160-sign.gpg");
		}

		public virtual void testK1024H224()
		{
			doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-224-sign.gpg");
		}

		public virtual void testK1024H256()
		{
			doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-256-sign.gpg");
		}

		public virtual void testK1024H384()
		{
			doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-384-sign.gpg");
		}

		public virtual void testK1024H512()
		{
			doSigVerifyTest("DSA-1024-160.pub", "dsa-1024-512-sign.gpg");
		}

		public virtual void testK2048H224()
		{
			doSigVerifyTest("DSA-2048-224.pub", "dsa-2048-224-sign.gpg");
		}

		public virtual void testK3072H256()
		{
			doSigVerifyTest("DSA-3072-256.pub", "dsa-3072-256-sign.gpg");
		}

		public virtual void testK7680H384()
		{
			doSigVerifyTest("DSA-7680-384.pub", "dsa-7680-384-sign.gpg");
		}

		public virtual void testK15360H512()
		{
			doSigVerifyTest("DSA-15360-512.pub", "dsa-15360-512-sign.gpg");
		}

		public virtual void testGenerateK1024H224()
		{
			doSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", PGPUtil.SHA224);
		}

		public virtual void testGenerateK1024H256()
		{
			doSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", PGPUtil.SHA256);
		}

		public virtual void testGenerateK1024H384()
		{
			doSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", PGPUtil.SHA384);
		}

		public virtual void testGenerateK1024H512()
		{
			doSigGenerateTest("DSA-1024-160.sec", "DSA-1024-160.pub", PGPUtil.SHA512);
		}

		public virtual void testGenerateK2048H256()
		{
			doSigGenerateTest("DSA-2048-224.sec", "DSA-2048-224.pub", PGPUtil.SHA256);
		}

		public virtual void testGenerateK2048H512()
		{
			doSigGenerateTest("DSA-2048-224.sec", "DSA-2048-224.pub", PGPUtil.SHA512);
		}

		private void doSigGenerateTest(string privateKeyFile, string publicKeyFile, int digest)
		{
			PGPSecretKeyRing secRing = loadSecretKey(privateKeyFile);
			PGPPublicKeyRing pubRing = loadPublicKey(publicKeyFile);
			string data = "hello world!";
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ByteArrayInputStream testIn = new ByteArrayInputStream(data.GetBytes());
			PGPSignatureGenerator sGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags_Fields.DSA, digest)).setProvider("BC"));

			sGen.init(PGPSignature.BINARY_DOCUMENT, secRing.getSecretKey().extractPrivateKey((new JcePBESecretKeyDecryptorBuilder((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build())).setProvider("BC").build("test".ToCharArray())));

			BCPGOutputStream bcOut = new BCPGOutputStream(bOut);

			sGen.generateOnePassVersion(false).encode(bcOut);

			PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

			DateTime testDate = new DateTime((System.currentTimeMillis() / 1000) * 1000);
			OutputStream lOut = lGen.open(new UncloseableOutputStream(bcOut), PGPLiteralData.BINARY, "_CONSOLE", data.GetBytes().length, testDate);

			int ch;
			while ((ch = testIn.read()) >= 0)
			{
				lOut.write(ch);
				sGen.update((byte)ch);
			}

			lGen.close();

			sGen.generate().encode(bcOut);

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(bOut.toByteArray());
			PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
			PGPOnePassSignature ops = p1.get(0);

			assertEquals(digest, ops.getHashAlgorithm());
			assertEquals(PublicKeyAlgorithmTags_Fields.DSA, ops.getKeyAlgorithm());

			PGPLiteralData p2 = (PGPLiteralData)pgpFact.nextObject();
			if (!p2.getModificationTime().Equals(testDate))
			{
				fail("Modification time not preserved");
			}

			InputStream dIn = p2.getInputStream();

			ops.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), pubRing.getPublicKey());

			while ((ch = dIn.read()) >= 0)
			{
				ops.update((byte)ch);
			}

			PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();
			PGPSignature sig = p3.get(0);

			assertEquals(digest, sig.getHashAlgorithm());
			assertEquals(PublicKeyAlgorithmTags_Fields.DSA, sig.getKeyAlgorithm());

			assertTrue(ops.verify(sig));
		}

		private void doSigVerifyTest(string publicKeyFile, string sigFile)
		{
			PGPPublicKeyRing publicKey = loadPublicKey(publicKeyFile);
			JcaPGPObjectFactory pgpFact = loadSig(sigFile);

			PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

			pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

			PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
			PGPOnePassSignature ops = p1.get(0);

			PGPLiteralData p2 = (PGPLiteralData)pgpFact.nextObject();

			InputStream dIn = p2.getInputStream();

			ops.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), publicKey.getPublicKey());

			int ch;
			while ((ch = dIn.read()) >= 0)
			{
				ops.update((byte)ch);
			}

			PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();

			assertTrue(ops.verify(p3.get(0)));
		}

		private JcaPGPObjectFactory loadSig(string sigName)
		{
			return new JcaPGPObjectFactory(this.GetType().getResourceAsStream("dsa/sigs/" + sigName));
		}

		private PGPPublicKeyRing loadPublicKey(string keyName)
		{
			return new PGPPublicKeyRing(this.GetType().getResourceAsStream("dsa/keys/" + keyName), new JcaKeyFingerprintCalculator());
		}

		private PGPSecretKeyRing loadSecretKey(string keyName)
		{
			return new PGPSecretKeyRing(this.GetType().getResourceAsStream("dsa/keys/" + keyName), new JcaKeyFingerprintCalculator());
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("GPG DSA2 tests");

			suite.addTestSuite(typeof(DSA2Test));

			return suite;
		}
	}

}