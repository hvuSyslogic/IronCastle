using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.test
{

	using NISTNamedCurves = org.bouncycastle.asn1.nist.NISTNamedCurves;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using ECKeyPairGenerator = org.bouncycastle.crypto.generators.ECKeyPairGenerator;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using PGPDigestCalculator = org.bouncycastle.openpgp.@operator.PGPDigestCalculator;
	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;
	using BcPBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.bc.BcPBESecretKeyDecryptorBuilder;
	using BcPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.bc.BcPGPContentSignerBuilder;
	using BcPGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.bc.BcPGPContentVerifierBuilderProvider;
	using BcPGPDigestCalculatorProvider = org.bouncycastle.openpgp.@operator.bc.BcPGPDigestCalculatorProvider;
	using BcPGPKeyPair = org.bouncycastle.openpgp.@operator.bc.BcPGPKeyPair;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcaPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentSignerBuilder;
	using JcaPGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentVerifierBuilderProvider;
	using JcaPGPDigestCalculatorProviderBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
	using JcaPGPKeyPair = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPKeyPair;
	using JcePBEProtectionRemoverFactory = org.bouncycastle.openpgp.@operator.jcajce.JcePBEProtectionRemoverFactory;
	using JcePBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyDecryptorBuilder;
	using JcePBESecretKeyEncryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyEncryptorBuilder;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class PGPECDSATest : SimpleTest
	{
		internal byte[] testPubKey = Base64.decode("mFIEUb4HqBMIKoZIzj0DAQcCAwSQynmjwsGJHYJakAEVYxrm3tt/1h8g9Uksx32J" + "zG/ZH4RwaD0PbjzEe5EVBmCwSErRZxt/5AxXa0TEHWjya8FetDVFQ0RTQSAoS2V5" + "IGlzIDI1NiBiaXRzIGxvbmcpIDx0ZXN0LmVjZHNhQGV4YW1wbGUuY29tPoh6BBMT" + "CAAiBQJRvgeoAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRDqO46kgPLi" + "vN1hAP4n0UApR36ziS5D8KUt7wEpBujQE4G3+efATJ+DMmY/SgEA+wbdDynFf/V8" + "pQs0+FtCYQ9schzIur+peRvol7OrNnc=");

		internal byte[] testPrivKey = Base64.decode("lKUEUb4HqBMIKoZIzj0DAQcCAwSQynmjwsGJHYJakAEVYxrm3tt/1h8g9Uksx32J" + "zG/ZH4RwaD0PbjzEe5EVBmCwSErRZxt/5AxXa0TEHWjya8Fe/gcDAqTWSUiFpEno" + "1n8izmLaWTy8GYw5/lK4R2t6D347YGgTtIiXfoNPOcosmU+3OibyTm2hc/WyG4fL" + "a0nxFtj02j0Bt/Fw0N4VCKJwKL/QJT+0NUVDRFNBIChLZXkgaXMgMjU2IGJpdHMg" + "bG9uZykgPHRlc3QuZWNkc2FAZXhhbXBsZS5jb20+iHoEExMIACIFAlG+B6gCGwMG" + "CwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEOo7jqSA8uK83WEA/ifRQClHfrOJ" + "LkPwpS3vASkG6NATgbf558BMn4MyZj9KAQD7Bt0PKcV/9XylCzT4W0JhD2xyHMi6" + "v6l5G+iXs6s2dw==");

		internal char[] testPasswd = "test".ToCharArray();

		internal byte[] sExprKey = Base64.decode("KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTU6YnJh" + "aW5wb29sUDM4NHIxKSgxOnE5NzoEi29XCqkugtlRvONnpAVMQgfecL+Gk86O" + "t8LnUizfHG2TqRrtqlMg1DdU8Z8dJWmhJG84IUOURCyjt8nE4BeeCfRIbTU5" + "7CB13OqveBdNIRfK45UQnxHLO2MPVXf4GMdtKSg5OnByb3RlY3RlZDI1Om9w" + "ZW5wZ3AtczJrMy1zaGExLWFlcy1jYmMoKDQ6c2hhMTg6itLEzGV4Cfg4OjEy" + "OTA1NDcyKTE2OgxmufENKFTZUB72+X7AwkgpMTEyOvMWNLZgaGdlTN8XCxa6" + "8ia0Xqqb9RvHgTh+iBf0RgY5Tx5hqO9fHOi76LTBMfxs9VC4f1rTketjEUKR" + "f5amKb8lrJ67kKEsny4oRtP9ejkNzcvHFqRdxmHyL10ui8M8rJN9OU8ArqWf" + "g22dTcKu02cpKDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE2MDg1MCkp" + "KQ==");

		private void generateAndSign()
		{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			keyGen.initialize(new ECGenParameterSpec("P-256"));

			KeyPair kpSign = keyGen.generateKeyPair();

			PGPKeyPair ecdsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDSA, kpSign, DateTime.Now);

			//
			// try a signature
			//
			PGPSignatureGenerator signGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags_Fields.SHA256)).setProvider("BC"));

			signGen.init(PGPSignature.BINARY_DOCUMENT, ecdsaKeyPair.getPrivateKey());

			signGen.update("hello world!".GetBytes());

			PGPSignature sig = signGen.generate();

			sig.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), ecdsaKeyPair.getPublicKey());

			sig.update("hello world!".GetBytes());

			if (!sig.verify())
			{
				fail("signature failed to verify!");
			}

			//
			// generate a key ring
			//
			char[] passPhrase = "test".ToCharArray();
			PGPDigestCalculator sha1Calc = (new JcaPGPDigestCalculatorProviderBuilder()).build().get(HashAlgorithmTags_Fields.SHA1);
			PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, ecdsaKeyPair, "test@bouncycastle.org", sha1Calc, null, null, (new JcaPGPContentSignerBuilder(ecdsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags_Fields.SHA1)).setProvider("BC"), (new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc)).setProvider("BC").build(passPhrase));

			PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

			PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

			KeyFingerPrintCalculator fingerCalc = new JcaKeyFingerprintCalculator();

			PGPPublicKeyRing pubRingEnc = new PGPPublicKeyRing(pubRing.getEncoded(), fingerCalc);

			if (!Arrays.areEqual(pubRing.getEncoded(), pubRingEnc.getEncoded()))
			{
				fail("public key ring encoding failed");
			}

			PGPSecretKeyRing secRingEnc = new PGPSecretKeyRing(secRing.getEncoded(), fingerCalc);

			if (!Arrays.areEqual(secRing.getEncoded(), secRingEnc.getEncoded()))
			{
				fail("secret key ring encoding failed");
			}


			//
			// try a signature using encoded key
			//
			signGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags_Fields.SHA256)).setProvider("BC"));

			signGen.init(PGPSignature.BINARY_DOCUMENT, secRing.getSecretKey().extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(passPhrase)));

			signGen.update("hello world!".GetBytes());

			sig = signGen.generate();

			sig.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), secRing.getSecretKey().getPublicKey());

			sig.update("hello world!".GetBytes());

			if (!sig.verify())
			{
				fail("re-encoded signature failed to verify!");
			}
		}

		private void generateAndSignBC()
		{
			ECKeyPairGenerator keyGen = new ECKeyPairGenerator();

			X9ECParameters x9ECParameters = NISTNamedCurves.getByName("P-256");
			keyGen.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(NISTNamedCurves.getOID("P-256"), x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN()), new SecureRandom()));

			AsymmetricCipherKeyPair kpEnc = keyGen.generateKeyPair();

			PGPKeyPair ecdsaKeyPair = new BcPGPKeyPair(PGPPublicKey.ECDSA, kpEnc, DateTime.Now);

			//
			// try a signature
			//
			PGPSignatureGenerator signGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags_Fields.SHA256));

			signGen.init(PGPSignature.BINARY_DOCUMENT, ecdsaKeyPair.getPrivateKey());

			signGen.update("hello world!".GetBytes());

			PGPSignature sig = signGen.generate();

			sig.init(new BcPGPContentVerifierBuilderProvider(), ecdsaKeyPair.getPublicKey());

			sig.update("hello world!".GetBytes());

			if (!sig.verify())
			{
				fail("signature failed to verify!");
			}

			//
			// generate a key ring
			//
			char[] passPhrase = "test".ToCharArray();
			PGPDigestCalculator sha1Calc = (new BcPGPDigestCalculatorProvider()).get(HashAlgorithmTags_Fields.SHA1);
			PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, ecdsaKeyPair, "test@bouncycastle.org", sha1Calc, null, null, new BcPGPContentSignerBuilder(ecdsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags_Fields.SHA1), (new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc)).setProvider("BC").build(passPhrase));

			PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

			PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

			KeyFingerPrintCalculator fingerCalc = new BcKeyFingerprintCalculator();

			PGPPublicKeyRing pubRingEnc = new PGPPublicKeyRing(pubRing.getEncoded(), fingerCalc);

			if (!Arrays.areEqual(pubRing.getEncoded(), pubRingEnc.getEncoded()))
			{
				fail("public key ring encoding failed");
			}

			PGPSecretKeyRing secRingEnc = new PGPSecretKeyRing(secRing.getEncoded(), fingerCalc);

			if (!Arrays.areEqual(secRing.getEncoded(), secRingEnc.getEncoded()))
			{
				fail("secret key ring encoding failed");
			}


			//
			// try a signature using encoded key
			//
			signGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags_Fields.SHA256));

			signGen.init(PGPSignature.BINARY_DOCUMENT, secRing.getSecretKey().extractPrivateKey((new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())).build(passPhrase)));

			signGen.update("hello world!".GetBytes());

			sig = signGen.generate();

			sig.init(new BcPGPContentVerifierBuilderProvider(), secRing.getSecretKey().getPublicKey());

			sig.update("hello world!".GetBytes());

			if (!sig.verify())
			{
				fail("re-encoded signature failed to verify!");
			}
		}

		public override void performTest()
		{
			//
			// Read the public key
			//
			PGPPublicKeyRing pubKeyRing = new PGPPublicKeyRing(testPubKey, new JcaKeyFingerprintCalculator());

			for (Iterator it = pubKeyRing.getPublicKey().getSignatures(); it.hasNext();)
			{
				PGPSignature certification = (PGPSignature)it.next();

				certification.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), pubKeyRing.getPublicKey());

				if (!certification.verifyCertification((string)pubKeyRing.getPublicKey().getUserIDs().next(), pubKeyRing.getPublicKey()))
				{
					fail("self certification does not verify");
				}
			}

			if (pubKeyRing.getPublicKey().getBitStrength() != 256)
			{
				fail("incorrect bit strength returned");
			}

			//
			// Read the private key
			//
			PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(testPrivKey, new JcaKeyFingerprintCalculator());

			PGPPrivateKey privKey = secretKeyRing.getSecretKey().extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).build(testPasswd));

			generateAndSign();
			generateAndSignBC();

			//
			// sExpr
			//
			PGPSecretKey key = PGPSecretKey.parseSecretKeyFromSExpr(new ByteArrayInputStream(sExprKey), new JcePBEProtectionRemoverFactory("test".ToCharArray()), new JcaKeyFingerprintCalculator());

			PGPSignatureGenerator signGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags_Fields.SHA256)).setProvider("BC"));

			signGen.init(PGPSignature.BINARY_DOCUMENT, key.extractPrivateKey(null));

			signGen.update("hello world!".GetBytes());

			PGPSignature sig = signGen.generate();

			sig.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), key.getPublicKey());

			sig.update("hello world!".GetBytes());

			if (!sig.verify())
			{
				fail("signature failed to verify!");
			}
		}

		public override string getName()
		{
			return "PGPECDSATest";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new PGPECDSATest());
		}
	}

}