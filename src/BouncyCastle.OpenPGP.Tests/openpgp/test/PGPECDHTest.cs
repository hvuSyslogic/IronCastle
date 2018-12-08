using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.test
{

	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using ECKeyPairGenerator = org.bouncycastle.crypto.generators.ECKeyPairGenerator;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using PGPDigestCalculator = org.bouncycastle.openpgp.@operator.PGPDigestCalculator;
	using BcPGPDataEncryptorBuilder = org.bouncycastle.openpgp.@operator.bc.BcPGPDataEncryptorBuilder;
	using BcPGPKeyPair = org.bouncycastle.openpgp.@operator.bc.BcPGPKeyPair;
	using BcPublicKeyDataDecryptorFactory = org.bouncycastle.openpgp.@operator.bc.BcPublicKeyDataDecryptorFactory;
	using BcPublicKeyKeyEncryptionMethodGenerator = org.bouncycastle.openpgp.@operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcaPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentSignerBuilder;
	using JcaPGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentVerifierBuilderProvider;
	using JcaPGPDigestCalculatorProviderBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
	using JcaPGPKeyPair = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPKeyPair;
	using JcePBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyDecryptorBuilder;
	using JcePBESecretKeyEncryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyEncryptorBuilder;
	using JcePGPDataEncryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePGPDataEncryptorBuilder;
	using JcePublicKeyDataDecryptorFactoryBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
	using JcePublicKeyKeyEncryptionMethodGenerator = org.bouncycastle.openpgp.@operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using UncloseableOutputStream = org.bouncycastle.util.test.UncloseableOutputStream;

	public class PGPECDHTest : SimpleTest
	{
		internal byte[] testPubKey = Base64.decode("mFIEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT" + "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKstFBUZXN0IEVDRFNB" + "LUVDREggKEtleSBhbmQgc3Via2V5IGFyZSAyNTYgYml0cyBsb25nKSA8dGVzdC5l" + "Y2RzYS5lY2RoQGV4YW1wbGUuY29tPoh6BBMTCAAiBQJRvgbAAhsDBgsJCAcDAgYV" + "CAIJCgsEFgIDAQIeAQIXgAAKCRD3wDlWjFo9U5O2AQDi89NO6JbaIObC63jMMWsi" + "AaQHrBCPkDZLibgNv73DLgD/faouH4YZJs+cONQBPVnP1baG1NpWR5ppN3JULFcr" + "hcq4VgRRvgbAEggqhkjOPQMBBwIDBLtY8Nmfz0zSEa8C1snTOWN+VcT8pXPwgJRy" + "z6kSP4nPt1xj1lPKj5zwPXKWxMkPO9ocqhKdg2mOh6/rc1ObIoMDAQgHiGEEGBMI" + "AAkFAlG+BsACGwwACgkQ98A5VoxaPVN8cgEAj4dMNMNwRSg2ZBWunqUAHqIedVbS" + "dmwmbysD192L3z4A/ReXEa0gtv8OFWjuALD1ovEK8TpDORLUb6IuUb5jUIzY");

		internal byte[] testPrivKey = Base64.decode("lKUEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT" + "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKs/gcDAo11YYCae/K2" + "1uKGJ/uU4b4QHYnPIsAdYpuo5HIdoAOL/WwduRa8C6vSFrtMJLDqPK3BUpMz3CXN" + "GyMhjuaHKP5MPbBZkIfgUGZO5qvU9+i0UFRlc3QgRUNEU0EtRUNESCAoS2V5IGFu" + "ZCBzdWJrZXkgYXJlIDI1NiBiaXRzIGxvbmcpIDx0ZXN0LmVjZHNhLmVjZGhAZXhh" + "bXBsZS5jb20+iHoEExMIACIFAlG+BsACGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4B" + "AheAAAoJEPfAOVaMWj1Tk7YBAOLz007oltog5sLreMwxayIBpAesEI+QNkuJuA2/" + "vcMuAP99qi4fhhkmz5w41AE9Wc/VtobU2lZHmmk3clQsVyuFyg==");

		internal byte[] testMessage = Base64.decode("hH4Dp5+FdoujIBwSAgMErx4BSvgXY3irwthgxU8zPoAoR+8rhmxdpwbw6ZJAO2GX" + "azWJ85JNcobHKDeGeUq6wkTFu+g6yG99gIX8J5xJAjBRhyCRcaFgwbdDV4orWTe3" + "iewiT8qs4BQ23e0c8t+thdKoK4thMsCJy7wSKqY0sJTSVAELroNbCOi2lcO15YmW" + "6HiuFH7VKWcxPUBjXwf5+Z3uOKEp28tBgNyDrdbr1BbqlgYzIKq/pe9zUbUXfitn" + "vFc6HcGhvmRQreQ+Yw1x3x0HJeoPwg==");

		private void generate()
		{
			//
			// Generate a master key
			//
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");

			keyGen.initialize(new ECGenParameterSpec("P-256"));

			KeyPair kpSign = keyGen.generateKeyPair();

			PGPKeyPair ecdsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDSA, kpSign, DateTime.Now);

			//
			// Generate an encryption key
			//
			keyGen = KeyPairGenerator.getInstance("ECDH", "BC");

			keyGen.initialize(new ECGenParameterSpec("P-256"));

			KeyPair kpEnc = keyGen.generateKeyPair();

			PGPKeyPair ecdhKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDH, kpEnc, DateTime.Now);

			//
			// generate a key ring
			//
			char[] passPhrase = "test".ToCharArray();
			PGPDigestCalculator sha1Calc = (new JcaPGPDigestCalculatorProviderBuilder()).build().get(HashAlgorithmTags_Fields.SHA1);
			PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, ecdsaKeyPair, "test@bouncycastle.org", sha1Calc, null, null, (new JcaPGPContentSignerBuilder(ecdsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags_Fields.SHA1)).setProvider("BC"), (new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc)).setProvider("BC").build(passPhrase));

			keyRingGen.addSubKey(ecdhKeyPair);

			PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

			// TODO: add check of KdfParameters
			doBasicKeyRingCheck(pubRing);

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

			PGPPrivateKey pgpPrivKey = secRing.getSecretKey().extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(passPhrase));
		}

		private void testDecrypt(PGPSecretKeyRing secretKeyRing)
		{
			JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(testMessage);

			PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

			PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

			PGPSecretKey secretKey = secretKeyRing.getSecretKey(); // secretKeyRing.getSecretKey(encP.getKeyID());

	//        PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(new JcePBESecretKeyEncryptorBuilder());

	//        clear = encP.getDataStream(pgpPrivKey, "BC");
	//
	//        bOut.reset();
	//
	//        while ((ch = clear.read()) >= 0)
	//        {
	//            bOut.write(ch);
	//        }
	//
	//        out = bOut.toByteArray();
	//
	//        if (!areEqual(out, text))
	//        {
	//            fail("wrong plain text in generated packet");
	//        }
		}

		private void encryptDecryptTest()
		{
			byte[] text = new byte[] {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};


			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");

			keyGen.initialize(new ECGenParameterSpec("P-256"));

			KeyPair kpEnc = keyGen.generateKeyPair();

			PGPKeyPair ecdhKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDH, kpEnc, DateTime.Now);

			PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
			ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
			OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.Length, DateTime.Now);

			pOut.write(text);

			pOut.close();

			byte[] data = ldOut.toByteArray();

			ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

			PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags_Fields.CAST5)).setProvider("BC").setSecureRandom(new SecureRandom()));

			cPk.addMethod((new JcePublicKeyKeyEncryptionMethodGenerator(ecdhKeyPair.getPublicKey())).setProvider("BC"));

			OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.Length);

			cOut.write(data);

			cOut.close();

			JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

			PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

			PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

			InputStream clear = encP.getDataStream((new JcePublicKeyDataDecryptorFactoryBuilder()).setProvider("BC").build(ecdhKeyPair.getPrivateKey()));

			pgpF = new JcaPGPObjectFactory(clear);

			PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

			clear = ld.getInputStream();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			int ch;
			while ((ch = clear.read()) >= 0)
			{
				bOut.write(ch);
			}

			byte[] @out = bOut.toByteArray();

			if (!areEqual(@out, text))
			{
				fail("wrong plain text in generated packet");
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private void encryptDecryptBCTest(final String curve) throws Exception
		private void encryptDecryptBCTest(string curve)
		{
			byte[] text = new byte[] {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};


			ECKeyPairGenerator keyGen = new ECKeyPairGenerator();

			X9ECParameters x9ECParameters = ECNamedCurveTable.getByName(curve);
			keyGen.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(ECNamedCurveTable.getOID(curve), x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN()), new SecureRandom()));

			AsymmetricCipherKeyPair kpEnc = keyGen.generateKeyPair();

			PGPKeyPair ecdhKeyPair = new BcPGPKeyPair(PGPPublicKey.ECDH, kpEnc, DateTime.Now);

			PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
			ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
			OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.Length, DateTime.Now);

			pOut.write(text);

			pOut.close();

			byte[] data = ldOut.toByteArray();

			ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

			PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator((new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags_Fields.CAST5)).setSecureRandom(new SecureRandom()));

			cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(ecdhKeyPair.getPublicKey()));

			OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.Length);

			cOut.write(data);

			cOut.close();

			JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

			PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

			PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

			InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(ecdhKeyPair.getPrivateKey()));

			pgpF = new JcaPGPObjectFactory(clear);

			PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

			clear = ld.getInputStream();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			int ch;
			while ((ch = clear.read()) >= 0)
			{
				bOut.write(ch);
			}

			byte[] @out = bOut.toByteArray();

			if (!areEqual(@out, text))
			{
				fail("wrong plain text in generated packet");
			}
		}

		public override void performTest()
		{
			//
			// Read the public key
			//
			PGPPublicKeyRing pubKeyRing = new PGPPublicKeyRing(testPubKey, new JcaKeyFingerprintCalculator());

			doBasicKeyRingCheck(pubKeyRing);

			//
			// Read the private key
			//
			PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(testPrivKey, new JcaKeyFingerprintCalculator());

			testDecrypt(secretKeyRing);

			encryptDecryptTest();
			encryptDecryptBCTest("P-256");
			encryptDecryptBCTest("brainpoolP512r1");

			generate();
		}

		private void doBasicKeyRingCheck(PGPPublicKeyRing pubKeyRing)
		{
			for (Iterator it = pubKeyRing.getPublicKeys(); it.hasNext();)
			{
				PGPPublicKey pubKey = (PGPPublicKey)it.next();

				if (pubKey.isMasterKey())
				{
					if (pubKey.isEncryptionKey())
					{
						fail("master key showed as encryption key!");
					}
				}
				else
				{
					if (!pubKey.isEncryptionKey())
					{
						fail("sub key not encryption key!");
					}

					for (Iterator sigIt = pubKeyRing.getPublicKey().getSignatures(); sigIt.hasNext();)
					{
						PGPSignature certification = (PGPSignature)sigIt.next();

						certification.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), pubKeyRing.getPublicKey());

						if (!certification.verifyCertification((string)pubKeyRing.getPublicKey().getUserIDs().next(), pubKeyRing.getPublicKey()))
						{
							fail("subkey certification does not verify");
						}
					}
				}
			}
		}

		public override string getName()
		{
			return "PGPECDHTest";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new PGPECDHTest());
		}
	}

}