using org.bouncycastle.asn1.cms;

using System;

namespace org.bouncycastle.openssl.test
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using KeyPurposeId = org.bouncycastle.asn1.x509.KeyPurposeId;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using BcPEMDecryptorProvider = org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
	using JcaPEMKeyConverter = org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
	using JcaPEMWriter = org.bouncycastle.openssl.jcajce.JcaPEMWriter;
	using JceOpenSSLPKCS8DecryptorProviderBuilder = org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
	using JcePEMDecryptorProviderBuilder = org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
	using InputDecryptorProvider = org.bouncycastle.@operator.InputDecryptorProvider;
	using PKCS8EncryptedPrivateKeyInfo = org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// basic class for reading test.pem - the password is "secret"
	/// </summary>
	public class ParserTest : SimpleTest
	{
		public override string getName()
		{
			return "PEMParserTest";
		}


		private PEMParser openPEMResource(string fileName)
		{
			InputStream res = this.GetType().getResourceAsStream(fileName);
			Reader fRd = new BufferedReader(new InputStreamReader(res));
			return new PEMParser(fRd);
		}

		public override void performTest()
		{
			PEMParser pemRd = openPEMResource("test.pem");
			object o;
			PEMKeyPair pemPair;
			KeyPair pair;

			while ((o = pemRd.readObject()) != null)
			{
				if (o is KeyPair)
				{
					//pair = (KeyPair)o;

					//JavaSystem.@out.println(pair.getPublic());
					//JavaSystem.@out.println(pair.getPrivate());
				}
				else
				{
					//JavaSystem.@out.println(o.toString());
				}
			}

			// test bogus lines before begin are ignored.
			pemRd = openPEMResource("extratest.pem");

			while ((o = pemRd.readObject()) != null)
			{
				if (!(o is X509CertificateHolder))
				{
					fail("wrong object found");
				}
			}

			//
			// pkcs 7 data
			//
			pemRd = openPEMResource("pkcs7.pem");
			ContentInfo d = (ContentInfo)pemRd.readObject();

			if (!d.getContentType().Equals(CMSObjectIdentifiers_Fields.envelopedData))
			{
				fail("failed envelopedData check");
			}

			//
			// ECKey
			//
			pemRd = openPEMResource("eckey.pem");
			ASN1ObjectIdentifier ecOID = (ASN1ObjectIdentifier)pemRd.readObject();
			X9ECParameters ecSpec = ECNamedCurveTable.getByOID(ecOID);

			if (ecSpec == null)
			{
				fail("ecSpec not found for named curve");
			}

			pemPair = (PEMKeyPair)pemRd.readObject();

			pair = (new JcaPEMKeyConverter()).setProvider("BC").getKeyPair(pemPair);

			Signature sgr = Signature.getInstance("ECDSA", "BC");

			sgr.initSign(pair.getPrivate());

			byte[] message = new byte[] {(byte)'a', (byte)'b', (byte)'c'};

			sgr.update(message);

			byte[] sigBytes = sgr.sign();

			sgr.initVerify(pair.getPublic());

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail("EC verification failed");
			}

			if (!pair.getPublic().getAlgorithm().Equals("ECDSA"))
			{
				fail("wrong algorithm name on public got: " + pair.getPublic().getAlgorithm());
			}

			if (!pair.getPrivate().getAlgorithm().Equals("ECDSA"))
			{
				fail("wrong algorithm name on private");
			}

			//
			// ECKey -- explicit parameters
			//
			pemRd = openPEMResource("ecexpparam.pem");
			ecSpec = (X9ECParameters)pemRd.readObject();

			pemPair = (PEMKeyPair)pemRd.readObject();

			pair = (new JcaPEMKeyConverter()).setProvider("BC").getKeyPair(pemPair);

			sgr = Signature.getInstance("ECDSA", "BC");

			sgr.initSign(pair.getPrivate());

			message = new byte[] {(byte)'a', (byte)'b', (byte)'c'};

			sgr.update(message);

			sigBytes = sgr.sign();

			sgr.initVerify(pair.getPublic());

			sgr.update(message);

			if (!sgr.verify(sigBytes))
			{
				fail("EC verification failed");
			}

			if (!pair.getPublic().getAlgorithm().Equals("ECDSA"))
			{
				fail("wrong algorithm name on public got: " + pair.getPublic().getAlgorithm());
			}

			if (!pair.getPrivate().getAlgorithm().Equals("ECDSA"))
			{
				fail("wrong algorithm name on private");
			}

			//
			// writer/parser test
			//
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			pair = kpGen.generateKeyPair();

			keyPairTest("RSA", pair);

			kpGen = KeyPairGenerator.getInstance("DSA", "BC");
			kpGen.initialize(512, new SecureRandom());
			pair = kpGen.generateKeyPair();

			keyPairTest("DSA", pair);

			//
			// PKCS7
			//
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			JcaPEMWriter pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));

			pWrt.writeObject(d);

			pWrt.close();

			pemRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));
			d = (ContentInfo)pemRd.readObject();

			if (!d.getContentType().Equals(CMSObjectIdentifiers_Fields.envelopedData))
			{
				fail("failed envelopedData recode check");
			}


			// OpenSSL test cases (as embedded resources)
			doOpenSslDsaTest("unencrypted");
			doOpenSslRsaTest("unencrypted");

			doOpenSslTests("aes128");
			doOpenSslTests("aes192");
			doOpenSslTests("aes256");
			doOpenSslTests("blowfish");
			doOpenSslTests("des1");
			doOpenSslTests("des2");
			doOpenSslTests("des3");
			doOpenSslTests("rc2_128");

			doOpenSslDsaTest("rc2_40_cbc");
			doOpenSslRsaTest("rc2_40_cbc");
			doOpenSslDsaTest("rc2_64_cbc");
			doOpenSslRsaTest("rc2_64_cbc");

			doDudPasswordTest("7fd98", 0, "corrupted stream - out of bounds length found");
			doDudPasswordTest("ef677", 1, "corrupted stream - out of bounds length found");
			doDudPasswordTest("800ce", 2, "unknown tag 26 encountered");
			doDudPasswordTest("b6cd8", 3, "DEF length 81 object truncated by 56");
			doDudPasswordTest("28ce09", 4, "DEF length 110 object truncated by 28");
			doDudPasswordTest("2ac3b9", 5, "DER length more than 4 bytes: 11");
			doDudPasswordTest("2cba96", 6, "DEF length 100 object truncated by 35");
			doDudPasswordTest("2e3354", 7, "DEF length 42 object truncated by 9");
			doDudPasswordTest("2f4142", 8, "DER length more than 4 bytes: 14");
			doDudPasswordTest("2fe9bb", 9, "DER length more than 4 bytes: 65");
			doDudPasswordTest("3ee7a8", 10, "DER length more than 4 bytes: 57");
			doDudPasswordTest("41af75", 11, "unknown tag 16 encountered");
			doDudPasswordTest("1704a5", 12, "corrupted stream detected");
			doDudPasswordTest("1c5822", 13, "Extra data detected in stream");
			doDudPasswordTest("5a3d16", 14, "corrupted stream detected");
			doDudPasswordTest("8d0c97", 15, "corrupted stream detected");
			doDudPasswordTest("bc0daf", 16, "corrupted stream detected");
			doDudPasswordTest("aaf9c4d",17, "corrupted stream - out of bounds length found");

			doNoPasswordTest();
			doNoECPublicKeyTest();

			// encrypted private key test
			InputDecryptorProvider pkcs8Prov = (new JceOpenSSLPKCS8DecryptorProviderBuilder()).setProvider("BC").build("password".ToCharArray());
			pemRd = openPEMResource("enckey.pem");

			PKCS8EncryptedPrivateKeyInfo encPrivKeyInfo = (PKCS8EncryptedPrivateKeyInfo)pemRd.readObject();
			JcaPEMKeyConverter converter = (new JcaPEMKeyConverter()).setProvider("BC");

			RSAPrivateCrtKey privKey = (RSAPrivateCrtKey)converter.getPrivateKey(encPrivKeyInfo.decryptPrivateKeyInfo(pkcs8Prov));

			if (!privKey.getPublicExponent().Equals(new BigInteger("10001", 16)))
			{
				fail("decryption of private key data check failed");
			}

			// general PKCS8 test

			pemRd = openPEMResource("pkcs8test.pem");

			object privInfo;

			while ((privInfo = pemRd.readObject()) != null)
			{
				if (privInfo is PrivateKeyInfo)
				{
					privKey = (RSAPrivateCrtKey)converter.getPrivateKey(PrivateKeyInfo.getInstance(privInfo));
				}
				else
				{
					privKey = (RSAPrivateCrtKey)converter.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo)privInfo).decryptPrivateKeyInfo(pkcs8Prov));
				}
				if (!privKey.getPublicExponent().Equals(new BigInteger("10001", 16)))
				{
					fail("decryption of private key data check failed");
				}
			}

			pemRd = openPEMResource("trusted_cert.pem");

			X509TrustedCertificateBlock trusted = (X509TrustedCertificateBlock)pemRd.readObject();

			checkTrustedCert(trusted);

			StringWriter stringWriter = new StringWriter();

			pWrt = new JcaPEMWriter(stringWriter);

			pWrt.writeObject(trusted);

			pWrt.close();

			pemRd = new PEMParser(new StringReader(stringWriter.ToString()));

			trusted = (X509TrustedCertificateBlock)pemRd.readObject();

			checkTrustedCert(trusted);


		}

		private void checkTrustedCert(X509TrustedCertificateBlock trusted)
		{
			CertificateTrustBlock trustBlock = trusted.getTrustBlock();

			if (!"Fred".Equals(trustBlock.getAlias()))
			{
				fail("alias not found");
			}

			if (trustBlock.getUses().size() != 3)
			{
				fail("key purpose usages wrong size");
			}
			if (!trustBlock.getUses().contains(KeyPurposeId.id_kp_OCSPSigning))
			{
				fail("key purpose use not found");
			}

			if (trustBlock.getProhibitions().size() != 1)
			{
				fail("key purpose prohibitions wrong size");
			}
			if (!trustBlock.getProhibitions().contains(KeyPurposeId.id_kp_clientAuth))
			{
				fail("key purpose prohibition not found");
			}
		}

		private void keyPairTest(string name, KeyPair pair)
		{
			PEMParser pemRd;
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			JcaPEMWriter pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));

			pWrt.writeObject(pair.getPublic());

			pWrt.close();

			pemRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));

			SubjectPublicKeyInfo pub = SubjectPublicKeyInfo.getInstance(pemRd.readObject());
			JcaPEMKeyConverter converter = (new JcaPEMKeyConverter()).setProvider("BC");

			PublicKey k = converter.getPublicKey(pub);

			if (!k.Equals(pair.getPublic()))
			{
				fail("Failed public key read: " + name);
			}

			bOut = new ByteArrayOutputStream();
			pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));

			pWrt.writeObject(pair.getPrivate());

			pWrt.close();

			pemRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));

			KeyPair kPair = converter.getKeyPair((PEMKeyPair)pemRd.readObject());
			if (!kPair.getPrivate().Equals(pair.getPrivate()))
			{
				fail("Failed private key read: " + name);
			}

			if (!kPair.getPublic().Equals(pair.getPublic()))
			{
				fail("Failed private key public read: " + name);
			}
		}

		private void doOpenSslTests(string baseName)
		{
			doOpenSslDsaModesTest(baseName);
			doOpenSslRsaModesTest(baseName);
		}

		private void doOpenSslDsaModesTest(string baseName)
		{
			doOpenSslDsaTest(baseName + "_cbc");
			doOpenSslDsaTest(baseName + "_cfb");
			doOpenSslDsaTest(baseName + "_ecb");
			doOpenSslDsaTest(baseName + "_ofb");
		}

		private void doOpenSslRsaModesTest(string baseName)
		{
			doOpenSslRsaTest(baseName + "_cbc");
			doOpenSslRsaTest(baseName + "_cfb");
			doOpenSslRsaTest(baseName + "_ecb");
			doOpenSslRsaTest(baseName + "_ofb");
		}

		private void doOpenSslDsaTest(string name)
		{
			string fileName = "dsa/openssl_dsa_" + name + ".pem";

			doOpenSslTestFile(fileName, typeof(DSAPrivateKey));
		}

		private void doOpenSslRsaTest(string name)
		{
			string fileName = "rsa/openssl_rsa_" + name + ".pem";

			doOpenSslTestFile(fileName, typeof(RSAPrivateKey));
		}

		private void doOpenSslTestFile(string fileName, Class expectedPrivKeyClass)
		{
			keyDecryptTest(fileName, expectedPrivKeyClass, (new JcePEMDecryptorProviderBuilder()).setProvider("BC").build("changeit".ToCharArray()));
			keyDecryptTest(fileName, expectedPrivKeyClass, new BcPEMDecryptorProvider("changeit".ToCharArray()));
		}

		private void keyDecryptTest(string fileName, Class expectedPrivKeyClass, PEMDecryptorProvider decProv)
		{
			PEMParser pr = openPEMResource("data/" + fileName);
			object o = pr.readObject();

			if (o == null || !((o is PEMKeyPair) || (o is PEMEncryptedKeyPair)))
			{
				fail("Didn't find OpenSSL key");
			}

			JcaPEMKeyConverter converter = (new JcaPEMKeyConverter()).setProvider("BC");
			KeyPair kp = (o is PEMEncryptedKeyPair) ? converter.getKeyPair(((PEMEncryptedKeyPair)o).decryptKeyPair(decProv)) : converter.getKeyPair((PEMKeyPair)o);

			PrivateKey privKey = kp.getPrivate();

			if (!expectedPrivKeyClass.isInstance(privKey))
			{
				fail("Returned key not of correct type");
			}
		}

		private void doDudPasswordTest(string password, int index, string message)
		{
			// illegal state exception check - in this case the wrong password will
			// cause an underlying class cast exception.
			try
			{
				PEMDecryptorProvider decProv = (new JcePEMDecryptorProviderBuilder()).setProvider("BC").build(password.ToCharArray());

				PEMParser pemRd = openPEMResource("test.pem");
				object o;

				while ((o = pemRd.readObject()) != null)
				{
					if (o is PEMEncryptedKeyPair)
					{
						((PEMEncryptedKeyPair)o).decryptKeyPair(decProv);
					}
				}

				fail("issue not detected: " + index);
			}
			catch (IOException e)
			{
				if (e.InnerException != null && !e.InnerException.Message.EndsWith(message))
				{
				   fail("issue " + index + " exception thrown, but wrong message");
				}
				else if (e.InnerException == null && !e.Message.Equals(message))
				{
								   Console.WriteLine(e.ToString());
								   Console.Write(e.StackTrace);
				   fail("issue " + index + " exception thrown, but wrong message");
				}
			}
		}

		private void doNoPasswordTest()
		{
			PEMDecryptorProvider decProv = (new JcePEMDecryptorProviderBuilder()).setProvider("BC").build("".ToCharArray());

			PEMParser pemRd = openPEMResource("smimenopw.pem");
			object o;
			PrivateKeyInfo key = null;

			while ((o = pemRd.readObject()) != null)
			{
				 key = (PrivateKeyInfo)o;
			}

			if (key == null)
			{
				fail("private key not detected");
			}
		}

		private void doNoECPublicKeyTest()
		{
			// EC private key without the public key defined. Note: this encoding is actually invalid.
			string ecSample = "-----BEGIN EC PRIVATE KEY-----\n" +
						"MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgvYiiubZYNO1WXXi3\n" +
						"jmGT9DLeFemvlmR1zTA0FdcSAG2gCgYIKoZIzj0DAQehRANCAATNXYa06ykwhxuy\n" +
						"Dg+q6zsVqOLk9LtXz/1fzf9AkAVm9lBMTZAh+FRfregBgl08LATztGlTh/z0dPnp\n" +
						"dW2jFrDn\n" +
						"-----END EC PRIVATE KEY-----";

			PEMParser pemRd = new PEMParser(new StringReader(ecSample));

			PEMKeyPair kp = (PEMKeyPair)pemRd.readObject();

			isTrue(kp.getPublicKeyInfo() == null);
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new ParserTest());
		}
	}

}