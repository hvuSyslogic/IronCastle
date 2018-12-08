using System;

namespace org.bouncycastle.jce.provider.test
{

	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using X509V3CertificateGenerator = org.bouncycastle.x509.X509V3CertificateGenerator;

	/// <summary>
	/// Exercise the various key stores, making sure we at least get back what we put in!
	/// <para>
	/// This tests both the BKS, and the UBER key store.
	/// </para>
	/// </summary>
	public class KeyStoreTest : SimpleTest
	{
		internal static char[] passwd = new char[] {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

		internal byte[] v1BKS = Base64.decode("AAAAAQAAABTqZbNMyPjsFazhFplWWDMBLPRdRAAABcYEAAdhbmRyb2lkAAAB" + "NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8" + "q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wD0b8OP5/XzOz/8knhxmqJZ" + "3yRJMw==");
		internal byte[] v2BKS = Base64.decode("AAAAAgAAABSkmTXz4VIznO1SSUqsIHdxWcxsuQAABFMEAAdhbmRyb2lkAAABN" + "OifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8q2" + "0AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wBO59KOGPvSrmJpd32P6ZAh9qLZJw==");

		internal byte[] v1UBER = Base64.decode("AAAAAQAAABRP0F6p2p3FyQKqyJiJt3NbvdybiwAAB2znqrO779YIW5gMtbt+" + "NUs96VPPcfZiKJPg7RKH7Yu3CQB0/g9nYsvgFB0fQ05mHcW3KjntN2/31A6G" + "i00n4ZnUTjJL16puZnQrloeGXxFy58tjwkFuwJ7V7ELYgiZlls0beHSdDGQW" + "iyYECwWs1la/");
		internal byte[] v2UBER = Base64.decode("AAAAAgAAABQ/D9k3376OG/REg4Ams9Up332tLQAABujoVcsRcKWwhlo4mMg5" + "lF2vJfK+okIYecJGWCvdykF5r8kDn68llt52IDXDkpRXVXcNJ0/aD7sa7iZ0" + "SL0TAwcfp/9v4j/w8slj/qgO0i/76+zROrP0NGFIa5k/iOg5Z0Tj77muMaJf" + "n3vLlIHa4IsX");

		internal byte[] negSaltBKS = Base64.decode("AAAAAv////+WnyglO06djy6JgCxGiIemnZdcOwAAB2AEAAdhbmRyb2lkAAAB" + "NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8" + "q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wDrg6gUHsh27wNjUwkR+REe" + "NeFYBg==");

		internal char[] oldStorePass = "fredfred".ToCharArray();

		public virtual void ecStoreTest(string storeName)
		{
			X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
			ECCurve curve = x9.getCurve();
			ECParameterSpec ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

			g.initialize(ecSpec, new SecureRandom());

			KeyPair keyPair = g.generateKeyPair();

			PublicKey pubKey = keyPair.getPublic();
			PrivateKey privKey = keyPair.getPrivate();

			//
			// distinguished name table.
			//
			Hashtable attrs = new Hashtable();
			Vector order = new Vector();

			attrs.put(X509Principal.C, "AU");
			attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
			attrs.put(X509Principal.L, "Melbourne");
			attrs.put(X509Principal.ST, "Victoria");
			attrs.put(X509Principal.E, "feedback-crypto@bouncycastle.org");

			order.addElement(X509Principal.C);
			order.addElement(X509Principal.O);
			order.addElement(X509Principal.L);
			order.addElement(X509Principal.ST);
			order.addElement(X509Principal.E);

			//
			// create the certificate - version 3
			//
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

			certGen.setSerialNumber(BigInteger.valueOf(1));
			certGen.setIssuerDN(new X509Principal(order, attrs));
			certGen.setNotBefore(new DateTime(System.currentTimeMillis() - 50000));
			certGen.setNotAfter(new DateTime(System.currentTimeMillis() + 50000));
			certGen.setSubjectDN(new X509Principal(order, attrs));
			certGen.setPublicKey(pubKey);
			certGen.setSignatureAlgorithm("ECDSAwithSHA1");

			Certificate[] chain = new Certificate[1];

			try
			{
				X509Certificate cert = certGen.generate(privKey);

				cert.checkValidity(DateTime.Now);

				cert.verify(pubKey);

				ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
				CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

				cert = (X509Certificate)fact.generateCertificate(bIn);

				chain[0] = cert;
			}
			catch (Exception e)
			{
				fail("error generating cert - " + e.ToString());
			}

			KeyStore store = KeyStore.getInstance(storeName, "BC");

			store.load(null, null);

			store.setKeyEntry("private", privKey, passwd, chain);

			//
			// write out and read back store
			//
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store.store(bOut, passwd);

			ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());

			//
			// start with a new key store
			//
			store = KeyStore.getInstance(storeName, "BC");

			store.load(bIn, passwd);

			//
			// load the private key
			//
			privKey = (PrivateKey)store.getKey("private", passwd);

			//
			// double public key encoding test
			//
			byte[] pubEnc = pubKey.getEncoded();
			KeyFactory keyFac = KeyFactory.getInstance(pubKey.getAlgorithm(), "BC");
			X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(pubEnc);

			pubKey = (PublicKey)keyFac.generatePublic(pubX509);

			pubEnc = pubKey.getEncoded();
			keyFac = KeyFactory.getInstance(pubKey.getAlgorithm(), "BC");
			pubX509 = new X509EncodedKeySpec(pubEnc);

			pubKey = (PublicKey)keyFac.generatePublic(pubX509);

			//
			// double private key encoding test
			//
			byte[] privEnc = privKey.getEncoded();

			keyFac = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");

			PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
			privKey = (PrivateKey)keyFac.generatePrivate(privPKCS8);

			keyFac = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");
			privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
			privKey = (PrivateKey)keyFac.generatePrivate(privPKCS8);
		}

		public virtual void keyStoreTest(string storeName)
		{
			KeyStore store = KeyStore.getInstance(storeName, "BC");

			store.load(null, null);

			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");

			gen.initialize(1024, new SecureRandom());

			KeyPair pair = gen.generateKeyPair();
			RSAPrivateKey privKey = (RSAPrivateKey)pair.getPrivate();
			RSAPublicKey pubKey = (RSAPublicKey)pair.getPublic();
			BigInteger modulus = privKey.getModulus();
			BigInteger privateExponent = privKey.getPrivateExponent();


			//
			// distinguished name table.
			//
			Hashtable attrs = new Hashtable();
			Vector order = new Vector();

			attrs.put(X509Principal.C, "AU");
			attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
			attrs.put(X509Principal.L, "Melbourne");
			attrs.put(X509Principal.ST, "Victoria");
			attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");

			order.addElement(X509Principal.C);
			order.addElement(X509Principal.O);
			order.addElement(X509Principal.L);
			order.addElement(X509Principal.ST);
			order.addElement(X509Principal.EmailAddress);

			//
			// extensions
			//

			//
			// create the certificate.
			//
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

			certGen.setSerialNumber(BigInteger.valueOf(1));
			certGen.setIssuerDN(new X509Principal(order, attrs));
			certGen.setNotBefore(new DateTime(System.currentTimeMillis() - 50000));
			certGen.setNotAfter(new DateTime(System.currentTimeMillis() + 50000));
			certGen.setSubjectDN(new X509Principal(order, attrs));
			certGen.setPublicKey(pubKey);
			certGen.setSignatureAlgorithm("MD5WithRSAEncryption");

			Certificate[] chain = new Certificate[1];

			try
			{
				X509Certificate cert = certGen.generate(privKey);

				cert.checkValidity(DateTime.Now);

				cert.verify(pubKey);

				ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
				CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

				cert = (X509Certificate)fact.generateCertificate(bIn);

				chain[0] = cert;
			}
			catch (Exception e)
			{
				fail("error generating cert - " + e.ToString());
			}

			store.setKeyEntry("private", privKey, passwd, chain);

			//
			// write out and read back store
			//
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store.store(bOut, passwd);

			ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());

			//
			// start with a new key store
			//
			store = KeyStore.getInstance(storeName, "BC");

			store.load(bIn, passwd);

			//
			// verify public key
			//
			privKey = (RSAPrivateKey)store.getKey("private", passwd);

			if (!privKey.getModulus().Equals(modulus))
			{
				fail("private key modulus wrong");
			}
			else if (!privKey.getPrivateExponent().Equals(privateExponent))
			{
				fail("private key exponent wrong");
			}

			//
			// verify certificate
			//
			Certificate cert = store.getCertificateChain("private")[0];

			cert.verify(pubKey);
		}

		private void oldStoreTest()
		{
			checkStore(KeyStore.getInstance("BKS", "BC"), v1BKS);
			checkStore(KeyStore.getInstance("BKS", "BC"), v2BKS);
			checkStore(KeyStore.getInstance("UBER", "BC"), v1UBER);
			checkStore(KeyStore.getInstance("UBER", "BC"), v2UBER);

			checkOldStore(KeyStore.getInstance("BKS-V1", "BC"), v1BKS);
			checkOldStore(KeyStore.getInstance("BKS-V1", "BC"), v2BKS);
		}

		private void checkStore(KeyStore ks, byte[] data)
		{
			ks.load(new ByteArrayInputStream(data), oldStorePass);

			if (!ks.containsAlias("android"))
			{
				fail("cannot find alias");
			}

			Key key = ks.getKey("android", oldStorePass);
			if (key == null)
			{
				fail("cannot find key");
			}

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			ks.store(bOut, oldStorePass);
		}

		private void checkOldStore(KeyStore ks, byte[] data)
		{
			ks.load(new ByteArrayInputStream(data), oldStorePass);

			if (!ks.containsAlias("android"))
			{
				fail("cannot find alias");
			}

			Key key = ks.getKey("android", oldStorePass);
			if (key == null)
			{
				fail("cannot find key");
			}

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			ks.store(bOut, oldStorePass);

			if (data.Length != bOut.toByteArray().length)
			{
				fail("Old version key store write incorrect");
			}
		}

		private void checkException()
		{
			KeyStore ks = KeyStore.getInstance("BKS", "BC");

			try
			{
				ks.load(new ByteArrayInputStream(negSaltBKS), oldStorePass);
			}
			catch (IOException e)
			{
				if (!e.Message.Equals("Invalid salt detected"))
				{
					fail("negative salt length not detected");
				}
			}
		}

		public override string getName()
		{
			return "KeyStore";
		}

		public override void performTest()
		{
			keyStoreTest("BKS");
			keyStoreTest("UBER");
			keyStoreTest("BKS-V1");
			ecStoreTest("BKS");
			oldStoreTest();
			checkException();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new KeyStoreTest());
		}
	}

}