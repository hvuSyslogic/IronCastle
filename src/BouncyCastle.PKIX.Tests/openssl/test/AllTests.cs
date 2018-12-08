using org.bouncycastle.util.test;

namespace org.bouncycastle.openssl.test
{

	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPEMKeyConverter = org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
	using JcaPEMWriter = org.bouncycastle.openssl.jcajce.JcaPEMWriter;
	using JcaPKCS8Generator = org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
	using JceOpenSSLPKCS8DecryptorProviderBuilder = org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
	using JceOpenSSLPKCS8EncryptorBuilder = org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using PKCS8EncryptedPrivateKeyInfo = org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
	using PKCSException = org.bouncycastle.pkcs.PKCSException;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;

	public class AllTests : TestCase
	{
		private static readonly byte[] aesVec = Base64.decode("MIIC2zBVBgkqhkiG9w0BBQ0wSDAnBgkqhkiG9w0BBQwwGgQUJCXGcAtNlIKnbOigO9dFiEax0VACAggAMB0GCWCGSAFlAwQBKgQQHc1vpUS4cErEZut/nwhkSQSCAoACXZhhr0lx1Ww3d6t+ALjEbX8KopM/odVnYn8QWIvwDwKm+1eYL9e72XAu7pDM8yiYctnnFR9n+RfRj19b3GXIJkhxtLcIb0LqmRgy/Gna07PhrNXcWZ8i5kzt/wpxbgKI06k2bqCovYmfMkrLOnRIUNx8hRMvzQosjp32enKoeYRVPRii0VrKgzwPv1Qqyaq6uW4NErkMqoYJU3asFhB/OH6vSwOEVW69U13Ort8g0mmZJGDDHhctRbu29HMNROxGlGwt4t/EBOXTM2PHFS34zQK128Z2Zc6X7q7tSo1ENcNQqL9fnyoK4iXMu7bHKe0fslGw+s55b5KysSu6fcQfxIHA/GYpn5AKutdLTCzIiaPCdd5f5kWoijrTfcNKn9r8eWpgpSEFU5n96RNevGr7sYO3P0xL2wQQKb/V9AIIdFwyMfL0e5gR85ToG66AqK2pXSSfX7hqQYMyndeP9CRmhefG6/8cSUzrXXpx1WZ1U/U3E/asNlXwJ9AfFESLnT32s6es+1qLbHMZ7vkCxFyXZb2oK7+eduUB+5QbddEDlHhbpUpxbBkjpRq7rHO+T1m+ZWbjgD6EhVhmS5BXrlPHdWIfTUBdB0mwcvM4qVgEnEHqE+JGq71Xl12XhDH8sQHcd1NDLtVPY8GMIxFghvL7cPdfs8HccCdDv3dDcJw54Dn5xqWYPYitn/eMeJB5pnfekR/ko+zZd7dJlfU9JqjGyfpy3KnsShERSJd2LZDAvdb1Xp54ZsujblMc1kPyyzJfxBWDvoygCag0/42eHDp6vTIpYI3v+Wm/nWuVpq6JMAip0XFHEMhdMKW0SNp8gZxKTuDfCpVWvuF2WBVG1rKu");

		private static readonly byte[] desEDEVec = Base64.decode("MIIC0jBMBgkqhkiG9w0BBQ0wPzAnBgkqhkiG9w0BBQwwGgQUaFB4TMBDEqCMfFRIb2G8Hc72p7wCAggAMBQGCCqGSIb3DQMHBAiMXRDFMwbnhwSCAoBLCzHx112fm3JTTOrYy9eiNrbb6dcAqYGBM+3uJm9D6/QOJ1dQOJKmZXFKebs057X6Uy7dpntpBC23golF53Mx7I+cM50xb3VzAXRWfLBZ7DmxgVojF4YgPFSFoOsdpaw1wTkCqU16O5q4zIk6uVjbPYcK9WhGxSYBmnw7ih38a3nBpehTWrWjbjP9QjK2TV79RRlLkU//QVrTJdDuOUhyFthfigWrNvPuC1nM62JbgsVrIFfNqmn63Du2356NVk4ZbI+0rnVxRG4LhFZix1xqj5BvYpUpMSjU4JwzcBFWhImoIq0RqXcFIKpaVqxLU/fNG8qq0v5ydb5Bfa/Ln2vUk/+yc7Y6eS/aD0kQXoaq+06h81FRBkkmeFFTMxMCrMCuycq6Rgufq9X2h4e+6dmWfc/d+CwpMY5BrVEc04jeVF0gOKevrfIHa7bhJJUNtGKO5hpHmIBvcqcC6NhaX+CvFS/RWNknxqb+aobyr/N/+bvA5h5UDRPKbUlyUWOIpkl9TGKNGrNwe7UnhmB6XYe5h2Dc/X2VFeRn43QqCTHbjSMX+o3yjS51Uqd8ufBFplV7o4dvw+46097G113Pbn/Bbqpl5w90r+G6+w0jpK9pB51ZfY9oAgKKhtFJVh1UFm6sXG+TTK1g7Yq4/BFjDRSMlnaIgGI8WaSWYSluxHes/Ek6Tmybsin+YXajmdfCg4LLxQJ/1UXksmQ19gtytXjXFtNtnFHiTqI5cWSfWkYoY7LLJw8qKzc2eRX3rLPmAnlOgyHRZ732V05CmYayHN/n440BU0GmuEqmTeINqrLpnUeq7Y6UrXV8wusgWaEhqSMn4fW7a0HvjTKdrWHhq8gP");

		private static readonly byte[] desEDEpkcs12Vec = Base64.decode("MIICrjAoBgoqhkiG9w0BDAEDMBoEFA0yd6BYRViRmzBKN/MHaXcKT4hkAgIIAASCAoD5Z3YR8tVD4d+fyGVvvx3f+ePw/FRuB91fjJNukDAPpGbhVXm33b81GrrzucjTBHv5YciVQdyrhkRoqVNN77rOPJkMGENKkggJt+DuFcjqoMFB6Tkug7QhtwRn0n3jMjw7LraCOSuHg1bZm0vKmrRvzlvk+fcFWoa0+GKunbzM/b8/mg3nViOkxrrGEx5fcaXB97hwxniTz7tKmlj+BnV72XMt/RUh/IsXlDNX9iUfmm0cMKjKPz4Kll31GGbt4vG/iWsYJ0rF6XP8Dd5ZlUy+1q9GMM9M2/w6kffH8QxkWELbitUAaba3QV8+dzQrkAgW8yzThY3fEeg3dYGS1oKHdP8r+OiRQEkh196xAs8aFidAbkpWS76UoI/R7yMrphRa2u2P+0AySkOKLbbF9sCEUXEDupif2uSMxW39rIX1E8Nn4MW/onL0UxRNQ4ufiQdQX1UmNSVs5GyPm7iGH5FfouFGkH3oZeIcXHJEAGt1BkKFDwQyH0CbS6ynvOBGku7P5SlmNogqy2IgLl3o4emyJc8Xi1S7Ygt+LdWNrSVmOIMAOJlrjVlVezOCAEGbsZyU/HgskZPVSbDTZydCvY9rY3htbnq+sm+4Ug8lrDsxkP+5NOu2YEcegPItj/EV0AWH6r96gzYuNPtkp+ij1MJn5He1Ms5Th6yhSL5Opuq20TNSS61Cml3Put7H402x+R+W+eLkf/7V10uKOZxT9RNKe6pd5HbO17nuY1/yMdq6WL5+B2YTOkBUl96Pn4frlOnu3Ll0h+27t/1rgeWWgXTU4YTxOrolI/ZIvIfaDAl34NeqmZQbRFy0wnLTH6fgOaBa+rgiOfHTc/PXMkALMHiu");

		public virtual void testOpenSSL()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}

			Test[] tests = new Test[]
			{
				new WriterTest(),
				new ParserTest()
			};

			for (int i = 0; i != tests.Length; i++)
			{
				SimpleTestResult result = (SimpleTestResult)tests[i].perform();

				if (!result.isSuccessful())
				{
					fail(result.ToString());
				}
			}
		}

		public virtual void testPKCS8Encrypted()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}

			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(1024);

			PrivateKey key = kpGen.generateKeyPair().getPrivate();

			encryptedTestNew(key, PKCS8Generator.AES_256_CBC);
			encryptedTestNew(key, PKCS8Generator.DES3_CBC);
			encryptedTestNew(key, PKCS8Generator.PBE_SHA1_3DES);

			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA1);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA224);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA384);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA512);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA3_224);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA3_256);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA3_384);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA3_512);
			encryptedTestNew(key, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACGOST3411);
		}

		private void encryptedTestNew(PrivateKey key, ASN1ObjectIdentifier algorithm)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			JcaPEMWriter pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));

			JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(algorithm);

			encryptorBuilder.setProvider("BC");
			encryptorBuilder.setPasssword("hello".ToCharArray());

			PKCS8Generator pkcs8 = new JcaPKCS8Generator(key, encryptorBuilder.build());

			pWrt.writeObject(pkcs8);

			pWrt.close();

			PEMParser pRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));

			PKCS8EncryptedPrivateKeyInfo pInfo = (PKCS8EncryptedPrivateKeyInfo)pRd.readObject();

			PrivateKey rdKey = (new JcaPEMKeyConverter()).setProvider("BC").getPrivateKey(pInfo.decryptPrivateKeyInfo((new JceOpenSSLPKCS8DecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray())));


			assertEquals(key, rdKey);
		}

		private void encryptedTestNew(PrivateKey key, ASN1ObjectIdentifier algorithm, AlgorithmIdentifier prf)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			JcaPEMWriter pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));

			JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(algorithm);

			encryptorBuilder.setProvider("BC");
			encryptorBuilder.setPasssword("hello".ToCharArray());
			encryptorBuilder.setPRF(prf);

			PKCS8Generator pkcs8 = new JcaPKCS8Generator(key, encryptorBuilder.build());

			pWrt.writeObject(pkcs8);

			pWrt.close();

			PEMParser pRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));

			PKCS8EncryptedPrivateKeyInfo pInfo = (PKCS8EncryptedPrivateKeyInfo)pRd.readObject();

			PrivateKey rdKey = (new JcaPEMKeyConverter()).setProvider("BC").getPrivateKey(pInfo.decryptPrivateKeyInfo((new JceOpenSSLPKCS8DecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray())));


			assertEquals(key, rdKey);
		}

		public virtual void testVectors()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}

			PKCS8EncryptedPrivateKeyInfo encInfo = new PKCS8EncryptedPrivateKeyInfo(aesVec);

			PrivateKey key = (new JcaPEMKeyConverter()).setProvider("BC").getPrivateKey(encInfo.decryptPrivateKeyInfo((new JceOpenSSLPKCS8DecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray())));

			encInfo = new PKCS8EncryptedPrivateKeyInfo(desEDEVec);

			PrivateKey rdKey = (new JcaPEMKeyConverter()).setProvider("BC").getPrivateKey(encInfo.decryptPrivateKeyInfo((new JceOpenSSLPKCS8DecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray())));

			TestCase.assertEquals(key, rdKey);

			encInfo = new PKCS8EncryptedPrivateKeyInfo(desEDEpkcs12Vec);

			rdKey = (new JcaPEMKeyConverter()).setProvider("BC").getPrivateKey(encInfo.decryptPrivateKeyInfo((new JceOpenSSLPKCS8DecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray())));

			TestCase.assertEquals(key, rdKey);
		}

		public virtual void testPKCS8PlainNew()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}

			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(1024);

			PrivateKey key = kpGen.generateKeyPair().getPrivate();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			JcaPEMWriter pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));
			PKCS8Generator pkcs8 = new JcaPKCS8Generator(key, null);

			pWrt.writeObject(pkcs8);

			pWrt.close();

			PEMParser pRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));

			PrivateKeyInfo kp = (PrivateKeyInfo)pRd.readObject();

			PrivateKey rdKey = (new JcaPEMKeyConverter()).setProvider("BC").getPrivateKey(kp);

			assertEquals(key, rdKey);
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("OpenSSL Tests");

			suite.addTestSuite(typeof(AllTests));

			return new BCTestSetup(suite);
		}

		public class BCTestSetup : TestSetup
		{
			public BCTestSetup(Test test) : base(test)
			{
			}

			public virtual void setUp()
			{

			}

			public virtual void tearDown()
			{

			}
		}
	}

}