using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.misc;
using org.bouncycastle.asn1.nist;

using System;

namespace org.bouncycastle.jce.provider.test
{


	using EncryptedObjectStoreData = org.bouncycastle.asn1.bc.EncryptedObjectStoreData;
	using ObjectStore = org.bouncycastle.asn1.bc.ObjectStore;
	using ObjectStoreIntegrityCheck = org.bouncycastle.asn1.bc.ObjectStoreIntegrityCheck;
	using PbkdMacIntegrityCheck = org.bouncycastle.asn1.bc.PbkdMacIntegrityCheck;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using ScryptParams = org.bouncycastle.asn1.misc.ScryptParams;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PBKDF2Config = org.bouncycastle.crypto.util.PBKDF2Config;
	using PBKDFConfig = org.bouncycastle.crypto.util.PBKDFConfig;
	using ScryptConfig = org.bouncycastle.crypto.util.ScryptConfig;
	using BCFKSLoadStoreParameter = org.bouncycastle.jcajce.BCFKSLoadStoreParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Exercise the  BCFKS KeyStore,
	/// </summary>
	public class BCFKSStoreTest : SimpleTest
	{
		private static byte[] trustedCertData = Base64.decode("MIIB/DCCAaagAwIBAgIBATANBgkqhkiG9w0BAQQFADCBhjELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIE" + "JvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExJjAkBgkqhkiG9w0BCQEWF2lzc3VlckBi" + "b3VuY3ljYXN0bGUub3JnMB4XDTE0MDIyODExMjcxMVoXDTE0MDQyOTExMjcxMVowgYcxCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaG" + "UgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMScwJQYJKoZI" + "hvcNAQkBFhhzdWJqZWN0QGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5" + "hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBETANBgkqhkiG9w0BAQQFAANBAJ/ZhfF21NykhbEY" + "RQrAo/yRr9XfpmBTVUSlLJXYoNVVRT5u9SGQqmPNfHElrTvNMZQPC0ridDZtBWb6S2tg9/E=");

		internal static char[] testPassword = new char[] {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
		internal static char[] invalidTestPassword = new char[] {'Y', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

		internal static byte[] kwpKeyStore = Base64.decode("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");

		internal static byte[] oldKeyStoreNoPW = Base64.decode("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" + "gEAHiOUu5c=");

		internal static byte[] oldKeyStore = Base64.decode("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" + "SQhMQ5k+xZ4=");

		public virtual void shouldCreateEmptyBCFKSNoPassword()
		{
			checkEmptyStore(null);
		}

		public virtual void shouldCreateEmptyBCFKSPassword()
		{
			checkEmptyStore(testPassword);
		}

		private void checkEmptyStore(char[] passwd)
		{
			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			isTrue("", 0 == store1.size());
			isTrue("", !store1.aliases().hasMoreElements());

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, passwd);

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

			isTrue("", 0 == store2.size());
			isTrue("", !store2.aliases().hasMoreElements());

			checkInvalidLoad(store2, passwd, bOut.toByteArray());
		}

		private void checkInvalidLoad(KeyStore store, char[] passwd, byte[] data)
		{
			checkInvalidLoadForPassword(store, invalidTestPassword, data);

			if (passwd != null)
			{
				checkInvalidLoadForPassword(store, null, data);
			}
		}

		private void checkInvalidLoadForPassword(KeyStore store, char[] password, byte[] data)
		{
			try
			{
				store.load(new ByteArrayInputStream(data), password);
			}
			catch (IOException e)
			{
				isTrue("wrong message", "BCFKS KeyStore corrupted: MAC calculation failed.".Equals(e.Message));
			}

			isTrue("", 0 == store.size());
			isTrue("", !store.aliases().hasMoreElements());
		}

		public virtual void shouldStoreOneCertificate()
		{
			X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(trustedCertData));

			checkOneCertificate(cert, null);
			checkOneCertificate(cert, testPassword);
		}

		private void checkOneCertificate(X509Certificate cert, char[] passwd)
		{
			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			store1.setCertificateEntry("cert", cert);

			isTrue("", 1 == store1.size());
			Enumeration<string> en1 = store1.aliases();

			isTrue("", "cert".Equals(en1.nextElement()));
			isTrue("", !en1.hasMoreElements());

			certStorageCheck(store1, "cert", cert);

			DateTime entryDate = store1.getCreationDate("cert");

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, passwd);

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

			isTrue("", entryDate.Equals(store2.getCreationDate("cert")));
			isTrue("", 1 == store2.size());
			Enumeration<string> en2 = store2.aliases();

			isTrue("", "cert".Equals(en2.nextElement()));
			isTrue("", !en2.hasMoreElements());

			certStorageCheck(store2, "cert", cert);

			// check invalid load with content

			checkInvalidLoad(store2, passwd, bOut.toByteArray());

			// check deletion on purpose

			store1.deleteEntry("cert");

			isTrue("", 0 == store1.size());
			isTrue("", !store1.aliases().hasMoreElements());

			bOut = new ByteArrayOutputStream();

			store1.store(bOut, passwd);

			store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

			isTrue("", 0 == store2.size());
			isTrue("", !store2.aliases().hasMoreElements());
		}

		public virtual void shouldStoreOnePrivateKey()
		{
			PrivateKey privKey = getPrivateKey();

			X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(trustedCertData));

			checkOnePrivateKeyFips(privKey, new X509Certificate[]{cert}, null);
			checkOnePrivateKeyFips(privKey, new X509Certificate[]{cert}, testPassword);
			checkOnePrivateKeyDef(privKey, new X509Certificate[]{cert}, null);
			checkOnePrivateKeyDef(privKey, new X509Certificate[]{cert}, testPassword);
		}

		public virtual void shouldStoreOnePrivateKeyWithChain()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(512);

			KeyPair kp1 = kpGen.generateKeyPair();
			KeyPair kp2 = kpGen.generateKeyPair();

			X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withRSA", kp2);
			X509Certificate interCert = TestUtils.createCert(TestUtils.getCertSubject(finalCert), kp2.getPrivate(), "CN=EE", "SHA1withRSA", null, kp1.getPublic());

			checkOnePrivateKeyFips(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, null);
			checkOnePrivateKeyFips(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, testPassword);

			checkOnePrivateKeyDef(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, null);
			checkOnePrivateKeyDef(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, testPassword);
		}

		public virtual void shouldStoreOneECKeyWithChain()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

			kpGen.initialize(256);

			KeyPair kp1 = kpGen.generateKeyPair();
			KeyPair kp2 = kpGen.generateKeyPair();

			X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withECDSA", kp2);
			X509Certificate interCert = TestUtils.createCert(TestUtils.getCertSubject(finalCert), kp2.getPrivate(), "CN=EE", "SHA1withECDSA", null, kp1.getPublic());

			checkOnePrivateKeyFips(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, null);
			checkOnePrivateKeyFips(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, testPassword);

			checkOnePrivateKeyDef(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, null);
			checkOnePrivateKeyDef(kp1.getPrivate(), new X509Certificate[]{interCert, finalCert}, testPassword);
		}

		public virtual void shouldRejectInconsistentKeys()
		{
			PrivateKey privKey = getPrivateKey();

			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

			X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));

			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			try
			{
				store1.setKeyEntry("privkey", privKey, "hello".ToCharArray(), new X509Certificate[]{interCert});
				fail("no exception");
			}
			catch (KeyStoreException e)
			{
				isTrue("", "RSA keys do not have the same modulus".Equals(e.InnerException.Message));
			}
		}

		private void checkOnePrivateKeyFips(PrivateKey key, X509Certificate[] certs, char[] passwd)
		{
			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			checkOnePrivateKey(key, store1, certs, passwd);
		}

		private void checkOnePrivateKeyDef(PrivateKey key, X509Certificate[] certs, char[] passwd)
		{
			KeyStore store1 = KeyStore.getInstance("BCFKS-DEF", "BC");

			store1.load(null, null);

			checkOnePrivateKey(key, store1, certs, passwd);
		}

		private void checkOnePrivateKey(PrivateKey key, KeyStore store1, X509Certificate[] certs, char[] passwd)
		{
			store1.setKeyEntry("privkey", key, passwd, certs);

			isTrue("", 1 == store1.size());
			Enumeration<string> en1 = store1.aliases();

			isTrue("", "privkey".Equals(en1.nextElement()));
			isTrue("", !en1.hasMoreElements());

			privateKeyStorageCheck(store1, "privkey", key, certs[0], passwd);

			DateTime entryDate = store1.getCreationDate("privkey");

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, passwd);

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

			isTrue("", store2.getCertificateChain("privkey").length == certs.Length);
			Certificate[] sChain = store2.getCertificateChain("privkey");
			for (int i = 0; i != sChain.Length; i++)
			{
				isTrue("", certs[i].Equals(sChain[i]));
			}
			isTrue("", entryDate.Equals(store2.getCreationDate("privkey")));
			isTrue("", 1 == store2.size());
			Enumeration<string> en2 = store2.aliases();

			isTrue("", "privkey".Equals(en2.nextElement()));
			isTrue("", !en2.hasMoreElements());

			privateKeyStorageCheck(store2, "privkey", key, certs[0], passwd);

			// check invalid load with content

			checkInvalidLoad(store2, passwd, bOut.toByteArray());

			// check deletion on purpose

			store1.deleteEntry("privkey");

			isTrue("", 0 == store1.size());
			isTrue("", !store1.aliases().hasMoreElements());

			bOut = new ByteArrayOutputStream();

			store1.store(bOut, passwd);

			store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

			isTrue("", 0 == store2.size());
			isTrue("", !store2.aliases().hasMoreElements());
		}

		public virtual void shouldStoreMultipleKeys()
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(512);

			KeyPair kp1 = kpGen.generateKeyPair();
			KeyPair kp2 = kpGen.generateKeyPair();

			X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withRSA", kp2);
			X509Certificate interCert = TestUtils.createCert(TestUtils.getCertSubject(finalCert), kp2.getPrivate(), "CN=EE", "SHA1withRSA", null, kp1.getPublic());

			PrivateKey privKey = kp1.getPrivate();

			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

			X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(trustedCertData));

			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			store1.setKeyEntry("privkey", privKey, testPassword, new X509Certificate[]{interCert, finalCert});
			store1.setCertificateEntry("trusted", cert);
			SecretKeySpec aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "AES");
			store1.setKeyEntry("secret1", aesKey, "secretPwd1".ToCharArray(), null);
			SecretKeySpec edeKey = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "DESede");
			store1.setKeyEntry("secret2", edeKey, "secretPwd2".ToCharArray(), null);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, testPassword);

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), testPassword);

			isTrue("", 4 == store2.size());

			Key storeDesEde = store2.getKey("secret2", "secretPwd2".ToCharArray());

			isTrue("", edeKey.getAlgorithm().Equals(storeDesEde.getAlgorithm()));

			isTrue("", Arrays.areEqual(edeKey.getEncoded(), storeDesEde.getEncoded()));

			Key storeAes = store2.getKey("secret1", "secretPwd1".ToCharArray());
			isTrue("", Arrays.areEqual(aesKey.getEncoded(), storeAes.getEncoded()));
			isTrue("", aesKey.getAlgorithm().Equals(storeAes.getAlgorithm()));

			Key storePrivKey = store2.getKey("privkey", testPassword);
			isTrue("", privKey.Equals(storePrivKey));
			isTrue("", 2 == store2.getCertificateChain("privkey").length);

			Certificate storeCert = store2.getCertificate("trusted");
			isTrue("", cert.Equals(storeCert));

			isTrue("", null == store2.getCertificate("unknown"));

			isTrue("", null == store2.getCertificateChain("unknown"));

			isTrue("", !store2.isCertificateEntry("unknown"));

			isTrue("", !store2.isKeyEntry("unknown"));

			isTrue("", !store2.containsAlias("unknown"));
		}

		public virtual void shouldParseKWPKeyStore()
		{
			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

			X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(trustedCertData));

			SecretKeySpec aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "AES");
			SecretKeySpec edeKey = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "DESede");

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(kwpKeyStore), testPassword);

			isTrue("", 4 == store2.size());

			Key storeDesEde = store2.getKey("secret2", "secretPwd2".ToCharArray());

			isTrue("", edeKey.getAlgorithm().Equals(storeDesEde.getAlgorithm()));

			isTrue("", Arrays.areEqual(edeKey.getEncoded(), storeDesEde.getEncoded()));

			Key storeAes = store2.getKey("secret1", "secretPwd1".ToCharArray());
			isTrue("", Arrays.areEqual(aesKey.getEncoded(), storeAes.getEncoded()));
			isTrue("", aesKey.getAlgorithm().Equals(storeAes.getAlgorithm()));

			Key storePrivKey = store2.getKey("privkey", testPassword);
			isTrue("", 2 == store2.getCertificateChain("privkey").length);
			isTrue("", storePrivKey is RSAPrivateCrtKey);

			Certificate storeCert = store2.getCertificate("trusted");
			isTrue("", cert.Equals(storeCert));

			isTrue("", null == store2.getCertificate("unknown"));

			isTrue("", null == store2.getCertificateChain("unknown"));

			isTrue("", !store2.isCertificateEntry("unknown"));

			isTrue("", !store2.isKeyEntry("unknown"));

			isTrue("", !store2.containsAlias("unknown"));
		}

		public virtual void shouldStoreSecretKeys()
		{
			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			SecretKeySpec aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "AES");
			SecretKeySpec edeKey1 = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "DESede");
			SecretKeySpec edeKey2 = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "TripleDES");
			SecretKeySpec edeKey3 = new SecretKeySpec(Hex.decode("010102020404070708080b0b0d0d0e0e"), "TDEA");
			SecretKeySpec hmacKey1 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff"), "HmacSHA1");
			SecretKeySpec hmacKey224 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff"), "HmacSHA224");
			SecretKeySpec hmacKey256 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff01ff"), "HmacSHA256");
			SecretKeySpec hmacKey384 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff0102ff"), "HmacSHA384");
			SecretKeySpec hmacKey512 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0eff010203ff"), "HmacSHA512");

			SecretKeySpec camellia128 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "Camellia");
			SecretKeySpec camellia192 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f0001020304050607"), "Camellia");
			SecretKeySpec camellia256 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "Camellia");
			SecretKeySpec seed = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "SEED");
			SecretKeySpec aria128 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "ARIA");
			SecretKeySpec aria192 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f0001020304050607"), "ARIA");
			SecretKeySpec aria256 = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), "ARIA");

			store1.setKeyEntry("secret1", aesKey, "secretPwd1".ToCharArray(), null);
			store1.setKeyEntry("secret2", edeKey1, "secretPwd2".ToCharArray(), null);
			store1.setKeyEntry("secret3", edeKey2, "secretPwd3".ToCharArray(), null);
			store1.setKeyEntry("secret4", edeKey3, "secretPwd4".ToCharArray(), null);
			store1.setKeyEntry("secret5", hmacKey1, "secretPwd5".ToCharArray(), null);
			store1.setKeyEntry("secret6", hmacKey224, "secretPwd6".ToCharArray(), null);
			store1.setKeyEntry("secret7", hmacKey256, "secretPwd7".ToCharArray(), null);
			store1.setKeyEntry("secret8", hmacKey384, "secretPwd8".ToCharArray(), null);
			store1.setKeyEntry("secret9", hmacKey512, "secretPwd9".ToCharArray(), null);

			store1.setKeyEntry("secret10", camellia128, "secretPwd10".ToCharArray(), null);
			store1.setKeyEntry("secret11", camellia192, "secretPwd11".ToCharArray(), null);
			store1.setKeyEntry("secret12", camellia256, "secretPwd12".ToCharArray(), null);
			store1.setKeyEntry("secret13", seed, "secretPwd13".ToCharArray(), null);
			store1.setKeyEntry("secret14", aria128, "secretPwd14".ToCharArray(), null);
			store1.setKeyEntry("secret15", aria192, "secretPwd15".ToCharArray(), null);
			store1.setKeyEntry("secret16", aria256, "secretPwd16".ToCharArray(), null);

			checkSecretKey(store1, "secret1", "secretPwd1".ToCharArray(), aesKey);
			checkSecretKey(store1, "secret2", "secretPwd2".ToCharArray(), edeKey1); // TRIPLEDES and TDEA will convert to DESEDE
			checkSecretKey(store1, "secret3", "secretPwd3".ToCharArray(), edeKey1);
			checkSecretKey(store1, "secret4", "secretPwd4".ToCharArray(), edeKey1);
			// TODO:
	//        checkSecretKey(store1, "secret5", "secretPwd5".toCharArray(), hmacKey1);
	//        checkSecretKey(store1, "secret6", "secretPwd6".toCharArray(), hmacKey224);
	//        checkSecretKey(store1, "secret7", "secretPwd7".toCharArray(), hmacKey256);
	//        checkSecretKey(store1, "secret8", "secretPwd8".toCharArray(), hmacKey384);
	//        checkSecretKey(store1, "secret9", "secretPwd9".toCharArray(), hmacKey512);

			checkSecretKey(store1, "secret10", "secretPwd10".ToCharArray(), camellia128);
			checkSecretKey(store1, "secret11", "secretPwd11".ToCharArray(), camellia192);
			checkSecretKey(store1, "secret12", "secretPwd12".ToCharArray(), camellia256);
			checkSecretKey(store1, "secret13", "secretPwd13".ToCharArray(), seed);
			checkSecretKey(store1, "secret14", "secretPwd14".ToCharArray(), aria128);
			checkSecretKey(store1, "secret15", "secretPwd15".ToCharArray(), aria192);
			checkSecretKey(store1, "secret16", "secretPwd16".ToCharArray(), aria256);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, "secretkeytest".ToCharArray());

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), "secretkeytest".ToCharArray());

			checkSecretKey(store2, "secret1", "secretPwd1".ToCharArray(), aesKey);
			checkSecretKey(store2, "secret2", "secretPwd2".ToCharArray(), edeKey1); // TRIPLEDES and TDEA will convert to DESEDE
			checkSecretKey(store2, "secret3", "secretPwd3".ToCharArray(), edeKey1);
			checkSecretKey(store2, "secret4", "secretPwd4".ToCharArray(), edeKey1);
			// TODO:
	//        checkSecretKey(store2, "secret5", "secretPwd5".toCharArray(), hmacKey1);
	//        checkSecretKey(store2, "secret6", "secretPwd6".toCharArray(), hmacKey224);
	//        checkSecretKey(store2, "secret7", "secretPwd7".toCharArray(), hmacKey256);
	//        checkSecretKey(store2, "secret8", "secretPwd8".toCharArray(), hmacKey384);
	//        checkSecretKey(store2, "secret9", "secretPwd9".toCharArray(), hmacKey512);

			isTrue("", null == store2.getKey("secret17", new char[0]));
		}

		public virtual void shouldFailOnWrongPassword()
		{
			failOnWrongPasswordTest("IBCFKS");
			failOnWrongPasswordTest("IBCFKS-DEF");
		}

		public virtual void failOnWrongPasswordTest(string storeName)
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(512);

			KeyPair kp1 = kpGen.generateKeyPair();
			KeyPair kp2 = kpGen.generateKeyPair();

			X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withRSA", kp2);
			X509Certificate interCert = TestUtils.createCert(X500Name.getInstance(finalCert.getSubjectX500Principal().getEncoded()), kp2.getPrivate(), "CN=EE", "SHA1withRSA", null, kp1.getPublic());

			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			store1.setKeyEntry("privkey", kp1.getPrivate(), testPassword, new X509Certificate[]{interCert, finalCert});

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, testPassword);

			store1 = KeyStore.getInstance(storeName, "BC");

			store1.load(new ByteArrayInputStream(bOut.toByteArray()), testPassword);

			isTrue("privKey test 1", store1.getKey("privkey", testPassword) != null);

			try
			{
				store1.getKey("privkey", invalidTestPassword);
				fail("no exception");
			}
			catch (UnrecoverableKeyException e)
			{
				isEquals("wrong message, got : " + e.Message, "unable to recover key (privkey)", e.Message);
			}

			isTrue("privKey test 2", store1.getKey("privkey", testPassword) != null);
		}

		private void checkSecretKey(KeyStore store, string alias, char[] passwd, SecretKey key)
		{
			SecretKey sKey = (SecretKey)store.getKey(alias, passwd);

			isTrue("", Arrays.areEqual(key.getEncoded(), sKey.getEncoded()));
			isTrue("", key.getAlgorithm().Equals(sKey.getAlgorithm()));

			if (!store.isKeyEntry(alias))
			{
				fail("key not identified as key entry");
			}
			if (!store.entryInstanceOf(alias, typeof(KeyStore.SecretKeyEntry)))
			{
				fail("not identified as key entry via SecretKeyEntry");
			}
		}

		private PrivateKey getPrivateKey()
		{
			PrivateKey privKey = null;

			RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16), new BigInteger("11", 16), new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16), new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16), new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16), new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16), new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16), new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));


			try
			{
				KeyFactory fact = KeyFactory.getInstance("RSA", "BC");

				privKey = fact.generatePrivate(privKeySpec);
			}
			catch (Exception e)
			{
				fail("error setting up keys - " + e.ToString());
			}

			return privKey;
		}

		public virtual void shouldFailOnRemovesOrOverwrite()
		{
			failOnRemovesOrOverwrite("IBCFKS");
			failOnRemovesOrOverwrite("IBCFKS-DEF");
		}

		private void failOnRemovesOrOverwrite(string storeName)
		{
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

			kpGen.initialize(512);

			KeyPair kp1 = kpGen.generateKeyPair();
			KeyPair kp2 = kpGen.generateKeyPair();

			X509Certificate finalCert = TestUtils.createSelfSignedCert("CN=Final", "SHA1withRSA", kp2);
			X509Certificate interCert = TestUtils.createCert(X500Name.getInstance(finalCert.getSubjectX500Principal().getEncoded()), kp2.getPrivate(), "CN=EE", "SHA1withRSA", null, kp1.getPublic());

			KeyStore store1 = KeyStore.getInstance(storeName, "BC");

			store1.load(new ByteArrayInputStream(oldKeyStoreNoPW), null);

			try
			{
				store1.setKeyEntry("privkey", kp1.getPrivate(), testPassword, new X509Certificate[]{interCert, finalCert});
				fail("no exception");
			}
			catch (KeyStoreException e)
			{
				isTrue("set operation not supported in shared mode".Equals(e.Message));
			}

			try
			{
				store1.setKeyEntry("privkey", kp1.getPrivate().getEncoded(), new X509Certificate[]{interCert, finalCert});
				fail("no exception");
			}
			catch (KeyStoreException e)
			{
				isTrue("set operation not supported in shared mode".Equals(e.Message));
			}

			try
			{
				store1.setCertificateEntry("cert", interCert);
				fail("no exception");
			}
			catch (KeyStoreException e)
			{
				isTrue("set operation not supported in shared mode".Equals(e.Message));
			}

			try
			{
				store1.deleteEntry("privkey");
				fail("no exception");
			}
			catch (KeyStoreException e)
			{
				isTrue("delete operation not supported in shared mode".Equals(e.Message));
			}
		}

		public virtual void shouldStoreOneSecretKey()
		{
			checkOneSecretKey(new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES"), null);
			checkOneSecretKey(new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES"), testPassword);
		}

		private void checkOneSecretKey(SecretKey key, char[] passwd)
		{
			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			store1.setKeyEntry("seckey", key, passwd, null);

			isTrue("", 1 == store1.size());
			Enumeration<string> en1 = store1.aliases();

			isTrue("", "seckey".Equals(en1.nextElement()));
			isTrue("", !en1.hasMoreElements());

			secretKeyStorageCheck(store1, "seckey", key, passwd);

			DateTime entryDate = store1.getCreationDate("seckey");

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, passwd);

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

			isTrue("", entryDate.Equals(store2.getCreationDate("seckey")));
			isTrue("", 1 == store2.size());
			Enumeration<string> en2 = store2.aliases();

			isTrue("", "seckey".Equals(en2.nextElement()));
			isTrue("", !en2.hasMoreElements());

			secretKeyStorageCheck(store2, "seckey", key, passwd);

			// check invalid load with content

			checkInvalidLoad(store2, passwd, bOut.toByteArray());

			// check deletion on purpose

			store1.deleteEntry("seckey");

			isTrue("", 0 == store1.size());
			isTrue("", !store1.aliases().hasMoreElements());

			bOut = new ByteArrayOutputStream();

			store1.store(bOut, passwd);

			store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

			isTrue("", 0 == store2.size());
			isTrue("", !store2.aliases().hasMoreElements());
		}

		private void privateKeyStorageCheck(KeyStore store, string keyName, PrivateKey key, Certificate cert, char[] password)
		{
			if (!store.containsAlias(keyName))
			{
				fail("couldn't find alias privateKey");
			}

			if (store.isCertificateEntry(keyName))
			{
				fail("key identified as certificate entry");
			}

			if (!store.isKeyEntry(keyName))
			{
				fail("key not identified as key entry");
			}

			Key storeKey = store.getKey(keyName, password);

			if (store.getType().Equals("BCFKS"))
			{
				isTrue("", key.Equals(storeKey));
			}

			if (password != null)
			{
				try
				{
					store.getKey(keyName, null);
				}
				catch (UnrecoverableKeyException e)
				{
					isTrue("", e.Message.StartsWith("BCFKS KeyStore unable to recover private key (privkey)"));
				}
			}

			Certificate[] certificateChain = store.getCertificateChain(keyName);
			if (certificateChain == null)
			{
				fail("Did not return certificate chain");
			}
			isTrue("", cert.Equals(certificateChain[0]));

			isTrue("", keyName.Equals(store.getCertificateAlias(cert)));

			if (store.entryInstanceOf(keyName, typeof(KeyStore.TrustedCertificateEntry)))
			{
				fail("identified as TrustedCertificateEntry");
			}

			if (!store.entryInstanceOf(keyName, typeof(KeyStore.PrivateKeyEntry)))
			{
				fail("not identified as key entry via PrivateKeyEntry");
			}

			if (store.entryInstanceOf(keyName, typeof(KeyStore.SecretKeyEntry)))
			{
				fail("identified as key entry via SecretKeyEntry");
			}
		}

		private void certStorageCheck(KeyStore store, string certName, Certificate cert)
		{
			if (!store.containsAlias(certName))
			{
				fail("couldn't find alias " + certName);
			}

			if (!store.isCertificateEntry(certName))
			{
				fail("cert not identified as certificate entry");
			}

			if (store.isKeyEntry(certName))
			{
				fail("cert identified as key entry");
			}

			if (!store.entryInstanceOf(certName, typeof(KeyStore.TrustedCertificateEntry)))
			{
				fail("cert not identified as TrustedCertificateEntry");
			}

			if (store.entryInstanceOf(certName, typeof(KeyStore.PrivateKeyEntry)))
			{
				fail("cert identified as key entry via PrivateKeyEntry");
			}

			if (store.entryInstanceOf(certName, typeof(KeyStore.SecretKeyEntry)))
			{
				fail("cert identified as key entry via SecretKeyEntry");
			}

			if (!certName.Equals(store.getCertificateAlias(cert)))
			{
				fail("Did not return alias for certificate entry");
			}
		}

		private void secretKeyStorageCheck(KeyStore store, string keyName, SecretKey key, char[] password)
		{
			if (!store.containsAlias(keyName))
			{
				fail("couldn't find alias privateKey");
			}

			if (store.isCertificateEntry(keyName))
			{
				fail("key identified as certificate entry");
			}

			if (!store.isKeyEntry(keyName))
			{
				fail("key not identified as key entry");
			}

			Key storeKey = store.getKey(keyName, password);

			isTrue("", Arrays.areEqual(key.getEncoded(), storeKey.getEncoded()));

			if (password != null)
			{
				try
				{
					store.getKey(keyName, null);
				}
				catch (UnrecoverableKeyException e)
				{
					isTrue("", e.Message.StartsWith("BCFKS KeyStore unable to recover secret key (seckey)"));
				}
			}

			Certificate[] certificateChain = store.getCertificateChain(keyName);
			if (certificateChain != null)
			{
				fail("returned certificates!");
			}

			if (store.entryInstanceOf(keyName, typeof(KeyStore.TrustedCertificateEntry)))
			{
				fail("identified as TrustedCertificateEntry");
			}

			if (store.entryInstanceOf(keyName, typeof(KeyStore.PrivateKeyEntry)))
			{
				fail("identified as key entry via PrivateKeyEntry");
			}

			if (!store.entryInstanceOf(keyName, typeof(KeyStore.SecretKeyEntry)))
			{
				fail("not identified as key entry via SecretKeyEntry");
			}
		}

		private void shouldParseOldStores()
		{
			KeyStore store = KeyStore.getInstance("BCFKS", "BC");

			store.load(new ByteArrayInputStream(oldKeyStore), testPassword);

			checkStore(store, oldKeyStore, testPassword);

			store.load(new ByteArrayInputStream(oldKeyStoreNoPW), null);

			checkStore(store, oldKeyStoreNoPW, null);
		}

		private void checkStore(KeyStore store1, byte[] data, char[] passwd)
		{
			isEquals(store1.getCertificateChain("privkey").length, 2);
			isEquals(1, store1.size());
			Enumeration<string> en2 = store1.aliases();

			isEquals("privkey", en2.nextElement());
			isTrue(!en2.hasMoreElements());

			// check invalid load with content

			checkInvalidLoad(store1, passwd, data);

			try
			{
				store1.store(new ByteArrayOutputStream(), passwd);
				fail("no exception");
			}
			catch (IOException e)
			{
				isEquals("KeyStore not initialized", e.Message);
			}

			// check deletion on purpose

			store1.load(new ByteArrayInputStream(data), passwd);

			store1.deleteEntry("privkey");

			isEquals(0, store1.size());
			isTrue(!store1.aliases().hasMoreElements());

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, passwd);

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), passwd);

			isEquals(0, store2.size());
			isTrue(!store2.aliases().hasMoreElements());
		}

		private void shouldStoreUsingSCRYPT()
		{
			byte[] enc = doStoreUsingStoreParameter(new ScryptConfig.Builder(1024, 8, 1)
				.withSaltLength(20).build());

			ObjectStore store = ObjectStore.getInstance(enc);

			ObjectStoreIntegrityCheck integrityCheck = store.getIntegrityCheck();

			isEquals(integrityCheck.getType(), ObjectStoreIntegrityCheck.PBKD_MAC_CHECK);

			PbkdMacIntegrityCheck check = PbkdMacIntegrityCheck.getInstance(integrityCheck.getIntegrityCheck());

			isTrue("wrong MAC", check.getMacAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512));
			isTrue("wrong PBE", check.getPbkdAlgorithm().getAlgorithm().Equals(MiscObjectIdentifiers_Fields.id_scrypt));

			ScryptParams sParams = ScryptParams.getInstance(check.getPbkdAlgorithm().getParameters());

			isEquals(20, sParams.getSalt().Length);
			isEquals(1024, sParams.getCostParameter().intValue());
			isEquals(8, sParams.getBlockSize().intValue());
			isEquals(1, sParams.getParallelizationParameter().intValue());

			EncryptedObjectStoreData objStore = EncryptedObjectStoreData.getInstance(store.getStoreData());

			AlgorithmIdentifier encryptionAlgorithm = objStore.getEncryptionAlgorithm();
			isTrue(encryptionAlgorithm.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBES2));

			PBES2Parameters pbeParams = PBES2Parameters.getInstance(encryptionAlgorithm.getParameters());

			isTrue(pbeParams.getKeyDerivationFunc().getAlgorithm().Equals(MiscObjectIdentifiers_Fields.id_scrypt));

			sParams = ScryptParams.getInstance(pbeParams.getKeyDerivationFunc().getParameters());

			isEquals(20, sParams.getSalt().Length);
			isEquals(1024, sParams.getCostParameter().intValue());
			isEquals(8, sParams.getBlockSize().intValue());
			isEquals(1, sParams.getParallelizationParameter().intValue());
		}

		private void shouldStoreUsingKWP()
		{
			X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(trustedCertData));

			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load((new BCFKSLoadStoreParameter.Builder()).withStoreEncryptionAlgorithm(BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_KWP).build());

			store1.setCertificateEntry("cert", cert);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store(bOut, testPassword);

			byte[] enc = bOut.toByteArray();

			ObjectStore store = ObjectStore.getInstance(enc);

			ObjectStoreIntegrityCheck integrityCheck = store.getIntegrityCheck();

			isEquals(integrityCheck.getType(), ObjectStoreIntegrityCheck.PBKD_MAC_CHECK);

			PbkdMacIntegrityCheck check = PbkdMacIntegrityCheck.getInstance(integrityCheck.getIntegrityCheck());

			isTrue("wrong MAC", check.getMacAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512));
			isTrue("wrong PBE", check.getPbkdAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBKDF2));

			EncryptedObjectStoreData objStore = EncryptedObjectStoreData.getInstance(store.getStoreData());

			AlgorithmIdentifier encryptionAlgorithm = objStore.getEncryptionAlgorithm();
			isTrue(encryptionAlgorithm.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBES2));

			PBES2Parameters pbeParams = PBES2Parameters.getInstance(encryptionAlgorithm.getParameters());

			isTrue(pbeParams.getKeyDerivationFunc().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBKDF2));

			isTrue(pbeParams.getEncryptionScheme().getAlgorithm().Equals(NISTObjectIdentifiers_Fields.id_aes256_wrap_pad));
		}

		private void shouldStoreUsingPBKDF2()
		{
			doStoreUsingPBKDF2(PBKDF2Config.PRF_SHA512);
			doStoreUsingPBKDF2(PBKDF2Config.PRF_SHA3_512);
		}

		private void doStoreUsingPBKDF2(AlgorithmIdentifier prf)
		{
			byte[] enc = doStoreUsingStoreParameter(new PBKDF2Config.Builder()
				.withPRF(prf).withIterationCount(1024).withSaltLength(20).build());

			ObjectStore store = ObjectStore.getInstance(enc);

			ObjectStoreIntegrityCheck integrityCheck = store.getIntegrityCheck();

			isEquals(integrityCheck.getType(), ObjectStoreIntegrityCheck.PBKD_MAC_CHECK);

			PbkdMacIntegrityCheck check = PbkdMacIntegrityCheck.getInstance(integrityCheck.getIntegrityCheck());

			isTrue("wrong MAC", check.getMacAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512));
			isTrue("wrong PBE", check.getPbkdAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBKDF2));

			PBKDF2Params pParams = PBKDF2Params.getInstance(check.getPbkdAlgorithm().getParameters());

			isTrue(pParams.getPrf().Equals(prf));
			isEquals(20, pParams.getSalt().Length);
			isEquals(1024, pParams.getIterationCount().intValue());

			EncryptedObjectStoreData objStore = EncryptedObjectStoreData.getInstance(store.getStoreData());

			AlgorithmIdentifier encryptionAlgorithm = objStore.getEncryptionAlgorithm();
			isTrue(encryptionAlgorithm.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBES2));

			PBES2Parameters pbeParams = PBES2Parameters.getInstance(encryptionAlgorithm.getParameters());

			isTrue(pbeParams.getKeyDerivationFunc().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBKDF2));

			pParams = PBKDF2Params.getInstance(check.getPbkdAlgorithm().getParameters());

			isTrue(pParams.getPrf().Equals(prf));
			isEquals(20, pParams.getSalt().Length);
			isEquals(1024, pParams.getIterationCount().intValue());
		}

		private byte[] doStoreUsingStoreParameter(PBKDFConfig config)
		{
			X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(trustedCertData));

			KeyStore store1 = KeyStore.getInstance("BCFKS", "BC");

			store1.load(null, null);

			store1.setCertificateEntry("cert", cert);

			isTrue("", 1 == store1.size());
			Enumeration<string> en1 = store1.aliases();

			isTrue("", "cert".Equals(en1.nextElement()));
			isTrue("", !en1.hasMoreElements());

			certStorageCheck(store1, "cert", cert);

			DateTime entryDate = store1.getCreationDate("cert");

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			store1.store((new BCFKSLoadStoreParameter.Builder(bOut, testPassword)).withStorePBKDFConfig(config).build());

			KeyStore store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), testPassword);

			isTrue("", entryDate.Equals(store2.getCreationDate("cert")));
			isTrue("", 1 == store2.size());
			Enumeration<string> en2 = store2.aliases();

			isTrue("", "cert".Equals(en2.nextElement()));
			isTrue("", !en2.hasMoreElements());

			certStorageCheck(store2, "cert", cert);

			// check invalid load with content

			checkInvalidLoad(store2, testPassword, bOut.toByteArray());

			// check deletion on purpose

			store1.deleteEntry("cert");

			isTrue("", 0 == store1.size());
			isTrue("", !store1.aliases().hasMoreElements());

			bOut = new ByteArrayOutputStream();

			store1.store(bOut, testPassword);

			store2 = KeyStore.getInstance("BCFKS", "BC");

			store2.load(new ByteArrayInputStream(bOut.toByteArray()), testPassword);

			isTrue("", 0 == store2.size());
			isTrue("", !store2.aliases().hasMoreElements());

			return bOut.toByteArray();
		}

		public override string getName()
		{
			return "BCFKS";
		}

		public override void performTest()
		{
			shouldCreateEmptyBCFKSNoPassword();
			shouldCreateEmptyBCFKSPassword();
			shouldStoreMultipleKeys();
			shouldStoreOneCertificate();
			shouldStoreOneECKeyWithChain();
			shouldStoreOnePrivateKey();
			shouldStoreOnePrivateKeyWithChain();
			shouldStoreOneSecretKey();
			shouldStoreSecretKeys();
			shouldStoreUsingSCRYPT();
			shouldStoreUsingPBKDF2();
			shouldFailOnWrongPassword();
			shouldParseKWPKeyStore();
			shouldFailOnRemovesOrOverwrite();
			shouldParseOldStores();
			shouldStoreUsingKWP();
			//shouldRejectInconsistentKeys();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new BCFKSStoreTest());
		}
	}

}