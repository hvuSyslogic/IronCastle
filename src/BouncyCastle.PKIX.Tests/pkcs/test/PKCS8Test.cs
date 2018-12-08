using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.pkcs.test
{

	using TestCase = junit.framework.TestCase;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RSAPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PBKDFConfig = org.bouncycastle.crypto.util.PBKDFConfig;
	using ScryptConfig = org.bouncycastle.crypto.util.ScryptConfig;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcePKCSPBEInputDecryptorProviderBuilder = org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
	using JcePKCSPBEOutputEncryptorBuilder = org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;

	public class PKCS8Test : TestCase
	{
		private static BigInteger modulus = new BigInteger("b6ce33ccbf839457b0d32487b6c807bca584f85c627466b787fc09d0b1f73d97c9a381eca20e0ba851d317a8964327fa0010de76c" + "6c0facb83f13612752d166b49d9ba272c38c9a4ed71a94ea69f7bbdc63d7a5c5d3f3c039223e4ac1bb5d433c6bf01e68364a7ef4f" + "061f7cdfba82fa471bb1444b2034e53cc9c3e402a8fa89", 16);

		private static byte[] pkInfo = Base64.decode("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALbOM8y/g5RXsNMkh7bIB7ylhPhcYnRmt4f8CdCx9z2XyaOB7KIOC6hR" + "0xeolkMn+gAQ3nbGwPrLg/E2EnUtFmtJ2bonLDjJpO1xqU6mn3u9xj16XF0/PAOSI+SsG7XUM8a/AeaDZKfvTwYffN+6gvpHG7FESyA0" + "5TzJw+QCqPqJAgMBAAECgYAMQxCeb0o4LRmjUBP6YriCIugkcK35+NneuT0/TnCzJPdVjGV/CUom5DYwpBJQNuJCFt+VQAe5yuTyzRm3" + "2mpicusxKsMHqJRJFWIQ5ztuRehGF1KB+NPze7GxWVB2vRWJQQhlgq/nRsAjWoUfxbFkKBlNPhUnLm1klwBptpqpcQJBAOBiAnrrraBu" + "3Lc9B8QtCdEAIr5LYyWYd3jSvyTt04OI8Q3l7zG9omKpdIskGNu7n5RRYixsNXAVCaiHsyHHCO8CQQDQkGdtlH5fQZ2PJVSNZ6RlDhUq" + "6RGqajnkXw/sK1GR388FGqc9xTB9Eu1vg7ywlsuWSWpiCe/q+1nGVJufLAQHAkEAyTba5oQGNYJ1J1Txa/i/fs7SWTedd49cQ9spUeJ7" + "9M6O7FmvwDlAL52qR0Rdjl6YYhcBJLj8yr/y41CdUML9vQJAYGDqurOtNj2vHrAkg3fKezxnwb2UgUi3WfYn+H4IIr3m/7fSYvQVtSai" + "/C5Hat80U0230HhBGzhtwv3kMEj5zwJAViD4ceQRYyC+G2z5fyFz8Ca6sjDB9LwY0YEOFxR+3nqtteJI2vgITl4HrrnTRGuiVSY6pqkX" + "hX2DZcWDZMieLA==");

		private static byte[] pkcs8Sha256 = Base64.decode("MIIC9TBvBgkqhkiG9w0BBQ0wYjBBBgkqhkiG9w0BBQwwNAQgsa99yy9MqsJQ+4l5" + "SehvabVidNKBoJeqPJDZAPmbKCgCAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUD" + "BAEqBBBAncGTD5Yp0oqVklTgmzt4BIICgDJLy5EF12+l9cjYIRVLcHFc7QE7prBy" + "yj+nENvxqPJaVAVo+VVguOPUSGKQAeZnUhpU1kwKa4EyUhA5CvVtTcQ3hd7v769E" + "n59EJ2NKFNOmplxbE3QU/Z7g63ECDvu4jsUVjZmWGrzDXwDEkraG5VdtVhIfdFOj" + "yR1CEnxLqq5l3qlkCjKFap/UBh6wbsItJJYw4HJ/7fCJtY8xKG9b1hxHiyH2Yhrh" + "Pak2P4ukFClg8Kzv92ZbUKSv92C/zrlkUWx7+u7b97YZVd/nL4VLVnQW79YI7ApL" + "QHFNZ9Jp3cm3XtddzlJJVWwghF+slvULsGzQ05yMICyCRHEwPAPSXvf6VpNezQ+v" + "8mD+lS7IavJRx7S4y2NFzZCLDaZfX32/S4vRv7Q4Ax87YKHqHwLnZRLWn3QimtX5" + "oJPsf8Sj0/w31W49c7I3a4rWLAWO3fTVSvH+vQdPUCq9geqatOjiwSnUy6oSP4f3" + "vvdMlvNFafWyLwqONM8nKijNSSk8fjJtncvIDBCRYmwuQFmkFBRtCpHNeY43vrCV" + "O04x5N6PPTnnp/Ru7xYbrEyO2SQX/JJQV2l/pZgyF4w/2Y3i0hW+dItkoFVPGuY0" + "XfBgPlVx5w/72Et8GKh8a5E03IPJOa3J+/vhx9hYc7Hc4AJHsQQwiXco5ybBNZBV" + "wteKQwP6XRL5GMWJr4v4fJk0ksZ7sDAIlLWOeZu0jxWSx3VLC6QR9Ij+uMGkkY3t" + "nVxJii5qFSnWSH5e2Qk9HJ64a0ossKBFaln8wT/2tryBxa1+YZDYwGrasG4EvKHC" + "N0PVvCZ6nreGoWpaBlTolOl7HpbjcsryQ2SMkWNIurrivWKAoqRQ53Q=");


		private static byte[] pkcs8Gost3411 = Base64.decode("MIIC8zBtBgkqhkiG9w0BBQ0wYDA/BgkqhkiG9w0BBQwwMgQgo40hf88LUYklfxUE" + "HO0KjJFo52p9lEqfYDDmJJosDpYCAggAMAoGBiqFAwICCgUAMB0GCWCGSAFlAwQB" + "KgQQJXNzoxem4QvtoToJbJVt1ASCAoBtcnpMvp/Skip+m8e0A+Hh8BnzoRDkKoeD" + "QFuyR1HRfXa6iZ+CT5Bt38kM7shDA1se1uEo5WnDCydmzQ5WdHinMaokryd+3l65" + "AszZLrbK56E78820RMTwFevDAXcwhneomCkEg059r+GfO0OLe6YJ1JR88uiPWxJy" + "gthltJoefOnK87cG53oOPAmgKkMS0lbd13FeYduo9r2473O80CtTpA0p5GHFHdI8" + "9ebu8PWoGez+HR3FU5+m4Qj63spW2F1qblgocywABFqVCWVp/8h4dptQ7754jNmK" + "HN4MWgXYb5SdScz8IkE9Cv+Xn0tAW5eqhgYDot4GfbYRqCjup0jnCmgNxFo/TMOS" + "H1EMXeFnEEEft/fx8K1jZ1jtfJQRBY1N0jOBBzsMKVgj8GYkFAlOYXziCK+YzYjY" + "gmD2/IQ1+VfPnCkT14BqM9KzJidOjMDE9jlMiBhaBzee0qpdCLZ9bPQ0L6s6Urwm" + "mR7l1nCvLY5GYRBUC/ZOZf+MiPEpD/Lu+DUv5RgPEDStSXoKqtxvgpsT4upDVpEw" + "i4z7TWGpkcOGZJEe8JHEw5rDC15FHm44WoeFhlgLaFhjUD9Ou4CYM3LYT6VwUbmF" + "XBBVuKssFbbvOcU1ez4vfx7i8r09R/olVmopsiUBapyLwfck3hlQEYrAJKHQ9HFV" + "qYM9tU0OoaZB1qYYmLQPIe99cr66xTmfUkRQaJ2RAhbZQDPTX3Bm4SseEfmrkfuY" + "/RzOT5l2cgEOuTmkzhfgxVqyhOBeWfGPWYWtDD2QmQBcAHZbf9XVaoRe7YDRXTG/" + "WhEN3fKJaM/Qfif5wwWvHjQb5TWrTyeNNuh4YtXsyQ3PkwOxHrmm");

		// from RFC 7914
		private static byte[] pkcs8Scrypt = Base64.decode("MIHiME0GCSqGSIb3DQEFDTBAMB8GCSsGAQQB2kcECzASBAVNb3VzZQIDEAAAAgEI" + "AgEBMB0GCWCGSAFlAwQBKgQQyYmguHMsOwzGMPoyObk/JgSBkJb47EWd5iAqJlyy" + "+ni5ftd6gZgOPaLQClL7mEZc2KQay0VhjZm/7MbBUNbqOAXNM6OGebXxVp6sHUAL" + "iBGY/Dls7B1TsWeGObE0sS1MXEpuREuloZjcsNVcNXWPlLdZtkSH6uwWzR0PyG/Z" + "+ZXfNodZtd/voKlvLOw5B3opGIFaLkbtLZQwMiGtl42AS89lZg==");

		private static byte[] scryptKey = Base64.decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4RaNK5CuHY3CXr9f" + "/CdVgOhEurMohrQmWbbLZK4ZInyhRANCAARs2WMV6UMlLjLaoc0Dsdnj4Vlffc9T" + "t48lJU0RiCzXc280Vg/H5fm1xAP1B7UnIVcBqgDHDcfqWm1h/xSeCHXS");

		public virtual void setUp()
		{
			Security.addProvider(new BouncyCastleProvider());
		}

		public virtual void testSHA256()
		{
			PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(pkcs8Sha256);

			PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo((new JcePKCSPBEInputDecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray()));

			RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

			assertEquals(modulus, k.getModulus());
		}

		public virtual void testGOST3411()
		{
			PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(pkcs8Gost3411);

			PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo((new JcePKCSPBEInputDecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray()));

			RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

			assertEquals(modulus, k.getModulus());
		}

		public virtual void testScrypt()
		{
			if (getJvmVersion() < 7) // runs out of memory
			{
				return;
			}

			PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(pkcs8Scrypt);

			PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo((new JcePKCSPBEInputDecryptorProviderBuilder()).setProvider("BC").build("Rabbit".ToCharArray()));

			assertTrue(Arrays.areEqual(scryptKey, pkInfo.getEncoded()));
		}

		public virtual void testSHA256Encryption()
		{
			PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo);

			PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers_Fields.id_aes256_CBC)
					.setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, DERNull.INSTANCE)).setProvider("BC").build("hello".ToCharArray()));

			EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

			assertEquals(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, DERNull.INSTANCE), PBKDF2Params.getInstance(PBES2Parameters.getInstance(encPkInfo.getEncryptionAlgorithm().getParameters()).getKeyDerivationFunc().getParameters()).getPrf());

			PrivateKeyInfo pkInfo = encInfo.decryptPrivateKeyInfo((new JcePKCSPBEInputDecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray()));

			RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

			assertEquals(modulus, k.getModulus());
		}

		public virtual void testSHA3_256Encryption()
		{
			 PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo);

			 PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers_Fields.id_aes256_CBC)
					 .setPRF(new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, DERNull.INSTANCE)).setProvider("BC").build("hello".ToCharArray()));

			 EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

			 assertEquals(new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, DERNull.INSTANCE), PBKDF2Params.getInstance(PBES2Parameters.getInstance(encPkInfo.getEncryptionAlgorithm().getParameters()).getKeyDerivationFunc().getParameters()).getPrf());

			 PrivateKeyInfo pkInfo = encInfo.decryptPrivateKeyInfo((new JcePKCSPBEInputDecryptorProviderBuilder()).setProvider("BC").build("hello".ToCharArray()));

			 RSAPrivateKey k = RSAPrivateKey.getInstance(pkInfo.parsePrivateKey());

			 assertEquals(modulus, k.getModulus());
		}

		public virtual void testScryptEncryption()
		{
			if (getJvmVersion() < 7) // runs out of memory
			{
				return;
			}

			PKCS8EncryptedPrivateKeyInfoBuilder bldr = new PKCS8EncryptedPrivateKeyInfoBuilder(scryptKey);

			PBKDFConfig scrypt = (new ScryptConfig.Builder(1048576, 8, 1)).withSaltLength(20).build();

			PKCS8EncryptedPrivateKeyInfo encInfo = bldr.build(new JcePKCSPBEOutputEncryptorBuilder(scrypt, NISTObjectIdentifiers_Fields.id_aes256_CBC)
					.setProvider("BC").build("Rabbit".ToCharArray()));

			EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

			PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(encPkInfo);

			PrivateKeyInfo pkInfo = info.decryptPrivateKeyInfo((new JcePKCSPBEInputDecryptorProviderBuilder()).setProvider("BC").build("Rabbit".ToCharArray()));

			assertTrue(Arrays.areEqual(scryptKey, pkInfo.getEncoded()));
		}

		private static int getJvmVersion()
		{
			string version = System.getProperty("java.version");

			if (version.StartsWith("1.7", StringComparison.Ordinal))
			{
				return 7;
			}
			if (version.StartsWith("1.8", StringComparison.Ordinal))
			{
				return 8;
			}
			if (version.StartsWith("1.9", StringComparison.Ordinal))
			{
				return 9;
			}
			if (version.StartsWith("1.1", StringComparison.Ordinal))
			{
				return 10;
			}

			return -1;
		}
	}

}