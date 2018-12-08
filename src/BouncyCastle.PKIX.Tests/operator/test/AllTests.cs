using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;

namespace org.bouncycastle.@operator.test
{


	using Assert = junit.framework.Assert;
	using TestCase = junit.framework.TestCase;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSAESOAEPparams = org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JceAsymmetricKeyWrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyWrapper;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class AllTests : TestCase
	{
		private static readonly byte[] TEST_DATA = "Hello world!".getBytes();
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;
		private const string TEST_DATA_HOME = "bc.test.data.home";

		public virtual void setUp()
		{
			if (Security.getProvider(BC) == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public virtual void testAlgorithmNameFinder()
		{
			AlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();

			assertTrue(nameFinder.hasAlgorithmName(OIWObjectIdentifiers_Fields.elGamalAlgorithm));
			assertFalse(nameFinder.hasAlgorithmName(Extension.authorityKeyIdentifier));

			assertEquals(nameFinder.getAlgorithmName(OIWObjectIdentifiers_Fields.elGamalAlgorithm), "ELGAMAL");
			assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers_Fields.rsaEncryption), "RSA");
			assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers_Fields.id_RSAES_OAEP), "RSAOAEP");
			assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers_Fields.md5), "MD5");
			assertEquals(nameFinder.getAlgorithmName(OIWObjectIdentifiers_Fields.idSHA1), "SHA1");
			assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers_Fields.id_sha224), "SHA224");
			assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers_Fields.id_sha256), "SHA256");
			assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers_Fields.id_sha384), "SHA384");
			assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers_Fields.id_sha512), "SHA512");
			assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption), "SHA512WITHRSA");
			assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS), "RSAPSS");
			assertEquals(nameFinder.getAlgorithmName(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160), "RIPEMD160WITHRSA");
			assertEquals(nameFinder.getAlgorithmName(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.elGamalAlgorithm, DERNull.INSTANCE)), "ELGAMAL");
			assertEquals(nameFinder.getAlgorithmName(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE)), "RSA");

			assertEquals(nameFinder.getAlgorithmName(Extension.authorityKeyIdentifier), Extension.authorityKeyIdentifier.getId());
		}

		public virtual void testOaepWrap()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(2048);

			KeyPair kp = kGen.generateKeyPair();

			checkAlgorithmId(kp, "SHA-1", OIWObjectIdentifiers_Fields.idSHA1);
			checkAlgorithmId(kp, "SHA-224", NISTObjectIdentifiers_Fields.id_sha224);
			checkAlgorithmId(kp, "SHA-256", NISTObjectIdentifiers_Fields.id_sha256);
			checkAlgorithmId(kp, "SHA-384", NISTObjectIdentifiers_Fields.id_sha384);
			checkAlgorithmId(kp, "SHA-512", NISTObjectIdentifiers_Fields.id_sha512);
			checkAlgorithmId(kp, "SHA-512/224", NISTObjectIdentifiers_Fields.id_sha512_224);
			checkAlgorithmId(kp, "SHA-512/256", NISTObjectIdentifiers_Fields.id_sha512_256);
			checkAlgorithmId(kp, "SHA-512(224)", NISTObjectIdentifiers_Fields.id_sha512_224);
			checkAlgorithmId(kp, "SHA-512(256)", NISTObjectIdentifiers_Fields.id_sha512_256);
		}

		private void checkAlgorithmId(KeyPair kp, string digest, ASN1ObjectIdentifier digestOid)
		{
			JceAsymmetricKeyWrapper wrapper = (new JceAsymmetricKeyWrapper(new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), new PSource.PSpecified(Hex.decode("beef"))), kp.getPublic())).setProvider(BC);

			Assert.assertEquals(PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, wrapper.getAlgorithmIdentifier().getAlgorithm());
			RSAESOAEPparams oaepParams = RSAESOAEPparams.getInstance(wrapper.getAlgorithmIdentifier().getParameters());
			Assert.assertEquals(digestOid, oaepParams.getHashAlgorithm().getAlgorithm());
			Assert.assertEquals(PKCSObjectIdentifiers_Fields.id_mgf1, oaepParams.getMaskGenAlgorithm().getAlgorithm());
			Assert.assertEquals(new AlgorithmIdentifier(digestOid, DERNull.INSTANCE), oaepParams.getMaskGenAlgorithm().getParameters());
			Assert.assertEquals(PKCSObjectIdentifiers_Fields.id_pSpecified, oaepParams.getPSourceAlgorithm().getAlgorithm());
			Assert.assertEquals(new DEROctetString(Hex.decode("beef")), oaepParams.getPSourceAlgorithm().getParameters());
		}
	}
}