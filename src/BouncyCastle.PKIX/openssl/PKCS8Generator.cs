using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.openssl
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using PemGenerationException = org.bouncycastle.util.io.pem.PemGenerationException;
	using PemObject = org.bouncycastle.util.io.pem.PemObject;
	using PemObjectGenerator = org.bouncycastle.util.io.pem.PemObjectGenerator;

	public class PKCS8Generator : PemObjectGenerator
	{
		public static readonly ASN1ObjectIdentifier AES_128_CBC = NISTObjectIdentifiers_Fields.id_aes128_CBC;
		public static readonly ASN1ObjectIdentifier AES_192_CBC = NISTObjectIdentifiers_Fields.id_aes192_CBC;
		public static readonly ASN1ObjectIdentifier AES_256_CBC = NISTObjectIdentifiers_Fields.id_aes256_CBC;

		public static readonly ASN1ObjectIdentifier DES3_CBC = PKCSObjectIdentifiers_Fields.des_EDE3_CBC;

		public static readonly ASN1ObjectIdentifier PBE_SHA1_RC4_128 = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4;
		public static readonly ASN1ObjectIdentifier PBE_SHA1_RC4_40 = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC4;
		public static readonly ASN1ObjectIdentifier PBE_SHA1_3DES = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC;
		public static readonly ASN1ObjectIdentifier PBE_SHA1_2DES = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd2_KeyTripleDES_CBC;
		public static readonly ASN1ObjectIdentifier PBE_SHA1_RC2_128 = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC2_CBC;
		public static readonly ASN1ObjectIdentifier PBE_SHA1_RC2_40 = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC2_CBC;

		public static readonly AlgorithmIdentifier PRF_HMACSHA1 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier PRF_HMACSHA224 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier PRF_HMACSHA256 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier PRF_HMACSHA384 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier PRF_HMACSHA512 = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier PRF_HMACGOST3411 = new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3411Hmac, DERNull.INSTANCE);

		public static readonly AlgorithmIdentifier PRF_HMACSHA3_224 = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_224, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier PRF_HMACSHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier PRF_HMACSHA3_384 = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_384, DERNull.INSTANCE);
		public static readonly AlgorithmIdentifier PRF_HMACSHA3_512 = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, DERNull.INSTANCE);

		private PrivateKeyInfo key;
		private OutputEncryptor outputEncryptor;

		/// <summary>
		/// Base constructor.
		/// </summary>
		public PKCS8Generator(PrivateKeyInfo key, OutputEncryptor outputEncryptor)
		{
			this.key = key;
			this.outputEncryptor = outputEncryptor;
		}

		public virtual PemObject generate()
		{
			if (outputEncryptor != null)
			{
				return generate(key, outputEncryptor);
			}
			else
			{
				return generate(key, null);
			}
		}

		private PemObject generate(PrivateKeyInfo key, OutputEncryptor encryptor)
		{
			try
			{
				byte[] keyData = key.getEncoded();

				if (encryptor == null)
				{
					return new PemObject("PRIVATE KEY", keyData);
				}

				ByteArrayOutputStream bOut = new ByteArrayOutputStream();

				OutputStream cOut = encryptor.getOutputStream(bOut);

				cOut.write(key.getEncoded());

				cOut.close();

				EncryptedPrivateKeyInfo info = new EncryptedPrivateKeyInfo(encryptor.getAlgorithmIdentifier(), bOut.toByteArray());

				return new PemObject("ENCRYPTED PRIVATE KEY", info.getEncoded());
			}
			catch (IOException e)
			{
				throw new PemGenerationException("unable to process encoded key data: " + e.Message, e);
			}
		}
	}

}