using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using Fingerprint = org.bouncycastle.util.Fingerprint;

	/// <summary>
	/// utility class for converting java.security RSA objects into their
	/// org.bouncycastle.crypto counterparts.
	/// </summary>
	public class RSAUtil
	{
		public static readonly ASN1ObjectIdentifier[] rsaOids = new ASN1ObjectIdentifier[] {PKCSObjectIdentifiers_Fields.rsaEncryption, X509ObjectIdentifiers_Fields.id_ea_rsa, PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, PKCSObjectIdentifiers_Fields.id_RSASSA_PSS};

		public static bool isRsaOid(ASN1ObjectIdentifier algOid)
		{
			for (int i = 0; i != rsaOids.Length; i++)
			{
				if (algOid.Equals(rsaOids[i]))
				{
					return true;
				}
			}

			return false;
		}

		internal static RSAKeyParameters generatePublicKeyParameter(RSAPublicKey key)
		{
			return new RSAKeyParameters(false, key.getModulus(), key.getPublicExponent());

		}

		internal static RSAKeyParameters generatePrivateKeyParameter(RSAPrivateKey key)
		{
			if (key is RSAPrivateCrtKey)
			{
				RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

				return new RSAPrivateCrtKeyParameters(k.getModulus(), k.getPublicExponent(), k.getPrivateExponent(), k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());
			}
			else
			{
				RSAPrivateKey k = key;

				return new RSAKeyParameters(true, k.getModulus(), k.getPrivateExponent());
			}
		}

		internal static string generateKeyFingerprint(BigInteger modulus)
		{
			return (new Fingerprint(modulus.toByteArray())).ToString();
		}

		internal static string generateExponentFingerprint(BigInteger exponent)
		{
			return (new Fingerprint(exponent.toByteArray(), 32)).ToString();
		}
	}

}