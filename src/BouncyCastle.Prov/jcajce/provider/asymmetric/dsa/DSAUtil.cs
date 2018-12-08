using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.x9;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dsa
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Fingerprint = org.bouncycastle.util.Fingerprint;

	/// <summary>
	/// utility class for converting jce/jca DSA objects
	/// objects into their org.bouncycastle.crypto counterparts.
	/// </summary>
	public class DSAUtil
	{
		public static readonly ASN1ObjectIdentifier[] dsaOids = new ASN1ObjectIdentifier[] {X9ObjectIdentifiers_Fields.id_dsa, OIWObjectIdentifiers_Fields.dsaWithSHA1, X9ObjectIdentifiers_Fields.id_dsa_with_sha1};

		/// <summary>
		/// Return true if the passed in OID could be associated with a DSA key.
		/// </summary>
		/// <param name="algOid"> algorithm OID from a key. </param>
		/// <returns> true if it's for a DSA key, false otherwise. </returns>
		public static bool isDsaOid(ASN1ObjectIdentifier algOid)
		{
			for (int i = 0; i != dsaOids.Length; i++)
			{
				if (algOid.Equals(dsaOids[i]))
				{
					return true;
				}
			}

			return false;
		}

		internal static DSAParameters toDSAParameters(DSAParams spec)
		{
			if (spec != null)
			{
				 return new DSAParameters(spec.getP(), spec.getQ(), spec.getG());
			}

			return null;
		}

		public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			if (key is BCDSAPublicKey)
			{
				return ((BCDSAPublicKey)key).engineGetKeyParameters();
			}

			if (key is DSAPublicKey)
			{
				return (new BCDSAPublicKey((DSAPublicKey)key)).engineGetKeyParameters();
			}

			try
			{
				byte[] bytes = key.getEncoded();

				BCDSAPublicKey bckey = new BCDSAPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

				return bckey.engineGetKeyParameters();
			}
			catch (Exception)
			{
				throw new InvalidKeyException("can't identify DSA public key: " + key.GetType().getName());
			}
		}

		public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
		{
			if (key is DSAPrivateKey)
			{
				DSAPrivateKey k = (DSAPrivateKey)key;

				return new DSAPrivateKeyParameters(k.getX(), new DSAParameters(k.getParams().getP(), k.getParams().getQ(), k.getParams().getG()));
			}

			throw new InvalidKeyException("can't identify DSA private key.");
		}

		internal static string generateKeyFingerprint(BigInteger y, DSAParams @params)
		{
			return (new Fingerprint(Arrays.concatenate(y.toByteArray(), @params.getP().toByteArray(), @params.getQ().toByteArray(), @params.getG().toByteArray()))).ToString();
		}
	}

}