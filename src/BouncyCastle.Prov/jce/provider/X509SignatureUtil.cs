using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Null = org.bouncycastle.asn1.ASN1Null;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

	public class X509SignatureUtil
	{
		private static readonly ASN1Null derNull = DERNull.INSTANCE;

		internal static void setSignatureParameters(Signature signature, ASN1Encodable @params)
		{
			if (@params != null && !derNull.Equals(@params))
			{
				AlgorithmParameters sigParams = AlgorithmParameters.getInstance(signature.getAlgorithm(), signature.getProvider());

				try
				{
					sigParams.init(@params.toASN1Primitive().getEncoded());
				}
				catch (IOException e)
				{
					throw new SignatureException("IOException decoding parameters: " + e.Message);
				}

				if (signature.getAlgorithm().EndsWith("MGF1"))
				{
					try
					{
						signature.setParameter(sigParams.getParameterSpec(typeof(PSSParameterSpec)));
					}
					catch (GeneralSecurityException e)
					{
						throw new SignatureException("Exception extracting parameters: " + e.Message);
					}
				}
			}
		}

		internal static string getSignatureName(AlgorithmIdentifier sigAlgId)
		{
			ASN1Encodable @params = sigAlgId.getParameters();

			if (@params != null && !derNull.Equals(@params))
			{
				if (sigAlgId.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS))
				{
					RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(@params);

					return getDigestAlgName(rsaParams.getHashAlgorithm().getAlgorithm()) + "withRSAandMGF1";
				}
				if (sigAlgId.getAlgorithm().Equals(X9ObjectIdentifiers_Fields.ecdsa_with_SHA2))
				{
					ASN1Sequence ecDsaParams = ASN1Sequence.getInstance(@params);

					return getDigestAlgName(ASN1ObjectIdentifier.getInstance(ecDsaParams.getObjectAt(0))) + "withECDSA";
				}
			}

			return sigAlgId.getAlgorithm().getId();
		}

		/// <summary>
		/// Return the digest algorithm using one of the standard JCA string
		/// representations rather the the algorithm identifier (if possible).
		/// </summary>
		private static string getDigestAlgName(ASN1ObjectIdentifier digestAlgOID)
		{
			if (PKCSObjectIdentifiers_Fields.md5.Equals(digestAlgOID))
			{
				return "MD5";
			}
			else if (OIWObjectIdentifiers_Fields.idSHA1.Equals(digestAlgOID))
			{
				return "SHA1";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha224.Equals(digestAlgOID))
			{
				return "SHA224";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha256.Equals(digestAlgOID))
			{
				return "SHA256";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha384.Equals(digestAlgOID))
			{
				return "SHA384";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha512.Equals(digestAlgOID))
			{
				return "SHA512";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd128.Equals(digestAlgOID))
			{
				return "RIPEMD128";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd160.Equals(digestAlgOID))
			{
				return "RIPEMD160";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd256.Equals(digestAlgOID))
			{
				return "RIPEMD256";
			}
			else if (CryptoProObjectIdentifiers_Fields.gostR3411.Equals(digestAlgOID))
			{
				return "GOST3411";
			}
			else
			{
				return digestAlgOID.getId();
			}
		}
	}

}