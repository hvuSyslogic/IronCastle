using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Null = org.bouncycastle.asn1.ASN1Null;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using MessageDigestUtils = org.bouncycastle.jcajce.util.MessageDigestUtils;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

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

					return getDigestAlgName((ASN1ObjectIdentifier)ecDsaParams.getObjectAt(0)) + "withECDSA";
				}
			}

			Provider prov = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

			if (prov != null)
			{
				string algName = prov.getProperty("Alg.Alias.Signature." + sigAlgId.getAlgorithm().getId());

				if (!string.ReferenceEquals(algName, null))
				{
					return algName;
				}
			}

			Provider[] provs = Security.getProviders();

			//
			// search every provider looking for a real algorithm
			//
			for (int i = 0; i != provs.Length; i++)
			{
				string algName = provs[i].getProperty("Alg.Alias.Signature." + sigAlgId.getAlgorithm().getId());
				if (!string.ReferenceEquals(algName, null))
				{
					return algName;
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
			string name = MessageDigestUtils.getDigestName(digestAlgOID);

			int dIndex = name.IndexOf('-');
			if (dIndex > 0 && !name.StartsWith("SHA3", StringComparison.Ordinal))
			{
				return name.Substring(0, dIndex) + name.Substring(dIndex + 1);
			}

			return MessageDigestUtils.getDigestName(digestAlgOID);
		}
	}

}