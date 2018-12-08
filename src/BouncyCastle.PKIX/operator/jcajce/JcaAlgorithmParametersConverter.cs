using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.@operator.jcajce
{



	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSAESOAEPparams = org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class JcaAlgorithmParametersConverter
	{
		public JcaAlgorithmParametersConverter()
		{
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier algId, AlgorithmParameters parameters)
		{
			try
			{
				ASN1Encodable @params = ASN1Primitive.fromByteArray(parameters.getEncoded());

				return new AlgorithmIdentifier(algId, @params);
			}
			catch (IOException e)
			{
				throw new InvalidAlgorithmParameterException("unable to encode parameters object: " + e.Message);
			}
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier algorithm, AlgorithmParameterSpec algorithmSpec)
		{
			if (algorithmSpec is OAEPParameterSpec)
			{
				if (algorithmSpec.Equals(OAEPParameterSpec.DEFAULT))
				{
					return new AlgorithmIdentifier(algorithm, new RSAESOAEPparams(RSAESOAEPparams.DEFAULT_HASH_ALGORITHM, RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION, RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM));
				}
				else
				{
					OAEPParameterSpec oaepSpec = (OAEPParameterSpec)algorithmSpec;
					PSource pSource = oaepSpec.getPSource();

					if (!oaepSpec.getMGFAlgorithm().Equals(OAEPParameterSpec.DEFAULT.getMGFAlgorithm()))
					{
						throw new InvalidAlgorithmParameterException("only " + OAEPParameterSpec.DEFAULT.getMGFAlgorithm() + " mask generator supported.");
					}

					AlgorithmIdentifier hashAlgorithm = (new DefaultDigestAlgorithmIdentifierFinder()).find(oaepSpec.getDigestAlgorithm());
					AlgorithmIdentifier mgf1HashAlgorithm = (new DefaultDigestAlgorithmIdentifierFinder()).find((((MGF1ParameterSpec)oaepSpec.getMGFParameters()).getDigestAlgorithm()));
					return new AlgorithmIdentifier(algorithm, new RSAESOAEPparams(hashAlgorithm, new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, mgf1HashAlgorithm), new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_pSpecified, new DEROctetString(((PSource.PSpecified)pSource).getValue()))));
				}
			}

			throw new InvalidAlgorithmParameterException("unknown parameter spec passed.");
		}
	}

}