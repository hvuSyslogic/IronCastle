using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{


	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSAESOAEPparams = org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestFactory = org.bouncycastle.jcajce.provider.util.DigestFactory;
	using MessageDigestUtils = org.bouncycastle.jcajce.util.MessageDigestUtils;

	public abstract class AlgorithmParametersSpi : java.security.AlgorithmParametersSpi
	{
		public virtual bool isASN1FormatString(string format)
		{
			return string.ReferenceEquals(format, null) || format.Equals("ASN.1");
		}

		public virtual AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec)
		{
			if (paramSpec == null)
			{
				throw new NullPointerException("argument to getParameterSpec must not be null");
			}

			return localEngineGetParameterSpec(paramSpec);
		}

		public abstract AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec);

		public class OAEP : AlgorithmParametersSpi
		{
			internal OAEPParameterSpec currentSpec;

			/// <summary>
			/// Return the PKCS#1 ASN.1 structure RSAES-OAEP-params.
			/// </summary>
			public virtual byte[] engineGetEncoded()
			{
				AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(DigestFactory.getOID(currentSpec.getDigestAlgorithm()), DERNull.INSTANCE);
				MGF1ParameterSpec mgfSpec = (MGF1ParameterSpec)currentSpec.getMGFParameters();
				AlgorithmIdentifier maskGenAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, new AlgorithmIdentifier(DigestFactory.getOID(mgfSpec.getDigestAlgorithm()), DERNull.INSTANCE));
				PSource.PSpecified pSource = (PSource.PSpecified)currentSpec.getPSource();
				AlgorithmIdentifier pSourceAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_pSpecified, new DEROctetString(pSource.getValue()));
				RSAESOAEPparams oaepP = new RSAESOAEPparams(hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm);

				try
				{
					return oaepP.getEncoded(ASN1Encoding_Fields.DER);
				}
				catch (IOException)
				{
					throw new RuntimeException("Error encoding OAEPParameters");
				}
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (isASN1FormatString(format) || format.Equals("X.509", StringComparison.OrdinalIgnoreCase))
				{
					return engineGetEncoded();
				}

				return null;
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(OAEPParameterSpec) || paramSpec == typeof(AlgorithmParameterSpec))
				{
					return currentSpec;
				}

				throw new InvalidParameterSpecException("unknown parameter spec passed to OAEP parameters object.");
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (!(paramSpec is OAEPParameterSpec))
				{
					throw new InvalidParameterSpecException("OAEPParameterSpec required to initialise an OAEP algorithm parameters object");
				}

				this.currentSpec = (OAEPParameterSpec)paramSpec;
			}

			public virtual void engineInit(byte[] @params)
			{
				try
				{
					RSAESOAEPparams oaepP = RSAESOAEPparams.getInstance(@params);

					if (!oaepP.getMaskGenAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_mgf1))
					{
						throw new IOException("unknown mask generation function: " + oaepP.getMaskGenAlgorithm().getAlgorithm());
					}

					currentSpec = new OAEPParameterSpec(MessageDigestUtils.getDigestName(oaepP.getHashAlgorithm().getAlgorithm()), OAEPParameterSpec.DEFAULT.getMGFAlgorithm(), new MGF1ParameterSpec(MessageDigestUtils.getDigestName(AlgorithmIdentifier.getInstance(oaepP.getMaskGenAlgorithm().getParameters()).getAlgorithm())), new PSource.PSpecified(ASN1OctetString.getInstance(oaepP.getPSourceAlgorithm().getParameters()).getOctets()));
				}
				catch (ClassCastException)
				{
					throw new IOException("Not a valid OAEP Parameter encoding.");
				}
				catch (ArrayIndexOutOfBoundsException)
				{
					throw new IOException("Not a valid OAEP Parameter encoding.");
				}
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (format.Equals("X.509", StringComparison.OrdinalIgnoreCase) || format.Equals("ASN.1", StringComparison.OrdinalIgnoreCase))
				{
					engineInit(@params);
				}
				else
				{
					throw new IOException("Unknown parameter format " + format);
				}
			}

			public virtual string engineToString()
			{
				return "OAEP Parameters";
			}
		}

		public class PSS : AlgorithmParametersSpi
		{
			internal PSSParameterSpec currentSpec;

			/// <summary>
			/// Return the PKCS#1 ASN.1 structure RSASSA-PSS-params.
			/// </summary>
			public virtual byte[] engineGetEncoded()
			{
				PSSParameterSpec pssSpec = currentSpec;
				AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(DigestFactory.getOID(pssSpec.getDigestAlgorithm()), DERNull.INSTANCE);
				MGF1ParameterSpec mgfSpec = (MGF1ParameterSpec)pssSpec.getMGFParameters();
				AlgorithmIdentifier maskGenAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, new AlgorithmIdentifier(DigestFactory.getOID(mgfSpec.getDigestAlgorithm()), DERNull.INSTANCE));
				RSASSAPSSparams pssP = new RSASSAPSSparams(hashAlgorithm, maskGenAlgorithm, new ASN1Integer(pssSpec.getSaltLength()), new ASN1Integer(pssSpec.getTrailerField()));

				return pssP.getEncoded("DER");
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (format.Equals("X.509", StringComparison.OrdinalIgnoreCase) || format.Equals("ASN.1", StringComparison.OrdinalIgnoreCase))
				{
					return engineGetEncoded();
				}

				return null;
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(PSSParameterSpec) && currentSpec != null)
				{
					return currentSpec;
				}

				throw new InvalidParameterSpecException("unknown parameter spec passed to PSS parameters object.");
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (!(paramSpec is PSSParameterSpec))
				{
					throw new InvalidParameterSpecException("PSSParameterSpec required to initialise an PSS algorithm parameters object");
				}

				this.currentSpec = (PSSParameterSpec)paramSpec;
			}

			public virtual void engineInit(byte[] @params)
			{
				try
				{
					RSASSAPSSparams pssP = RSASSAPSSparams.getInstance(@params);

					if (!pssP.getMaskGenAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_mgf1))
					{
						throw new IOException("unknown mask generation function: " + pssP.getMaskGenAlgorithm().getAlgorithm());
					}

					currentSpec = new PSSParameterSpec(MessageDigestUtils.getDigestName(pssP.getHashAlgorithm().getAlgorithm()), PSSParameterSpec.DEFAULT.getMGFAlgorithm(), new MGF1ParameterSpec(MessageDigestUtils.getDigestName(AlgorithmIdentifier.getInstance(pssP.getMaskGenAlgorithm().getParameters()).getAlgorithm())), pssP.getSaltLength().intValue(), pssP.getTrailerField().intValue());
				}
				catch (ClassCastException)
				{
					throw new IOException("Not a valid PSS Parameter encoding.");
				}
				catch (ArrayIndexOutOfBoundsException)
				{
					throw new IOException("Not a valid PSS Parameter encoding.");
				}
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (isASN1FormatString(format) || format.Equals("X.509", StringComparison.OrdinalIgnoreCase))
				{
					engineInit(@params);
				}
				else
				{
					throw new IOException("Unknown parameter format " + format);
				}
			}

			public virtual string engineToString()
			{
				return "PSS Parameters";
			}
		}
	}

}