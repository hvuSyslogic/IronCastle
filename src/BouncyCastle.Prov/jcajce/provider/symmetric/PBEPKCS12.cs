using org.bouncycastle.asn1;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public class PBEPKCS12
	{
		private PBEPKCS12()
		{

		}

		public class AlgParams : BaseAlgorithmParameters
		{
			internal PKCS12PBEParams @params;

			public virtual byte[] engineGetEncoded()
			{
				try
				{
					return @params.getEncoded(ASN1Encoding_Fields.DER);
				}
				catch (IOException e)
				{
					throw new RuntimeException("Oooops! " + e.ToString());
				}
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (this.isASN1FormatString(format))
				{
					return engineGetEncoded();
				}

				return null;
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(PBEParameterSpec))
				{
					return new PBEParameterSpec(@params.getIV(), @params.getIterations().intValue());
				}

				throw new InvalidParameterSpecException("unknown parameter spec passed to PKCS12 PBE parameters object.");
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (!(paramSpec is PBEParameterSpec))
				{
					throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PKCS12 PBE parameters algorithm parameters object");
				}

				PBEParameterSpec pbeSpec = (PBEParameterSpec)paramSpec;

				this.@params = new PKCS12PBEParams(pbeSpec.getSalt(), pbeSpec.getIterationCount());
			}

			public virtual void engineInit(byte[] @params)
			{
				this.@params = PKCS12PBEParams.getInstance(ASN1Primitive.fromByteArray(@params));
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (this.isASN1FormatString(format))
				{
					engineInit(@params);
					return;
				}

				throw new IOException("Unknown parameters format in PKCS12 PBE parameters object");
			}

			public virtual string engineToString()
			{
				return "PKCS12 PBE Parameters";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(PBEPKCS12).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameters.PKCS12PBE", PREFIX + "$AlgParams");
			}
		}
	}

}