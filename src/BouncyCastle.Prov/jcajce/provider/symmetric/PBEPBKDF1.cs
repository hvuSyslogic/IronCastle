using org.bouncycastle.asn1;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using PBEParameter = org.bouncycastle.asn1.pkcs.PBEParameter;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public class PBEPBKDF1
	{
		private PBEPBKDF1()
		{

		}

		public class AlgParams : BaseAlgorithmParameters
		{
			internal PBEParameter @params;

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
					return new PBEParameterSpec(@params.getSalt(), @params.getIterationCount().intValue());
				}

				throw new InvalidParameterSpecException("unknown parameter spec passed to PBKDF1 PBE parameters object.");
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (!(paramSpec is PBEParameterSpec))
				{
					throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PBKDF1 PBE parameters algorithm parameters object");
				}

				PBEParameterSpec pbeSpec = (PBEParameterSpec)paramSpec;

				this.@params = new PBEParameter(pbeSpec.getSalt(), pbeSpec.getIterationCount());
			}

			public virtual void engineInit(byte[] @params)
			{
				this.@params = PBEParameter.getInstance(@params);
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (this.isASN1FormatString(format))
				{
					engineInit(@params);
					return;
				}

				throw new IOException("Unknown parameters format in PBKDF2 parameters object");
			}

			public virtual string engineToString()
			{
				return "PBKDF1 Parameters";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(PBEPBKDF1).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameters.PBKDF1", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.pbeWithMD2AndDES_CBC, "PBKDF1");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.pbeWithMD5AndDES_CBC, "PBKDF1");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.pbeWithMD5AndRC2_CBC, "PBKDF1");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.pbeWithSHA1AndDES_CBC, "PBKDF1");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.pbeWithSHA1AndRC2_CBC, "PBKDF1");
			}
		}
	}

}