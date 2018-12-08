using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.gost
{

	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using GOST3410ParametersGenerator = org.bouncycastle.crypto.generators.GOST3410ParametersGenerator;
	using GOST3410Parameters = org.bouncycastle.crypto.@params.GOST3410Parameters;
	using BaseAlgorithmParameterGeneratorSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAlgorithmParameterGeneratorSpi;
	using GOST3410ParameterSpec = org.bouncycastle.jce.spec.GOST3410ParameterSpec;
	using GOST3410PublicKeyParameterSetSpec = org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

	public abstract class AlgorithmParameterGeneratorSpi : BaseAlgorithmParameterGeneratorSpi
	{
		protected internal SecureRandom random;
		protected internal int strength = 1024;

		public virtual void engineInit(int strength, SecureRandom random)
		{
			this.strength = strength;
			this.random = random;
		}

		public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
		{
			throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for GOST3410 parameter generation.");
		}

		public virtual AlgorithmParameters engineGenerateParameters()
		{
			GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

			if (random != null)
			{
				pGen.init(strength, 2, random);
			}
			else
			{
				pGen.init(strength, 2, CryptoServicesRegistrar.getSecureRandom());
			}

			GOST3410Parameters p = pGen.generateParameters();

			AlgorithmParameters @params;

			try
			{
				@params = createParametersInstance("GOST3410");
				@params.init(new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(p.getP(), p.getQ(), p.getA())));
			}
			catch (Exception e)
			{
				throw new RuntimeException(e.Message);
			}

			return @params;
		}
	}

}