using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{


	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using DHParametersGenerator = org.bouncycastle.crypto.generators.DHParametersGenerator;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using BaseAlgorithmParameterGeneratorSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAlgorithmParameterGeneratorSpi;
	using PrimeCertaintyCalculator = org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

	public class AlgorithmParameterGeneratorSpi : BaseAlgorithmParameterGeneratorSpi
	{
		protected internal SecureRandom random;
		protected internal int strength = 2048;

		private int l = 0;

		public virtual void engineInit(int strength, SecureRandom random)
		{
			this.strength = strength;
			this.random = random;
		}

		public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
		{
			if (!(genParamSpec is DHGenParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("DH parameter generator requires a DHGenParameterSpec for initialisation");
			}
			DHGenParameterSpec spec = (DHGenParameterSpec)genParamSpec;

			this.strength = spec.getPrimeSize();
			this.l = spec.getExponentSize();
			this.random = random;
		}

		public virtual AlgorithmParameters engineGenerateParameters()
		{
			DHParametersGenerator pGen = new DHParametersGenerator();

			int certainty = PrimeCertaintyCalculator.getDefaultCertainty(strength);

			if (random != null)
			{
				pGen.init(strength, certainty, random);
			}
			else
			{
				pGen.init(strength, certainty, CryptoServicesRegistrar.getSecureRandom());
			}

			DHParameters p = pGen.generateParameters();

			AlgorithmParameters @params;

			try
			{
				@params = createParametersInstance("DH");
				@params.init(new DHParameterSpec(p.getP(), p.getG(), l));
			}
			catch (Exception e)
			{
				throw new RuntimeException(e.Message);
			}

			return @params;
		}

	}

}