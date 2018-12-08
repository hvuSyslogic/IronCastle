using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.elgamal
{


	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using ElGamalParametersGenerator = org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
	using ElGamalParameters = org.bouncycastle.crypto.@params.ElGamalParameters;
	using BaseAlgorithmParameterGeneratorSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAlgorithmParameterGeneratorSpi;

	public class AlgorithmParameterGeneratorSpi : BaseAlgorithmParameterGeneratorSpi
	{
		protected internal SecureRandom random;
		protected internal int strength = 1024;

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
			ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();

			if (random != null)
			{
				pGen.init(strength, 20, random);
			}
			else
			{
				pGen.init(strength, 20, CryptoServicesRegistrar.getSecureRandom());
			}

			ElGamalParameters p = pGen.generateParameters();

			AlgorithmParameters @params;

			try
			{
				@params = createParametersInstance("ElGamal");
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