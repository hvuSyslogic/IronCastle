using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dsa
{

	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using DSAParametersGenerator = org.bouncycastle.crypto.generators.DSAParametersGenerator;
	using DSAParameterGenerationParameters = org.bouncycastle.crypto.@params.DSAParameterGenerationParameters;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using BaseAlgorithmParameterGeneratorSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAlgorithmParameterGeneratorSpi;
	using PrimeCertaintyCalculator = org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

	public class AlgorithmParameterGeneratorSpi : BaseAlgorithmParameterGeneratorSpi
	{
		protected internal SecureRandom random;
		protected internal int strength = 2048;
		protected internal DSAParameterGenerationParameters @params;

		public virtual void engineInit(int strength, SecureRandom random)
		{
			if (strength < 512 || strength > 3072)
			{
				throw new InvalidParameterException("strength must be from 512 - 3072");
			}

			if (strength <= 1024 && strength % 64 != 0)
			{
				throw new InvalidParameterException("strength must be a multiple of 64 below 1024 bits.");
			}

			if (strength > 1024 && strength % 1024 != 0)
			{
				throw new InvalidParameterException("strength must be a multiple of 1024 above 1024 bits.");
			}

			this.strength = strength;
			this.random = random;
		}

		public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
		{
			throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DSA parameter generation.");
		}

		public virtual AlgorithmParameters engineGenerateParameters()
		{
			DSAParametersGenerator pGen;

			if (strength <= 1024)
			{
				pGen = new DSAParametersGenerator();
			}
			else
			{
				pGen = new DSAParametersGenerator(new SHA256Digest());
			}

			if (random == null)
			{
				random = CryptoServicesRegistrar.getSecureRandom();
			}

			int certainty = PrimeCertaintyCalculator.getDefaultCertainty(strength);

			if (strength == 1024)
			{
				@params = new DSAParameterGenerationParameters(1024, 160, certainty, random);
				pGen.init(@params);
			}
			else if (strength > 1024)
			{
				@params = new DSAParameterGenerationParameters(strength, 256, certainty, random);
				pGen.init(@params);
			}
			else
			{
				pGen.init(strength, certainty, random);
			}

			DSAParameters p = pGen.generateParameters();

			AlgorithmParameters @params;

			try
			{
				@params = createParametersInstance("DSA");
				@params.init(new DSAParameterSpec(p.getP(), p.getQ(), p.getG()));
			}
			catch (Exception e)
			{
				throw new RuntimeException(e.Message);
			}

			return @params;
		}
	}

}