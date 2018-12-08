namespace org.bouncycastle.jcajce.provider.symmetric.util
{

	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;

	public abstract class BaseAlgorithmParameterGenerator : AlgorithmParameterGeneratorSpi
	{
		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		protected internal SecureRandom random;
		protected internal int strength = 1024;

		public BaseAlgorithmParameterGenerator()
		{
		}

		public AlgorithmParameters createParametersInstance(string algorithm)
		{
			return helper.createAlgorithmParameters(algorithm);
		}

		public virtual void engineInit(int strength, SecureRandom random)
		{
			this.strength = strength;
			this.random = random;
		}
	}

}