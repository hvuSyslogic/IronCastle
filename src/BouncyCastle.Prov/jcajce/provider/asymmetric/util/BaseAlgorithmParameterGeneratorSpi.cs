namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;

	public abstract class BaseAlgorithmParameterGeneratorSpi : AlgorithmParameterGeneratorSpi
	{
		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		public BaseAlgorithmParameterGeneratorSpi()
		{
		}

		public AlgorithmParameters createParametersInstance(string algorithm)
		{
			return helper.createAlgorithmParameters(algorithm);
		}
	}

}