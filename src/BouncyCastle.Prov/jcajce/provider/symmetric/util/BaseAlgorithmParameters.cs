namespace org.bouncycastle.jcajce.provider.symmetric.util
{

	public abstract class BaseAlgorithmParameters : AlgorithmParametersSpi
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
	}

}