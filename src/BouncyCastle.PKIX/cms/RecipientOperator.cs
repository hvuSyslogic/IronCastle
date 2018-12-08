namespace org.bouncycastle.cms
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using TeeInputStream = org.bouncycastle.util.io.TeeInputStream;

	public class RecipientOperator
	{
		private readonly AlgorithmIdentifier algorithmIdentifier;
		private readonly object @operator;

		public RecipientOperator(InputDecryptor decryptor)
		{
			this.algorithmIdentifier = decryptor.getAlgorithmIdentifier();
			this.@operator = decryptor;
		}

		public RecipientOperator(MacCalculator macCalculator)
		{
			this.algorithmIdentifier = macCalculator.getAlgorithmIdentifier();
			this.@operator = macCalculator;
		}

		public virtual InputStream getInputStream(InputStream dataIn)
		{
			if (@operator is InputDecryptor)
			{
				return ((InputDecryptor)@operator).getInputStream(dataIn);
			}
			else
			{
				return new TeeInputStream(dataIn, ((MacCalculator)@operator).getOutputStream());
			}
		}

		public virtual bool isMacBased()
		{
			return @operator is MacCalculator;
		}

		public virtual byte[] getMac()
		{
			return ((MacCalculator)@operator).getMac();
		}
	}

}