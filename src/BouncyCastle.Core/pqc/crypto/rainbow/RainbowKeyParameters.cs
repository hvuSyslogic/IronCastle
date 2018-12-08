namespace org.bouncycastle.pqc.crypto.rainbow
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public class RainbowKeyParameters : AsymmetricKeyParameter
	{
		private int docLength;

		public RainbowKeyParameters(bool isPrivate, int docLength) : base(isPrivate)
		{
			this.docLength = docLength;
		}

		/// <returns> the docLength </returns>
		public virtual int getDocLength()
		{
			return this.docLength;
		}
	}

}