using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.pqc.crypto.rainbow
{
	
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