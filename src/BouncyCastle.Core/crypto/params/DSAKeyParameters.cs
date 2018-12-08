namespace org.bouncycastle.crypto.@params
{
	public class DSAKeyParameters : AsymmetricKeyParameter
	{
		private DSAParameters @params;

		public DSAKeyParameters(bool isPrivate, DSAParameters @params) : base(isPrivate)
		{

			this.@params = @params;
		}

		public virtual DSAParameters getParameters()
		{
			return @params;
		}
	}

}