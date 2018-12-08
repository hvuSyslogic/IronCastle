namespace org.bouncycastle.crypto.@params
{
	public class GOST3410KeyParameters : AsymmetricKeyParameter
	{
		private GOST3410Parameters @params;

		public GOST3410KeyParameters(bool isPrivate, GOST3410Parameters @params) : base(isPrivate)
		{

			this.@params = @params;
		}

		public virtual GOST3410Parameters getParameters()
		{
			return @params;
		}
	}

}