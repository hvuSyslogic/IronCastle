namespace org.bouncycastle.crypto.@params
{
	public class ECKeyParameters : AsymmetricKeyParameter
	{
		internal ECDomainParameters @params;

		public ECKeyParameters(bool isPrivate, ECDomainParameters @params) : base(isPrivate)
		{

			this.@params = @params;
		}

		public virtual ECDomainParameters getParameters()
		{
			return @params;
		}
	}

}