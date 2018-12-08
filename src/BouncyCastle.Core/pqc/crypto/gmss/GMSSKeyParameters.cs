namespace org.bouncycastle.pqc.crypto.gmss
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public class GMSSKeyParameters : AsymmetricKeyParameter
	{
		private GMSSParameters @params;

		public GMSSKeyParameters(bool isPrivate, GMSSParameters @params) : base(isPrivate)
		{
			this.@params = @params;
		}

		public virtual GMSSParameters getParameters()
		{
			return @params;
		}
	}
}