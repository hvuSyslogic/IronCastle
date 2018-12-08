namespace org.bouncycastle.crypto.@params
{

	public class DHKeyParameters : AsymmetricKeyParameter
	{
		private DHParameters @params;

		public DHKeyParameters(bool isPrivate, DHParameters @params) : base(isPrivate)
		{

			this.@params = @params;
		}

		public virtual DHParameters getParameters()
		{
			return @params;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is DHKeyParameters))
			{
				return false;
			}

			DHKeyParameters dhKey = (DHKeyParameters)obj;

			if (@params == null)
			{
				return dhKey.getParameters() == null;
			}
			else
			{
				return @params.Equals(dhKey.getParameters());
			}
		}

		public override int GetHashCode()
		{
			int code = isPrivate() ? 0 : 1;

			if (@params != null)
			{
				code ^= @params.GetHashCode();
			}

			return code;
		}
	}

}