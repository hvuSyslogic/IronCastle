namespace org.bouncycastle.crypto.@params
{

	public class ElGamalKeyParameters : AsymmetricKeyParameter
	{
		private ElGamalParameters @params;

		public ElGamalKeyParameters(bool isPrivate, ElGamalParameters @params) : base(isPrivate)
		{

			this.@params = @params;
		}

		public virtual ElGamalParameters getParameters()
		{
			return @params;
		}

		public override int GetHashCode()
		{
			return (@params != null) ? @params.GetHashCode() : 0;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is ElGamalKeyParameters))
			{
				return false;
			}

			ElGamalKeyParameters dhKey = (ElGamalKeyParameters)obj;

			if (@params == null)
			{
				return dhKey.getParameters() == null;
			}
			else
			{
				return @params.Equals(dhKey.getParameters());
			}
		}
	}

}