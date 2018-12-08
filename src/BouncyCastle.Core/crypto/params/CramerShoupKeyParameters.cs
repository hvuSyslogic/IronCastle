namespace org.bouncycastle.crypto.@params
{
	public class CramerShoupKeyParameters : AsymmetricKeyParameter
	{

		private CramerShoupParameters @params;

		public CramerShoupKeyParameters(bool isPrivate, CramerShoupParameters @params) : base(isPrivate)
		{

			this.@params = @params;
		}

		public virtual CramerShoupParameters getParameters()
		{
			return @params;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is CramerShoupKeyParameters))
			{
				return false;
			}

			CramerShoupKeyParameters csKey = (CramerShoupKeyParameters) obj;

			if (@params == null)
			{
				return csKey.getParameters() == null;
			}
			else
			{
				return @params.Equals(csKey.getParameters());
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