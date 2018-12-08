namespace org.bouncycastle.pqc.crypto.mceliece
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;


	public class McElieceKeyParameters : AsymmetricKeyParameter
	{
		private McElieceParameters @params;

		public McElieceKeyParameters(bool isPrivate, McElieceParameters @params) : base(isPrivate)
		{
			this.@params = @params;
		}


		public virtual McElieceParameters getParameters()
		{
			return @params;
		}

	}

}