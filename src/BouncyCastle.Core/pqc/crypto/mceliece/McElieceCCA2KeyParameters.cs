using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.pqc.crypto.mceliece
{
	

	public class McElieceCCA2KeyParameters : AsymmetricKeyParameter
	{
		private string @params;

		public McElieceCCA2KeyParameters(bool isPrivate, string @params) : base(isPrivate)
		{
			this.@params = @params;
		}


		public virtual string getDigest()
		{
			return @params;
		}

	}

}