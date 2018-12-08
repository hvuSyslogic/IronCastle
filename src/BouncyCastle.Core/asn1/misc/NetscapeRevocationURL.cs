namespace org.bouncycastle.asn1.misc
{

	public class NetscapeRevocationURL : DERIA5String
	{
		public NetscapeRevocationURL(DERIA5String str) : base(str.getString())
		{
		}

		public override string ToString()
		{
			return "NetscapeRevocationURL: " + this.getString();
		}
	}

}