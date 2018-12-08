namespace org.bouncycastle.asn1.misc
{

	public class VerisignCzagExtension : DERIA5String
	{
		public VerisignCzagExtension(DERIA5String str) : base(str.getString())
		{
		}

		public override string ToString()
		{
			return "VerisignCzagExtension: " + this.getString();
		}
	}

}