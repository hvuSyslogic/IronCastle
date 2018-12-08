namespace org.bouncycastle.asn1.x500.style
{

	/// <summary>
	/// Variation of BCStyle that insists on strict ordering for equality
	/// and hashCode comparisons
	/// </summary>
	public class BCStrictStyle : BCStyle
	{
		public new static readonly X500NameStyle INSTANCE = new BCStrictStyle();

		public override bool areEqual(X500Name name1, X500Name name2)
		{
			RDN[] rdns1 = name1.getRDNs();
			RDN[] rdns2 = name2.getRDNs();

			if (rdns1.Length != rdns2.Length)
			{
				return false;
			}

			for (int i = 0; i != rdns1.Length; i++)
			{
				if (!rdnAreEqual(rdns1[i], rdns2[i]))
				{
					return false;
				}
			}

			return true;
		}
	}

}