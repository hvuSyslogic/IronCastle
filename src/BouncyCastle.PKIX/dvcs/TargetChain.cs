namespace org.bouncycastle.dvcs
{
	using TargetEtcChain = org.bouncycastle.asn1.dvcs.TargetEtcChain;

	public class TargetChain
	{
		private readonly TargetEtcChain certs;

		public TargetChain(TargetEtcChain certs)
		{
			this.certs = certs;
		}

		public virtual TargetEtcChain toASN1Structure()
		{
			return certs;
		}
	}

}