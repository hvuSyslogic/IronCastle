namespace org.bouncycastle.cert.cmp
{

	using RevDetails = org.bouncycastle.asn1.cmp.RevDetails;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	public class RevocationDetails
	{
		private RevDetails revDetails;

		public RevocationDetails(RevDetails revDetails)
		{
			this.revDetails = revDetails;
		}

		public virtual X500Name getSubject()
		{
			return revDetails.getCertDetails().getSubject();
		}

		public virtual X500Name getIssuer()
		{
			return revDetails.getCertDetails().getIssuer();
		}

		public virtual BigInteger getSerialNumber()
		{
			return revDetails.getCertDetails().getSerialNumber().getValue();
		}

		public virtual RevDetails toASN1Structure()
		{
			return revDetails;
		}
	}

}