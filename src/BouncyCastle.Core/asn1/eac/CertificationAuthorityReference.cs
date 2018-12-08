namespace org.bouncycastle.asn1.eac
{
	public class CertificationAuthorityReference : CertificateHolderReference
	{
		public CertificationAuthorityReference(string countryCode, string holderMnemonic, string sequenceNumber) : base(countryCode, holderMnemonic, sequenceNumber)
		{
		}

		public CertificationAuthorityReference(byte[] contents) : base(contents)
		{
		}
	}

}