namespace org.bouncycastle.asn1.smime
{
	using Attribute = org.bouncycastle.asn1.cms.Attribute;

	public class SMIMECapabilitiesAttribute : Attribute
	{
		public SMIMECapabilitiesAttribute(SMIMECapabilityVector capabilities) : base(SMIMEAttributes_Fields.smimeCapabilities, new DERSet(new DERSequence(capabilities.toASN1EncodableVector())))
		{
		}
	}

}