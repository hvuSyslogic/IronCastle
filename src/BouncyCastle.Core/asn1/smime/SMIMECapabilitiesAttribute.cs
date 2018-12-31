namespace org.bouncycastle.asn1.smime
{
	
	public class SMIMECapabilitiesAttribute : Attribute
	{
		public SMIMECapabilitiesAttribute(SMIMECapabilityVector capabilities) : base(SMIMEAttributes_Fields.smimeCapabilities, new DERSet(new DERSequence(capabilities.toASN1EncodableVector())))
		{
		}
	}

}