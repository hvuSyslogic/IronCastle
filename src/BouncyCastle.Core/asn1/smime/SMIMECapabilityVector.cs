namespace org.bouncycastle.asn1.smime
{

	/// <summary>
	/// Handler for creating a vector S/MIME Capabilities
	/// </summary>
	public class SMIMECapabilityVector
	{
		private ASN1EncodableVector capabilities = new ASN1EncodableVector();

		public virtual void addCapability(ASN1ObjectIdentifier capability)
		{
			capabilities.add(new DERSequence(capability));
		}

		public virtual void addCapability(ASN1ObjectIdentifier capability, int value)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(capability);
			v.add(new ASN1Integer(value));

			capabilities.add(new DERSequence(v));
		}

		public virtual void addCapability(ASN1ObjectIdentifier capability, ASN1Encodable @params)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(capability);
			v.add(@params);

			capabilities.add(new DERSequence(v));
		}

		public virtual ASN1EncodableVector toASN1EncodableVector()
		{
			return capabilities;
		}
	}

}