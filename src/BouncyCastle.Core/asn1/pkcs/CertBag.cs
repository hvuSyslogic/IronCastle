namespace org.bouncycastle.asn1.pkcs
{

	public class CertBag : ASN1Object
	{
		private ASN1ObjectIdentifier certId;
		private ASN1Encodable certValue;

		private CertBag(ASN1Sequence seq)
		{
			this.certId = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			this.certValue = ((DERTaggedObject)seq.getObjectAt(1)).getObject();
		}

		public static CertBag getInstance(object o)
		{
			if (o is CertBag)
			{
				return (CertBag)o;
			}
			else if (o != null)
			{
				return new CertBag(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CertBag(ASN1ObjectIdentifier certId, ASN1Encodable certValue)
		{
			this.certId = certId;
			this.certValue = certValue;
		}

		public virtual ASN1ObjectIdentifier getCertId()
		{
			return certId;
		}

		public virtual ASN1Encodable getCertValue()
		{
			return certValue;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certId);
			v.add(new DERTaggedObject(0, certValue));

			return new DERSequence(v);
		}
	}

}