namespace org.bouncycastle.asn1
{
	public class DERFactory
	{
		internal static readonly ASN1Sequence EMPTY_SEQUENCE = new DERSequence();
		internal static readonly ASN1Set EMPTY_SET = new DERSet();

		internal static ASN1Sequence createSequence(ASN1EncodableVector v)
		{
			return v.size() < 1 ? EMPTY_SEQUENCE : new DLSequence(v);
		}

		internal static ASN1Set createSet(ASN1EncodableVector v)
		{
			return v.size() < 1 ? EMPTY_SET : new DLSet(v);
		}
	}

}