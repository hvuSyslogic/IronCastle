namespace org.bouncycastle.asn1
{
	public class BERFactory
	{
		internal static readonly BERSequence EMPTY_SEQUENCE = new BERSequence();
		internal static readonly BERSet EMPTY_SET = new BERSet();

		internal static BERSequence createSequence(ASN1EncodableVector v)
		{
			return v.size() < 1 ? EMPTY_SEQUENCE : new BERSequence(v);
		}

		internal static BERSet createSet(ASN1EncodableVector v)
		{
			return v.size() < 1 ? EMPTY_SET : new BERSet(v);
		}
	}

}