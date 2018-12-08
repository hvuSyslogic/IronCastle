using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.esf
{


	/// <summary>
	/// <pre>
	/// CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
	/// </pre>
	/// </summary>
	public class CompleteRevocationRefs : ASN1Object
	{

		private ASN1Sequence crlOcspRefs;

		public static CompleteRevocationRefs getInstance(object obj)
		{
			if (obj is CompleteRevocationRefs)
			{
				return (CompleteRevocationRefs)obj;
			}
			else if (obj != null)
			{
				return new CompleteRevocationRefs(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private CompleteRevocationRefs(ASN1Sequence seq)
		{
			Enumeration seqEnum = seq.getObjects();
			while (seqEnum.hasMoreElements())
			{
				CrlOcspRef.getInstance(seqEnum.nextElement());
			}
			this.crlOcspRefs = seq;
		}

		public CompleteRevocationRefs(CrlOcspRef[] crlOcspRefs)
		{
			this.crlOcspRefs = new DERSequence(crlOcspRefs);
		}

		public virtual CrlOcspRef[] getCrlOcspRefs()
		{
			CrlOcspRef[] result = new CrlOcspRef[this.crlOcspRefs.size()];
			for (int idx = 0; idx < result.Length; idx++)
			{
				result[idx] = CrlOcspRef.getInstance(this.crlOcspRefs.getObjectAt(idx));
			}
			return result;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return this.crlOcspRefs;
		}
	}

}