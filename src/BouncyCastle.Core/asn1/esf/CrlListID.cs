using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.esf
{


	/// <summary>
	/// <pre>
	/// CRLListID ::= SEQUENCE {
	///     crls SEQUENCE OF CrlValidatedID }
	/// </pre>
	/// </summary>
	public class CrlListID : ASN1Object
	{

		private ASN1Sequence crls;

		public static CrlListID getInstance(object obj)
		{
			if (obj is CrlListID)
			{
				return (CrlListID)obj;
			}
			else if (obj != null)
			{
				return new CrlListID(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private CrlListID(ASN1Sequence seq)
		{
			this.crls = (ASN1Sequence)seq.getObjectAt(0);
			Enumeration e = this.crls.getObjects();
			while (e.hasMoreElements())
			{
				CrlValidatedID.getInstance(e.nextElement());
			}
		}

		public CrlListID(CrlValidatedID[] crls)
		{
			this.crls = new DERSequence(crls);
		}

		public virtual CrlValidatedID[] getCrls()
		{
			CrlValidatedID[] result = new CrlValidatedID[this.crls.size()];
			for (int idx = 0; idx < result.Length; idx++)
			{
				result[idx] = CrlValidatedID.getInstance(this.crls.getObjectAt(idx));
			}
			return result;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(this.crls);
		}
	}

}