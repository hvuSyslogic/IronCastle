namespace org.bouncycastle.asn1.cmp
{

	public class CertConfirmContent : ASN1Object
	{
		private ASN1Sequence content;

		private CertConfirmContent(ASN1Sequence seq)
		{
			content = seq;
		}

		public static CertConfirmContent getInstance(object o)
		{
			if (o is CertConfirmContent)
			{
				return (CertConfirmContent)o;
			}

			if (o != null)
			{
				return new CertConfirmContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual CertStatus[] toCertStatusArray()
		{
			CertStatus[] result = new CertStatus[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = CertStatus.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// CertConfirmContent ::= SEQUENCE OF CertStatus
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}