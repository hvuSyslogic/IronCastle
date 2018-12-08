namespace org.bouncycastle.asn1.crmf
{

	public class CertReqMessages : ASN1Object
	{
		private ASN1Sequence content;

		private CertReqMessages(ASN1Sequence seq)
		{
			content = seq;
		}

		public static CertReqMessages getInstance(object o)
		{
			if (o is CertReqMessages)
			{
				return (CertReqMessages)o;
			}

			if (o != null)
			{
				return new CertReqMessages(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CertReqMessages(CertReqMsg msg)
		{
			content = new DERSequence(msg);
		}

		public CertReqMessages(CertReqMsg[] msgs)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < msgs.Length; i++)
			{
				v.add(msgs[i]);
			}
			content = new DERSequence(v);
		}

		public virtual CertReqMsg[] toCertReqMsgArray()
		{
			CertReqMsg[] result = new CertReqMsg[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = CertReqMsg.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
		/// </pre>
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}