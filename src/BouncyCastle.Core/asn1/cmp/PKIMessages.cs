namespace org.bouncycastle.asn1.cmp
{

	public class PKIMessages : ASN1Object
	{
		private ASN1Sequence content;

		private PKIMessages(ASN1Sequence seq)
		{
			content = seq;
		}

		public static PKIMessages getInstance(object o)
		{
			if (o is PKIMessages)
			{
				return (PKIMessages)o;
			}

			if (o != null)
			{
				return new PKIMessages(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public PKIMessages(PKIMessage msg)
		{
			content = new DERSequence(msg);
		}

		public PKIMessages(PKIMessage[] msgs)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < msgs.Length; i++)
			{
				v.add(msgs[i]);
			}
			content = new DERSequence(v);
		}

		public virtual PKIMessage[] toPKIMessageArray()
		{
			PKIMessage[] result = new PKIMessage[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = PKIMessage.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}