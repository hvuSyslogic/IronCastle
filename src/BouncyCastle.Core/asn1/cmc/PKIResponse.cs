using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	///    --  This defines the response message in the protocol
	///  id-cct-PKIResponse OBJECT IDENTIFIER ::= { id-cct 3 }
	/// 
	/// ResponseBody ::= PKIResponse
	/// 
	/// PKIResponse ::= SEQUENCE {
	///     controlSequence   SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
	///     cmsSequence       SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
	///     otherMsgSequence  SEQUENCE SIZE(0..MAX) OF OtherMsg
	/// }
	/// </pre>
	/// </summary>
	public class PKIResponse : ASN1Object
	{
		private readonly ASN1Sequence controlSequence;
		private readonly ASN1Sequence cmsSequence;
		private readonly ASN1Sequence otherMsgSequence;

		private PKIResponse(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.controlSequence = ASN1Sequence.getInstance(seq.getObjectAt(0));
			this.cmsSequence = ASN1Sequence.getInstance(seq.getObjectAt(1));
			this.otherMsgSequence = ASN1Sequence.getInstance(seq.getObjectAt(2));
		}


		public static PKIResponse getInstance(object o)
		{
			if (o is PKIResponse)
			{
				return (PKIResponse)o;
			}

			if (o != null)
			{
				return new PKIResponse(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public static PKIResponse getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(controlSequence);
			v.add(cmsSequence);
			v.add(otherMsgSequence);

			return new DERSequence(v);
		}

		public virtual ASN1Sequence getControlSequence()
		{
			return controlSequence;
		}

		public virtual ASN1Sequence getCmsSequence()
		{
			return cmsSequence;
		}

		public virtual ASN1Sequence getOtherMsgSequence()
		{
			return otherMsgSequence;
		}
	}

}