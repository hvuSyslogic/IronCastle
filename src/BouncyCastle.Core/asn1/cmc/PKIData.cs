using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	/// PKIData ::= SEQUENCE {
	/// controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
	/// reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
	/// cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
	/// otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
	/// }
	/// </pre>
	/// </summary>
	public class PKIData : ASN1Object
	{
		private readonly TaggedAttribute[] controlSequence;
		private readonly TaggedRequest[] reqSequence;
		private readonly TaggedContentInfo[] cmsSequence;
		private readonly OtherMsg[] otherMsgSequence;


		public PKIData(TaggedAttribute[] controlSequence, TaggedRequest[] reqSequence, TaggedContentInfo[] cmsSequence, OtherMsg[] otherMsgSequence)
		{
			this.controlSequence = copy(controlSequence);
			this.reqSequence = copy(reqSequence);
			this.cmsSequence = copy(cmsSequence);
			this.otherMsgSequence = copy(otherMsgSequence);
		}

		private PKIData(ASN1Sequence seq)
		{
			if (seq.size() != 4)
			{
				throw new IllegalArgumentException("Sequence not 4 elements.");
			}

			ASN1Sequence s = ((ASN1Sequence)seq.getObjectAt(0));
			controlSequence = new TaggedAttribute[s.size()];
			for (int t = 0; t < controlSequence.Length; t++)
			{
				controlSequence[t] = TaggedAttribute.getInstance(s.getObjectAt(t));
			}

			s = ((ASN1Sequence)seq.getObjectAt(1));
			reqSequence = new TaggedRequest[s.size()];
			for (int t = 0; t < reqSequence.Length; t++)
			{
				reqSequence[t] = TaggedRequest.getInstance(s.getObjectAt(t));
			}

			s = ((ASN1Sequence)seq.getObjectAt(2));
			cmsSequence = new TaggedContentInfo[s.size()];
			for (int t = 0; t < cmsSequence.Length; t++)
			{
				cmsSequence[t] = TaggedContentInfo.getInstance(s.getObjectAt(t));
			}

			s = ((ASN1Sequence)seq.getObjectAt(3));
			otherMsgSequence = new OtherMsg[s.size()];
			for (int t = 0; t < otherMsgSequence.Length; t++)
			{
				otherMsgSequence[t] = OtherMsg.getInstance(s.getObjectAt(t));
			}
		}

		public static PKIData getInstance(object src)
		{
			if (src is PKIData)
			{
				return (PKIData)src;
			}
			if (src != null)
			{
				return new PKIData(ASN1Sequence.getInstance(src));
			}
			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(new ASN1Encodable[]
			{
				new DERSequence(controlSequence),
				new DERSequence(reqSequence),
				new DERSequence(cmsSequence),
				new DERSequence(otherMsgSequence)
			});

		}

		public virtual TaggedAttribute[] getControlSequence()
		{
			return copy(controlSequence);
		}

		private TaggedAttribute[] copy(TaggedAttribute[] taggedAtts)
		{
			TaggedAttribute[] tmp = new TaggedAttribute[taggedAtts.Length];

			JavaSystem.arraycopy(taggedAtts, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		public virtual TaggedRequest[] getReqSequence()
		{
			return copy(reqSequence);
		}

		private TaggedRequest[] copy(TaggedRequest[] taggedReqs)
		{
			TaggedRequest[] tmp = new TaggedRequest[taggedReqs.Length];

			JavaSystem.arraycopy(taggedReqs, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		public virtual TaggedContentInfo[] getCmsSequence()
		{
			return copy(cmsSequence);
		}

		private TaggedContentInfo[] copy(TaggedContentInfo[] taggedConts)
		{
			TaggedContentInfo[] tmp = new TaggedContentInfo[taggedConts.Length];

			JavaSystem.arraycopy(taggedConts, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		public virtual OtherMsg[] getOtherMsgSequence()
		{
			return copy(otherMsgSequence);
		}

		private OtherMsg[] copy(OtherMsg[] otherMsgs)
		{
			OtherMsg[] tmp = new OtherMsg[otherMsgs.Length];

			JavaSystem.arraycopy(otherMsgs, 0, tmp, 0, tmp.Length);

			return tmp;
		}
	}

}