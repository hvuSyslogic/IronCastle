namespace org.bouncycastle.asn1.cmp
{

	public class PollRepContent : ASN1Object
	{
		private ASN1Integer[] certReqId;
		private ASN1Integer[] checkAfter;
		private PKIFreeText[] reason;

		private PollRepContent(ASN1Sequence seq)
		{
			certReqId = new ASN1Integer[seq.size()];
			checkAfter = new ASN1Integer[seq.size()];
			reason = new PKIFreeText[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				ASN1Sequence s = ASN1Sequence.getInstance(seq.getObjectAt(i));

				certReqId[i] = ASN1Integer.getInstance(s.getObjectAt(0));
				checkAfter[i] = ASN1Integer.getInstance(s.getObjectAt(1));

				if (s.size() > 2)
				{
					reason[i] = PKIFreeText.getInstance(s.getObjectAt(2));
				}
			}
		}

		public static PollRepContent getInstance(object o)
		{
			if (o is PollRepContent)
			{
				return (PollRepContent)o;
			}

			if (o != null)
			{
				return new PollRepContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public PollRepContent(ASN1Integer certReqId, ASN1Integer checkAfter) : this(certReqId, checkAfter, null)
		{
		}

		public PollRepContent(ASN1Integer certReqId, ASN1Integer checkAfter, PKIFreeText reason)
		{
			this.certReqId = new ASN1Integer[1];
			this.checkAfter = new ASN1Integer[1];
			this.reason = new PKIFreeText[1];

			this.certReqId[0] = certReqId;
			this.checkAfter[0] = checkAfter;
			this.reason[0] = reason;
		}

		public virtual int size()
		{
			return certReqId.Length;
		}

		public virtual ASN1Integer getCertReqId(int index)
		{
			return certReqId[index];
		}

		public virtual ASN1Integer getCheckAfter(int index)
		{
			return checkAfter[index];
		}

		public virtual PKIFreeText getReason(int index)
		{
			return reason[index];
		}

		/// <summary>
		/// <pre>
		/// PollRepContent ::= SEQUENCE OF SEQUENCE {
		///         certReqId              INTEGER,
		///         checkAfter             INTEGER,  -- time in seconds
		///         reason                 PKIFreeText OPTIONAL
		///     }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector outer = new ASN1EncodableVector();

			for (int i = 0; i != certReqId.Length; i++)
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				v.add(certReqId[i]);
				v.add(checkAfter[i]);

				if (reason[i] != null)
				{
					v.add(reason[i]);
				}

				outer.add(new DERSequence(v));
			}

			return new DERSequence(outer);
		}
	}

}