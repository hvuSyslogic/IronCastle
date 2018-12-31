using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.crmf
{


	/// <summary>
	/// <pre>
	/// PKIPublicationInfo ::= SEQUENCE {
	///                  action     INTEGER {
	///                                 dontPublish (0),
	///                                 pleasePublish (1) },
	///                  pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
	/// -- pubInfos MUST NOT be present if action is "dontPublish"
	/// -- (if action is "pleasePublish" and pubInfos is omitted,
	/// -- "dontCare" is assumed)
	/// </pre>
	/// </summary>
	public class PKIPublicationInfo : ASN1Object
	{
		public static readonly ASN1Integer dontPublish = new ASN1Integer(0);
		public static readonly ASN1Integer pleasePublish = new ASN1Integer(1);

		private ASN1Integer action;
		private ASN1Sequence pubInfos;

		private PKIPublicationInfo(ASN1Sequence seq)
		{
			action = ASN1Integer.getInstance(seq.getObjectAt(0));
			if (seq.size() > 1)
			{
				pubInfos = ASN1Sequence.getInstance(seq.getObjectAt(1));
			}
		}

		public static PKIPublicationInfo getInstance(object o)
		{
			if (o is PKIPublicationInfo)
			{
				return (PKIPublicationInfo)o;
			}

			if (o != null)
			{
				return new PKIPublicationInfo(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public PKIPublicationInfo(BigInteger action) : this(new ASN1Integer(action))
		{
		}

		public PKIPublicationInfo(ASN1Integer action)
		{
			this.action = action;
		}

		/// <summary>
		/// Constructor with a single pubInfo, assumes pleasePublish as the action.
		/// </summary>
		/// <param name="pubInfo"> the pubInfo to be published (can be null if don't care is required). </param>
		public PKIPublicationInfo(SinglePubInfo pubInfo) : this(pubInfo != null ? new SinglePubInfo[] {pubInfo} : null)
		{
		}

		/// <summary>
		/// Constructor with multiple pubInfo, assumes pleasePublish as the action.
		/// </summary>
		/// <param name="pubInfos"> the pubInfos to be published (can be null if don't care is required). </param>
		public PKIPublicationInfo(SinglePubInfo[] pubInfos)
		{
			this.action = pleasePublish;

			if (pubInfos != null)
			{
				this.pubInfos = new DERSequence(pubInfos);
			}
			else
			{
				this.pubInfos = null;
			}
		}

		public virtual ASN1Integer getAction()
		{
			return action;
		}

		public virtual SinglePubInfo[] getPubInfos()
		{
			if (pubInfos == null)
			{
				return null;
			}

			SinglePubInfo[] results = new SinglePubInfo[pubInfos.size()];

			for (int i = 0; i != results.Length; i++)
			{
				results[i] = SinglePubInfo.getInstance(pubInfos.getObjectAt(i));
			}

			return results;
		}

		/// <summary>
		/// Return the primitive representation of PKIPublicationInfo.
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(action);

			if (pubInfos != null)
			{
				v.add(pubInfos);
			}

			return new DERSequence(v);
		}
	}

}