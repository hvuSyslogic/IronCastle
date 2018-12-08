using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	/// -- Used to return status state in a response
	/// 
	/// id-cmc-statusInfo OBJECT IDENTIFIER ::= {id-cmc 1}
	/// 
	/// CMCStatusInfo ::= SEQUENCE {
	///     cMCStatus       CMCStatus,
	///     bodyList        SEQUENCE SIZE (1..MAX) OF BodyPartID,
	///     statusString    UTF8String OPTIONAL,
	///     otherInfo        CHOICE {
	///       failInfo         CMCFailInfo,
	///       pendInfo         PendInfo } OPTIONAL
	/// }
	/// </pre>
	/// </summary>
	public class CMCStatusInfo : ASN1Object
	{
		private readonly CMCStatus cMCStatus;
		private readonly ASN1Sequence bodyList;
		private readonly DERUTF8String statusString;
		private readonly OtherInfo otherInfo;

		public CMCStatusInfo(CMCStatus cMCStatus, ASN1Sequence bodyList, DERUTF8String statusString, OtherInfo otherInfo)
		{
			this.cMCStatus = cMCStatus;
			this.bodyList = bodyList;
			this.statusString = statusString;
			this.otherInfo = otherInfo;
		}

		private CMCStatusInfo(ASN1Sequence seq)
		{
			if (seq.size() < 2 || seq.size() > 4)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.cMCStatus = CMCStatus.getInstance(seq.getObjectAt(0));
			this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));

			if (seq.size() > 3)
			{
				this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
				this.otherInfo = OtherInfo.getInstance(seq.getObjectAt(3));
			}
			else if (seq.size() > 2)
			{
				if (seq.getObjectAt(2) is DERUTF8String)
				{
					this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
					this.otherInfo = null;
				}
				else
				{
					this.statusString = null;
					this.otherInfo = OtherInfo.getInstance(seq.getObjectAt(2));
				}
			}
			else
			{
				this.statusString = null;
				this.otherInfo = null;
			}
		}

		public static CMCStatusInfo getInstance(object o)
		{
			if (o is CMCStatusInfo)
			{
				return (CMCStatusInfo)o;
			}

			if (o != null)
			{
				return new CMCStatusInfo(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(cMCStatus);
			v.add(bodyList);
			if (statusString != null)
			{
				v.add(statusString);
			}
			if (otherInfo != null)
			{
				v.add(otherInfo);
			}
			return new DERSequence(v);
		}

		public virtual CMCStatus getCMCStatus()
		{
			return cMCStatus;
		}

		public virtual BodyPartID[] getBodyList()
		{
			return Utils.toBodyPartIDArray(bodyList);
		}

		public virtual DERUTF8String getStatusString()
		{
			return statusString;
		}

		public virtual bool hasOtherInfo()
		{
			return otherInfo != null;
		}

		public virtual OtherInfo getOtherInfo()
		{
			return otherInfo;
		}

		/// <summary>
		/// Other info implements the choice component of CMCStatusInfo.
		/// </summary>
		public class OtherInfo : ASN1Object, ASN1Choice
		{
			internal readonly CMCFailInfo failInfo;
			internal readonly PendInfo pendInfo;

			internal static OtherInfo getInstance(object obj)
			{
				if (obj is OtherInfo)
				{
					return (OtherInfo)obj;
				}

				if (obj is ASN1Encodable)
				{
					ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();

					if (asn1Value is ASN1Integer) // CMCFail info is an asn1 integer.
					{
						return new OtherInfo(CMCFailInfo.getInstance(asn1Value));
					}
					else if (asn1Value is ASN1Sequence) // PendInfo is a sequence.
					{
						return new OtherInfo(PendInfo.getInstance(asn1Value));
					}
				}
				throw new IllegalArgumentException("unknown object in getInstance(): " + obj.GetType().getName());
			}

			public OtherInfo(CMCFailInfo failInfo) : this(failInfo, null)
			{
			}

			public OtherInfo(PendInfo pendInfo) : this(null, pendInfo)
			{
			}

			public OtherInfo(CMCFailInfo failInfo, PendInfo pendInfo)
			{
				this.failInfo = failInfo;
				this.pendInfo = pendInfo;
			}

			public virtual bool isFailInfo()
			{
				return failInfo != null;
			}

			public override ASN1Primitive toASN1Primitive()
			{
				if (pendInfo != null)
				{
					return pendInfo.toASN1Primitive();
				}
				return failInfo.toASN1Primitive();
			}
		}
	}

}